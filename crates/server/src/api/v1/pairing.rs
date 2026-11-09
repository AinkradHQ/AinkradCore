//! Pairing, the approver's side (handshake spec §7.2 steps 1, 5 and 7): an `admin` device
//! creates a pairing bound to a name, kind and scopes (never wider than its own), sees the
//! claimant and the SAS the Core computed, and approves by sending that SAS back, or rejects.
//! Every route needs `admin` (`scopes`) and a live elevation (`scopes::DESTRUCTIVE`). The new
//! device's side is `pair` (`passkey` for a browser's passkey).

use ainkrad_core::settings::{Key, Scope};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::auth::pairing::{qr, show_code};
use crate::scheduler::iso_of_unix;
use crate::store::gov::{self, Decider, Decision, NewPairing, SCOPES};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPairingBody {
    /// What to call the new device.
    pub name: String,
    /// `device`, `runner`, or `passkey` (a browser, E1-08; only when the Core has passkeys).
    pub kind: String,
    /// What it may do: within the approver's own scopes; a runner gets exactly `runner`.
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PairingCreated {
    /// `p_…`.
    pub pairing_id: Option<String>,
    /// The typed code, `ABCDE-FGHJK`: shown once, good once, for 5 minutes.
    pub code: Option<String>,
    /// `ainkrad-pair:v1?h=…&p=…&c=<core_fp>&s=<secret>&e=…`, for a QR code: shown once.
    pub qr: Option<String>,
    pub expires_at: Option<Timestamp>,
}

/// A pairing as the approver sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PairingView {
    pub pairing_id: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    /// `live`, `claimed`, `approved`, `rejected`, `expired` or `burned`.
    pub status: Option<String>,
    pub expires_at: Option<Timestamp>,
    /// The claimant, once claimed.
    pub device_id: Option<String>,
    /// The SAS the Core computed from its key and the claimant's: compare it with the new
    /// device's screen, then send it back to approve.
    pub sas: Option<String>,
    /// The claimant's routine key fingerprint.
    pub fingerprint: Option<String>,
    pub platform: Option<String>,
    /// Where the claimant says its key lives: a claim, not verified.
    pub key_storage: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    /// The SAS shown on both screens.
    pub sas: String,
    /// Narrower scopes than the pairing bound; never wider.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

/// T-PK-3: a passkey never gets `admin` unless `auth.passkey_admin` is 1. Checked wherever a
/// passkey device would newly hold it: at pairing, at approval and at a scope change.
pub(super) async fn passkey_admin(
    app: &App,
    kind: &str,
    scopes: &[String],
) -> Result<(), ApiError> {
    if kind != "passkey" || !scopes.iter().any(|s| s == "admin") {
        return Ok(());
    }
    let on = crate::store::settings::value(&app.pool, Key::AuthPasskeyAdmin, Scope::Server).await?;
    match on {
        0 => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "a passkey does not get the admin scope (setting auth.passkey_admin)",
        )),
        _ => Ok(()),
    }
}

fn forbidden_scope() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden_scope",
        "this device's scopes do not allow that",
    )
}

#[utoipa::path(post, path = "/api/v1/pairings", operation_id = "createPairing", tag = "pairing",
    request_body = NewPairingBody,
    responses((status = 200, description = "A pairing, live 5 minutes, with its typed code and \
        QR payload, shown only now (audited as `pairing.created`). Needs `admin`; the scopes are \
        within the caller's (403 otherwise); 409 with three live already", body = PairingCreated)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewPairingBody>,
) -> ApiResult<PairingCreated> {
    let mut scopes = b.scopes;
    scopes.sort();
    scopes.dedup();
    if b.name.trim().is_empty() || b.name.len() > 100 {
        return Err(ApiError::bad_request(
            "a device needs a name, at most 100 bytes",
        ));
    }
    match b.kind.as_str() {
        "device" => {}
        "runner" if scopes == ["runner"] => {}
        "runner" => {
            return Err(ApiError::bad_request(
                "a runner gets exactly the runner scope",
            ));
        }
        // A browser's passkey (E1-08.2): created only here, by an elevated admin device, never
        // by the browser itself; it never holds `runner`.
        "passkey" if app.passkeys.is_none() => {
            return Err(ApiError::bad_request(
                "passkeys are not enabled on this Core",
            ));
        }
        "passkey" if scopes.iter().any(|s| s == "runner") => {
            return Err(ApiError::bad_request(
                "a passkey never gets the runner scope",
            ));
        }
        "passkey" => {}
        _ => return Err(ApiError::bad_request("kind is device, runner or passkey")),
    }
    if scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return Err(ApiError::bad_request("unknown scope"));
    }
    if scopes.iter().any(|s| !me.device.scopes.contains(s)) {
        return Err(forbidden_scope());
    }
    passkey_admin(&app, &b.kind, &scopes).await?;
    let new = NewPairing {
        kind: &b.kind,
        name: &b.name,
        scopes: &scopes,
        created_by: Some(&me.device.id),
        bootstrap: false,
        recovery: false,
    };
    let created = gov::create_pairing(&app.pool, &new, BY, app.clock.unix())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::conflict(why),
            e => e.into(),
        })?;
    Ok(Json(PairingCreated {
        pairing_id: Some(created.id),
        code: Some(show_code(&created.code)),
        qr: Some(qr(
            &app.host,
            &app.auth.identity.fp,
            &created.secret,
            created.expires,
        )),
        expires_at: Some(ts(&iso_of_unix(created.expires))),
    }))
}

async fn view(app: &App, id: &str) -> ApiResult<PairingView> {
    let p = match is_id(id, "p_") {
        true => gov::get_pairing(&app.pool, id).await?,
        false => None,
    }
    .ok_or_else(|| ApiError::not_found("no such pairing"))?;
    let device = match &p.device_id {
        Some(d) => gov::get_device(&app.pool, d).await?,
        None => None,
    };
    Ok(Json(PairingView {
        pairing_id: Some(p.id),
        kind: Some(p.kind),
        name: Some(p.name),
        scopes: Some(p.scopes),
        status: Some(p.status),
        expires_at: Some(ts(&p.expires_at)),
        device_id: p.device_id,
        sas: p.sas,
        fingerprint: device.as_ref().map(|d| d.fingerprint.clone()),
        platform: device.as_ref().and_then(|d| d.platform.clone()),
        key_storage: device.and_then(|d| d.key_storage),
    }))
}

#[utoipa::path(get, path = "/api/v1/pairings/{id}", operation_id = "getPairing", tag = "pairing",
    params(("id" = String, Path, description = "Pairing id, `p_…`")),
    responses((status = 200, description = "The pairing, and once claimed the claimant and the \
        SAS to compare. Needs `admin`", body = PairingView)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<PairingView> {
    view(&app, &id).await
}

fn decision(d: Decision) -> Result<(), ApiError> {
    let conflict = |code, why: &str| ApiError::new(StatusCode::CONFLICT, code, why);
    match d {
        Decision::Done => Ok(()),
        Decision::NotFound => Err(ApiError::not_found("no such pairing")),
        Decision::NotPending => Err(conflict(
            "conflict",
            "the pairing is not waiting on a decision",
        )),
        Decision::Expired => Err(conflict("pairing_expired", "the pairing expired")),
        Decision::SasMismatch => Err(conflict("sas_mismatch", "the SAS does not match")),
        Decision::Wider => Err(forbidden_scope()),
    }
}

#[utoipa::path(post, path = "/api/v1/pairings/{id}/approve", operation_id = "approvePairing",
    tag = "pairing", request_body = ApproveBody,
    params(("id" = String, Path, description = "Pairing id, `p_…`")),
    responses((status = 200, description = "Approved: the claimant is active with the bound (or \
        narrower) scopes (audited as `pairing.approved`). 409 `sas_mismatch` leaves it pending; \
        409 `pairing_expired` past its 5 minutes; 403 for scopes wider than bound. Needs `admin`",
        body = PairingView)))]
pub async fn approve(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<ApproveBody>,
) -> ApiResult<PairingView> {
    let by = Decider {
        actor: BY,
        device: Some(&me.device.id),
        scopes: Some(&me.device.scopes),
    };
    // The setting may have been turned off since the pairing was created. Kind and bound
    // scopes never change after creation, so this read cannot race the decision below.
    if let Some(p) = gov::get_pairing(&app.pool, &id).await? {
        passkey_admin(&app, &p.kind, b.scopes.as_deref().unwrap_or(&p.scopes)).await?;
    }
    let now = app.clock.unix();
    decision(gov::approve_pairing(&app.pool, &id, &b.sas, b.scopes.as_deref(), by, now).await?)?;
    view(&app, &id).await
}

#[utoipa::path(post, path = "/api/v1/pairings/{id}/reject", operation_id = "rejectPairing",
    tag = "pairing", params(("id" = String, Path, description = "Pairing id, `p_…`")),
    responses((status = 200, description = "Rejected, claimed or not: a claimant is never \
        usable (audited as `pairing.rejected`). Needs `admin`", body = PairingView)))]
pub async fn reject(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<PairingView> {
    let by = Decider {
        actor: BY,
        device: Some(&me.device.id),
        scopes: Some(&me.device.scopes),
    };
    decision(gov::reject_pairing(&app.pool, &id, by, app.clock.unix()).await?)?;
    view(&app, &id).await
}
