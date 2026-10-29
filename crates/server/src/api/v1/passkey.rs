//! Passkey pairing, the browser's side (handshake spec §9 and §7.2, E1-08.2). A passkey is never
//! self-enrolled: an elevated `admin` device creates a pairing of kind `passkey`
//! (`POST /api/v1/pairings`), the browser takes the typed code or QR secret to
//! `POST /pair/passkey/options` for the registration options, creates the credential, and
//! sends it with the same credential to `POST /pair/passkey/claim`. The new device is pending
//! with the credential's public key as its key; the approver compares the SAS (computed over
//! that key) and approves exactly as for any device.
//!
//! Both calls run under the claim budgets (`pair::budgeted`): a wrong, used, expired or burned
//! credential, or one of a pairing that is not a passkey's, is a wrong claim, counted against
//! the address and the global wrong-claim budget, answered as the one `pairing_failed`. Asking
//! for options spends nothing; a new ask replaces the pairing's previous ceremony.

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use super::ApiError;
use super::gate::{self, Refusal};
use super::pair::{Claimed, What, bad, budgeted, live_pairing};
use super::types::{Timestamp, ts};
use crate::api::App;
use crate::auth::crypto::{b64, random_id};
use crate::auth::pairing::sas;
use crate::auth::web::{Passkeys, p256_spki, passkey_count};
use crate::gateway::preauth::PREAUTH_BODY;
use crate::scheduler::unix_secs;
use crate::store::gov::{self, Claim, NewCredential};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyOptionsBody {
    /// The typed code (`ABCDE-FGHJK`, any case); or `secret`.
    #[serde(default)]
    pub code: Option<String>,
    /// The QR secret; or `code`.
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyRegistrationOptions {
    /// `{"publicKey": PublicKeyCredentialCreationOptions}` (WebAuthn, binary fields base64url):
    /// ES256 only, attestation `none`, user verification required, a resident key preferred.
    /// Decode it and pass it to `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub options: Option<Value>,
    /// The pairing's expiry: the credential must be claimed before it.
    pub expires_at: Option<Timestamp>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyClaimBody {
    /// The same code as for the options; or `secret`.
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    /// The created credential as a WebAuthn `RegisterPublicKeyCredential` (`id`, `rawId`,
    /// `type`, `response.attestationObject`, `response.clientDataJSON`, optional
    /// `response.transports`), binary fields base64url.
    #[schema(value_type = Object)]
    pub credential: Value,
    #[serde(default)]
    pub platform: Option<String>,
}

/// The answer of every passkey route on a Core without passkeys.
pub(super) fn disabled() -> Response {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "passkeys_disabled",
        "passkeys are not enabled on this Core",
    )
    .into_response()
}

fn passkeys(app: &App) -> Result<&Passkeys, Refusal> {
    app.passkeys.as_deref().ok_or_else(|| disabled().into())
}

/// A pre-auth JSON body (at most 16 KiB).
pub(super) async fn body<T: for<'de> Deserialize<'de>>(raw: Body) -> Result<T, Refusal> {
    let bytes = gate::body(raw, PREAUTH_BODY).await?;
    serde_json::from_slice(&bytes).map_err(|_| bad("malformed body").into())
}

#[utoipa::path(post, path = "/pair/passkey/options", operation_id = "passkeyRegistrationOptions",
    tag = "pairing", request_body = PasskeyOptionsBody, security(()),
    responses((status = 200, description = "Registration options for a live pairing of kind \
        `passkey`; nothing is spent, and a new ask replaces the previous ceremony. A wrong, used, \
        expired or burned credential, or a pairing of another kind, is 401 `pairing_failed` and \
        counts as a wrong claim; 400 `passkeys_disabled` when the Core has no passkeys",
        body = PasskeyRegistrationOptions)))]
pub async fn options_route(State(app): State<App>, req: Request) -> Response {
    budgeted(&app, req, What::PasskeyOptions).await
}

#[utoipa::path(post, path = "/pair/passkey/claim", operation_id = "claimPasskeyPairing",
    tag = "pairing", request_body = PasskeyClaimBody, security(()),
    responses((status = 202, description = "Claimed: a pending device of kind `passkey`, whose \
        key is the credential's public key (the SAS is computed over it); the approver compares \
        the SAS and approves as for any device. 401 `pairing_failed` as for `/pair/claim`; 400 \
        for a credential that does not verify, is not ES256 or comes without options first (the \
        pairing is not spent); 409 for a credential enrolled already", body = Claimed)))]
pub async fn claim_route(State(app): State<App>, req: Request) -> Response {
    budgeted(&app, req, What::PasskeyClaim).await
}

/// `/pair/passkey/options`, inside the claim budgets.
pub(super) async fn options(
    app: &App,
    parts: &Parts,
    raw: Body,
    now: i64,
) -> Result<Response, &'static str> {
    let pk = match passkeys(app) {
        Ok(pk) => pk,
        Err(r) => return Ok(*r),
    };
    let b: PasskeyOptionsBody = match body(raw).await {
        Ok(b) => b,
        Err(r) => return Ok(*r),
    };
    let (pairing, _) = match live_pairing(app, parts, &b.code, &b.secret, true).await? {
        Ok(found) => found,
        Err(r) => return Ok(r),
    };
    let expires = unix_secs(&pairing.expires_at).unwrap_or(now);
    let options = pk.start_registration(&pairing.id, &pairing.name, now, expires);
    tracing::info!(pairing = pairing.id, "passkey registration options issued");
    Ok(Json(PasskeyRegistrationOptions {
        options: Some(options),
        expires_at: Some(ts(&pairing.expires_at)),
    })
    .into_response())
}

/// `/pair/passkey/claim`, inside the claim budgets.
pub(super) async fn claim(
    app: &App,
    parts: &Parts,
    raw: Body,
    now: i64,
) -> Result<Response, &'static str> {
    let pk = match passkeys(app) {
        Ok(pk) => pk,
        Err(r) => return Ok(*r),
    };
    let b: PasskeyClaimBody = match body(raw).await {
        Ok(b) => b,
        Err(r) => return Ok(*r),
    };
    if b.platform.as_deref().is_some_and(|p| p.len() > 64) {
        return Ok(bad("a platform over 64 bytes"));
    }
    let (pairing, _) = match live_pairing(app, parts, &b.code, &b.secret, true).await? {
        Ok(found) => found,
        Err(r) => return Ok(r),
    };
    let Ok(reg) = serde_json::from_value::<RegisterPublicKeyCredential>(b.credential) else {
        return Ok(bad("credential is a RegisterPublicKeyCredential"));
    };
    let Some(state) = pk.take_registration(&pairing.id, now) else {
        return Ok(bad("ask /pair/passkey/options first"));
    };
    let passkey = match pk.webauthn.finish_passkey_registration(&reg, &state) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(pairing = pairing.id, error = %e, "passkey registration refused");
            return Ok(bad("the credential does not verify"));
        }
    };
    let Some(spki) = p256_spki(&passkey) else {
        return Ok(bad("only ES256 (P-256) passkeys"));
    };
    let record = serde_json::to_string(&passkey).expect("a passkey serialises");
    let transports = reg
        .response
        .transports
        .as_ref()
        .map(|t| serde_json::to_string(t).expect("transports serialise"));
    let device_id = random_id("d_");
    let sas = sas(&app.auth.identity.spki, &spki, &pairing.id);
    let claim = Claim {
        pairing: &pairing,
        device_id: &device_id,
        routine_spki: &spki,
        stepup_spki: None,
        platform: b.platform.as_deref(),
        key_storage: None,
        sas: &sas,
        passkey: Some(NewCredential {
            credential_id: passkey.cred_id(),
            passkey: &record,
            sign_count: passkey_count(&passkey),
            transports: transports.as_deref(),
        }),
    };
    match gov::claim_pairing(&app.pool, &claim, now).await {
        Ok(true) => {}
        Ok(false) => return Err("pairing no longer live"),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Ok(ApiError::conflict("this passkey is enrolled already").into_response());
        }
        Err(e) => return Ok(ApiError::from(e).into_response()),
    }
    tracing::info!(
        device = device_id,
        pairing = pairing.id,
        "passkey pairing claimed"
    );
    let body = Claimed {
        device_id: Some(device_id),
        core_spki: Some(b64(&app.auth.identity.spki)),
        pairing_id: Some(pairing.id.clone()),
        sas: Some(sas),
    };
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}
