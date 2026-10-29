//! Pairing, the new device's side (handshake spec §7.2 steps 3 and 8), before it has any
//! standing: `POST /pair/claim` with the typed code or the QR secret, its public keys and their
//! proof of possession, then `POST /pair/status`, signed with session `-`, until approved.
//!
//! A wrong, used, expired or burned credential is the one `pairing_failed`, counted against the
//! address (§11) and the global wrong-claim budget (20 in 5 minutes burn every live pairing,
//! §7.4), and audited. A bootstrap pairing is claimable only over this server's Unix socket by
//! its own user (§7.3).

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::gate::{self, Mode};
use super::{ApiError, too_many};
use crate::api::App;
use crate::auth::crypto::{b64, fingerprint, random_id, spki_point, unb64, verify};
use crate::auth::pairing::{code_hash, normal_code, pop_message, sas, secret_hash};
use crate::gateway::Local;
use crate::gateway::preauth::PREAUTH_BODY;
use crate::store::gov::{self, ADDRESS, Claim};

const KEY_STORAGE: [&str; 5] = ["secure_enclave", "strongbox", "tee", "tpm", "software"];

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimBody {
    /// The typed code (`ABCDE-FGHJK`, any case); or `secret`.
    #[serde(default)]
    pub code: Option<String>,
    /// The QR secret; or `code`.
    #[serde(default)]
    pub secret: Option<String>,
    /// The routine key: a P-256 SubjectPublicKeyInfo, base64url.
    pub routine_spki: String,
    /// The step-up key, where the device has one.
    #[serde(default)]
    pub stepup_spki: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    /// `secure_enclave`, `strongbox`, `tee`, `tpm` or `software`: a claim.
    #[serde(default)]
    pub key_storage: Option<String>,
    /// The routine key over `AINKRAD-PAIR-V1\n<core_fp>\n<b64(SHA-256(credential))>\n
    /// <fp(routine)>\n<fp(stepup) or ->`, raw r||s, base64url.
    pub pop: String,
    /// The step-up key over the same string, with `stepup_spki`.
    #[serde(default)]
    pub pop_stepup: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Claimed {
    /// The new device, `d_…`, pending until approved.
    pub device_id: Option<String>,
    /// The Core identity SPKI, base64url: its fingerprint must equal the QR's `c`.
    pub core_spki: Option<String>,
    /// Show this; the approver compares it with theirs.
    pub sas: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PairStatus {
    /// `pending`, `active`, `rejected` or `expired`.
    pub status: Option<String>,
}

fn pairing_failed() -> Response {
    ApiError::new(StatusCode::UNAUTHORIZED, "pairing_failed", "pairing failed").into_response()
}

/// A wrong claim: counted against the address and the global budget (which, once spent,
/// burns every live pairing), audited, and answered as the one `pairing_failed`.
async fn wrong(app: &App, addr: &str, why: &'static str) -> Response {
    tracing::warn!(addr, why, "pairing claim refused");
    let now = app.clock.unix();
    let counted = async {
        gov::record_failure(&app.pool, addr, ADDRESS, now).await?;
        if gov::spend_pair_budget(&app.pool, now).await? {
            let burned = gov::burn_pairings(&app.pool).await?;
            tracing::warn!(
                burned = burned.len(),
                "wrong-claim budget spent: pairings burned"
            );
        }
        gov::audit_refusal(&app.pool, json!({"reason": why, "address": addr})).await
    };
    match counted.await {
        Ok(()) => pairing_failed(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

fn bad(why: &str) -> Response {
    ApiError::bad_request(why).into_response()
}

#[utoipa::path(post, path = "/pair/claim", operation_id = "claimPairing", tag = "pairing",
    request_body = ClaimBody, security(()),
    responses((status = 202, description = "Claimed: the device is pending until the approver \
        matches the SAS. 401 `pairing_failed` for a wrong, used, expired or burned credential; \
        400 for keys or proofs that do not hold (the pairing is not spent)", body = Claimed)))]
pub async fn claim(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let now = app.clock.unix();
    match gov::locked_until(&app.pool, &[&addr], now).await {
        Ok(Some(until)) => return too_many(std::time::Duration::from_secs((until - now) as u64)),
        Ok(None) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    let bytes = match gate::body(raw, PREAUTH_BODY).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Ok(b) = serde_json::from_slice::<ClaimBody>(&bytes) else {
        return bad("malformed body");
    };
    let (hash, by_code) = match (&b.code, &b.secret) {
        (Some(code), None) => match normal_code(code) {
            Some(c) => (code_hash(&c), true),
            None => return wrong(&app, &addr, "malformed code").await,
        },
        (None, Some(secret)) => match unb64(secret, 22) {
            Some(s) => (secret_hash(&s), false),
            None => return wrong(&app, &addr, "malformed secret").await,
        },
        _ => return bad("send one of code and secret"),
    };
    let pairing = match gov::find_pairing(&app.pool, &hash, by_code).await {
        Ok(Some(p)) if p.status == "live" => p,
        Ok(_) => return wrong(&app, &addr, "no live pairing").await,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let local = parts.extensions.get::<Local>().is_some_and(|l| l.same_user);
    if pairing.bootstrap && !local {
        return wrong(
            &app,
            &addr,
            "bootstrap claimed from outside the host's socket",
        )
        .await;
    }
    // The keys and their proofs; a failure here does not spend the pairing.
    let key = |text: &str| unb64(text, 122).filter(|k| spki_point(k).is_some());
    let Some(routine) = key(&b.routine_spki) else {
        return bad("routine_spki is a P-256 SubjectPublicKeyInfo, base64url");
    };
    let stepup = match &b.stepup_spki {
        Some(s) => match key(s) {
            Some(k) => Some(k),
            None => return bad("stepup_spki is a P-256 SubjectPublicKeyInfo, base64url"),
        },
        None => None,
    };
    if b.key_storage
        .as_deref()
        .is_some_and(|k| !KEY_STORAGE.contains(&k))
        || b.platform.as_deref().is_some_and(|p| p.len() > 64)
    {
        return bad("unknown key_storage, or a platform over 64 bytes");
    }
    let stepup_fp = stepup.as_deref().map(fingerprint);
    let message = pop_message(
        &app.auth.identity.fp,
        &hash,
        &fingerprint(&routine),
        stepup_fp.as_deref(),
    );
    let proves = |key: &[u8], sig: Option<&String>| {
        sig.and_then(|s| unb64(s, 86))
            .is_some_and(|s| verify(key, &message, &s))
    };
    if !proves(&routine, Some(&b.pop))
        || stepup
            .as_ref()
            .is_some_and(|k| !proves(k, b.pop_stepup.as_ref()))
    {
        return bad("a proof of possession does not verify");
    }
    let device_id = random_id("d_");
    let sas = sas(&app.auth.identity.spki, &routine, &pairing.id);
    let claim = Claim {
        pairing: &pairing,
        device_id: &device_id,
        routine_spki: &routine,
        stepup_spki: stepup.as_deref(),
        platform: b.platform.as_deref(),
        key_storage: b.key_storage.as_deref(),
        sas: &sas,
    };
    match gov::claim_pairing(&app.pool, &claim, now).await {
        Ok(true) => {}
        Ok(false) => return wrong(&app, &addr, "pairing no longer live").await,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return ApiError::conflict("this key is enrolled already").into_response();
        }
        Err(e) => return ApiError::from(e).into_response(),
    }
    tracing::info!(device = device_id, pairing = pairing.id, "pairing claimed");
    let body = Claimed {
        device_id: Some(device_id),
        core_spki: Some(b64(&app.auth.identity.spki)),
        sas: Some(sas),
    };
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

#[utoipa::path(post, path = "/pair/status", operation_id = "pairStatus", tag = "pairing",
    security(()),
    params(
        ("Ainkrad-Device" = String, Header, description = "The claimed device, `d_…`"),
        ("Ainkrad-Alg" = String, Header, description = "`ES256`"),
        ("Ainkrad-Timestamp" = i64, Header, description = "Unix seconds"),
        ("Ainkrad-Nonce" = String, Header, description = "16 random bytes, base64url"),
        ("Ainkrad-Signature" = String, Header,
            description = "Raw r||s over the canonical string with session `-`, base64url")),
    responses((status = 200, description = "Where the claimed device stands. Signed with \
        session `-`; the one call a pending device may make. Once `active`, it takes a session \
        (`/handshake/challenge`)", body = PairStatus)))]
pub async fn status(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    match gate::verify(&app, &parts, raw, PREAUTH_BODY, &addr, Mode::Pairing).await {
        Ok(v) => Json(PairStatus {
            status: Some(v.device.status),
        })
        .into_response(),
        Err(r) => *r,
    }
}
