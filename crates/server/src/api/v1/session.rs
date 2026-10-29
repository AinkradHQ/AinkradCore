//! Sessions by challenge-response (handshake spec §6): `POST /handshake/challenge` hands out a
//! single-use challenge for a device id (always 200, unknown ids included), and
//! `POST /handshake/session`, signed with session `-`, spends it for a 15-minute session. A
//! session is a non-secret handle, useless without a valid signature; refreshing is running
//! both again. Sessions live in memory: a restart ends every one.

use axum::Json;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::gate::{self, Mode};
use super::types::{Timestamp, ts};
use super::{ApiError, too_many};
use crate::api::App;
use crate::auth::{CHALLENGE_SECS, crypto};
use crate::gateway::preauth::PREAUTH_BODY;
use crate::scheduler::iso_of_unix;
use crate::store::gov;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// The device that will answer it, `d_…`.
    pub device_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Challenge {
    /// 32 random bytes, base64url; spend it once within `expires_in` seconds.
    pub challenge: Option<String>,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    /// A live challenge issued for the signing device.
    pub challenge: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionGrant {
    /// `s_…`: sent as `Ainkrad-Session` on every signed request. Not a secret.
    pub session_id: Option<String>,
    pub expires_at: Option<Timestamp>,
    /// The device's scopes.
    pub scopes: Option<Vec<String>>,
    /// Until when the session is elevated (E1-09); null when it is not.
    pub elevated_until: Option<Timestamp>,
}

fn json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|_| ApiError::bad_request("malformed body"))
}

#[utoipa::path(post, path = "/handshake/challenge", operation_id = "createChallenge",
    tag = "handshake", request_body = ChallengeRequest, security(()),
    responses((status = 200, description = "A single-use challenge for the device, live 60 s. \
        Always answered, for any well-formed device id; 429 past 30 a minute from one address",
        body = Challenge)))]
pub async fn challenge(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let now = app.clock.unix();
    match gov::locked_until(&app.pool, &[&addr], now).await {
        Ok(Some(until)) => {
            return too_many(std::time::Duration::from_secs((until - now).max(1) as u64));
        }
        Ok(None) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    if let Err(wait) = app
        .auth
        .challenge_limit
        .take(&addr, std::time::Instant::now())
    {
        return too_many(wait);
    }
    let bytes = match gate::body(raw, PREAUTH_BODY).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let body: ChallengeRequest = match json(&bytes) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    if !crypto::is_id(&body.device_id, "d_") {
        return ApiError::bad_request("device_id is not a device id").into_response();
    }
    // Only a usable device's challenge is kept; any other id gets one that is never stored.
    let known = match gov::device_usable(&app.pool, &body.device_id).await {
        Ok(k) => k,
        Err(e) => return ApiError::from(e).into_response(),
    };
    match app.auth.challenge(&body.device_id, &addr, known, now) {
        Some(c) => Json(Challenge {
            challenge: Some(c),
            expires_in: Some(CHALLENGE_SECS),
        })
        .into_response(),
        None => too_many(std::time::Duration::from_secs(CHALLENGE_SECS as u64)),
    }
}

#[utoipa::path(post, path = "/handshake/session", operation_id = "createSession",
    tag = "handshake", request_body = SessionRequest, security(()),
    params(
        ("Ainkrad-Device" = String, Header, description = "The device, `d_…`"),
        ("Ainkrad-Alg" = String, Header, description = "`ES256`"),
        ("Ainkrad-Timestamp" = i64, Header, description = "Unix seconds"),
        ("Ainkrad-Nonce" = String, Header, description = "16 random bytes, base64url"),
        ("Ainkrad-Signature" = String, Header,
            description = "Raw r||s over the canonical string with session `-`, base64url")),
    responses((status = 200, description = "A 15-minute session. Signed with session `-`; a \
        challenge that is unknown, used, expired or another device's is `auth_failed`",
        body = SessionGrant)))]
pub async fn session(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let v = match gate::verify(&app, &parts, raw, PREAUTH_BODY, &addr, Mode::NoSession).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let device = v.device;
    let body: SessionRequest = match json(&v.body) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    let now = app.clock.unix();
    if !app.auth.take_challenge(&body.challenge, &device.id, now) {
        // The signature verified: this is the device itself with a stale or unknown challenge,
        // not a guess, so it does not count against its address (review N3).
        tracing::warn!(device = device.id, "session refused: bad challenge");
        return gate::auth_failed().into_response();
    }
    let s = app.auth.issue_session(&device.id, now);
    tracing::info!(device = device.id, "session issued");
    Json(SessionGrant {
        session_id: Some(s.id),
        expires_at: Some(ts(&iso_of_unix(s.expires))),
        scopes: Some(device.scopes),
        elevated_until: s.elevated_until.map(|t| ts(&iso_of_unix(t))),
    })
    .into_response()
}
