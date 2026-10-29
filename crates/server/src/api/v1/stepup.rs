//! Step-up over the API (handshake spec §8, E1-09.3; the mechanism is `auth::stepup`):
//! `POST /api/v1/auth/step-up/challenge` gives the calling session a challenge, and
//! `POST /api/v1/auth/step-up` spends it with the device's step-up key's signature. On success
//! the **session** is elevated for `auth.step_up_secs` (default 300 s, 60 to 900), replacing any
//! elevation it had; it is audited as `auth.step_up`. Nothing else ever extends it. Elevation
//! lives with the session in memory, so revocation and a restart end it.
//!
//! Every failed proof is the same 403 `step_up_failed`; a spent budget is 429.

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_core::settings::{Key, Scope};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use super::session::Challenge;
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller, Client, too_many};
use crate::api::App;
use crate::auth::{CHALLENGE_SECS, Proof, crypto};
use crate::scheduler::iso_of_unix;
use crate::store::gov::{self, STEP_UP};
use crate::store::{audit, begin_write};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpRequest {
    /// The challenge from `POST /api/v1/auth/step-up/challenge` for this session.
    pub challenge: String,
    /// The step-up key's ES256 signature (raw r||s, base64url) over the UTF-8 string
    /// `AINKRAD-STEPUP-V1` LF `<core_fp>` LF `<device_id>` LF `<session_id>` LF `<challenge>`,
    /// no trailing newline. The device's OS releases that key only after user verification.
    pub stepup_sig: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Elevation {
    /// Until when this session may call routes marked `x-ainkrad-destructive`.
    pub elevated_until: Option<Timestamp>,
}

/// The one answer for a failed proof, whatever the reason.
fn failed() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "step_up_failed",
        "the step-up proof was not accepted; get a new challenge",
    )
}

#[utoipa::path(post, path = "/api/v1/auth/step-up/challenge", operation_id = "createStepUpChallenge",
    tag = "devices",
    responses((status = 200, description = "A single-use step-up challenge bound to the calling \
        session, live 60 s; a new one replaces the session's previous one", body = Challenge)))]
pub async fn challenge(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Challenge> {
    let now = app.clock.unix();
    let c = app
        .auth
        .stepup_challenge(&me.session, &me.device.id, now)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "session_expired", "no session"))?;
    Ok(Json(Challenge {
        challenge: Some(c),
        expires_in: Some(CHALLENGE_SECS),
    }))
}

#[utoipa::path(post, path = "/api/v1/auth/step-up", operation_id = "stepUp", tag = "devices",
    request_body = StepUpRequest,
    responses((status = 200, description = "The session is elevated (audited as `auth.step_up`). \
        A device without a step-up key, a challenge that is unknown, used, expired or another \
        session's, and a bad signature are all 403 `step_up_failed`; 429 once the device's or \
        the address's failure budget is spent", body = Elevation)))]
pub async fn step_up(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(Client(addr)): Extension<Client>,
    Json(b): Json<StepUpRequest>,
) -> Response {
    match elevate(&app, &me, &addr, &b).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn elevate(
    app: &App,
    me: &Caller,
    addr: &str,
    b: &StepUpRequest,
) -> Result<Response, ApiError> {
    let now = app.clock.unix();
    let key = format!("stepup:{}", me.device.id);
    if let Some(until) = gov::locked_until(&app.pool, &[&key], now).await? {
        return Ok(throttled(until - now));
    }
    let sig = crypto::unb64(&b.stepup_sig, 86);
    let proof = app.auth.prove_stepup(
        addr,
        &me.device,
        &me.session,
        &b.challenge,
        sig.as_deref(),
        now,
    );
    match proof {
        Proof::Verified => {}
        Proof::Throttled => {
            tracing::warn!(device = me.device.id, "step-up refused: budget spent");
            return Ok(throttled(STEP_UP.lock));
        }
        Proof::Failed => {
            tracing::warn!(device = me.device.id, "step-up refused: proof failed");
            gov::record_failure(&app.pool, &key, STEP_UP, now).await?;
            return Err(failed());
        }
    }
    let secs = crate::store::settings::value(&app.pool, Key::AuthStepUpSecs, Scope::Server).await?;
    let until = now + secs;
    // Audited first, then elevated: a request dropped in between is never elevated unaudited.
    let mut tx = begin_write(&app.pool).await?;
    let event = NewAuditEvent {
        actor: BY,
        action: "auth.step_up".to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: me.device.seq,
        }),
        details: json!({"device": me.device.id, "by_device": me.device.id, "until": until})
            .to_string(),
    };
    audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    if !app.auth.elevate(&me.session, &me.device.id, until) {
        return Err(failed());
    }
    tracing::info!(device = me.device.id, until, "session elevated");
    Ok(Json(Elevation {
        elevated_until: Some(ts(&iso_of_unix(until))),
    })
    .into_response())
}

fn throttled(secs: i64) -> Response {
    too_many(std::time::Duration::from_secs(secs.max(1) as u64))
}

/// The answer a route marked destructive gives a session that is not elevated.
pub fn required() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "step_up_required",
        "this needs a recent step-up (POST /api/v1/auth/step-up)",
    )
}
