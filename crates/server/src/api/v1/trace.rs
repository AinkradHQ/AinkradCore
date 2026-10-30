//! Error ids (the app's "Copy error"): every refusal or failure of a client route carries an
//! `error_id`, `err_` and a ULID (26 Crockford base32 characters: the time in milliseconds,
//! then 80 random bits), logged with its code and status. A refused write (any method but
//! `GET`, from an authenticated device) is also audited as `api.refused` with its id, method,
//! path and code, so the id finds its trace in the audit log as well as in the server log.
//!
//! Except what an abuser can repeat at will (review M4: the audit log is permanent): a 429, and
//! any refusal of the routes in [`AGGREGATED`] (step-up, lockouts, device management) is counted
//! in memory (`auth::refusals`, bounded, keyed by code, method and route) and logged once per
//! window, never written. Those routes audit their transitions themselves: a lock
//! (`auth.lockout`), a grant (`auth.step_up`), a change (`device.*`, `auth.lockout_cleared`),
//! and a last-admin refusal once per device per window (`device.last_admin_refused`).

use std::time::{SystemTime, UNIX_EPOCH};

use ainkrad_core::audit::NewAuditEvent;
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::BY;
use super::types::ErrorBody;
use crate::api::App;
use crate::store::audit;

/// A refusal or failure of a client route; answered as an [`ErrorBody`] with its `error_id`
/// (`trace`), which is logged with it.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub error_id: String,
    /// The server's clock, on a `clock_skew` refusal.
    pub server_time: Option<i64>,
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            error_id: error_id(),
            server_time: None,
        }
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", what)
    }

    pub fn bad_request(why: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", why)
    }

    pub fn conflict(why: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", why)
    }
}

/// A database failure is logged here and answered without its text.
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        let internal = Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        );
        let error_id = &internal.error_id;
        tracing::error!(error = %e, error_id, "client api store call failed");
        internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, error_id) = (self.status.as_u16(), self.code, &self.error_id);
        match self.status.is_server_error() {
            true => tracing::error!(error_id, code, status, message = self.message, "api error"),
            false => tracing::warn!(
                error_id,
                code,
                status,
                message = self.message,
                "api refusal"
            ),
        }
        let refused = Refused {
            error_id: self.error_id.clone(),
            code: self.code,
        };
        let body = ErrorBody {
            code: self.code.to_owned(),
            message: self.message,
            error_id: self.error_id,
            server_time: self.server_time,
        };
        let mut response = (self.status, Json(body)).into_response();
        response.extensions_mut().insert(refused);
        if self.status == StatusCode::UNAUTHORIZED {
            // Requests are signed (handshake spec §5); there is no bearer scheme.
            let scheme = HeaderValue::from_static("Ainkrad-ES256");
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, scheme);
        }
        response
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A new error id: `err_` + a ULID.
pub fn error_id() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let mut random = [0u8; 10];
    // ponytail: without randomness the id is still unique enough by its millisecond.
    getrandom::fill(&mut random).ok();
    let bits = (ms & ((1 << 48) - 1)) << 80
        | random
            .iter()
            .fold(0u128, |acc, b| (acc << 8) | u128::from(*b));
    let ulid: String = (0..26)
        .rev()
        .map(|i| CROCKFORD[((bits >> (i * 5)) & 31) as usize] as char)
        .collect();
    format!("err_{ulid}")
}

/// What a refusal's response carries for `audit_refusals`.
#[derive(Debug, Clone)]
pub struct Refused {
    pub error_id: String,
    pub code: &'static str,
}

/// Routes whose refusals are counted, not audited: `(method, path template)`.
pub const AGGREGATED: &[(&str, &str)] = &[
    ("POST", "/api/v1/auth/step-up/challenge"),
    ("POST", "/api/v1/auth/step-up"),
    ("POST", "/api/v1/ws-ticket"),
    ("POST", "/api/v1/auth/lockouts/clear"),
    ("PATCH", "/api/v1/devices/{id}"),
    ("PUT", "/api/v1/devices/{id}/scopes"),
    ("DELETE", "/api/v1/devices/{id}"),
    // A runner's only route (E2-07, review M1): a stolen runner key must not grow the log per
    // request. A redemption that succeeds is audited as `secret.redeemed`.
    ("POST", "/api/v1/secret-leases/redeem"),
];

/// Audits each refused write as `api.refused`, but counts a 429 and the [`AGGREGATED`] routes'.
pub(super) async fn audit_refusals(State(app): State<App>, req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let client = req.extensions().get::<super::Client>().map(|c| c.0.clone());
    let device = req
        .extensions()
        .get::<super::Caller>()
        .map(|c| c.device.id.clone());
    let response = next.run(req).await;
    let Some(refused) = response.extensions().get::<Refused>() else {
        return response;
    };
    if method == Method::GET {
        return response;
    }
    let route = AGGREGATED
        .iter()
        .find(|(m, t)| *m == method.as_str() && super::scopes::fits(t, &path))
        .map(|r| r.1);
    if route.is_some() || response.status() == StatusCode::TOO_MANY_REQUESTS {
        let key = format!(
            "{} {method} {}",
            refused.code,
            route.unwrap_or("(rate limited)")
        );
        if app.auth.refusals.note(&key, app.clock.unix()) {
            tracing::warn!(key, "refusals counted, not audited, for this window");
        }
        return response;
    }
    let event = NewAuditEvent {
        actor: BY,
        action: "api.refused".to_owned(),
        entity: None,
        details: json!({"error_id": refused.error_id, "code": refused.code,
                        "status": response.status().as_u16(), "method": method.as_str(),
                        "path": path, "client": client, "device": device})
        .to_string(),
    };
    let written = async {
        let mut tx = crate::store::begin_write(&app.pool).await?;
        audit::append(&mut tx, &event).await?;
        tx.commit().await
    };
    if let Err(e) = written.await {
        tracing::error!(error = %e, error_id = refused.error_id, "auditing a refusal failed");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_ids_are_ulids_in_time_order() {
        let a = error_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = error_id();
        assert_eq!(a.len(), 30);
        assert!(a.starts_with("err_") && a[4..].bytes().all(|c| CROCKFORD.contains(&c)));
        assert!(a < b, "{a} then {b}");
    }
}
