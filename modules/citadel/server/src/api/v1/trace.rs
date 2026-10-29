//! Error ids (the app's "Copy error"): every refusal or failure of a client route carries an
//! `error_id`, `err_` and a ULID (26 Crockford base32 characters: the time in milliseconds,
//! then 80 random bits), logged with its code and status. A refused write (any method but
//! `GET`, from an authenticated device) is also audited as `api.refused` with its id, method,
//! path and code, so the id finds its trace in the audit log as well as in the server log.

use std::time::{SystemTime, UNIX_EPOCH};

use citadel_core::audit::NewAuditEvent;
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
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            error_id: error_id(),
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
        };
        let mut response = (self.status, Json(body)).into_response();
        response.extensions_mut().insert(refused);
        if self.status == StatusCode::UNAUTHORIZED {
            let bearer = HeaderValue::from_static("Bearer");
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, bearer);
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

/// Audits each refused write as `api.refused`.
pub(super) async fn audit_refusals(State(app): State<App>, req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let client = req.extensions().get::<super::Client>().map(|c| c.0.clone());
    let response = next.run(req).await;
    let Some(refused) = response.extensions().get::<Refused>() else {
        return response;
    };
    if method == Method::GET {
        return response;
    }
    let event = NewAuditEvent {
        actor: BY,
        action: "api.refused".to_owned(),
        entity: None,
        company_id: None,
        run_id: None,
        details: json!({"error_id": refused.error_id, "code": refused.code,
                        "status": response.status().as_u16(), "method": method.as_str(),
                        "path": path, "client": client})
        .to_string(),
    };
    let written = async {
        let mut tx = crate::store::begin_write(&app.pool).await?;
        audit::append(&mut *tx, &event).await?;
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
