//! The client API (E10): everything under `/api/v1`, for the Ainkrad app. Every request
//! passes the gate (`gate`, handshake spec §5.3) before routing: the shared checks, the
//! signed-request headers, the address lockouts, the clock, the device and its signature, the
//! replay cache, the session, and the device's request bucket.
//!
//! Single admin (#18): whichever device calls, it acts as the admin user, and every write is
//! audited as that user through the same store calls the CLI uses.
//!
//! The contract (E10.1) is `api/openapi.json` at the repo root, generated from the
//! `#[utoipa::path]` annotations here by `spec` (`make contract`); `make test` fails when it
//! is stale. Its versioning rule is in `types`.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::UserId;
use ainkrad_core::settings::{Key, Scope};
use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use serde::Deserialize;
use utoipa::IntoParams;

use super::App;
use super::limit::Limiter;

mod audit;
mod devices;
pub mod events;
pub mod gate;
pub mod handshake;
mod lockouts;
mod me;
pub mod pair;
mod pairing;
mod runners;
pub mod scopes;
pub mod session;
mod settings;
pub mod spec;
mod stepup;
mod trace;
pub use trace::{ApiError, ApiResult};
pub mod types;

/// The one admin user every device acts as (#18).
pub const ADMIN: UserId = UserId(1);
pub const BY: AuditActor = AuditActor::User(ADMIN);

/// Query parameter names any `/api/v1` route may take; nothing else is let through.
pub const QUERY: &[&str] = &["after", "limit", "before", "kind", "target", "actor"];

/// A page of a list: the cursor to continue after (its meaning is per route) and how many.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Paging {
    pub after: Option<i64>,
    pub limit: Option<u32>,
}

/// The device a request authenticated as, and its session, for the handlers.
#[derive(Debug, Clone)]
pub struct Caller {
    pub device: crate::store::gov::Device,
    pub session: String,
}

/// The address a request came from, past any trusted proxy (`limit::client_ip`), or `local`
/// on the Unix socket.
#[derive(Debug, Clone)]
pub struct Client(pub String);

/// The client API's rate limits.
pub struct Limits {
    /// Requests, by device (§5.3 step 10). Authentication failures are counted in the store
    /// (`store::gov::limits`).
    pub requests: Limiter,
}

impl Limits {
    /// A bucket of `burst` refilled at `per_min`.
    fn of([burst, per_min]: [i64; 2]) -> Self {
        Self {
            requests: Limiter::new(burst as u32, per_min as f64 / 60.0),
        }
    }

    const KEYS: [Key; 2] = [Key::ApiRequestBurst, Key::ApiRequestsPerMin];

    /// The limits from the `api.*` settings (E15.17), read once at start.
    pub async fn from_settings(pool: &sqlx::SqlitePool) -> Result<Self, sqlx::Error> {
        let mut v = [0; 2];
        for (v, key) in v.iter_mut().zip(Self::KEYS) {
            *v = crate::store::settings::value(pool, key, Scope::Server).await?;
        }
        Ok(Self::of(v))
    }
}

impl Default for Limits {
    /// The settings' defaults: 120 requests at once, then 20 a second.
    fn default() -> Self {
        Self::of(Self::KEYS.map(Key::default))
    }
}

pub(crate) fn too_many(wait: std::time::Duration) -> Response {
    let mut response = ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests; retry later",
    )
    .into_response();
    let secs = wait.as_secs().max(1).to_string();
    if let Ok(v) = HeaderValue::from_str(&secs) {
        response.headers_mut().insert(header::RETRY_AFTER, v);
    }
    response
}

/// Whether every query parameter name is one of [`QUERY`].
fn query_ok(query: &str) -> bool {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .all(|pair| QUERY.contains(&pair.split('=').next().unwrap_or(pair)))
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/api/v1/devices", get(devices::list))
        .route(
            "/api/v1/devices/{id}",
            get(devices::get)
                .patch(devices::rename)
                .delete(devices::revoke),
        )
        .route("/api/v1/devices/{id}/scopes", put(devices::set_scopes))
        .route("/api/v1/pairings", post(pairing::create))
        .route("/api/v1/pairings/{id}", get(pairing::get))
        .route("/api/v1/pairings/{id}/approve", post(pairing::approve))
        .route("/api/v1/pairings/{id}/reject", post(pairing::reject))
        .route(
            "/api/v1/push-token",
            put(devices::set_push).delete(devices::clear_push),
        )
        .route("/api/v1/events", get(events::replay))
        .route("/api/v1/events/ws", get(events::ws))
        .route("/api/v1/events/latest", get(events::latest))
        .route("/api/v1/audit", get(audit::list))
        .route("/api/v1/runners", get(runners::list))
        .route("/api/v1/runners/{id}", get(runners::get))
        .route("/api/v1/runners/{id}/noop", post(runners::noop))
        .route("/api/v1/me", get(me::me))
        .route("/api/v1/auth/step-up/challenge", post(stepup::challenge))
        .route("/api/v1/auth/step-up", post(stepup::step_up))
        .route("/api/v1/auth/lockouts", get(lockouts::list))
        .route("/api/v1/auth/lockouts/clear", post(lockouts::clear))
        .route("/api/v1/settings", get(settings::list_server))
        .route("/api/v1/settings/{scope}", get(settings::list))
        .route(
            "/api/v1/settings/{scope}/{key}",
            get(settings::get)
                .put(settings::set)
                .delete(settings::reset),
        )
        .route(
            "/api/v1/settings/{scope}/{key}/history",
            get(settings::history),
        )
        // Modules sit inside the same gate: they never authenticate for themselves.
        .merge(crate::module::mount(&app.modules))
        // Refused writes, authenticated (`trace`).
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            trace::audit_refusals,
        ))
        .with_state(app)
}

#[cfg(test)]
mod tests;
