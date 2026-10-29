//! The client API (E10): everything under `/api/v1`, for the Ainkrad app. Every request
//! passes, in order:
//!
//! 1. The shared gate (`super::refusal`): `Host` must be the server's name (403), no
//!    `Origin` (403). A query string is allowed, but only the paging and filter names in
//!    [`QUERY`]; anything else, a `?token=` above all, is a 400, so a key never ends up in a
//!    URL.
//! 2. The failure bucket of the client's address (`limit`): too many failed authentications
//!    and every request from that address is a 429 until it refills.
//! 3. A live device key as `Authorization: Bearer` (401 otherwise, counted as a failure).
//! 4. The device's request bucket (429).
//!
//! Single admin (#18): whichever device calls, it acts as the admin user, and every write is
//! audited as that user through the same store calls the CLI uses.
//!
//! The contract (E10.1) is `api/openapi.json` at the repo root, generated from the
//! `#[utoipa::path]` annotations here by `spec` (`make contract`); `make test` fails when it
//! is stale. Its versioning rule is in `types`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::{DeviceKeyId, UserId};
use ainkrad_core::settings::{Key, Scope};
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, put};
use serde::Deserialize;
use utoipa::IntoParams;

use super::limit::Limiter;
use super::{App, bearer, refusal};
use crate::store::gov::authorize_device_key;

mod audit;
mod devices;
pub mod events;
mod me;
mod pairing;
mod settings;
pub mod spec;
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

/// The device a request authenticated as, for the handlers.
#[derive(Debug, Clone, Copy)]
pub struct Device(pub DeviceKeyId);

/// The address a request came from, past any trusted proxy (`limit::client_ip`).
#[derive(Debug, Clone)]
pub struct Client(pub String);

/// The client API's rate limits.
pub struct Limits {
    /// Failed authentications, by client address.
    pub failures: Limiter,
    /// Requests, by device key.
    pub requests: Limiter,
}

impl Limits {
    /// Buckets of `burst` refilled at `per_min`: failures, then requests.
    fn of([fail_burst, fail_per_min, burst, per_min]: [i64; 4]) -> Self {
        Self {
            failures: Limiter::new(fail_burst as u32, fail_per_min as f64 / 60.0),
            requests: Limiter::new(burst as u32, per_min as f64 / 60.0),
        }
    }

    const KEYS: [Key; 4] = [
        Key::ApiAuthFailureBurst,
        Key::ApiAuthFailuresPerMin,
        Key::ApiRequestBurst,
        Key::ApiRequestsPerMin,
    ];

    /// The limits from the `api.*` settings (E15.17), read once at start.
    pub async fn from_settings(pool: &sqlx::SqlitePool) -> Result<Self, sqlx::Error> {
        let mut v = [0; 4];
        for (v, key) in v.iter_mut().zip(Self::KEYS) {
            *v = crate::store::settings::value(pool, key, Scope::Server).await?;
        }
        Ok(Self::of(v))
    }
}

impl Default for Limits {
    /// The settings' defaults: ten wrong keys, then one more every six seconds; 120 requests
    /// at once, then 20 a second.
    fn default() -> Self {
        Self::of(Self::KEYS.map(Key::default))
    }
}

fn too_many(wait: std::time::Duration) -> Response {
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

/// The one route that needs no device key (`pairing`).
pub fn pairing_router(app: App) -> Router {
    pairing::public_router(app)
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/api/v1/devices", get(devices::list).post(devices::create))
        .route("/api/v1/devices/{id}", delete(devices::revoke))
        .route(
            "/api/v1/push-token",
            put(devices::set_push).delete(devices::clear_push),
        )
        .route("/api/v1/events", get(events::replay))
        .route("/api/v1/events/ws", get(events::ws))
        .route("/api/v1/events/latest", get(events::latest))
        .route("/api/v1/audit", get(audit::list))
        .route("/api/v1/me", get(me::me))
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
        .merge(pairing::routes())
        // Modules sit inside the same gate: they never authenticate for themselves.
        .merge(crate::module::mount(&app.modules))
        // Refused writes, authenticated (`trace`).
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            trace::audit_refusals,
        ))
        .route_layer(middleware::from_fn_with_state(app.clone(), client_gate))
        .with_state(app)
}

pub(crate) async fn client_gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    if let Some((status, why)) = refusal(&app, req.uri(), req.headers(), query_ok) {
        tracing::warn!(%status, why, "client request refused");
        return ApiError::new(status, "refused", why).into_response();
    }
    let client = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(
            || "local".to_owned(),
            |c| {
                let xff = req.headers().get_all("x-forwarded-for").iter();
                let xff = xff.filter_map(|v| v.to_str().ok());
                super::limit::client_ip(c.0.ip(), xff, &app.trusted_proxies).to_string()
            },
        );
    let limits = Arc::clone(&app.limits);
    let now = Instant::now();
    if let Err(wait) = limits.failures.check(&client, now) {
        return too_many(wait);
    }
    let failed = |why: &'static str| {
        tracing::warn!(client, why, "device key refused");
        // The bucket was not empty a moment ago; a race only lets one more through.
        limits.failures.take(&client, now).ok();
        ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", why).into_response()
    };
    let Some(key) = bearer(req.headers()).map(str::to_owned) else {
        return failed("missing device key");
    };
    req.headers_mut().remove(header::AUTHORIZATION);
    let device = match authorize_device_key(&app.pool, &key, &app.clock.now()).await {
        Ok(Some(device)) => device,
        Ok(None) => return failed("invalid or revoked device key"),
        Err(e) => return ApiError::from(e).into_response(),
    };
    if let Err(wait) = limits.requests.take(&device.id.0.to_string(), now) {
        return too_many(wait);
    }
    req.extensions_mut().insert(Device(device.id));
    req.extensions_mut().insert(Client(client));
    next.run(req).await
}

#[cfg(test)]
mod tests;
