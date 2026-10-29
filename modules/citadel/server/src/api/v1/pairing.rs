//! Pairing a device with a code (API minor 18). The admin, from a device already paired, asks
//! for a 6-character code (`startPairing`, good for 5 minutes); the new device sends it with a
//! name to `pairDevice`, which needs no key (it has none yet) and answers with its device key,
//! once. A code works once. Wrong codes count against the client address like wrong keys do
//! (the `api.auth_failure_*` limits, then 429), and every pairing is audited (`device.paired`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::devices::{Device, IssuedDevice};
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Client, too_many};
use crate::api::{App, refusal};
use crate::store::gov::{pair_device, start_pairing};

#[derive(Debug, Serialize, ToSchema)]
pub struct Pairing {
    /// Six characters, letters and digits; shown to the user once.
    pub code: String,
    pub expires_at: Timestamp,
}

#[utoipa::path(post, path = "/api/v1/devices/pairing", operation_id = "startPairing", tag = "devices",
    responses((status = 200, description = "A pairing code, good once for 5 minutes (audited as \
        `device.pairing_started`)", body = Pairing)))]
pub async fn start(State(app): State<App>) -> ApiResult<Pairing> {
    let (code, expires) = start_pairing(&app.pool, BY, &app.clock.now()).await?;
    Ok(Json(Pairing {
        code,
        expires_at: ts(&expires),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PairBody {
    /// The code the admin was shown, in any case.
    pub code: String,
    /// What to call the new device.
    pub name: String,
}

#[utoipa::path(post, path = "/api/v1/devices/pair", operation_id = "pairDevice", tag = "devices",
    request_body = PairBody, security(()),
    responses((status = 200, description = "The new device and its key, shown only now; the code \
        is spent (audited as `device.paired`). Needs no device key. 404 for a code that is \
        unknown, used or expired, counted against the client address; 429 once too many are",
        body = IssuedDevice)))]
pub async fn pair(
    State(app): State<App>,
    Extension(client): Extension<Client>,
    Json(b): Json<PairBody>,
) -> ApiResult<IssuedDevice> {
    if b.name.trim().is_empty() {
        return Err(ApiError::bad_request("a device needs a name"));
    }
    match pair_device(&app.pool, &b.code, &b.name, &app.clock.now()).await? {
        Some((device, key)) => Ok(Json(IssuedDevice {
            device: Device::from(device),
            key,
        })),
        None => {
            app.limits.failures.take(&client.0, Instant::now()).ok();
            tracing::warn!(client = client.0, "pairing code refused");
            Err(ApiError::not_found("no such pairing code"))
        }
    }
}

/// The routes with a key: asking for a code.
pub fn routes() -> Router<App> {
    Router::new().route("/api/v1/devices/pairing", post(start))
}

/// The one route without a key, behind the shared gate (host, no origin) and the client
/// address's failure bucket.
pub fn public_router(app: App) -> Router {
    Router::new()
        .route("/api/v1/devices/pair", post(pair))
        .route_layer(middleware::from_fn_with_state(app.clone(), gate))
        .with_state(app)
}

async fn gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    if let Some((status, why)) = refusal(&app, req.uri(), req.headers(), |q| q.is_empty()) {
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
                crate::api::limit::client_ip(c.0.ip(), xff, &app.trusted_proxies).to_string()
            },
        );
    let limits = Arc::clone(&app.limits);
    if let Err(wait) = limits.failures.check(&client, Instant::now()) {
        return too_many(wait);
    }
    req.extensions_mut().insert(Client(client));
    next.run(req).await
}
