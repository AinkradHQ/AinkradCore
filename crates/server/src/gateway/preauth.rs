//! The pre-auth gate (E1-06.4, handshake spec §4): before routing, only these route prefixes
//! answer without a signed request, on segment boundaries (`/handshake` and `/handshake/…`,
//! never `/handshakes`):
//!
//! - `/handshake`: what the server is, and the session challenge-response
//!   (`api::v1::handshake`, `api::v1::session`);
//! - `/pair`: pairing a new device (E1-07.4);
//! - `/.well-known/acme-challenge/` on the :80 listener only, when HTTP-01 is on
//!   (`http01_router`);
//! - `/healthz`: `ok`, nothing else;
//! - `/runner/v2/connect`: the runner hub, which verifies the signed request and the runner's
//!   channel-bound proof itself (`hub::connect`);
//! - the declared token routes of the mounted modules, `/token/<module>/v1/…`, behind their own
//!   gate (`token`, E2-13 S8): a bearer token the module checks, never a signature.
//!
//! They still pass the shared checks (Host, no Origin, no Authorization, a canonical path, no
//! query string) and take at most a 16 KiB body (413). Every other request runs the client
//! gate (`api::v1::gate`) here, before routing, so without a valid signature every path,
//! unknown ones included, gets the same 401 and the routes cannot be enumerated.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::tls::Certs;
use crate::api::v1::ApiError;
use crate::api::{App, refusal};

/// The largest body a pre-auth route takes.
pub const PREAUTH_BODY: usize = 16 * 1024;

/// The route prefixes reachable without a signed request on the main listener.
pub const ALLOWED: [&str; 4] = ["/handshake", "/pair", "/healthz", crate::hub::connect::PATH];

/// The HTTP-01 challenge prefix, served on :80 only.
pub const ACME_CHALLENGE: &str = "/.well-known/acme-challenge";

/// `path` is `prefix` or below it.
fn under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether a path needs no key.
pub fn allowed(path: &str) -> bool {
    ALLOWED.iter().any(|p| under(path, p))
}

/// The gate, as an outer layer on the whole router (fallback included). Everything logged while
/// a request is handled carries its peer address and the device it claims (E1 exit gate
/// finding 4: an `auth_failed` line said nothing about who was refused). The device is the
/// `Ainkrad-Device` header, only when it is a well-formed id; never a signature, nonce,
/// challenge or key.
pub async fn gate(State(app): State<App>, req: Request, next: Next) -> Response {
    use tracing::Instrument;
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "local".to_owned(), |c| c.0.to_string());
    let device = req
        .headers()
        .get(crate::auth::signed::DEVICE)
        .and_then(|v| v.to_str().ok())
        .filter(|d| crate::auth::crypto::is_id(d, "d_"))
        .unwrap_or("-")
        .to_owned();
    let span = tracing::info_span!("request", peer, device);
    gated(app, req, next).instrument(span).await
}

async fn gated(app: App, req: Request, next: Next) -> Response {
    // A declared token route has its own gate (`token`); an undeclared path under the prefix is
    // the plain 401.
    if req.uri().path().starts_with(super::token::PREFIX) {
        return match super::token::resolve(&app.modules, req.method(), req.uri().path()) {
            Some((module, route)) => {
                let module = module.clone();
                super::token::gate(State(app), module, route, req, next).await
            }
            // The plain 401 of any unsigned unknown path, whatever else the request carries, so
            // a declared route cannot be told from an undeclared one.
            None => refused().await,
        };
    }
    if !allowed(req.uri().path()) {
        return crate::api::v1::gate::client_gate(State(app), req, next).await;
    }
    if let Some((status, code, why)) = refusal(&app, req.uri(), req.headers(), str::is_empty) {
        return ApiError::new(status, code, why).into_response();
    }
    let length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
    if length.is_some_and(|n| n > PREAUTH_BODY) {
        return too_large();
    }
    // A body without a length is cut by `DefaultBodyLimit` as the handler reads it; answer
    // that 413 in the same shape.
    match next.run(req).await {
        r if r.status() == StatusCode::PAYLOAD_TOO_LARGE => too_large(),
        r => r,
    }
}

pub fn too_large() -> Response {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        "the request is too large",
    )
    .into_response()
}

/// `GET /healthz`: up, and nothing about what or which version.
pub async fn healthz() -> &'static str {
    "ok"
}

/// The :80 listener: the HTTP-01 answers and nothing else.
pub fn http01_router(certs: Arc<Certs>) -> Router {
    Router::new()
        .route(&format!("{ACME_CHALLENGE}/{{token}}"), get(http01))
        .fallback(refused)
        .with_state(certs)
}

async fn http01(State(certs): State<Arc<Certs>>, Path(token): Path<String>) -> Response {
    match certs.http01(&token) {
        Some(key_authorization) => key_authorization.into_response(),
        None => refused().await,
    }
}

/// What an unauthenticated request outside the allowlist gets, the same everywhere.
pub async fn refused() -> Response {
    crate::api::v1::gate::auth_failed().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_match_whole_segments() {
        for ok in [
            "/handshake",
            "/handshake/session",
            "/pair",
            "/pair/claim",
            "/healthz",
            "/runner/v2/connect",
        ] {
            assert!(allowed(ok), "{ok}");
        }
        for no in [
            "/handshakes",
            "/pairing",
            "/api/v1/devices/pair",
            "/api/v1/devices",
            "/healthzz",
            "/",
            "",
            "/.well-known/acme-challenge/x",
            "/API/V1/DEVICES/PAIR",
            "/runner",
            "/runner/v2",
            "/runner/v1/connect",
        ] {
            assert!(!allowed(no), "{no}");
        }
    }
}
