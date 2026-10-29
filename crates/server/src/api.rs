//! The HTTP surface: the client API under `/api/v1` (`v1`) and the modules mounted inside
//! it. Every request passes the same checks first (`refusal`):
//!
//! - `Host` must be the configured server name, so a page on a rebound DNS name cannot
//!   reach a loopback server (403). Paperclip had exactly that hole.
//! - Any `Origin` header is refused (403): clients are not browsers, and a browser always
//!   sends one on a WebSocket, so no web page can open a socket here.
//! - A query string is refused (400) unless every name in it is one the route group lets
//!   through: keys travel in `Authorization: Bearer`, never in a URL that proxies and logs
//!   keep.
//!
//! Then a live device key (`v1`); nothing answers without one, loopback included, except
//! trading a pairing code for a key.
//!
//! The runner endpoint is not here: runners reconnect through the rebuilt hub (E1-11).

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use sqlx::SqlitePool;

use crate::scheduler::Clock;

pub mod limit;
pub mod v1;

/// What every request handler shares.
#[derive(Clone)]
pub struct App {
    pub pool: SqlitePool,
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// The `Host` every request must carry, as clients send it: `core.lan`, or
    /// `127.0.0.1:7700` with the port.
    pub host: String,
    /// The client API's rate limits (E10.3).
    pub limits: Arc<v1::Limits>,
    /// Proxies whose `X-Forwarded-For` names the client (`serve --trusted-proxy`).
    pub trusted_proxies: Arc<[limit::Cidr]>,
    /// How the client event stream paces itself (E10.2).
    pub stream: v1::events::StreamConfig,
    /// Modules mounted on the client API under `/modules/<id>/v1` (`crate::module`).
    pub modules: Arc<[Arc<dyn crate::module::Module>]>,
    /// Set when serve is stopping: event sockets close so their clients reconnect to the next
    /// server.
    pub closing: Arc<tokio::sync::watch::Sender<bool>>,
}

/// Resolves once serve is stopping (`App::closing`).
pub(crate) async fn stopping(closing: &mut tokio::sync::watch::Receiver<bool>) {
    if closing.wait_for(|c| *c).await.is_err() {
        std::future::pending::<()>().await;
    }
}

impl App {
    pub fn new(pool: SqlitePool, clock: Arc<dyn Clock + Send + Sync>, host: String) -> Self {
        Self {
            pool,
            clock,
            host,
            limits: Arc::default(),
            trusted_proxies: Arc::new(limit::Cidr::LOOPBACK),
            stream: v1::events::StreamConfig::default(),
            modules: Arc::from([]),
            closing: Arc::new(tokio::sync::watch::Sender::new(false)),
        }
    }
}

pub fn router(app: App) -> Router {
    Router::new()
        .merge(v1::pairing_router(app.clone()))
        .merge(v1::router(app))
}

/// The bearer token of an `Authorization: Bearer <token>` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// The shared checks as a status and reason: the `Host`, no `Origin`, and a query string
/// only when `query_ok` accepts it.
pub(crate) fn refusal(
    app: &App,
    uri: &Uri,
    headers: &HeaderMap,
    query_ok: fn(&str) -> bool,
) -> Option<(StatusCode, &'static str)> {
    // HTTP/2 carries the host as the `:authority`, which hyper puts in the URI.
    let host = match headers.get(header::HOST) {
        Some(h) => h.to_str().ok(),
        None => uri.authority().map(|a| a.as_str()),
    };
    if !host.is_some_and(|h| h.eq_ignore_ascii_case(&app.host)) {
        return Some((StatusCode::FORBIDDEN, "unknown host"));
    }
    if headers.contains_key(header::ORIGIN) {
        return Some((StatusCode::FORBIDDEN, "browsers may not connect"));
    }
    if uri.query().is_some_and(|q| !query_ok(q)) {
        return Some((
            StatusCode::BAD_REQUEST,
            "no query string: the key goes in the Authorization header",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_a_bearer_authorization() {
        let with = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, value.parse().unwrap());
            h
        };
        assert_eq!(bearer(&with("Bearer k1")), Some("k1"));
        assert_eq!(bearer(&with("bearer  k1 ")), Some("k1"));
        assert_eq!(bearer(&with("Basic k1")), None);
        assert_eq!(bearer(&with("Bearer ")), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
    }
}
