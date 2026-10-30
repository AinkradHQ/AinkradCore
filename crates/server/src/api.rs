//! The HTTP surface: the client API under `/api/v1` (`v1`) and the modules mounted inside
//! it. Every request passes the same checks first (`refusal`):
//!
//! - `Host` must be the configured server name, so a page on a rebound DNS name cannot
//!   reach a loopback server (403). Paperclip had exactly that hole.
//! - An `Origin` header is refused (403 `origin_refused`) unless it is the Core's own origin
//!   (`https://<host>`, `http://localhost:<port>` on loopback) or one configured with
//!   `serve --allow-origin` (handshake spec §9, E1-08.5). Native clients send none. There is no
//!   CORS: no `Access-Control-Allow-*` is ever sent, so a page elsewhere cannot read an answer,
//!   and since a browser sends `Origin` on every cross-origin request and every WebSocket, no
//!   page elsewhere reaches a route either.
//! - An `Authorization` header is refused (400): there are no bearer secrets, and this catches
//!   a leftover bearer client (handshake spec §5.1).
//! - A request-target path that is not canonical (`..`, `//`, NUL, a lowercase escape) is
//!   refused (400), so the router and the signer always see the same bytes (§5.2).
//! - A query string is refused (400) unless every name in it is one the route group lets
//!   through.
//!
//! Then a signed request from a live device (`v1::gate`), checked before routing; nothing
//! answers without one, loopback included, except the pre-auth routes (`gateway::preauth`).
//!
//! The runner hub's endpoint (`crate::hub::connect`) is pre-auth here: it verifies the
//! runner's signed request and its channel-bound proof itself.

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::routing::{get, post};
use sqlx::SqlitePool;

use crate::auth::{Auth, Identity};
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
    /// Proxies whose `X-Forwarded-For` names the client (`serve --trusted-proxy`); none by
    /// default, since the Core terminates TLS itself (handshake spec §11).
    pub trusted_proxies: Arc<[limit::Cidr]>,
    /// Device authentication: the Core identity key, sessions, challenges, the replay cache
    /// and revocation fan-out, all per process (`crate::auth`).
    pub auth: Arc<Auth>,
    /// How the client event stream paces itself (E10.2).
    pub stream: v1::events::StreamConfig,
    /// Modules mounted on the client API under `/modules/<id>/v1` (`crate::module`).
    pub modules: Arc<[Arc<dyn crate::module::Module>]>,
    /// Set when serve is stopping: event sockets close so their clients reconnect to the next
    /// server.
    pub closing: Arc<tokio::sync::watch::Sender<bool>>,
    /// The runner hub: runner connections and command routing (`crate::hub`).
    pub hub: Arc<crate::hub::Hub>,
    /// The only `Origin` values let through: the Core's own first (`refusal`).
    pub origins: Arc<[String]>,
    /// Passkeys and the web client (E1-08), when `serve --passkeys` turned them on.
    pub passkeys: Option<Arc<crate::auth::web::Passkeys>>,
    /// The event head and device snapshot every socket shares (`crate::live`, E1-19).
    pub live: Arc<crate::live::Live>,
    /// The master key (`keys/master.key`) for the secrets broker (E2-07); without it the broker
    /// stores and redeems nothing (503 `secrets_unavailable`).
    pub secrets: Option<Arc<crate::ops::secretbox::SecretBox>>,
}

/// Resolves once serve is stopping (`App::closing`).
pub(crate) async fn stopping(closing: &mut tokio::sync::watch::Receiver<bool>) {
    if closing.wait_for(|c| *c).await.is_err() {
        std::future::pending::<()>().await;
    }
}

impl App {
    pub fn new(
        pool: SqlitePool,
        clock: Arc<dyn Clock + Send + Sync>,
        host: String,
        identity: Arc<Identity>,
    ) -> Self {
        Self {
            origins: Arc::from([crate::auth::web::own_origin(&host)]),
            pool,
            clock,
            host,
            limits: Arc::default(),
            trusted_proxies: Arc::from([]),
            auth: Arc::new(Auth::new(identity)),
            stream: v1::events::StreamConfig::default(),
            modules: Arc::from([]),
            closing: Arc::new(tokio::sync::watch::Sender::new(false)),
            hub: Arc::new(crate::hub::Hub::new(crate::hub::HubConfig::default())),
            passkeys: None,
            live: Arc::default(),
            secrets: None,
        }
    }
}

/// The whole surface: the pre-auth routes and the client API, behind the pre-auth gate
/// (`gateway::preauth`), which runs before routing.
pub fn router(app: App) -> Router {
    use crate::gateway::preauth;
    let preauth_routes = Router::new()
        .route(
            "/handshake",
            get(v1::handshake::handshake).post(v1::handshake::prove),
        )
        .route("/handshake/challenge", post(v1::session::challenge))
        .route("/handshake/session", post(v1::session::session))
        .route("/pair/claim", post(v1::pair::claim))
        .route("/pair/status", post(v1::pair::status))
        .route("/pair/passkey/options", post(v1::passkey::options_route))
        .route("/pair/passkey/claim", post(v1::passkey::claim_route))
        .route("/handshake/passkey/options", post(v1::websession::options))
        .route("/handshake/passkey/session", post(v1::websession::session))
        .route("/healthz", get(preauth::healthz))
        .route(crate::hub::connect::PATH, get(crate::hub::connect::connect))
        .layer(DefaultBodyLimit::max(preauth::PREAUTH_BODY))
        .with_state(app.clone());
    Router::new()
        .merge(preauth_routes)
        .merge(v1::router(app.clone()))
        .layer(axum::middleware::from_fn_with_state(app, preauth::gate))
}

/// The shared checks as a status, code and reason: the `Host`, an allowed `Origin` or none, no `Authorization`, a
/// canonical path, and a query string only when `query_ok` accepts it.
pub(crate) fn refusal(
    app: &App,
    uri: &Uri,
    headers: &HeaderMap,
    query_ok: impl Fn(&str) -> bool,
) -> Option<(StatusCode, &'static str, &'static str)> {
    // HTTP/2 carries the host as the `:authority`, which hyper puts in the URI.
    let host = match headers.get(header::HOST) {
        Some(h) => h.to_str().ok(),
        None => uri.authority().map(|a| a.as_str()),
    };
    if !host.is_some_and(|h| h.eq_ignore_ascii_case(&app.host)) {
        return Some((StatusCode::FORBIDDEN, "unknown_host", "unknown host"));
    }
    if let Some(origin) = headers.get(header::ORIGIN)
        && !origin
            .to_str()
            .is_ok_and(|o| app.origins.iter().any(|a| a.eq_ignore_ascii_case(o)))
    {
        return Some((
            StatusCode::FORBIDDEN,
            "origin_refused",
            "this origin may not connect",
        ));
    }
    if headers.contains_key(header::AUTHORIZATION) {
        let why = "no Authorization header: requests are signed";
        return Some((StatusCode::BAD_REQUEST, "bad_request", why));
    }
    if !crate::auth::signed::canonical_path(uri.path()) {
        return Some((
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the path is not canonical",
        ));
    }
    if uri.query().is_some_and(|q| !query_ok(q)) {
        let why = "a query parameter that is not allowed";
        return Some((StatusCode::BAD_REQUEST, "bad_request", why));
    }
    None
}
