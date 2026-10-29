//! The HTTP surface: `GET /runner/v1/connect` (E3.1), which upgrades to the runner protocol
//! (`ainkrad_proto::runner`), and `/mcp/v1` (E4.2), the MCP server agents call back through
//! (`mcp`). Every request passes the same gate first:
//!
//! - `Host` must be the configured server name, so a page on a rebound DNS name cannot
//!   reach a loopback server (403). Paperclip had exactly that hole.
//! - Any `Origin` header is refused (403): runners are not browsers, and a browser always
//!   sends one on a WebSocket, so no web page can open this socket.
//! - A query string is refused (400): keys travel in `Authorization: Bearer`, never in a URL
//!   that proxies and logs keep. The client API (`v1`) lets its paging and filter names
//!   through, and nothing else.
//! - The bearer must be a registered runner key, checked against its stored hash before the
//!   upgrade (401); on `/mcp/v1`, a live run token (`authorize_run_token`), whose `RunScope`
//!   every tool then checks; on `/api/v1` (E10), a live device key (`v1`). Nothing here
//!   answers without one, loopback included.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::exec::RunnerId;
use axum::Router;
use axum::extract::ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use sqlx::SqlitePool;

use crate::scheduler::Clock;
use crate::store::exec::{AuthError, authorize_run_token, get_runner_by_key};

pub mod limit;
mod mcp;
mod runner;
pub mod v1;

/// What every request handler shares.
#[derive(Clone)]
pub struct App {
    pub pool: SqlitePool,
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// The `Host` every request must carry, as clients send it: `citadel.lan`, or
    /// `127.0.0.1:7700` with the port.
    pub host: String,
    /// How often a connection looks for decided escalations.
    pub poll: Duration,
    /// How often a runner's waiting `Ready` looks for work besides being signalled of new
    /// wakes (E15.6): the `dispatch.fallback_poll_ms` setting, read at start.
    pub dispatch_poll: Duration,
    /// The client API's rate limits (E10.3).
    pub limits: Arc<v1::Limits>,
    /// Proxies whose `X-Forwarded-For` names the client (`serve --trusted-proxy`).
    pub trusted_proxies: Arc<[limit::Cidr]>,
    /// How the client event stream paces itself (E10.2).
    pub stream: v1::events::StreamConfig,
    /// Where artifacts are stored (E15.12): `artifacts/` next to the database unless
    /// `serve --artifacts` says otherwise.
    pub artifacts: std::path::PathBuf,
    /// The latest connection of each runner, so an old socket closing late does not mark a
    /// reconnected runner offline.
    connections: Arc<Mutex<HashMap<RunnerId, u64>>>,
    next_connection: Arc<AtomicU64>,
    /// Log tails the admin asked runners for (1.20).
    pub log_tails: Arc<runner::LogTails>,
    pub probes: Arc<runner::Probes>,
    /// Set when serve is stopping: runner and event sockets close so their clients reconnect
    /// to the next server.
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
        let artifacts = pool
            .connect_options()
            .get_filename()
            .parent()
            .map_or_else(|| "artifacts".into(), |dir| dir.join("artifacts"));
        Self {
            pool,
            clock,
            host,
            poll: Duration::from_secs(1),
            dispatch_poll: Duration::from_millis(
                ainkrad_core::settings::Key::DispatchPollMs.default() as u64,
            ),
            limits: Arc::default(),
            trusted_proxies: Arc::new(limit::Cidr::LOOPBACK),
            stream: v1::events::StreamConfig::default(),
            artifacts,
            connections: Arc::default(),
            next_connection: Arc::default(),
            log_tails: Arc::default(),
            probes: Arc::default(),
            closing: Arc::new(tokio::sync::watch::Sender::new(false)),
        }
    }

    /// Records a new connection of `runner` and returns its number.
    fn connected(&self, runner: RunnerId) -> u64 {
        let n = self.next_connection.fetch_add(1, Ordering::Relaxed);
        self.connections.lock().unwrap().insert(runner, n);
        n
    }

    /// Whether `runner` is connected now.
    pub fn is_connected(&self, runner: RunnerId) -> bool {
        self.connections.lock().unwrap().contains_key(&runner)
    }

    /// Whether connection `n` is still `runner`'s latest; forgets it if so.
    fn disconnected(&self, runner: RunnerId, n: u64) -> bool {
        let mut connections = self.connections.lock().unwrap();
        let latest = connections.get(&runner) == Some(&n);
        if latest {
            connections.remove(&runner);
        }
        latest
    }
}

pub fn router(app: App) -> Router {
    let mcp = Router::new()
        .route_service("/mcp/v1", mcp::service(app.clone()))
        // The run's `citadel` CLI (E15.18): one operation per POST, JSON in and out.
        .route("/mcp/v1/call/{op}", post(mcp::cli_call))
        .route_layer(middleware::from_fn_with_state(app.clone(), mcp_gate))
        .with_state(app.clone());
    Router::new()
        .route("/runner/v1/connect", get(connect))
        .with_state(app.clone())
        .merge(mcp)
        .merge(v1::pairing_router(app.clone()))
        .merge(v1::router(app))
}

fn refuse(status: StatusCode, why: &'static str) -> Response {
    tracing::warn!(%status, why, "request refused");
    let mut response = (status, why).into_response();
    if status == StatusCode::UNAUTHORIZED {
        let bearer = header::HeaderValue::from_static("Bearer");
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, bearer);
    }
    response
}

/// The bearer token of an `Authorization: Bearer <token>` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// The checks every route shares, before its bearer: a refusal, or `None` to go on.
fn gate(app: &App, uri: &Uri, headers: &HeaderMap) -> Option<Response> {
    refusal(app, uri, headers, |_| false).map(|(status, why)| refuse(status, why))
}

/// The shared checks as a status and reason: the `Host`, no `Origin`, and a query string
/// only when `query_ok` accepts it (the runner and MCP routes take none).
fn refusal(
    app: &App,
    uri: &Uri,
    headers: &HeaderMap,
    query_ok: fn(&str) -> bool,
) -> Option<(StatusCode, &'static str)> {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
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

/// `/mcp/v1`: the gate, then a live run token, whose scope goes on to the tools as a request
/// extension. The token itself is taken off the request, so nothing past here can echo it.
async fn mcp_gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    if let Some(refused) = gate(&app, req.uri(), req.headers()) {
        return refused;
    }
    let Some(token) = bearer(req.headers()).map(str::to_owned) else {
        return refuse(StatusCode::UNAUTHORIZED, "missing run token");
    };
    req.headers_mut().remove(header::AUTHORIZATION);
    match authorize_run_token(&app.pool, &token, &app.clock.now()).await {
        Ok(scope) => {
            req.extensions_mut().insert(scope);
            // Only to redact it from what the agent publishes (E15.18).
            let mut secrets = ainkrad_proto::redact::Redactor::new();
            secrets.known("run_token", &token);
            req.extensions_mut()
                .insert(mcp::RunSecrets(Arc::new(secrets)));
            next.run(req).await
        }
        Err(AuthError::Db(e)) => {
            tracing::error!(error = %e, "run token lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::warn!(reason = %e, "run token refused");
            refuse(StatusCode::UNAUTHORIZED, "invalid run token")
        }
    }
}

async fn connect(
    State(app): State<App>,
    uri: Uri,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    if let Some(refused) = gate(&app, &uri, &headers) {
        return refused;
    }
    let Some(key) = bearer(&headers) else {
        return refuse(StatusCode::UNAUTHORIZED, "missing runner key");
    };
    let runner = match get_runner_by_key(&app.pool, key).await {
        Ok(Some(runner)) => runner,
        Ok(None) => return refuse(StatusCode::UNAUTHORIZED, "unknown runner key"),
        Err(e) => {
            tracing::error!(error = %e, "runner key lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match ws {
        Ok(ws) => {
            let key = key.to_owned();
            ws.on_upgrade(move |socket| runner::session(app, runner, key, socket))
        }
        Err(rejection) => rejection.into_response(),
    }
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
