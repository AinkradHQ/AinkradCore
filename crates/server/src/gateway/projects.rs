//! The Host router (Core 0.9 Projects, P6-02): public `https://<slug>.ainkrad.io` traffic to a
//! project's running run, over the runner's port stream (`port.open`, P6-01). Cloudflare proxies
//! `*.ainkrad.io` here; the Core's own listener on :443 terminates TLS with the Origin CA wildcard.
//!
//! SECURITY MODEL.
//! - **Split before routing.** On the public listener, a TLS connection whose SNI is a project host
//!   (`tls::Certs::is_project_host`) is served by this router alone (`conn::accept`). It holds no
//!   Core route, so the Core API, auth, pairing and the runner hub cannot be reached through a
//!   project host, whatever the path or `Host`. Every other SNI (the Core's, or none) gets the Core,
//!   whose Host check refuses a project `Host`.
//! - **Only a project host answers.** `<slug>` or `<slug>-<service>`, one label under the domain,
//!   neither reserved nor the Core's own host. Any other `Host` (`core.ainkrad.io` included) is a
//!   404 here and is never forwarded.
//! - **Expose is enforced here.** The project must be active with `expose` on (else 404), its live
//!   run must be `running` (else a 503 "not running" page), and the port must be one that the run's
//!   own spec version marks `expose: true`. The runner checks the port again (P6-01).
//! - **What reaches the project.** The client's method, path, query, body and end-to-end headers.
//!   Hop-by-hop headers (and any that `Connection` names) are dropped, as are a client's
//!   `Forwarded`, `X-Forwarded-*`, `X-Real-IP` and `X-Ainkrad-*`. We set `X-Forwarded-For`,
//!   `-Proto` and `-Host` ourselves. The router adds no credential: the Core sets no cookies, and
//!   its keys and tokens never enter this path. A project's `Set-Cookie` loses its `Domain`, so a
//!   project cannot set a cookie for the Core or for another project.
//! - **Bounds.** A rate cap per project (429). Request bodies are capped at [`MAX_BODY`] (413).
//!   The gateway's header limits, idle cut and request deadline apply, plus [`HEAD`] to a response
//!   head (504). The `run.port` stream cap gives 503 when the runner is full. Credit goes back to
//!   the runner only as the public client takes the bytes.
//! - **Upgrades.** A WebSocket upgrade (HTTP/1.1) is carried end to end. Any other upgrade is
//!   dropped as hop-by-hop, and CONNECT is refused.
//! - **Activity.** Real traffic (a request, or bytes moving on a WebSocket) pushes the run's idle
//!   stop back (`store::runs::touch`, P5-03). It is throttled to one write per [`TOUCH_EVERY`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::PortOpen;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version, header};
use axum::response::{IntoResponse, Response};
use http_body_util::Limited;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::time::Instant;

use crate::api::App;
use crate::store::run_specs::{self, RunSpec};
use crate::store::{projects, runs};

/// A request body's cap.
pub const MAX_BODY: usize = 10 * 1024 * 1024;
/// To the project's response head (under the gateway's 30 s request deadline).
pub const HEAD: Duration = Duration::from_secs(25);
/// Requests per second per project, sustained, and the burst on top.
pub const RATE: f64 = 200.0;
pub const BURST: f64 = 400.0;
/// The idle stop is pushed back at most this often per project.
pub const TOUCH_EVERY: Duration = Duration::from_secs(30);
/// A WebSocket that moves no byte for this long is closed.
const WS_IDLE: Duration = Duration::from_secs(10 * 60);

/// Headers that belong to one hop and are never forwarded either way (RFC 9110 §7.6.1).
const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The project label `name` (an SNI or a `Host` without its port) names under `domain`: one label
/// of `a-z0-9-`, not reserved, and `name` is not `core` (the Core's own host). `domain` and `core`
/// are lower case.
pub fn label(name: &str, domain: &str, core: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name == core {
        return None;
    }
    let label = name.strip_suffix(domain)?.strip_suffix('.')?;
    let ok = (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !projects::RESERVED.contains(&label);
    ok.then(|| label.to_owned())
}

/// Per project: the rate bucket, and when the idle stop was last pushed back.
struct Slot {
    tokens: f64,
    at: Instant,
    touched: Option<Instant>,
}

struct Host {
    app: App,
    dial: Arc<dyn Dial>,
    domain: String,
    core: String,
    // ponytail: one lock for every project; per-project locks if a single Core ever serves many.
    slots: Mutex<HashMap<i64, Slot>>,
}

impl Host {
    fn slot<T>(&self, project: i64, f: impl FnOnce(&mut Slot) -> T) -> T {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        let slot = slots.entry(project).or_insert_with(|| Slot {
            tokens: BURST,
            at: Instant::now(),
            touched: None,
        });
        f(slot)
    }

    /// One request's token, if the project has one left.
    fn admit(&self, project: i64) -> bool {
        self.slot(project, |s| {
            let now = Instant::now();
            let refill = now.duration_since(s.at).as_secs_f64() * RATE;
            s.tokens = (s.tokens + refill).min(BURST);
            s.at = now;
            let ok = s.tokens >= 1.0;
            if ok {
                s.tokens -= 1.0;
            }
            ok
        })
    }

    /// Pushes the run's idle stop back, at most once per [`TOUCH_EVERY`].
    async fn touch(&self, project: i64) {
        let due = self.slot(project, |s| {
            let due = s.touched.is_none_or(|t| t.elapsed() >= TOUCH_EVERY);
            if due {
                s.touched = Some(Instant::now());
            }
            due
        });
        if due && let Err(e) = runs::touch(&self.app.pool, project, &self.app.clock.now()).await {
            tracing::warn!(error = %e, project, "the run's activity was not recorded");
        }
    }
}

/// The Host router: project hosts under `domain` only. `app.host` is the Core's own host, which
/// never answers here.
pub fn router(app: App, dial: Arc<dyn Dial>, domain: &str) -> Router {
    let core = strip_port(&app.host).to_ascii_lowercase();
    let host = Arc::new(Host {
        app,
        dial,
        domain: domain.to_ascii_lowercase(),
        core,
        slots: Mutex::default(),
    });
    Router::new().fallback(handle).with_state(host)
}

async fn handle(State(h): State<Arc<Host>>, req: Request) -> Response {
    proxy(h, req).await.unwrap_or_else(|refused| refused)
}

async fn proxy(h: Arc<Host>, mut req: Request) -> Result<Response, Response> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host())
        .map(strip_port)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let label = label(&host, &h.domain, &h.core).ok_or_else(not_found)?;
    if req.method() == Method::CONNECT {
        return Err(page(StatusCode::METHOD_NOT_ALLOWED, "Not allowed"));
    }
    let pool = &h.app.pool;
    let project = projects::for_host(pool, &label)
        .await
        .map_err(|_| unavailable())?
        .filter(|p| p.state == "active" && p.expose)
        .ok_or_else(not_found)?;
    let service = label.get(project.slug.len() + 1..).map(str::to_owned);
    if !h.admit(project.id) {
        return Err(page(StatusCode::TOO_MANY_REQUESTS, "Too many requests"));
    }
    let run = runs::live(pool, project.id)
        .await
        .map_err(|_| unavailable())?
        .filter(|r| r.state == "running")
        .ok_or_else(|| {
            page(
                StatusCode::SERVICE_UNAVAILABLE,
                "This project is not running",
            )
        })?;
    let spec = run_specs::version(pool, project.id, run.spec_version)
        .await
        .map_err(|_| not_found())?;
    let (service, port) = target(&spec.spec, service.as_deref()).ok_or_else(not_found)?;
    let too_big = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY as u64);
    if too_big {
        return Err(page(StatusCode::PAYLOAD_TOO_LARGE, "Request too large"));
    }
    h.touch(project.id).await;
    let open = PortOpen {
        project: u64::try_from(project.id).unwrap_or(0),
        run: run.id.clone(),
        service,
        port,
    };
    let io = h.dial.dial(&run.runner, open).map_err(|e| match e {
        DialError::Busy => busy(),
        DialError::Unreachable => bad_gateway(),
    })?;
    let ws = is_websocket(&req);
    let on_client = ws.then(|| hyper::upgrade::on(&mut req));
    let client = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let out = outbound(req, &host, client, ws);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| bad_gateway())?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut resp = match tokio::time::timeout(HEAD, sender.send_request(out)).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => return Err(bad_gateway()),
        Err(_) => {
            return Err(page(
                StatusCode::GATEWAY_TIMEOUT,
                "The project did not answer",
            ));
        }
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(inbound(resp, false));
    }
    // A 101 nobody asked for is not passed on.
    let on_client = on_client.ok_or_else(bad_gateway)?;
    let on_project = hyper::upgrade::on(&mut resp);
    tokio::spawn(tunnel(Arc::clone(&h), project.id, on_client, on_project));
    Ok(inbound(resp, true))
}

/// The service and container port a host names: `<slug>-<service>`'s exposed port, or for `<slug>`
/// the primary one, which is `web`'s exposed port if it has one, else the first service's by name.
fn target(spec: &RunSpec, service: Option<&str>) -> Option<(String, u16)> {
    let exposed = |(name, s): (&String, &run_specs::spec::Service)| {
        let port = s.ports.iter().find(|p| p.expose)?.port;
        Some((name.clone(), port))
    };
    match service {
        Some(name) => spec.services.get_key_value(name).and_then(exposed),
        None => spec
            .services
            .get_key_value("web")
            .and_then(exposed)
            .or_else(|| spec.services.iter().find_map(exposed)),
    }
}

/// A WebSocket handshake: HTTP/1.1 with `Upgrade: websocket` and `Connection: upgrade`.
fn is_websocket(req: &Request) -> bool {
    let h = req.headers();
    req.version() == Version::HTTP_11
        && h.get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && tokens(h).iter().any(|t| t == "upgrade")
}

/// The lower-case tokens of every `Connection` header.
fn tokens(h: &HeaderMap) -> Vec<String> {
    h.get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect()
}

/// End-to-end headers only: no hop-by-hop, none `Connection` names, no proxy or Core headers.
fn forwardable(from: &HeaderMap) -> HeaderMap {
    let named = tokens(from);
    let mut out = HeaderMap::new();
    for (name, value) in from {
        let n = name.as_str();
        let drop = HOP.contains(&n)
            || named.iter().any(|t| t == n)
            || n == "host"
            || n == "forwarded"
            || n == "x-real-ip"
            || n.starts_with("x-forwarded-")
            || n.starts_with("x-ainkrad-");
        if !drop {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// The request as the project gets it: origin-form, HTTP/1.1, end-to-end headers plus ours.
fn outbound(
    req: Request,
    host: &str,
    client: Option<IpAddr>,
    ws: bool,
) -> hyper::Request<Limited<Body>> {
    let (parts, body) = req.into_parts();
    let mut out = hyper::Request::new(Limited::new(body, MAX_BODY));
    *out.method_mut() = parts.method;
    *out.uri_mut() = parts
        .uri
        .path_and_query()
        .map_or_else(|| Uri::from_static("/"), |p| Uri::from(p.clone()));
    *out.version_mut() = Version::HTTP_11;
    let mut headers = forwardable(&parts.headers);
    let mut set = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            headers.insert(name, v);
        }
    };
    set("host", host);
    set("x-forwarded-host", host);
    set("x-forwarded-proto", "https");
    if let Some(ip) = client {
        set("x-forwarded-for", &ip.to_string());
    }
    // ponytail: one upstream connection per request; keep-alive to the service if it ever matters.
    if ws {
        set("connection", "upgrade");
        set("upgrade", "websocket");
    } else {
        set("connection", "close");
    }
    *out.headers_mut() = headers;
    out
}

/// The project's answer as the client gets it: end-to-end headers, cookies host-only.
fn inbound(resp: hyper::Response<hyper::body::Incoming>, upgrade: bool) -> Response {
    let (parts, body) = resp.into_parts();
    let mut headers = forwardable(&parts.headers);
    let cookies: Vec<HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| HeaderValue::from_str(&host_only(v.to_str().ok()?)).ok())
        .collect();
    // Every value goes; one that is not text is dropped rather than passed on unchecked.
    headers.remove(header::SET_COOKIE);
    for c in cookies {
        headers.append(header::SET_COOKIE, c);
    }
    if upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    }
    let body = if upgrade {
        Body::empty()
    } else {
        Body::new(body)
    };
    let mut out = Response::new(body);
    *out.status_mut() = parts.status;
    *out.headers_mut() = headers;
    out
}

/// A `Set-Cookie` value without its `Domain` attribute: the cookie stays on the project's host.
fn host_only(cookie: &str) -> String {
    cookie
        .split(';')
        .enumerate()
        .filter(|(i, a)| {
            *i == 0
                || !a
                    .trim_start()
                    .get(..6)
                    .is_some_and(|n| n.eq_ignore_ascii_case("domain"))
        })
        .map(|(_, a)| a)
        .collect::<Vec<_>>()
        .join(";")
}

/// A WebSocket's bytes both ways, until either side closes or nothing moves for [`WS_IDLE`]. Bytes
/// moving push the idle stop back.
async fn tunnel(h: Arc<Host>, project: i64, client: OnUpgrade, upstream: OnUpgrade) {
    let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream) else {
        return;
    };
    let mut client = TokioIo::new(client);
    let (mut upstream, activity) = super::idle::wrap(TokioIo::new(upstream));
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    tokio::pin!(copy);
    let mut tick = tokio::time::interval(TOUCH_EVERY);
    let mut seen = activity.deadline(Duration::ZERO);
    loop {
        tokio::select! {
            _ = &mut copy => return,
            _ = tick.tick() => {
                let moved = activity.deadline(Duration::ZERO);
                if moved > seen {
                    seen = moved;
                    h.touch(project).await;
                } else if moved + WS_IDLE <= Instant::now() {
                    return;
                }
            }
        }
    }
}

fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// A small page: the title is always one of ours, never request text.
fn page(status: StatusCode, title: &'static str) -> Response {
    let html = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
         <title>{title}</title><body style=\"font:16px system-ui;margin:20vh auto;\
         max-width:28rem;text-align:center;color:#444\"><h1 style=\"font-size:1.25rem\">{title}</h1>"
    );
    let headers = [
        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    (status, headers, html).into_response()
}

fn not_found() -> Response {
    page(StatusCode::NOT_FOUND, "Nothing here")
}

fn unavailable() -> Response {
    page(StatusCode::SERVICE_UNAVAILABLE, "Try again shortly")
}

fn busy() -> Response {
    let mut r = page(StatusCode::SERVICE_UNAVAILABLE, "Too busy, try again");
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

fn bad_gateway() -> Response {
    page(StatusCode::BAD_GATEWAY, "The project could not be reached")
}

mod dial;
pub use dial::{Dial, DialError, HubDial};

#[cfg(test)]
mod tests;
