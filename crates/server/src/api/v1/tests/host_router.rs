//! The Host router (P6-02) against a fixture "runner": a [`Local`] dial that bridges each port
//! stream to a service on loopback, which echoes what it got. Covered: only project hosts answer
//! and no Core route is reachable through one; expose off, archived and not running are refused
//! server-side; `<slug>-<service>` and the primary port; hop-by-hop and proxy headers stripped,
//! `X-Forwarded-*` set, `Set-Cookie` made host-only; body cap; the stream cap's 503; the idle
//! stop pushed back; a WebSocket end to end. The 100 rps load test is `host_router_load.rs`.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use ainkrad_proto::v2::PortOpen;
use axum::extract::ws::{Message as AxMessage, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::io::DuplexStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::project_runs::w;
use super::*;
use crate::gateway::projects::{self as host, Dial, DialError};
use crate::store::run_specs;
use crate::store::runs as store;

pub(super) const DOMAIN: &str = "proj.test";

/// The fixture runner: every port stream is a loopback connection to `addr`.
pub(super) struct Local {
    pub(super) addr: SocketAddr,
    pub(super) opened: Mutex<Vec<PortOpen>>,
    pub(super) busy: AtomicBool,
}

impl Dial for Local {
    fn dial(&self, _runner: &str, open: PortOpen) -> Result<DuplexStream, DialError> {
        if self.busy.load(AtomicOrdering::Relaxed) {
            return Err(DialError::Busy);
        }
        self.opened.lock().unwrap().push(open);
        let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let addr = self.addr;
        tokio::spawn(async move {
            if let Ok(mut tcp) = tokio::net::TcpStream::connect(addr).await {
                let _ = tokio::io::copy_bidirectional(&mut theirs, &mut tcp).await;
            }
        });
        Ok(ours)
    }
}

/// What the service saw, echoed as JSON; with cookies (one for the parent domain) and a
/// hop-by-hop header the router must drop.
async fn echo(method: Method, uri: axum::http::Uri, headers: HeaderMap, body: Body) -> Response {
    let len = to_bytes(body, usize::MAX).await.map_or(0, |b| b.len());
    let seen: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(n, v)| (n.to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    let body = json!({"method": method.as_str(), "uri": uri.to_string(), "headers": seen,
                      "len": len});
    (
        [
            ("set-cookie", "sid=1; Domain=ainkrad.io; Path=/"),
            ("keep-alive", "timeout=5"),
        ],
        axum::Json(body),
    )
        .into_response()
}

async fn ws(up: WebSocketUpgrade) -> Response {
    up.on_upgrade(|mut s| async move {
        while let Some(Ok(m)) = s.recv().await {
            if let AxMessage::Text(t) = m
                && s.send(AxMessage::Text(t)).await.is_err()
            {
                return;
            }
        }
    })
}

/// The fixture service on loopback.
pub(super) async fn service() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route("/ws", axum::routing::get(ws))
        .route(
            "/missing",
            axum::routing::get(|| async { StatusCode::NOT_FOUND }),
        )
        .fallback(echo);
    tokio::spawn(async move { axum::serve(listener, app).await });
    addr
}

pub(super) async fn local() -> Arc<Local> {
    Arc::new(Local {
        addr: service().await,
        opened: Mutex::default(),
        busy: AtomicBool::new(false),
    })
}

/// An exposed project with `web` (3000) and `api` (4000) exposed, `db` not, and a running run.
pub(super) async fn running(fx: &Fx, slug: &str) -> i64 {
    let now = fx.app.clock.now();
    let p = crate::store::projects::create(&fx.app.pool, slug, slug, "", "manual", w(&now))
        .await
        .unwrap();
    let spec = json!({"services": {
        "web": {"image": "node:22", "ports": [{"port": 3000, "expose": true}]},
        "api": {"image": "node:22", "ports": [{"port": 4000, "expose": true}]},
        "db": {"image": "postgres:17", "ports": [{"port": 5432}]}}});
    let v = run_specs::save(&fx.app.pool, p.id, &spec, "manual", w(&now))
        .await
        .unwrap();
    let id = format!("r_{slug}");
    store::begin(&fx.app.pool, &id, p.id, v.version, "r1", w(&now))
        .await
        .unwrap();
    assert!(store::mark_running(&fx.app.pool, &id, &now).await.unwrap());
    p.id
}

pub(super) fn get(host: &str, path: &str) -> Request<Body> {
    Request::get(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

pub(super) async fn call(r: &axum::Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let res = r.clone().oneshot(req).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

#[tokio::test]
async fn only_project_hosts_answer_and_no_core_route_is_reachable() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    // The Core's own host, reserved names, other domains, two levels: 404, never forwarded.
    for h in [
        HOST,
        "core.proj.test",
        "signin.proj.test",
        "www.proj.test",
        "proj.test",
        "a.shop.proj.test",
        "shop.other.test",
        "shop.proj.test.evil",
    ] {
        let (status, _, _) = call(&r, get(h, "/api/v1/me")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{h}");
    }
    // A Core path on a project host is the project's path: it goes to the project, not the Core.
    for path in ["/api/v1/me", "/handshake", "/healthz", "/runner/v2/connect"] {
        let (status, _, body) = call(&r, get("shop.proj.test", path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(body["uri"], path);
    }
    assert!(dial.opened.lock().unwrap().iter().all(|o| o.port == 3000));
}

#[tokio::test]
async fn expose_off_archived_and_not_running_are_refused_server_side() {
    let fx = fx().await;
    let dial = local().await;
    let p = running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    assert_eq!(call(&r, get("shop.proj.test", "/")).await.0, StatusCode::OK);
    let now = fx.app.clock.now();
    crate::store::projects::update(&fx.app.pool, p, None, None, Some(false), w(&now))
        .await
        .unwrap();
    assert_eq!(
        call(&r, get("shop.proj.test", "/")).await.0,
        StatusCode::NOT_FOUND
    );
    crate::store::projects::update(&fx.app.pool, p, None, None, Some(true), w(&now))
        .await
        .unwrap();
    // Stopped: the small "not running" page, and nothing is dialled.
    let opened = dial.opened.lock().unwrap().len();
    let end = store::End {
        state: "stopped",
        reason: Some("user"),
        error: None,
    };
    assert!(
        store::finish(&fx.app.pool, "r_shop", end, w(&now))
            .await
            .unwrap()
    );
    let res = r.clone().oneshot(get("shop.proj.test", "/")).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let page = to_bytes(res.into_body(), 1 << 16).await.unwrap();
    assert!(String::from_utf8_lossy(&page).contains("not running"));
    assert_eq!(dial.opened.lock().unwrap().len(), opened);
    // Archived: 404.
    crate::store::projects::archive(&fx.app.pool, p, w(&now))
        .await
        .unwrap();
    assert_eq!(
        call(&r, get("shop.proj.test", "/")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_service_host_reaches_its_exposed_port_and_nothing_else() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "my-shop").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    for (h, want) in [
        ("my-shop.proj.test", Some(("web", 3000))),
        ("my-shop-web.proj.test", Some(("web", 3000))),
        ("my-shop-api.proj.test", Some(("api", 4000))),
        ("my-shop-db.proj.test", None),
        ("my-shop-nope.proj.test", None),
        ("my.proj.test", None),
    ] {
        dial.opened.lock().unwrap().clear();
        let (status, _, _) = call(&r, get(h, "/")).await;
        let opened = dial.opened.lock().unwrap().clone();
        match want {
            Some((service, port)) => {
                assert_eq!(status, StatusCode::OK, "{h}");
                assert_eq!(
                    (opened[0].service.as_str(), opened[0].port),
                    (service, port)
                );
                assert_eq!(opened[0].run, "r_my-shop");
            }
            None => {
                assert_eq!(status, StatusCode::NOT_FOUND, "{h}");
                assert!(opened.is_empty(), "{h}");
            }
        }
    }
}

#[tokio::test]
async fn headers_are_cleaned_forwarded_and_cookies_kept_host_only() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let mut req = Request::post("/a/b?x=1")
        .header(header::HOST, "shop.proj.test")
        .header("connection", "x-hop, keep-alive")
        .header("x-hop", "1")
        .header("keep-alive", "timeout=1")
        .header("proxy-authorization", "Basic Zm9vOmJhcg==")
        .header("x-forwarded-for", "6.6.6.6")
        .header("forwarded", "for=6.6.6.6")
        .header("x-real-ip", "6.6.6.6")
        .header("x-ainkrad-device", "d_core")
        .header("cf-connecting-ip", "6.6.6.6")
        .header("true-client-ip", "6.6.6.6")
        .header("x-client-ip", "6.6.6.6")
        .header("x-app", "kept")
        .body(Body::from("hello"))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 5555))));
    let (status, headers, body) = call(&r, req).await;
    assert_eq!(status, StatusCode::OK);
    let seen = &body["headers"];
    for gone in [
        "x-hop",
        "keep-alive",
        "proxy-authorization",
        "forwarded",
        "x-real-ip",
        "x-ainkrad-device",
        // Not from Cloudflare's edge: the client's own claims about its address go.
        "cf-connecting-ip",
        "true-client-ip",
        "x-client-ip",
    ] {
        assert!(seen.get(gone).is_none(), "{gone}: {seen}");
    }
    assert_eq!(seen["x-app"], "kept");
    assert_eq!(seen["host"], "shop.proj.test");
    assert_eq!(seen["x-forwarded-for"], "203.0.113.7");
    assert_eq!(seen["x-forwarded-proto"], "https");
    assert_eq!(seen["x-forwarded-host"], "shop.proj.test");
    assert_eq!(
        (body["method"].as_str(), body["len"].as_u64()),
        (Some("POST"), Some(5))
    );
    assert_eq!(body["uri"], "/a/b?x=1");
    // The project's answer: no hop-by-hop, and its cookie cannot reach the parent domain.
    assert!(headers.get("keep-alive").is_none());
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert_eq!(cookie, "sid=1; Path=/");
}

#[tokio::test]
async fn too_big_bodies_connect_and_a_full_runner_are_refused() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    let big = Request::post("/")
        .header(header::HOST, "shop.proj.test")
        .header(header::CONTENT_LENGTH, (host::MAX_BODY + 1).to_string())
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&r, big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let connect = Request::connect("shop.proj.test:443")
        .header(header::HOST, "shop.proj.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&r, connect).await.0, StatusCode::METHOD_NOT_ALLOWED);
    // The runner's `run.port` cap: 503 with a Retry-After.
    dial.busy.store(true, AtomicOrdering::Relaxed);
    let (status, headers, _) = call(&r, get("shop.proj.test", "/")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers[header::RETRY_AFTER], "1");
}

#[tokio::test]
async fn traffic_pushes_the_idle_stop_back() {
    let fx = fx().await;
    let dial = local().await;
    let p = running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let before = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    fx.clock.advance(600);
    assert_eq!(call(&r, get("shop.proj.test", "/")).await.0, StatusCode::OK);
    let after = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    assert_ne!(after.last_activity_at, before.last_activity_at);
    assert_eq!(
        after.last_activity_at.as_deref(),
        Some(fx.app.clock.now().as_str())
    );
    // A refused request (unknown service) is not traffic to the run.
    fx.clock.advance(600);
    assert_eq!(
        call(&r, get("shop-nope.proj.test", "/")).await.0,
        StatusCode::NOT_FOUND
    );
    let again = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    assert_eq!(again.last_activity_at, after.last_activity_at);
}

#[tokio::test]
async fn a_websocket_is_carried_end_to_end() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = r.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut()
        .insert(header::HOST, "shop.proj.test".parse().unwrap());
    let (mut s, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    s.send(Message::Text("ping".into())).await.unwrap();
    let back = tokio::time::timeout(std::time::Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(back, Message::Text("ping".into()));
}
