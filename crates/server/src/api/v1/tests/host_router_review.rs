//! The Host router's security review fixes (P6-02, PR #338): in-flight caps per project and per
//! client (503 + `Retry-After`), the client address from Cloudflare only, activity on 2xx/3xx
//! only, an archived or hidden project never shadowing a live one's service host, the client's
//! `Content-Length` never passed on, and an open WebSocket closed once the project stops serving.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use ainkrad_proto::v2::PortOpen;
use futures_util::{SinkExt, StreamExt};
use tokio::io::DuplexStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::host_router::{DOMAIN, Local, call, get, local, running};
use super::project_runs::w;
use super::*;
use crate::gateway::projects::{self as host, Dial, DialError};
use crate::store::runs as store;

/// A runner whose port streams never answer: every request through it stays in flight.
#[derive(Default)]
struct Silent {
    opened: AtomicUsize,
    held: Mutex<Vec<DuplexStream>>,
}

impl Dial for Silent {
    fn dial(&self, _runner: &str, _open: PortOpen) -> Result<DuplexStream, DialError> {
        let (ours, theirs) = tokio::io::duplex(1024);
        self.held.lock().unwrap().push(theirs);
        self.opened.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(ours)
    }
}

fn from(peer: [u8; 4], mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 4000))));
    req
}

async fn opened_reaches(dial: &Silent, n: usize) {
    let wait = async {
        while dial.opened.load(AtomicOrdering::Relaxed) < n {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .expect("the requests reached the runner");
}

#[tokio::test]
async fn in_flight_caps_per_client_and_per_project_answer_503_with_retry_after() {
    let fx = fx().await;
    let dial = Arc::new(Silent::default());
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    let hang = |peer: [u8; 4]| {
        let r = r.clone();
        tokio::spawn(async move { call(&r, from(peer, get("shop.proj.test", "/"))).await })
    };
    let mut hung: Vec<_> = (0..host::PER_CLIENT)
        .map(|_| hang([203, 0, 113, 1]))
        .collect();
    opened_reaches(&dial, host::PER_CLIENT).await;
    // One client past its cap: refused before the runner is dialled.
    let (status, headers, _) = call(&r, from([203, 0, 113, 1], get("shop.proj.test", "/"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(headers.contains_key(header::RETRY_AFTER));
    assert_eq!(dial.opened.load(AtomicOrdering::Relaxed), host::PER_CLIENT);
    // Other clients fill the project's cap; past it, any client is refused.
    for i in 0..(host::PER_PROJECT - host::PER_CLIENT) {
        hung.push(hang([198, 51, 100, i as u8]));
    }
    opened_reaches(&dial, host::PER_PROJECT).await;
    let (status, headers, _) = call(&r, from([192, 0, 2, 9], get("shop.proj.test", "/"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(headers.contains_key(header::RETRY_AFTER));
    assert_eq!(dial.opened.load(AtomicOrdering::Relaxed), host::PER_PROJECT);
    assert!(
        host::PER_PROJECT < 32,
        "well under the runner's run.port streams"
    );
    for h in hung {
        h.abort();
    }
}

#[tokio::test]
async fn the_client_address_is_cloudflares_header_only_from_cloudflare() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let claim = |peer: [u8; 4]| {
        let mut req = get("shop.proj.test", "/");
        for n in ["cf-connecting-ip", "true-client-ip"] {
            req.headers_mut().insert(n, "198.51.100.4".parse().unwrap());
        }
        from(peer, req)
    };
    let (_, _, direct) = call(&r, claim([203, 0, 113, 7])).await;
    assert_eq!(direct["headers"]["x-forwarded-for"], "203.0.113.7");
    assert!(direct["headers"].get("cf-connecting-ip").is_none());
    let (_, _, edge) = call(&r, claim([104, 16, 0, 1])).await;
    assert_eq!(edge["headers"]["x-forwarded-for"], "198.51.100.4");
    assert_eq!(edge["headers"]["cf-connecting-ip"], "198.51.100.4");
}

#[tokio::test]
async fn only_a_2xx_or_3xx_answer_pushes_the_idle_stop_back() {
    let fx = fx().await;
    let dial = local().await;
    let p = running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let before = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    fx.clock.advance(600);
    let (status, _, _) = call(&r, get("shop.proj.test", "/missing")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let after = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    assert_eq!(after.last_activity_at, before.last_activity_at);
    assert_eq!(call(&r, get("shop.proj.test", "/")).await.0, StatusCode::OK);
    let after = store::live(&fx.app.pool, p).await.unwrap().unwrap();
    assert_ne!(after.last_activity_at, before.last_activity_at);
}

/// `shop-api.proj.test` reaches `shop`'s `api` service (port 4000).
async fn reaches_shop_api(r: &axum::Router, dial: &Local) -> bool {
    dial.opened.lock().unwrap().clear();
    let status = call(r, get("shop-api.proj.test", "/")).await.0;
    let opened = dial.opened.lock().unwrap().clone();
    status == StatusCode::OK && opened.first().is_some_and(|o| o.port == 4000)
}

#[tokio::test]
async fn an_archived_or_hidden_project_never_shadows_a_live_service_host() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let now = fx.app.clock.now();
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    let pool = &fx.app.pool;
    let shadow = crate::store::projects::create(pool, "shop-api", "x", "", "manual", w(&now))
        .await
        .unwrap();
    crate::store::projects::update(pool, shadow.id, None, None, Some(false), w(&now))
        .await
        .unwrap();
    assert!(reaches_shop_api(&r, &dial).await, "hidden");
    crate::store::projects::update(pool, shadow.id, None, None, Some(true), w(&now))
        .await
        .unwrap();
    crate::store::projects::archive(pool, shadow.id, w(&now))
        .await
        .unwrap();
    assert!(reaches_shop_api(&r, &dial).await, "archived");
}

#[tokio::test]
async fn the_clients_content_length_is_not_passed_on() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let req = Request::post("/")
        .header(header::HOST, "shop.proj.test")
        .header(header::CONTENT_LENGTH, "2")
        .body(Body::from("hello"))
        .unwrap();
    let (status, _, body) = call(&r, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["len"], 5);
    assert_eq!(body["headers"]["content-length"], "5");
}

#[tokio::test]
async fn an_open_websocket_closes_once_the_project_is_no_longer_exposed() {
    let fx = fx().await;
    let dial = local().await;
    let p = running(&fx, "shop").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = r.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut()
        .insert(header::HOST, "shop.proj.test".parse().unwrap());
    let (mut s, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    s.send(Message::Text("ping".into())).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(5), s.next()).await;
    assert_eq!(
        back.unwrap().unwrap().unwrap(),
        Message::Text("ping".into())
    );
    let now = fx.app.clock.now();
    crate::store::projects::update(&fx.app.pool, p, None, None, Some(false), w(&now))
        .await
        .unwrap();
    // Closed within a few checks: the stream ends (or errors), with no more echoes.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match s.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the WebSocket stayed open");
}
