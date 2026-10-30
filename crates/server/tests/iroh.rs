//! The iroh listener (E2-19): hermetic, on loopback with no relay and no public service. An
//! iroh peer reaches the same API as any listener, only with the device handshake; the transport
//! key grants nothing.
#![cfg(feature = "iroh")]

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::gateway::p2p::{ALPN, Config};
use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode};

const HOST: &str = "core.test";

struct Fx {
    dir: std::path::PathBuf,
    dev: TestDevice,
    closing: Arc<tokio::sync::watch::Sender<bool>>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
    addr: EndpointAddr,
}

impl Fx {
    async fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("core-iroh-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = store::connect(&dir.join("core.db")).await.unwrap();
        let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
        let dev = TestDevice::enroll(
            &pool,
            "mac",
            "device",
            &["read"],
            &identity.fp,
            Arc::new(SystemClock),
        )
        .await;
        let app = App::new(pool, Arc::new(SystemClock), HOST.to_owned(), identity);
        let s = app.auth.issue_session(&dev.id, SystemClock.unix());
        dev.set_session(Some(s.id));
        let config = Config {
            key_path: dir.join("iroh.key"),
            relays: vec![],
            bind: vec!["127.0.0.1:0".parse().unwrap()],
        };
        // The main listener is a socket nobody dials; iroh is the one under test.
        let gateway = Gateway::bind(Listen::Unix(dir.join("core.sock")), Limits::default())
            .await
            .unwrap()
            .with_iroh(config)
            .await
            .unwrap();
        let endpoint = gateway.iroh_endpoint().unwrap();
        let addr = EndpointAddr::new(endpoint.id()).with_ip_addr(endpoint.bound_sockets()[0]);
        let closing = Arc::clone(&app.closing);
        let served =
            tokio::spawn(gateway.serve(router(app), Arc::clone(&closing), Duration::from_secs(5)));
        Self {
            dir,
            dev,
            closing,
            served,
            addr,
        }
    }

    async fn stop(self) {
        self.closing.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), self.served)
            .await
            .expect("drains in time")
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn client() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

/// One raw HTTP/1.1 request on its own stream: everything the Core answers.
async fn raw(conn: &iroh::endpoint::Connection, request: &str) -> String {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(request.as_bytes()).await.unwrap();
    // No `finish` here: hyper closes a connection whose peer shut its write half, answer or not.
    // `connection: close` makes the Core end the stream itself.
    let answer = recv.read_to_end(1 << 20).await.unwrap();
    drop(send);
    String::from_utf8_lossy(&answer).into_owned()
}

/// A GET, signed when `signer` is given: the status and the body.
async fn request(
    conn: &iroh::endpoint::Connection,
    path: &str,
    signer: Option<&TestDevice>,
) -> (u16, String) {
    let auth: String = signer
        .map(|d| d.headers("GET", path, b""))
        .unwrap_or_default()
        .iter()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .collect();
    let head = format!("GET {path} HTTP/1.1\r\nhost: {HOST}\r\nconnection: close\r\n{auth}\r\n");
    let raw = raw(conn, &head).await;
    let status = raw
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn a_peer_reaches_the_api_only_with_the_device_handshake() {
    let fx = Fx::start("api").await;
    let client = client().await;
    let conn = client.connect(fx.addr.clone(), ALPN).await.unwrap();

    // The transport is up and authenticated as the endpoint the client pinned, and that grants
    // nothing: the pre-auth routes answer, everything else is the same 401 as for a stranger on TCP.
    assert_eq!(request(&conn, "/healthz", None).await, (200, "ok".into()));
    let (status, body) = request(&conn, "/handshake", None).await;
    assert_eq!(status, 200, "{body}");
    for path in [
        "/api/v1/me",
        "/api/v1/devices",
        "/api/v1/settings",
        "/api/v1/events",
        "/nope",
        "/modules/citadel/v1/anything",
    ] {
        let (status, body) = request(&conn, path, None).await;
        assert_eq!(status, 401, "{path}: {body}");
    }
    // The runner hub is not reachable without a TLS channel binding.
    let (status, _) = request(&conn, "/runner/v2/connect", None).await;
    assert_ne!(status, 101);
    assert_ne!(status, 200);

    // The same device-key signature that works on any listener works inside the stream.
    let (status, body) = request(&conn, "/api/v1/me", Some(&fx.dev)).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"mac\""), "{body}");

    // The Host rule holds over iroh.
    let rebound = "GET /handshake HTTP/1.1\r\nhost: rebound.example\r\nconnection: close\r\n\r\n";
    assert!(
        raw(&conn, rebound).await.starts_with("HTTP/1.1 403"),
        "Host"
    );

    // And so does the Origin rule: a browser Origin is refused whoever carries it.
    let origin = format!(
        "GET /handshake HTTP/1.1\r\nhost: {HOST}\r\norigin: https://evil.example\r\nconnection: close\r\n\r\n"
    );
    assert!(
        raw(&conn, &origin).await.starts_with("HTTP/1.1 403"),
        "Origin"
    );

    conn.close(0u8.into(), b"done");
    client.close().await;
    fx.stop().await;
}

#[tokio::test]
async fn dialling_a_different_endpoint_id_fails() {
    // The pinned id is what the client checks: the same address under another id is refused.
    let fx = Fx::start("pin").await;
    let client = client().await;
    let wrong = iroh::SecretKey::generate().public();
    let mut addr = EndpointAddr::new(wrong);
    for ip in fx.addr.ip_addrs() {
        addr = addr.with_ip_addr(*ip);
    }
    let dial = tokio::time::timeout(Duration::from_secs(5), client.connect(addr, ALPN)).await;
    assert!(!matches!(dial, Ok(Ok(_))), "a wrong id must not connect");
    client.close().await;
    fx.stop().await;
}

#[tokio::test]
async fn another_alpn_is_refused() {
    let fx = Fx::start("alpn").await;
    let client = client().await;
    let dial = tokio::time::timeout(
        Duration::from_secs(5),
        client.connect(fx.addr.clone(), b"something/else"),
    )
    .await;
    assert!(!matches!(dial, Ok(Ok(_))));
    client.close().await;
    fx.stop().await;
}

#[tokio::test]
async fn the_listener_is_off_unless_asked_for() {
    // A gateway as `serve` builds it without `--iroh` has no endpoint, and no key is made.
    let dir = std::env::temp_dir().join(format!("core-iroh-off-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let gateway = Gateway::bind(Listen::Unix(dir.join("core.sock")), Limits::default())
        .await
        .unwrap();
    assert!(gateway.iroh_endpoint().is_none());
    assert!(!dir.join("iroh.key").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
