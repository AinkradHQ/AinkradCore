//! The connection limits (E1-06.4), with deadlines shortened to 300 ms: headers sent too
//! slowly (slowloris), a connection that sends nothing, too many headers, a request that
//! runs too long, and a TLS connection that never says hello.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::common::{Ca, Fx, get as http_get};

const SHORT: Duration = Duration::from_millis(300);

fn limits() -> Limits {
    Limits {
        tls_handshake: SHORT,
        header_read: SHORT,
        request: SHORT,
        headers: 8,
        idle: SHORT * 2,
        ..Limits::default()
    }
}

/// Reads until the server closes; what it sent and how long that took.
async fn until_closed(tcp: &mut TcpStream, what: &str) -> (String, Duration) {
    let started = Instant::now();
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
    assert!(
        read.is_ok(),
        "{what}: the server kept the connection open for 5 s"
    );
    (
        String::from_utf8_lossy(&got).into_owned(),
        started.elapsed(),
    )
}

#[tokio::test]
async fn slow_headers_silence_many_headers_and_long_requests_are_cut() {
    let gateway = Gateway::bind(Listen::Tcp("127.0.0.1:0".to_owned()), limits())
        .await
        .unwrap();
    let port = gateway.local_addr().unwrap().port();
    let app = Router::new().route("/ok", get(|| async { "ok" })).route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            "late"
        }),
    );
    let closing = Arc::new(tokio::sync::watch::Sender::new(false));
    let served = tokio::spawn(gateway.serve(app, Arc::clone(&closing), Duration::from_secs(2)));
    let connect = || TcpStream::connect(("127.0.0.1", port));
    let host = format!("127.0.0.1:{port}");

    // Slowloris: headers started, never finished.
    let mut tcp = connect().await.unwrap();
    tcp.write_all(b"GET /ok HTTP/1.1\r\nhost: h\r\n")
        .await
        .unwrap();
    let (_, took) = until_closed(&mut tcp, "slow headers").await;
    assert!(
        took < Duration::from_secs(2),
        "slow headers cut after {took:?}"
    );

    // A connection that never sends a byte.
    let mut tcp = connect().await.unwrap();
    let (_, took) = until_closed(&mut tcp, "silence").await;
    assert!(
        took < Duration::from_secs(2),
        "a silent connection cut after {took:?}"
    );

    // Too many headers: 431.
    let mut tcp = connect().await.unwrap();
    let many: String = (0..20).map(|i| format!("x-h{i}: v\r\n")).collect();
    let head = format!("GET /ok HTTP/1.1\r\nhost: {host}\r\n{many}\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    let (answer, _) = until_closed(&mut tcp, "many headers").await;
    assert!(answer.starts_with("HTTP/1.1 431"), "{answer}");

    // A request past its deadline: 408 `timeout`, and the connection still serves.
    let mut tcp = connect().await.unwrap();
    let (status, body) = http_get(&mut tcp, "/slow", &host, None).await;
    assert_eq!(status, 408, "{body}");
    assert!(body.contains("\"timeout\""), "{body}");
    assert_eq!(
        http_get(&mut tcp, "/ok", &host, None).await,
        (200, "ok".into())
    );

    closing.send_replace(true);
    served.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_tls_connection_without_a_hello_is_cut() {
    let ca = Ca::new();
    let fx = Fx::new("limits-tls").await;
    let acme = super::acme(&fx);
    let (chain, key) = ca.leaf(90);
    acme.store_cert(&chain, &key).unwrap();
    let listen = Listen::Public {
        port: 0,
        http01: None,
        acme,
    };
    let gateway = Gateway::bind(listen, limits()).await.unwrap();
    let port = gateway.local_addr().unwrap().port();
    let closing = Arc::new(tokio::sync::watch::Sender::new(false));
    let served =
        tokio::spawn(gateway.serve(Router::new(), Arc::clone(&closing), Duration::from_secs(2)));
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (_, took) = until_closed(&mut tcp, "no hello").await;
    assert!(
        took < Duration::from_secs(2),
        "no hello, cut after {took:?}"
    );
    closing.send_replace(true);
    served.await.unwrap().unwrap();
}
