//! The drain (E1-06.5): once `closing` is set the listener stops accepting, and every request
//! already accepted (here, ten slow ones on ten connections) gets its full answer before
//! `serve` returns. The binary's SIGTERM path, event sockets included, is `tests/shutdown.rs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use axum::Router;
use axum::routing::get;

use super::common::get as http_get;

#[tokio::test]
async fn closing_stops_accepting_and_finishes_every_request_in_flight() {
    let gateway = Gateway::bind(Listen::Tcp("127.0.0.1:0".to_owned()), Limits::default())
        .await
        .unwrap();
    let port = gateway.local_addr().unwrap().port();
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            "done"
        }),
    );
    let closing = Arc::new(tokio::sync::watch::Sender::new(false));
    let served = tokio::spawn(gateway.serve(app, Arc::clone(&closing), Duration::from_secs(5)));

    let host = format!("127.0.0.1:{port}");
    let mut in_flight = Vec::new();
    for _ in 0..10 {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let host = host.clone();
        in_flight.push(tokio::spawn(async move {
            http_get(&mut tcp, "/slow", &host, None).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stopping = Instant::now();
    closing.send_replace(true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "no longer accepting"
    );
    for request in in_flight {
        assert_eq!(
            request.await.unwrap(),
            (200, "done".to_owned()),
            "dropped in flight"
        );
    }
    tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("serve returns once drained")
        .unwrap()
        .unwrap();
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "within the grace"
    );
}
