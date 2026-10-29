//! A clean stop: on SIGTERM `serve` stops accepting, closes a connected client's event socket
//! with 1012 (so it reconnects to the next server), checkpoints the database and exits 0
//! within its grace. Requests in flight finishing is `tests/gateway/drain.rs`.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::SystemClock;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[tokio::test]
async fn sigterm_closes_event_sockets_checkpoints_and_exits_zero() {
    let dir = std::env::temp_dir().join(format!("core-shutdown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    let db_arg = db.to_str().unwrap();
    // A device enrolled before the server starts, signing for the identity it will load.
    let identity = Identity::load_or_create(&dir).unwrap();
    let pool = ainkrad_core_server::store::connect(&db).await.unwrap();
    let clock = Arc::new(SystemClock);
    let mac = TestDevice::enroll(&pool, "mac", "device", &["read"], &identity.fp, clock).await;
    pool.close().await;

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let listen = format!("loopback:{port}");
    let mut server = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["serve", db_arg, "--listen", &listen])
        .stderr(std::fs::File::create(dir.join("server.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&bind).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The handshake as a client does it: the fingerprint, a challenge, a session.
    let http = reqwest::Client::new();
    let handshake: serde_json::Value = http
        .get(format!("http://{bind}/handshake"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(handshake["identity_fingerprint"], identity.fp.as_str());
    let challenge: serde_json::Value = http
        .post(format!("http://{bind}/handshake/challenge"))
        .json(&serde_json::json!({"device_id": mac.id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = serde_json::json!({"challenge": challenge["challenge"]}).to_string();
    let mut login = http
        .post(format!("http://{bind}/handshake/session"))
        .header("content-type", "application/json")
        .body(body.clone());
    for (name, value) in mac.headers_session("POST", "/handshake/session", body.as_bytes(), None) {
        login = login.header(name, value);
    }
    let session: serde_json::Value = login.send().await.unwrap().json().await.unwrap();
    mac.set_session(session["session_id"].as_str().map(str::to_owned));
    assert!(mac.session.lock().unwrap().is_some(), "{session}");

    let mut req = format!("ws://{bind}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    for (name, value) in mac.headers("GET", "/api/v1/events/ws", b"") {
        req.headers_mut().insert(name, value.parse().unwrap());
    }
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();

    let pid = server.id().unwrap().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );

    let close = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Close(frame) = msg {
                return frame.map(|f| u16::from(f.code));
            }
        }
        None
    });
    assert_eq!(close.await.unwrap(), Some(1012), "a clean close: reconnect");
    assert!(
        tokio::net::TcpStream::connect(&bind).await.is_err(),
        "no longer accepting"
    );
    let status = tokio::time::timeout(Duration::from_secs(15), server.wait())
        .await
        .expect("serve stops within its grace")
        .unwrap();
    let log = std::fs::read_to_string(dir.join("server.log")).unwrap();
    assert!(status.success(), "exit 0; log:\n{log}");
    assert!(log.contains("stopped"), "{log}");
    let wal = std::fs::metadata(dir.join("core.db-wal")).map_or(0, |m| m.len());
    assert_eq!(wal, 0, "the WAL is checkpointed");
    let _ = std::fs::remove_dir_all(&dir);
}
