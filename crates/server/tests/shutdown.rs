//! A clean stop: on SIGTERM `serve` closes a connected client's event socket with 1012 (so it
//! reconnects to the next server), checkpoints the database and exits 0.

use std::process::Command;
use std::time::Duration;

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
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["device", "add", db_arg, "mac"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let key = String::from_utf8(out.stdout).unwrap().trim().to_owned();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(["serve", db_arg, "--bind", &bind])
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
    let mut req = format!("ws://{bind}/api/v1/events/ws")
        .into_client_request()
        .unwrap();
    let bearer = format!("Bearer {key}").parse().unwrap();
    req.headers_mut().insert("authorization", bearer);
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
