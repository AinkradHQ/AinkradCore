//! The host's own socket (handshake spec §7.3): a request over a Unix socket of the gateway
//! carries `Local`, saying whether the peer runs as the server's user; a TCP request never does.
//! Beside a TCP listener, `with_admin_socket` adds that socket.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::gateway::{Gateway, Limits, Listen, Local};
use axum::Router;
use axum::extract::Extension;
use axum::routing::get;
use tokio::sync::watch;

use super::common::get as http_get;

async fn who(local: Option<Extension<Local>>) -> &'static str {
    match local {
        Some(Extension(Local { same_user: true })) => "same user",
        Some(_) => "another user",
        None => "network",
    }
}

#[tokio::test]
async fn a_socket_peer_is_marked_local_and_a_tcp_one_is_not() {
    let dir = std::env::temp_dir().join(format!("core-gw-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let admin = dir.join("admin.sock");
    let gateway = Gateway::bind(Listen::Tcp("127.0.0.1:0".to_owned()), Limits::default())
        .await
        .unwrap()
        .with_admin_socket(&admin)
        .unwrap();
    let port = gateway.local_addr().unwrap().port();
    let closing = Arc::new(watch::Sender::new(false));
    let app = Router::new().route("/who", get(who));
    let served = tokio::spawn(gateway.serve(app, Arc::clone(&closing), Duration::from_secs(1)));

    let host = format!("127.0.0.1:{port}");
    let mut tcp = tokio::net::TcpStream::connect(&host).await.unwrap();
    assert_eq!(http_get(&mut tcp, "/who", &host, None).await.1, "network");
    let mut unix = tokio::net::UnixStream::connect(&admin).await.unwrap();
    assert_eq!(
        http_get(&mut unix, "/who", "localhost", None).await.1,
        "same user"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&admin).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    closing.send_replace(true);
    drop((tcp, unix));
    served.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
