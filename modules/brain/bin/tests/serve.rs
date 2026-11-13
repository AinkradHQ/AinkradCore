//! The released binary, booted for real: plain `serve` (no --enable-module) mounts the Brain, behind the
//! Core's gate (an unsigned request is 401).

use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-core-brain");

#[tokio::test]
async fn plain_serve_mounts_the_brain() {
    let dir = std::env::temp_dir().join(format!("core-brain-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    let key = dir.join("keys/master.key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = tokio::process::Command::new(BIN)
        .args(["serve", dir.join("core.db").to_str().unwrap(), "--listen", &format!("loopback:{port}")])
        .stderr(std::fs::File::create(dir.join("server.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let get = |p: &str| {
        let url = format!("http://{addr}{p}");
        async move { reqwest::get(url).await.unwrap().status().as_u16() }
    };
    let brain = get("/modules/brain/v1/status").await;
    let _ = child.kill().await;
    let log = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(brain, 401, "brain not mounted by default; server log:\n{log}");
}
