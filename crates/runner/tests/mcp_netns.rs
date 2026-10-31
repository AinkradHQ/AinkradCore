//! A denied-network Linux session reaches its MCP route through the bridge, and nothing else:
//! not a TCP service on the host's loopback, not the cloud metadata address.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_runner::mcp_bridge::{self, Target};

fn serve(listener: TcpListener, reply: &'static str, hits: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            hits.fetch_add(1, Ordering::SeqCst);
            let mut conn = conn;
            let _ = conn.read(&mut [0; 512]);
            let _ = conn.write_all(reply.as_bytes());
        }
    });
}

#[tokio::test]
async fn a_denied_session_reaches_only_its_mcp_route() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "bubblewrap cannot run here: the network-isolation test must not be skipped"
    );
    let root = std::env::temp_dir().join(format!("mcp-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let root = root.canonicalize().unwrap();

    let mcp_hits = Arc::new(AtomicUsize::new(0));
    let mcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let mcp_port = mcp.local_addr().unwrap().port();
    serve(mcp, "HTTP/1.0 200 OK\r\n\r\nmcp-ok", mcp_hits.clone());
    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary = TcpListener::bind("127.0.0.1:0").unwrap();
    let canary_port = canary.local_addr().unwrap().port();
    serve(
        canary,
        "HTTP/1.0 200 OK\r\n\r\ncanary-reached",
        canary_hits.clone(),
    );

    let sock = root.join("mcp.sock");
    let _bridge = mcp_bridge::start(
        &sock,
        Target {
            host: "127.0.0.1".into(),
            port: mcp_port,
            tls: false,
        },
        None,
    )
    .unwrap();

    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env: vec![
            ("AINKRAD_SANDBOX".into(), "1".into()),
            ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
            ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
            ("AINKRAD_SANDBOX_MCP_SOCK".into(), sock.clone().into()),
            (
                "AINKRAD_SANDBOX_MCP_FWD".into(),
                env!("CARGO_BIN_EXE_ainkrad-runner").into(),
            ),
            (
                "AINKRAD_SANDBOX_MCP_PORT".into(),
                mcp_bridge::FORWARD_PORT.to_string().into(),
            ),
        ],
        ..ainkrad_harness::Spec::default()
    };
    let script = format!(
        r#"get() {{ exec 3<>/dev/tcp/$1/$2 && printf 'GET / HTTP/1.0\r\n\r\n' >&3 && cat <&3; }}
for i in $(seq 60); do out=$( (get 127.0.0.1 {fwd}) 2>/dev/null) && break; sleep 0.2; done
echo "mcp:$out"
echo "canary:$( (timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{canary_port} && echo reached') 2>&1 | tail -1)"
echo "imds:$( (timeout 3 bash -c 'exec 3<>/dev/tcp/169.254.169.254/80 && echo reached') 2>&1 | tail -1)"
"#,
        fwd = mcp_bridge::FORWARD_PORT
    );
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin");
    let out = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output())
        .await
        .expect("probe timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(
        text.contains("mcp-ok"),
        "the MCP route is unreachable: {text} {err}"
    );
    assert!(mcp_hits.load(Ordering::SeqCst) >= 1);
    assert!(
        !text.contains("canary:reached"),
        "reached a host loopback service: {text}"
    );
    assert_eq!(
        canary_hits.load(Ordering::SeqCst),
        0,
        "the canary was contacted"
    );
    assert!(
        !text.contains("imds:reached"),
        "reached the metadata address: {text}"
    );
    let _ = std::fs::remove_dir_all(root);
}
