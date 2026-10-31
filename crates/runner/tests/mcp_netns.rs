//! A denied-network Linux session reaches its MCP route through the bridge, and nothing else:
//! not a TCP service on the host's loopback, not the cloud metadata address.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_runner::mcp_bridge::{self, Target};

/// A keep-alive HTTP server that answers 403 to any `Host` but `want` (the Core's `unknown_host`).
fn serve(listener: TcpListener, want: String, hits: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let (want, hits) = (want.clone(), hits.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                loop {
                    let end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        let mut chunk = [0; 512];
                        match conn.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end);
                    hits.fetch_add(1, Ordering::SeqCst);
                    let ok = head.lines().any(|l| l == format!("Host: {want}"));
                    let (status, body) = if ok {
                        ("200 OK", "mcp-ok")
                    } else {
                        ("403 Forbidden", "denied")
                    };
                    let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 6\r\n\r\n{body}");
                    if conn.write_all(reply.as_bytes()).is_err() {
                        return;
                    }
                }
            });
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
    serve(mcp, format!("127.0.0.1:{mcp_port}"), mcp_hits.clone());
    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary = TcpListener::bind("127.0.0.1:0").unwrap();
    let canary_port = canary.local_addr().unwrap().port();
    serve(canary, String::new(), canary_hits.clone());

    let sock = root.join("mcp.sock");
    let _bridge = mcp_bridge::start(
        &sock,
        Target {
            host: "127.0.0.1".into(),
            port: mcp_port,
            tls: false,
            authority: format!("127.0.0.1:{mcp_port}"),
            path: "/token/citadel/v1/mcp".into(),
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
        r#"for i in $(seq 60); do exec 3<>/dev/tcp/127.0.0.1/{fwd} 2>/dev/null && break; sleep 0.2; done
for n in 1 2; do
  printf 'POST /token/citadel/v1/mcp HTTP/1.1\r\nHost: 127.0.0.1:{fwd}\r\nContent-Length: 0\r\n\r\n' >&3
  read -r -t 5 l1 <&3; read -r -t 5 l2 <&3; read -r -t 5 l3 <&3; read -r -t 5 -N 6 body <&3
  echo "mcp$n:${{l1%$'\r'}} $body"
done
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

    // Two requests on one keep-alive connection, both with the Core's Host rewritten in.
    for n in 1..=2 {
        assert!(
            text.contains(&format!("mcp{n}:HTTP/1.1 200 OK mcp-ok")),
            "request {n} failed: {text} {err}"
        );
    }
    assert_eq!(mcp_hits.load(Ordering::SeqCst), 2);
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
