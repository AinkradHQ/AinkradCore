//! N16 / D3: a macOS runner serves the Core's accounts. Real `sandbox-exec` (Seatbelt), no mocks:
//! the auth gateway's start-up check and the egress filter's pass here, and a session-shaped
//! sandbox (state directory hidden, as in a real session) reaches only its own gateway and proxy.
//!
//! `sandbox-exec` cannot run inside another sandbox (an agent's, a CI step with its own profile):
//! run these in a normal Terminal, `cargo test -p ainkrad-runner --test macos_accounts`
//! (Runbooks/ainkrad-core-terminals-and-agents.md section 6). They fail, never skip, when the
//! sandbox cannot run.
#![cfg(target_os = "macos")]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_proto::v2::{Ceiling, GatewayAuth, GatewayGrant, ModelPrice, Rate, Upstream, Wire};
use ainkrad_runner::egress::{self, Policy};
use ainkrad_runner::gateway::dial::Dialer;
use ainkrad_runner::gateway::{self, Config, Key};
use zeroize::Zeroizing;

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner"))
}

fn require_sandbox() {
    let ok = std::process::Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        ok,
        "sandbox-exec cannot run here (inside another sandbox?): run this test in a normal Terminal"
    );
}

/// A short private state dir (a unix socket path is 104 bytes at most on macOS).
fn state(tag: &str) -> PathBuf {
    let root = PathBuf::from(format!("/tmp/ma-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp", "state/agents"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    root.canonicalize().unwrap()
}

#[tokio::test]
async fn the_gateway_start_up_check_passes_under_real_seatbelt_and_fails_clearly_on_a_long_path() {
    require_sandbox();
    let root = state("gwself");
    gateway::selftest(&root.join("state/agents"), &exe())
        .await
        .expect("the gateway start-up check passes on this Mac");
    let long = PathBuf::from(format!("/{}", "a".repeat(90)));
    let why = gateway::selftest(&long, &exe()).await.unwrap_err();
    assert!(why.contains("shorter state directory"), "{why}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn the_egress_start_up_check_passes_under_real_seatbelt() {
    require_sandbox();
    let policy = Policy::parse("", "model.test", "443").unwrap();
    egress::selftest(&policy, &exe())
        .await
        .expect("the egress start-up check passes on this Mac");
}

fn grant() -> GatewayGrant {
    GatewayGrant {
        lease: String::new(),
        account: 1,
        provider: "anthropic".to_owned(),
        user_key: None,
        upstream: Upstream {
            host: "api.anthropic.com".to_owned(),
            base_path: String::new(),
            wire: Wire::AnthropicMessages,
            auth: GatewayAuth::XApiKey,
        },
        models: vec!["m".to_owned()],
        prices: vec![ModelPrice {
            model: "m".to_owned(),
            input: 1,
            output: 1,
            cache_read: 1,
            cache_write: 1,
        }],
        ceiling: Ceiling {
            tokens: 1,
            usd_micros: 1,
        },
        rate: Rate {
            per_minute: 1,
            concurrent: 1,
        },
    }
}

/// A host listener that counts connections: whatever a sandbox must not reach.
fn host_listener() -> (u16, Arc<AtomicUsize>) {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in tcp.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let _ = c.write_all(b"hello");
        }
    });
    (port, hits)
}

/// Runs `script` in a sandbox shaped as a session's: the state dir hidden, the slots set.
fn run(root: &Path, mode: &str, slots: Vec<(String, std::ffi::OsString)>, script: &str) -> String {
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_STATE".into(), root.join("state").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), mode.into()),
    ];
    env.extend(slots);
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script.into()],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin")
        .current_dir(root.join("work"));
    // A sandbox that is refused fails closed at spawn (the program is a stub that does not exist).
    let Ok(out) = cmd.into_std().stdin(std::process::Stdio::null()).output() else {
        return "REFUSED".to_owned();
    };
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn port_of(env: &[(String, std::ffi::OsString)], name: &str) -> u16 {
    ainkrad_harness::last_env(env, name)
        .and_then(|v| v.to_str()?.parse().ok())
        .unwrap()
}

/// Waits for the forwarder on `fwd`, sends `req`, prints the status line as `<tag>=...`.
fn ask(tag: &str, fwd: u16, req: &str) -> String {
    format!(
        r#"for i in $(seq 100); do exec 3<>/dev/tcp/127.0.0.1/{fwd} 2>/dev/null && break; sleep 0.1; done
printf '{req}' >&3; read -r -t 5 l <&3; echo "{tag}=${{l%$'\r'}}"; exec 3>&-
"#
    )
}

// The sandbox is run with a blocking call: the gateway or proxy needs a worker of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_shaped_sandbox_reaches_its_gateway_and_nothing_else() {
    require_sandbox();
    let root = state("gwsess");
    let dir = root.join("state/agents/as_aaaaaaaaaaaaaaaaaaaaaaaaaa");
    std::fs::create_dir_all(&dir).unwrap();
    let key = format!("sk-ant-{}", "0".repeat(24));
    let cfg = Config::new(
        &grant(),
        Key::new(Zeroizing::new(key.clone())).unwrap(),
        Arc::new(Dialer::new(vec![])),
    )
    .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let sock = gateway::socket_in(&dir);
    let _gw = gateway::start(&sock, cfg, tx).unwrap();
    let slot = gateway::sandbox_env(&sock, &exe());
    let fwd = port_of(&slot, "AINKRAD_SANDBOX_GW_PORT");
    let (host_port, hits) = host_listener();

    let script = format!(
        "{}{}\n(exec 4<>/dev/tcp/127.0.0.1/{host_port}) 2>/dev/null && echo direct=reached || echo direct=none\n\
         (exec 4<>/dev/tcp/192.0.2.1/443) 2>/dev/null & p=$!; sleep 1; if kill -0 $p 2>/dev/null; then kill $p; echo outside=hung; elif wait $p; then echo outside=reached; else echo outside=none; fi\n\
         ls {} >/dev/null 2>&1 && echo state=readable || echo state=hidden\n\
         echo key=$(env | grep -c {key})",
        ask(
            "gw",
            fwd,
            "GET /nothing HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n"
        ),
        "",
        root.join("state").display()
    );
    let out = run(&root, "deny", slot.clone(), &script);
    assert!(
        out.contains("gw=HTTP/1.1 403 "),
        "the gateway refuses: {out}"
    );
    assert!(out.contains("direct=none"), "{out}");
    assert!(out.contains("outside=none"), "{out}");
    assert!(out.contains("state=hidden"), "{out}");
    assert!(
        out.contains("key=0"),
        "the key is not in the sandbox: {out}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the host listener was reached"
    );

    // The forwarder ended with the harness: none is left on this session's port.
    let left = || {
        std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", &format!("mcp-forward {fwd} ")])
            .output()
            .is_ok_and(|o| o.status.success())
    };
    for _ in 0..50 {
        if !left() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!left(), "the forwarder outlived its sandbox");

    // The same sandbox on the host network is refused outright for a gateway session.
    let out = run(&root, "allow", slot, "echo ran");
    assert_eq!(
        out, "REFUSED",
        "a gateway session built with the host network"
    );
    let _ = std::fs::remove_dir_all(root);
}

// The sandbox is run with a blocking call: the gateway or proxy needs a worker of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_sandbox_gets_its_proxy_variables_and_tunnels_only_what_the_policy_lists() {
    require_sandbox();
    let root = state("egsess");
    let dir = root.join("state/agents/as_bbbbbbbbbbbbbbbbbbbbbbbbbb");
    std::fs::create_dir_all(&dir).unwrap();
    let (host_port, hits) = host_listener();
    let policy = Policy::parse("127.0.0.1/32", "", &host_port.to_string()).unwrap();
    let sock = egress::socket_in(&dir);
    let _proxy = egress::start(&sock, Arc::new(policy)).unwrap();
    let slot = egress::sandbox_env(&sock, &exe());
    let fwd = port_of(&slot, "AINKRAD_SANDBOX_EGRESS_PORT");
    let connect = |t: &str| format!("CONNECT {t} HTTP/1.1\\r\\nHost: {t}\\r\\n\\r\\n");
    let script = format!(
        "echo proxy=$HTTPS_PROXY\n{}{}(exec 4<>/dev/tcp/127.0.0.1/{host_port}) 2>/dev/null && echo direct=reached || echo direct=none",
        ask("ok", fwd, &connect(&format!("127.0.0.1:{host_port}"))),
        ask("named", fwd, &connect("example.com:443")),
    );
    let out = run(&root, "filtered", slot.clone(), &script);
    assert!(
        out.contains(&format!("proxy=http://127.0.0.1:{fwd}")),
        "{out}"
    );
    assert!(out.contains("ok=HTTP/1.1 200 "), "{out}");
    assert!(out.contains("named=HTTP/1.1 403 "), "{out}");
    assert!(out.contains("direct=none"), "{out}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "only the tunnel reached the listener"
    );

    // `filtered` without its egress socket is never built.
    assert_eq!(run(&root, "filtered", vec![], "echo ran"), "REFUSED");
    // `deny` ignores an egress slot: no proxy variable, no route.
    let out = run(&root, "deny", slot, "echo proxy=${HTTPS_PROXY:-none}");
    assert!(out.contains("proxy=none"), "{out}");
    let _ = std::fs::remove_dir_all(root);
}
