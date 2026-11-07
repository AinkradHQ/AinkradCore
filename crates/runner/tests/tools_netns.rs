//! C4b: the connection tools socket under the real bubblewrap sandbox. The start-up check that
//! gates the `connection-tools` capability passes for real; a sandbox given one session's socket
//! reaches that session's tools through the stdio shim and cannot see or reach another session's
//! (the session is the socket); the slot works in a networkless sandbox and a host-network one; a
//! half-set slot refuses the sandbox. On Linux CI these fail, never skip, when bwrap cannot run.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ConnTool, ToolResult, ToolsPoll};
use ainkrad_runner::v2::agent::tools::Tools;
use ainkrad_runner::v2::agent::tools::selftest::selftest;
use ainkrad_runner::v2::agent::tools::sock::{Front, sandbox_env, socket_in, start};
use serde_json::json;

fn require_sandbox() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .status();
    assert!(
        probe.is_ok_and(|s| s.success()),
        "bubblewrap cannot run here: the tools test must not be skipped"
    );
}

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner"))
}

fn scratch(tag: &str) -> PathBuf {
    let root = PathBuf::from(format!("/tmp/tn-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    root.canonicalize().unwrap()
}

fn tool(name: &str) -> ConnTool {
    ConnTool {
        name: name.to_owned(),
        description: "d".to_owned(),
        write: false,
        input_schema: None,
    }
}

async fn session(root: &Path, tools: &Arc<Tools>, id: &str, tool_name: &str) -> (Front, PathBuf) {
    let dir = root.join("agents").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let poll = ToolsPoll {
        session: id.to_owned(),
        after: 0,
        wait_ms: None,
        results: vec![],
        tools: Some(vec![tool(tool_name)]),
    };
    tools.poll(&poll, Duration::ZERO).await;
    let sock = socket_in(&dir);
    (start(&sock, tools.clone(), id).unwrap(), sock)
}

/// Runs `script` in a sandbox built as a session's is, given `slot` (or nothing), and returns its
/// stdout; `None` when the sandbox itself could not be built or run.
async fn sandboxed(
    root: &Path,
    slot: Option<&Path>,
    network: &str,
    script: String,
) -> Option<String> {
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), network.into()),
    ];
    if let Some(sock) = slot {
        env.extend(
            sandbox_env(sock, &exe())
                .into_iter()
                .map(|(n, v)| (n, v.into())),
        );
    }
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .ok()?
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn shim(sock: &Path, request: &str) -> String {
    format!(
        "printf '%s\\n' '{request}' | \"{}\" mcp-stdio \"{}\" 2>/dev/null",
        exe().display(),
        sock.display()
    )
}

#[tokio::test]
async fn the_start_up_check_passes_under_real_bubblewrap_and_fails_clearly_when_it_cannot() {
    require_sandbox();
    let agents = scratch("selftest").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    selftest(&agents, &exe())
        .await
        .expect("the tools start-up check passes on this host");
    let long = PathBuf::from(format!("/{}", "a".repeat(90)));
    let why = selftest(&long, &exe()).await.unwrap_err();
    assert!(why.contains("shorter state directory"), "{why}");
}

#[tokio::test]
async fn a_sandbox_reaches_its_own_sessions_tools_and_cannot_see_the_others() {
    require_sandbox();
    let root = scratch("iso");
    let tools = Arc::new(Tools::default());
    let (_fa, sa) = session(&root, &tools, "as_aaaa", "github.alpha").await;
    let (_fb, sb) = session(&root, &tools, "as_bbbb", "github.beta").await;
    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    // The sandbox of session B is given B's socket: B's tool, and A's path is not there at all.
    let script = format!(
        "echo own=$({}); if [ -e '{}' ]; then echo a=visible; else echo a=hidden; fi; echo peek=$({}); echo dirs=$(ls -A '{}/agents' | tr '\\n' ' ')",
        shim(&sb, list),
        sa.display(),
        shim(&sa, list),
        root.display()
    );
    let said = sandboxed(&root, Some(&sb), "deny", script)
        .await
        .expect("the sandbox ran");
    assert!(
        said.contains("github_beta") && !said.contains("github_alpha"),
        "{said}"
    );
    assert!(said.contains("a=hidden"), "{said}");
    assert!(
        said.contains("peek=\n") || said.ends_with("peek=\n") || said.contains("peek= "),
        "{said}"
    );
    assert!(
        said.contains("dirs=as_bbbb"),
        "only its own session directory: {said}"
    );
    // With no slot at all, no session's socket is there.
    let none = sandboxed(
        &root,
        None,
        "deny",
        format!("[ -e '{}' ] && echo seen || echo hidden", sa.display()),
    )
    .await
    .unwrap();
    assert_eq!(none.trim(), "hidden");
}

#[tokio::test]
async fn a_call_runs_end_to_end_from_inside_the_sandbox_with_or_without_a_network() {
    require_sandbox();
    let root = scratch("flow");
    let tools = Arc::new(Tools::default());
    let (_f, sock) = session(&root, &tools, "as_cccc", "github.get_issue").await;
    // The Core, hand-played: answers each call the harness makes.
    let core = {
        let tools = tools.clone();
        tokio::spawn(async move {
            let mut after = 0;
            let mut results = Vec::new();
            loop {
                let poll = ToolsPoll {
                    session: "as_cccc".to_owned(),
                    after,
                    wait_ms: Some(500),
                    results: std::mem::take(&mut results),
                    tools: None,
                };
                let batch = tools.poll(&poll, Duration::from_millis(500)).await;
                for c in batch.calls {
                    after = after.max(c.tc_seq);
                    results.push(ToolResult {
                        id: c.id,
                        ok: true,
                        result: Some(json!({"echo": c.args})),
                        code: None,
                        message: None,
                    });
                }
            }
        })
    };
    let call = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"github_get_issue","arguments":{"repo":"o/r","number":3}}}"#;
    for network in ["deny", "allow"] {
        let said = sandboxed(
            &root,
            Some(&sock),
            network,
            format!("echo out=$({})", shim(&sock, call)),
        )
        .await
        .unwrap_or_else(|| panic!("the {network} sandbox did not run"));
        assert!(
            said.contains(r#"\"number\":3"#) && said.contains("\"isError\":false"),
            "{network}: {said}"
        );
    }
    core.abort();
}

#[tokio::test]
async fn a_half_set_slot_refuses_the_sandbox() {
    require_sandbox();
    let root = scratch("half");
    let tools = Arc::new(Tools::default());
    let (_f, sock) = session(&root, &tools, "as_dddd", "github.get_issue").await;
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env: vec![
            ("AINKRAD_SANDBOX".into(), "1".into()),
            ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
            ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
            ("AINKRAD_SANDBOX_TOOLS_SOCK".into(), sock.clone().into()),
        ],
        ..ainkrad_harness::Spec::default()
    };
    let mut cmd = ainkrad_harness::sandbox_command(std::ffi::OsStr::new("/bin/true"), &[], &spec);
    assert!(
        cmd.output().await.is_err(),
        "a sandbox with a half-set slot ran"
    );
    // A socket path that is not a socket is refused too.
    let mut spec = spec;
    std::fs::write(root.join("plain"), b"x").unwrap();
    spec.env
        .push(("AINKRAD_SANDBOX_TOOLS_FWD".into(), exe().into()));
    spec.env.push((
        "AINKRAD_SANDBOX_TOOLS_SOCK".into(),
        root.join("plain").into(),
    ));
    let mut cmd = ainkrad_harness::sandbox_command(std::ffi::OsStr::new("/bin/true"), &[], &spec);
    assert!(
        cmd.output().await.is_err(),
        "a sandbox with a non-socket ran"
    );
}

/// C4b review: the sandbox builder refuses a layout that would put another session's socket in
/// reach. A harness binary kept in a directory that holds the agents dir binds that whole tree (via
/// `program_dirs`), so the session fails closed; one kept elsewhere is fine.
#[tokio::test]
async fn a_bound_path_that_holds_another_sessions_socket_refuses_the_sandbox() {
    require_sandbox();
    let root = scratch("holds");
    let tools = Arc::new(Tools::default());
    let (_fa, sa) = session(&root, &tools, "as_aaaa", "github.alpha").await;
    let (_fb, _sb) = session(&root, &tools, "as_bbbb", "github.beta").await;
    let spec_for = || {
        let mut env: Vec<(String, std::ffi::OsString)> = vec![
            ("AINKRAD_SANDBOX".into(), "1".into()),
            ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
            ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
        ];
        env.extend(
            sandbox_env(&sa, &exe())
                .into_iter()
                .map(|(n, v)| (n, v.into())),
        );
        ainkrad_harness::Spec {
            cwd: root.join("work"),
            config_dir: root.join("config"),
            env,
            ..ainkrad_harness::Spec::default()
        }
    };
    // The harness binary sits directly in `root`, which holds `agents/` (every session's socket).
    let bad = root.join("claude");
    std::fs::copy("/bin/true", &bad).unwrap();
    let mut cmd = ainkrad_harness::sandbox_command(bad.as_os_str(), &[], &spec_for());
    assert!(
        cmd.output().await.is_err(),
        "a sandbox that binds the agents dir ran"
    );
    // The same binary in a directory away from the sockets runs.
    let away = std::env::temp_dir().join(format!("tn-away-{}", std::process::id()));
    std::fs::create_dir_all(&away).unwrap();
    let good = away.join("claude");
    std::fs::copy("/bin/true", &good).unwrap();
    let mut cmd = ainkrad_harness::sandbox_command(good.as_os_str(), &[], &spec_for());
    let out = cmd.output().await.expect("the sandbox was refused");
    assert!(out.status.success(), "{out:?}");
    let _ = std::fs::remove_dir_all(&away);
}
