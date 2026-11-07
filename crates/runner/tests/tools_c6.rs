//! C6: more of the tools socket under the real bubblewrap sandbox (Linux, vps-1): from inside the
//! sandbox of one session, no spelling of another session's socket path reaches it (`..`, a
//! symlink made inside, `/proc/*/root`), the only socket in the whole namespace is its own, and the
//! start-up check that advertises `connection-tools` fails when isolation cannot be proven.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ConnTool, ToolsPoll};
use ainkrad_runner::v2::agent::tools::Tools;
use ainkrad_runner::v2::agent::tools::selftest::selftest;
use ainkrad_runner::v2::agent::tools::sock::{Front, sandbox_env, socket_in, start};

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
    let root = PathBuf::from(format!("/tmp/tc6-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    root.canonicalize().unwrap()
}

async fn session(root: &Path, tools: &Arc<Tools>, id: &str, name: &str) -> (Front, PathBuf) {
    let dir = root.join("agents").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let tool = ConnTool {
        name: name.to_owned(),
        description: "d".to_owned(),
        write: false,
        input_schema: None,
    };
    let poll = ToolsPoll {
        session: id.to_owned(),
        after: 0,
        wait_ms: None,
        results: vec![],
        tools: Some(vec![tool]),
    };
    tools.poll(&poll, Duration::ZERO).await;
    let sock = socket_in(&dir);
    (start(&sock, tools.clone(), id).unwrap(), sock)
}

async fn sandboxed(root: &Path, slot: &Path, script: String) -> Option<String> {
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
    ];
    env.extend(
        sandbox_env(slot, &exe())
            .into_iter()
            .map(|(n, v)| (n, v.into())),
    );
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
    let out = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .ok()?
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn shim(sock: &str) -> String {
    format!(
        "printf '%s\\n' '{}' | timeout 5 \"{}\" mcp-stdio \"{sock}\" 2>/dev/null",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        exe().display(),
    )
}

#[tokio::test]
async fn no_spelling_of_another_sessions_socket_path_reaches_it_from_inside_the_sandbox() {
    require_sandbox();
    let root = scratch("reach");
    let tools = Arc::new(Tools::default());
    let (_fa, sa) = session(&root, &tools, "as_aaaa", "github.alpha").await;
    let (_fb, sb) = session(&root, &tools, "as_bbbb", "github.beta").await;
    let a = sa.display().to_string();
    let b_dir = sb.parent().unwrap().display().to_string();
    let attempts = [
        a.clone(),
        format!("{b_dir}/../as_aaaa/tools.sock"),
        format!("{b_dir}/../../agents/as_aaaa/tools.sock"),
        format!("/proc/self/root{a}"),
        format!("/proc/1/root{a}"),
        "/proc/self/cwd/../agents/as_aaaa/tools.sock".to_owned(),
        format!("{}/work/link", root.display()),
        format!("{b_dir}//..//as_aaaa//tools.sock"),
    ];
    let mut script = format!("ln -s '{a}' '{}/work/link' 2>/dev/null\n", root.display());
    for (i, p) in attempts.iter().enumerate() {
        script.push_str(&format!("echo try{i}=$({})\n", shim(p)));
    }
    script.push_str(&format!(
        "echo own=$({})\n",
        shim(&sb.display().to_string())
    ));
    script.push_str(&format!(
        "echo found=$(find '{}' -name tools.sock 2>/dev/null | sort | tr '\\n' ' ')\n",
        root.display()
    ));
    let said = sandboxed(&root, &sb, script)
        .await
        .expect("the sandbox ran");
    assert!(
        !said.contains("github_alpha"),
        "another session's tool is reachable: {said}"
    );
    assert!(
        said.contains("own=") && said.contains("github_beta"),
        "its own socket works: {said}"
    );
    for i in 0..attempts.len() {
        let line = said
            .lines()
            .find(|l| l.starts_with(&format!("try{i}=")))
            .unwrap();
        assert!(!line.contains("tools"), "try{i} got an answer: {line}");
    }
    let found = said.lines().find(|l| l.starts_with("found=")).unwrap();
    assert_eq!(
        found.trim(),
        format!("found={}", sb.display()),
        "the sandbox sees exactly one tools socket"
    );
}

#[tokio::test]
async fn the_start_up_check_fails_when_isolation_cannot_be_proven() {
    require_sandbox();
    let agents = scratch("selftest").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    // The check passes with a runner that is there, and fails (so the capability is not
    // advertised) for a runner that is not, and for a forwarder that cannot reach the socket.
    selftest(&agents, &exe()).await.expect("the control passes");
    assert!(
        selftest(&agents, Path::new("/nonexistent/ainkrad-runner"))
            .await
            .is_err()
    );
    // A forwarder that runs but cannot reach the socket proves nothing either.
    assert!(selftest(&agents, Path::new("/bin/true")).await.is_err());
}
