//! The start-up check behind the `connection-tools` capability (C4b): a runner offers it only after
//! the real thing has worked on this host. Two sessions' sockets are opened under paths shaped like
//! real ones (`<agents>/as_<26 characters>/tools.sock`), and a sandbox is built the way a session's
//! is (`ainkrad_harness::sandbox_command`, network denied, the `TOOLS` slot of the FIRST session
//! only). Inside it the shim must reach the first socket and list the first session's tool, the
//! second socket's path must not exist, nothing of `agents/` but the first session's own socket
//! may be visible, and the shim pointed at the second path must get nothing.
//!
//! It fails clearly, and the capability stays unadvertised, when the path would not fit, when
//! bubblewrap cannot run, or when any of that does not hold. Nothing is dialled and no credential
//! is involved. The directory is mode 0700 with a random name.

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ConnTool, ToolsPoll};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::time::timeout;

use super::Tools;
use super::sock::{MAX_SOCK_PATH, sandbox_env, socket_in, start};

const STEP: Duration = Duration::from_secs(20);
const SESSION_ID_LEN: usize = 29;

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no randomness for the tools self-test".to_owned())?;
    Ok(b)
}

fn sample_session() -> Result<String, String> {
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let id: String = random(SESSION_ID_LEN - 3)?
        .iter()
        .map(|b| char::from(chars[usize::from(*b) % chars.len()]))
        .collect();
    Ok(format!("as_{id}"))
}

fn private_dir(path: &Path, recursive: bool) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("self-test directory: {e}"))
}

async fn tell(tools: &Tools, session: &str, tool: &str) {
    let list = vec![ConnTool {
        name: tool.to_owned(),
        description: "self-test".to_owned(),
        write: false,
        input_schema: None,
    }];
    let poll = ToolsPoll {
        session: session.to_owned(),
        after: 0,
        wait_ms: None,
        results: vec![],
        tools: Some(list),
    };
    tools.poll(&poll, Duration::ZERO).await;
}

/// Whether this runner offers the connection tools: the check passed (a failure is logged and
/// withholds the capability; it does not stop the driver).
pub async fn offered(agents: &Path) -> bool {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => return false,
    };
    match selftest(agents, &exe).await {
        Ok(()) => true,
        Err(why) => {
            tracing::warn!(
                "the connection tools are not offered: their start-up check failed: {why}"
            );
            false
        }
    }
}

/// Runs the check. `agents` is where sessions' directories live (`<state>/agents`) and `forwarder`
/// the runner executable the sandbox runs as the shim. The error is a reason fit for the log.
pub async fn selftest(agents: &Path, forwarder: &Path) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("the tools socket's sandbox slot is Linux only".to_owned());
    }
    let (a, b) = (sample_session()?, sample_session()?);
    let real = socket_in(&agents.join(&a));
    if real.as_os_str().len() > MAX_SOCK_PATH {
        return Err(format!(
            "a session's tools socket would be {} bytes under {}; a unix socket path is at most {MAX_SOCK_PATH}: use a shorter state directory",
            real.as_os_str().len(),
            agents.display()
        ));
    }
    let tag: String = random(8)?.iter().map(|x| format!("{x:02x}")).collect();
    let root = std::env::temp_dir().join(format!("ainkrad-tools-{tag}"));
    private_dir(&root, false)?;
    let result = async {
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        for d in ["work", "config", "tmp"] {
            private_dir(&root.join(d), false)?;
        }
        run(&root, &a, &b, forwarder).await
    }
    .await;
    let _ = std::fs::remove_dir_all(&root);
    result
}

async fn run(root: &Path, a: &str, b: &str, forwarder: &Path) -> Result<(), String> {
    let agents = root.join("agents");
    let (da, db) = (agents.join(a), agents.join(b));
    private_dir(&da, true)?;
    private_dir(&db, true)?;
    let (sa, sb) = (socket_in(&da), socket_in(&db));
    for s in [&sa, &sb] {
        if s.as_os_str().len() > MAX_SOCK_PATH {
            return Err(format!(
                "the self-test's socket path would be {} bytes (a unix socket path is at most {MAX_SOCK_PATH}): TMPDIR is too long",
                s.as_os_str().len()
            ));
        }
    }
    let tools = Arc::new(Tools::default());
    tell(&tools, a, "selftest.alpha").await;
    tell(&tools, b, "selftest.beta").await;
    let _fa = start(&sa, tools.clone(), a).map_err(|e| format!("the tools socket: {e}"))?;
    let _fb = start(&sb, tools, b).map_err(|e| format!("the tools socket: {e}"))?;

    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
        // As a session's has it: the builder judges every bind against `<state>/agents`.
        ("AINKRAD_SANDBOX_STATE".into(), root.into()),
    ];
    // The first session's slot only: the second session's socket is not given to this sandbox.
    env.extend(
        sandbox_env(&sa, forwarder)
            .into_iter()
            .map(|(n, v)| (n, v.into())),
    );
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let (fwd, sa_s, sb_s) = (forwarder.display(), sa.display(), sb.display());
    let script = format!(
        r#"q='{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}'
echo "own=$(printf '%s\n' "$q" | "{fwd}" mcp-stdio "{sa_s}" 2>/dev/null)"
if [ -e "{sb_s}" ]; then echo "other=visible"; else echo "other=hidden"; fi
echo "agents=$(ls -A "{agents}" 2>&1 | tr '\n' ' ')"
echo "dir=$(ls -A "{da}" 2>&1 | tr '\n' ' ')"
echo "peek=$(printf '%s\n' "$q" | "{fwd}" mcp-stdio "{sb_s}" 2>/dev/null)"
"#,
        agents = agents.display(),
        da = da.display(),
    );
    // The negative control, through the same builder: a harness binary whose folder holds the agents
    // dir has that folder bound whole (`program_dirs`), and every session's socket with it. The
    // builder must refuse; a runner whose builder runs that is not offered the capability.
    let prog = root.join("prog");
    std::fs::copy("/bin/true", &prog).map_err(|e| format!("self-test program: {e}"))?;
    let mut leaky = ainkrad_harness::sandbox_command(prog.as_os_str(), &[], &spec);
    leaky.stdin(std::process::Stdio::null());
    if timeout(STEP, leaky.output()).await.is_ok_and(|r| r.is_ok()) {
        return Err("a sandbox that binds the state dir was built: other sessions' sockets would be reachable".to_owned());
    }
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    let out = timeout(STEP, cmd.output())
        .await
        .map_err(|_| "the sandbox probe did not finish".to_owned())?
        .map_err(|_| "bubblewrap cannot be run".to_owned())?;
    if !out.status.success() {
        return Err("bubblewrap cannot create the tools sandbox here".to_owned());
    }
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let field = |k: &str| {
        said.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let own = field("own");
    if !own.contains("selftest_alpha") || own.contains("selftest_beta") {
        return Err("the shim inside the sandbox did not reach its session's socket".to_owned());
    }
    if field("other") != "hidden" || !field("peek").is_empty() {
        return Err("another session's tools socket is reachable from this sandbox".to_owned());
    }
    if field("dir") != "tools.sock" || field("agents") != a {
        return Err(
            "the sandbox sees more of the session directories than its own socket".to_owned(),
        );
    }
    Ok(())
}
