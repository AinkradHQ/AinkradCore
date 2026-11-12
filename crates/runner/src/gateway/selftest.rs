//! The start-up check behind the `gateway` capability (KAN-435 G3/G4): a runner offers it only
//! after the real thing has worked on this host. It builds a sandbox the way a session's is built
//! (`ainkrad_harness::sandbox_command`, network denied, the `GW` slot bound), under a socket path
//! shaped like a real session's (`<agents>/as_<26 characters>/gateway.sock`), sends a request from
//! inside to the forwarder's loopback port, and expects the gateway's 403 for a path it does not
//! serve. Nothing is dialled and no key is involved: the grant is made up and its key a filler.
//!
//! It fails clearly, and the capability stays unadvertised, when a real session's socket path
//! would not fit (a unix socket path is 100 bytes at most), when bubblewrap cannot run, or when
//! the answer is not the refusal. The directory it works in is mode 0700 and its name is random.

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{Ceiling, GatewayAuth, GatewayGrant, ModelPrice, Rate, Upstream, Wire};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::dial::Dialer;
use super::{Config, Key, MAX_SOCK_PATH, sandbox_env, socket_in, start};

const STEP: Duration = Duration::from_secs(20);
/// The length of a session id (`as_` and 26 characters), which the socket path is checked for.
const SESSION_ID_LEN: usize = 29;

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no randomness for the gateway self-test".to_owned())?;
    Ok(b)
}

/// `as_` and 26 random lower-case letters and digits: a valid session id of the real length.
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

/// What the harness inside runs: wait for the forwarder (on `port`), ask for a path the gateway
/// refuses, and print the status line.
fn probe(port: u16) -> String {
    format!(
        r#"for i in $(seq 100); do exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null && break; sleep 0.1; done
printf 'GET /selftest HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' >&3
read -r -t 5 l <&3
echo "gw=${{l%$'\r'}}"
"#
    )
}

/// Runs the check. `agents` is where sessions' directories live (`<state>/agents`) and
/// `forwarder` the runner executable the sandbox runs as its in-sandbox forwarder. The error is
/// a reason fit for the operator's log.
pub async fn selftest(agents: &Path, forwarder: &Path) -> Result<(), String> {
    let id = sample_session()?;
    // A real session's socket must fit, whatever this check's own directory is.
    let real = socket_in(&agents.join(&id));
    if real.as_os_str().len() > MAX_SOCK_PATH {
        return Err(format!(
            "a session's gateway socket would be {} bytes under {}; a unix socket path is at most {MAX_SOCK_PATH}: use a shorter state directory",
            real.as_os_str().len(),
            agents.display()
        ));
    }
    // macOS's temp dir is long (about 50 bytes), which no session-shaped socket path fits under:
    // work beside the sessions' own directory instead, which is private to the runner.
    let base = match agents.parent() {
        Some(state) if cfg!(target_os = "macos") => state.to_path_buf(),
        _ => std::env::temp_dir(),
    };
    // Short on macOS: the socket path under it must fit a unix socket's limit.
    let (name, bytes) = if cfg!(target_os = "macos") {
        ("g", 3)
    } else {
        ("ainkrad-gw-", 8)
    };
    let root = base.join(format!(
        "{name}{}",
        random(bytes)?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    private_dir(&root, false)?;
    let result = async {
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let dir = root.join("agents").join(&id);
        private_dir(&dir, true)?;
        for d in ["work", "config", "tmp"] {
            private_dir(&root.join(d), false)?;
        }
        run(&root, &dir, forwarder).await
    }
    .await;
    let _ = std::fs::remove_dir_all(&root);
    result
}

async fn run(root: &Path, dir: &Path, forwarder: &Path) -> Result<(), String> {
    let sock = socket_in(dir);
    if sock.as_os_str().len() > MAX_SOCK_PATH {
        return Err(format!(
            "the self-test's socket path would be {} bytes (a unix socket path is at most {MAX_SOCK_PATH}): TMPDIR is too long",
            sock.as_os_str().len()
        ));
    }
    let grant = GatewayGrant {
        lease: String::new(),
        account: 0,
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
    };
    // Built, not written: a filler in the shape the key rule accepts for the host.
    let key =
        Key::new(Zeroizing::new(format!("sk-ant-{}", "0".repeat(24)))).map_err(str::to_owned)?;
    let cfg = Config::new(&grant, key, Arc::new(Dialer::new(vec![]))).map_err(str::to_owned)?;
    let (events, _unused) = tokio::sync::mpsc::unbounded_channel();
    let _gateway = start(&sock, cfg, events).map_err(|e| format!("the gateway socket: {e}"))?;

    // Inside a sandbox built exactly as a session's is: no network, the gateway's slot.
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
    ];
    env.extend(sandbox_env(&sock, forwarder));
    let port = ainkrad_harness::last_env(&env, "AINKRAD_SANDBOX_GW_PORT")
        .and_then(|v| v.to_str()?.parse::<u16>().ok())
        .ok_or("the gateway forwarder has no port")?;
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), probe(port)],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null());
    let out = timeout(STEP, cmd.output())
        .await
        .map_err(|_| "the sandbox probe did not finish".to_owned())?
        .map_err(|_| "the sandbox program cannot be run".to_owned())?;
    if !out.status.success() {
        return Err("the sandbox program cannot create the gateway's sandbox here".to_owned());
    }
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = said
        .lines()
        .find_map(|l| l.strip_prefix("gw="))
        .unwrap_or("");
    if !line.starts_with("HTTP/1.1 403 ") {
        return Err(
            "a request from inside the sandbox did not reach the gateway's refusal".to_owned(),
        );
    }
    Ok(())
}
