//! The start-up check of a filtered runner (E8a-01.3). A runner offers `egress-filter` only when
//! this passed; a failure stops the agent driver from starting, so no session can run with a
//! filter that was never seen to work.
//!
//! It runs the real thing on this host: the proxy, and a sandbox built by the same argument builder
//! a session uses (`ainkrad_harness::sandbox_command`, `AINKRAD_SANDBOX_NETWORK=filtered`) with the
//! in-sandbox forwarder started. From inside that sandbox it checks that a `CONNECT` to an allowed
//! address is tunnelled, that the metadata address is refused, and that a direct connection to the
//! same host listener finds no route. A host-side proxy with an empty policy must refuse loopback.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::timeout;

use super::{Policy, sandbox_env, start};

const STEP: Duration = Duration::from_secs(20);

/// The status line the proxy at `sock` answers a `CONNECT target` with.
async fn status(sock: &Path, target: &str) -> Result<String, String> {
    let io = async {
        let mut c = UnixStream::connect(sock).await?;
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await?;
        let mut out = vec![0u8; 256];
        let n = c.read(&mut out).await?;
        out.truncate(n);
        Ok::<_, std::io::Error>(
            String::from_utf8_lossy(&out)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
        )
    };
    timeout(STEP, io)
        .await
        .map_err(|_| "the proxy did not answer".to_owned())?
        .map_err(|e| format!("the proxy: {e}"))
}

/// Run from inside the sandbox: wait for the forwarder, then three attempts, one result per line.
fn probe(port: u16) -> String {
    format!(
        r#"for i in $(seq 100); do exec 3<>/dev/tcp/127.0.0.1/47832 2>/dev/null && break; sleep 0.1; done
ask() {{ printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&3; read -r -t 5 l <&3; echo "${{l%$'\r'}}"; exec 3>&-; }}
echo "via=$(ask 127.0.0.1:{port})"
exec 3<>/dev/tcp/127.0.0.1/47832 2>/dev/null
echo "meta=$(ask 169.254.169.254:80)"
if timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; then echo direct=reached; else echo direct=none; fi
"#
    )
}

/// Runs the checks; the error is a reason fit for the operator's log (no destinations).
/// `forwarder` is the runner executable the sandbox runs as its in-sandbox forwarder.
pub async fn selftest(policy: &Policy, forwarder: &Path) -> Result<(), String> {
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    if policy.check_ip(metadata, false).is_ok() || policy.check_ip(metadata, true).is_ok() {
        return Err("the egress policy would allow the metadata address".into());
    }
    let dir = std::env::temp_dir().join(format!(
        "ainkrad-egress-selftest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let made = std::fs::create_dir(&dir)
        .and_then(|()| {
            std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        })
        .and_then(|()| dir.canonicalize());
    let dir = made.map_err(|e| format!("self-test directory: {e}"))?;
    let result = run(&dir, forwarder).await;
    let _ = std::fs::remove_dir_all(&dir);
    result
}

async fn run(dir: &Path, forwarder: &Path) -> Result<(), String> {
    for d in ["work", "config", "tmp"] {
        std::fs::create_dir(dir.join(d)).map_err(|e| e.to_string())?;
    }
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = target.local_addr().map_err(|e| e.to_string())?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let counter = tokio::spawn(async move {
        while target.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let result = checks(dir, forwarder, port, &accepted).await;
    counter.abort();
    result
}

async fn checks(
    dir: &Path,
    forwarder: &Path,
    port: u16,
    accepted: &AtomicUsize,
) -> Result<(), String> {
    let sock = dir.join("allow.sock");
    let allow = Policy::parse("127.0.0.1/32", "", &port.to_string())?;
    let open =
        start(&sock, Arc::new(allow)).map_err(|e| format!("the egress proxy cannot start: {e}"))?;

    // Inside a sandbox built exactly as a session's is.
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), dir.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "filtered".into()),
    ];
    env.extend(sandbox_env(&sock, forwarder));
    let spec = ainkrad_harness::Spec {
        cwd: dir.join("work"),
        config_dir: dir.join("config"),
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
        .map_err(|_| "bubblewrap cannot be run".to_owned())?;
    if !out.status.success() {
        return Err("bubblewrap cannot create the filtered sandbox here".into());
    }
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = |key: &str| {
        said.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or("")
            .to_owned()
    };
    if !line("via=").contains(" 200 ") {
        return Err("the egress proxy does not tunnel an allowed address from the sandbox".into());
    }
    if !line("meta=").contains(" 403 ") {
        return Err("the egress proxy does not refuse the metadata address".into());
    }
    if line("direct=") != "none" {
        return Err("a sandbox without a network reached a host listener directly".into());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    if accepted.load(Ordering::SeqCst) != 1 {
        return Err(
            "the host listener saw a connection that did not come through the proxy".into(),
        );
    }
    drop(open);

    // Host side: an empty policy refuses loopback, and nothing dials.
    let deny_sock = dir.join("deny.sock");
    let deny = start(
        &deny_sock,
        Arc::new(Policy::parse("", "", &port.to_string())?),
    )
    .map_err(|e| format!("the egress proxy cannot start: {e}"))?;
    let got = status(&deny_sock, &format!("127.0.0.1:{port}")).await?;
    if !got.contains(" 403 ") || deny.dials() != 0 {
        return Err("the egress proxy does not refuse an address outside the policy".into());
    }
    Ok(())
}
