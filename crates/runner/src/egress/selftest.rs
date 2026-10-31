//! The start-up check of a filtered runner (E8a-01.3). A runner offers `egress-filter` only when
//! this passed; a failure stops the agent driver from starting, so no session can run with a
//! filter that was never seen to work.
//!
//! It proves, on this host, that: bubblewrap runs and a sandbox with `--unshare-net` cannot reach
//! a listener on the host's loopback; the proxy tunnels to an address the policy allows; it
//! refuses the metadata address and (with an empty policy) loopback; and the operator's policy
//! refuses the metadata address too.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::timeout;

use super::{Policy, start};

const STEP: Duration = Duration::from_secs(10);

/// The status line the proxy at `sock` answers a `CONNECT target` with.
pub(super) async fn status(sock: &Path, target: &str) -> Result<String, String> {
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

async fn isolated(loopback: &TcpListener) -> Result<(), String> {
    let port = loopback.local_addr().map_err(|e| e.to_string())?.port();
    let script =
        format!("if exec 3<>/dev/tcp/127.0.0.1/{port}; then echo reached; else echo isolated; fi");
    let run = tokio::process::Command::new("/usr/bin/bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--cap-drop",
            "ALL",
            "--disable-userns",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/bash",
            "-c",
            &script,
        ])
        .stderr(std::process::Stdio::null())
        .output();
    let out = timeout(STEP, run)
        .await
        .map_err(|_| "bubblewrap did not finish".to_owned())?
        .map_err(|_| "bubblewrap cannot be run".to_owned())?;
    let said = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err("bubblewrap cannot create a network-isolated sandbox here".into());
    }
    if said.trim() != "isolated" {
        return Err("a sandbox without a network reached the host loopback".into());
    }
    // Nothing connected, from inside or from anywhere else.
    if timeout(Duration::from_millis(200), loopback.accept())
        .await
        .is_ok()
    {
        return Err("a sandbox without a network reached the host loopback".into());
    }
    Ok(())
}

/// Runs the checks; the error is a reason fit for the operator's log (no destinations).
pub async fn selftest(policy: &Policy) -> Result<(), String> {
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
    std::fs::create_dir(&dir).map_err(|e| format!("self-test directory: {e}"))?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|e| format!("self-test directory: {e}"))?;
    let result = run(&dir).await;
    let _ = std::fs::remove_dir_all(&dir);
    result
}

async fn run(dir: &Path) -> Result<(), String> {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    isolated(&target).await?;
    let port = target.local_addr().map_err(|e| e.to_string())?.port();
    let metadata = "169.254.169.254:80";

    // Allow path: a policy that names exactly this listener tunnels to it, and refuses the metadata address.
    let allow = Policy::parse("127.0.0.1/32", "", &port.to_string())?;
    let open = start(&dir.join("allow.sock"), Arc::new(allow))
        .map_err(|e| format!("the egress proxy cannot start: {e}"))?;
    let got = status(&dir.join("allow.sock"), &format!("127.0.0.1:{port}")).await?;
    if !got.contains(" 200 ") {
        return Err("the egress proxy does not tunnel to an allowed address".into());
    }
    let _ = timeout(STEP, target.accept()).await;
    if !status(&dir.join("allow.sock"), metadata)
        .await?
        .contains(" 403 ")
    {
        return Err("the egress proxy does not refuse the metadata address".into());
    }
    drop(open);

    // Deny path: an empty policy refuses loopback, and nothing dials.
    let deny = start(
        &dir.join("deny.sock"),
        Arc::new(Policy::parse("", "", &port.to_string())?),
    )
    .map_err(|e| format!("the egress proxy cannot start: {e}"))?;
    let got = status(&dir.join("deny.sock"), &format!("127.0.0.1:{port}")).await?;
    if !got.contains(" 403 ") || deny.dials() != 0 {
        return Err("the egress proxy does not refuse an address outside the policy".into());
    }
    Ok(())
}
