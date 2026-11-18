//! Running a pre-set command on a host (Y4-02): the only place Leyline sends `ssh.exec`.
//!
//! Security model.
//! - [`run`] takes the gate's `Authorized` by value and runs the steps IT carries (the ones the gate
//!   decided and a person approved), never a fresh read of the command. No `Authorized`, no dispatch:
//!   a runner that holds a key could otherwise use it with no Core check.
//! - Before each step `gate::still_valid` re-checks the host (rule and whole connection), the run and an
//!   AI session; a step that fails, times out or is refused ends the run (the later steps never run).
//! - No key leaves the Core here: each hop carries a one-use lease the runner redeems itself. Pinned host
//!   keys are sent with every hop (none trusted = the runner ends it before any login).
//! - What is stored is redacted again, cut at 64 KB, and every error is a fixed sentence.

use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::store::gov::LOCAL_ENROL_SAS;
use ainkrad_core_server::store::secrets;
use ainkrad_proto::v2::{
    Body, ErrorCode, ExecLimits, ExecResult, MAX_SSH_HOPS, Reply, SshExec, SshHop,
};
use sqlx::Row;

use crate::gate::{Authorized, finish, redact_text, still_valid};

/// The most output one host's run keeps.
const KEPT: usize = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(300);
const LEASE_SECS: i64 = 60;

/// Runs every step of the gated command, in order, and closes the host's row with the result.
pub(crate) async fn run(app: ainkrad_core_server::api::App, auth: Authorized) {
    let (ok, steps, last_exit, ms, log) = steps(&app, &auth).await;
    let done = sqlx::query(
        "UPDATE leyline_run_hosts SET step = ?, exit_code = ?, duration_ms = ?, output = ? \
         WHERE run_id = ? AND host_id = ?",
    )
    .bind(steps)
    .bind(last_exit)
    .bind(ms)
    .bind(cut(redact_text(&log)))
    .bind(auth.run_id())
    .bind(auth.host_id())
    .execute(&app.pool)
    .await;
    if let Err(e) = done {
        tracing::error!(error = %e, "storing a leyline run result failed");
    }
    if let Err(e) = finish(&app, auth, ok).await {
        tracing::error!(error = %e.message, "closing a leyline run failed");
    }
}

/// (all ok, steps reached, last exit code, total ms, log). The log is written after every step is
/// known, so a process that dies mid-run leaves the row `queued` with no output, never a half story.
async fn steps(app: &App, auth: &Authorized) -> (bool, i64, Option<i64>, i64, String) {
    let (mut log, mut reached, mut exit, mut ms) = (String::new(), 0_i64, None, 0_i64);
    for (i, step) in auth.steps().iter().enumerate() {
        reached = i64::try_from(i + 1).unwrap_or(i64::MAX);
        log.push_str(&format!("$ {step}\n"));
        let res = match still_valid(app, auth).await {
            Ok(()) => one(app, auth, step).await,
            Err(e) => Err(e.message),
        };
        match res {
            Ok(r) => {
                exit = r.exit_code.map(i64::from);
                ms += i64::try_from(r.duration_ms).unwrap_or(0);
                log.push_str(&r.stdout.text);
                if !r.stderr.text.is_empty() {
                    log.push_str("\n[stderr]\n");
                    log.push_str(&r.stderr.text);
                }
                if r.timed_out {
                    log.push_str("\n[timed out]");
                }
                log.push('\n');
                if r.exit_code != Some(0) || r.timed_out {
                    return (false, reached, exit, ms, log);
                }
            }
            Err(why) => {
                exit = None;
                log.push_str(&format!("[not run: {why}]\n"));
                return (false, reached, exit, ms, log);
            }
        }
    }
    (true, reached, exit, ms, log)
}

fn cut(s: String) -> String {
    if s.len() <= KEPT {
        return s;
    }
    let mut n = KEPT;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    format!("{}\n[output cut]", &s[..n])
}

/// One `ssh.exec` of `step` on the authorised host: leases, hops, dispatch, the answer.
async fn one(app: &App, auth: &Authorized, step: &str) -> Result<ExecResult, String> {
    let fixed = |s: &str| s.to_owned();
    let (target, hops, runner) = chain(app, auth.host_id()).await.map_err(|e| fixed(e))?;
    let (target, hops) = (hop(app, auth, &runner, target).await?, {
        let mut v = Vec::new();
        for h in hops {
            v.push(hop(app, auth, &runner, h).await?);
        }
        v
    });
    let exec = SshExec {
        target,
        hops,
        run: step.to_owned(),
        limits: ExecLimits {
            timeout_ms: Some(u64::try_from(STEP_TIMEOUT.as_millis()).unwrap_or(u64::MAX)),
            max_output_bytes: Some(KEPT as u64),
        },
    };
    let sent = app
        .hub
        .dispatch_ssh_exec(&runner, exec)
        .map_err(|e| why(e.code))?;
    match sent.outcome().await {
        Ok(Body::Result(Reply::SshExec(r))) => Ok(r),
        Ok(_) => Err(fixed("the runner answered something else")),
        Err(e) => Err(why(e.code)),
    }
}

fn why(c: ErrorCode) -> String {
    match c {
        ErrorCode::Offline => "the runner is not connected",
        ErrorCode::Busy => "the runner is busy",
        ErrorCode::UnsupportedCommand => "the runner cannot run commands over ssh",
        ErrorCode::HostKeyUnknown => "the host key is not trusted yet",
        ErrorCode::HostKeyChanged => "the host key changed",
        ErrorCode::SshAuthFailed => "the host refused the key",
        ErrorCode::SshFailed => "could not connect or run it",
        ErrorCode::Lost => "the connection to the runner was lost",
        _ => "the runner could not run it",
    }
    .to_owned()
}

/// A machine on the path before its lease: host, port, user, its key's secret, its trusted keys.
struct Stop {
    host: String,
    port: u16,
    user: String,
    secret: Option<String>,
    pinned: Vec<String>,
}

/// The target, its jump hosts in order, and the runner that connects (the host's `via_runner`, else
/// the Core machine's built-in one).
async fn chain(app: &App, host: &str) -> Result<(Stop, Vec<Stop>, String), &'static str> {
    const NO: &str = "the host cannot be read";
    let mut conn = app.pool.acquire().await.map_err(|_| NO)?;
    let r = sqlx::query("SELECT jump_chain, via_runner FROM leyline_hosts WHERE id = ?")
        .bind(host)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| NO)?
        .ok_or(NO)?;
    let jumps: Vec<String> =
        serde_json::from_str(&r.try_get::<String, _>("jump_chain").map_err(|_| NO)?)
            .map_err(|_| NO)?;
    let via: Option<String> = r.try_get("via_runner").map_err(|_| NO)?;
    if jumps.len() > MAX_SSH_HOPS {
        return Err("too many jump hosts");
    }
    let runner = match via {
        Some(r) => r,
        None => sqlx::query_scalar(
            "SELECT p.device_id FROM core_pairings p JOIN core_devices d ON d.id = p.device_id \
             WHERE p.kind = 'runner' AND p.sas = ? AND d.status = 'active' AND d.revoked_at IS NULL LIMIT 1",
        )
        .bind(LOCAL_ENROL_SAS)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| NO)?
        .ok_or("the Core has no built-in runner")?,
    };
    let mut stops = Vec::new();
    for id in jumps.iter().map(String::as_str).chain([host]) {
        let h = sqlx::query(
            "SELECT h.address, h.port, h.username, k.secret FROM leyline_hosts h \
             LEFT JOIN leyline_keys k ON k.id = h.key_id WHERE h.id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| NO)?
        .ok_or(NO)?;
        let pinned: Vec<String> = sqlx::query_scalar(
            "SELECT fingerprint FROM leyline_host_keys WHERE host_id = ? AND state = 'trusted'",
        )
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| NO)?;
        stops.push(Stop {
            host: h.try_get("address").map_err(|_| NO)?,
            port: u16::try_from(h.try_get::<i64, _>("port").map_err(|_| NO)?).map_err(|_| NO)?,
            user: h.try_get("username").map_err(|_| NO)?,
            secret: h.try_get("secret").map_err(|_| NO)?,
            pinned,
        });
    }
    let target = stops.pop().ok_or(NO)?;
    Ok((target, stops, runner))
}

/// The hop with a one-use lease on its key for `runner`.
async fn hop(app: &App, auth: &Authorized, runner: &str, s: Stop) -> Result<SshHop, String> {
    let secret = s.secret.ok_or("a host on the path has no key")?;
    let (lease, _) = secrets::lease(
        &app.pool,
        &secret,
        runner,
        Some(LEASE_SECS),
        &auth.principal().label(),
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await
    .map_err(|_| "the key could not be leased to the runner".to_owned())?;
    Ok(SshHop {
        host: s.host,
        port: s.port,
        user: s.user,
        pinned_keys: s.pinned,
        lease,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is stored is masked and cut at the cap, on a character boundary.
    #[test]
    fn stored_output_is_redacted_and_capped() {
        let secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let kept = cut(redact_text(&format!("$ env\nANTHROPIC_API_KEY={secret}\n")));
        assert!(!kept.contains(secret), "{kept}");
        let big = cut(format!("{}\u{e9}", "x".repeat(KEPT - 1)));
        assert!(
            big.len() <= KEPT + 20 && big.ends_with("[output cut]"),
            "{}",
            big.len()
        );
        assert_eq!(cut("short".into()), "short");
    }
}
