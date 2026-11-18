//! Running a pre-set command on a host (Y4-02): the only place Leyline sends `ssh.exec`.
//!
//! Security model.
//! - [`run`] takes the gate's `Authorized` by value and runs the steps IT carries (the ones the gate
//!   decided and a person approved), never a fresh read of the command. No `Authorized`, no dispatch:
//!   a runner that holds a key could otherwise use it with no Core check.
//! - Before each step `gate::checked` re-checks the host (rule and whole connection, every jump hop
//!   included), the run and the principal, and hands back the connection it compared: dispatch uses
//!   exactly that, never a second read; a step that fails, times out or is refused ends the run (the later steps never run).
//! - No key leaves the Core here: each hop carries a one-use lease the runner redeems itself. Pinned host
//!   keys are sent with every hop (none trusted = the runner ends it before any login).
//! - What is stored is redacted again, cut at 64 KB, and every error is a fixed sentence.

use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::hub::Dispatched;
use ainkrad_core_server::store::secrets;
use ainkrad_proto::v2::{
    Body, Command, ErrorCode, ExecLimits, ExecResult, Reply, SshExec, SshHop, SshRoute,
};
use tokio::sync::watch;

use crate::gate::{Authorized, Link, Stop, checked, finish, redact_text};

/// The most output one host's run keeps.
const KEPT: usize = 64 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(300);
const LEASE_SECS: i64 = 60;
/// What the log says when a stop ended the wait for a step already sent to the host.
const STOPPED: &str = "cancelled; the step may still finish on the host";

/// A fleet run's stop signal (`true` = stop). A single run has none.
pub(crate) type Cancel = watch::Receiver<bool>;

/// Resolves when `cancel` says stop; never if there is none (or its sender is gone).
pub(crate) async fn stopped(cancel: &Option<Cancel>) {
    if let Some(c) = cancel {
        let gone = c.clone().wait_for(|v| *v).await.is_err();
        if !gone {
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// Runs every step of the gated command, in order, and closes the host's row with the result.
pub(crate) async fn run(
    app: ainkrad_core_server::api::App,
    auth: Authorized,
    cancel: Option<Cancel>,
) {
    let (ok, steps, last_exit, ms, log) = steps(&app, &auth, &cancel).await;
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
async fn steps(
    app: &App,
    auth: &Authorized,
    cancel: &Option<Cancel>,
) -> (bool, i64, Option<i64>, i64, String) {
    let (mut log, mut reached, mut exit, mut ms) = (String::new(), 0_i64, None, 0_i64);
    for (i, step) in auth.steps().iter().enumerate() {
        reached = i64::try_from(i + 1).unwrap_or(i64::MAX);
        log.push_str(&format!("$ {step}\n"));
        let res = match checked(app, auth).await {
            Ok(link) => one(app, auth, step, link, cancel).await,
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
                if why == STOPPED {
                    log.push_str(&format!("[stopped waiting: {why}]\n"));
                } else {
                    log.push_str(&format!("[not run: {why}]\n"));
                }
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

/// `link`'s target and jump hops, each with a fresh one-use lease for its runner.
async fn leased(
    app: &App,
    auth: &Authorized,
    link: Link,
) -> Result<(SshHop, Vec<SshHop>, String), String> {
    let Link {
        target,
        hops,
        runner,
    } = link;
    let target = hop(app, auth, &runner, target).await?;
    let mut v = Vec::new();
    for h in hops {
        v.push(hop(app, auth, &runner, h).await?);
    }
    Ok((target, v, runner))
}

/// One reading SFTP op (Y7-01: list, stat, read) on the authorised host: the gate re-checked
/// (`checked`) right before it is sent, with exactly the connection it compared. Like `ssh.exec`,
/// only this file sends it, and only with an `Authorized` in hand.
pub(crate) async fn sftp(
    app: &App,
    auth: &Authorized,
    make: impl FnOnce(SshRoute) -> Command,
) -> Result<(Dispatched, String), String> {
    let link = checked(app, auth).await.map_err(|e| e.message)?;
    let (target, hops, runner) = leased(app, auth, link).await?;
    let d = app
        .hub
        .dispatch_ssh_sftp_read(&runner, make(SshRoute { target, hops }))
        .map_err(|e| why(e.code))?;
    Ok((d, runner))
}

/// The runner that connects and the `ssh.exec` for `step`, with a one-use lease per hop. `link` is
/// the very read `checked` compared: nothing is read again after the check. Shared with the health
/// prober (Y5-01), which dispatches it itself to tell "host down" from "runner away".
pub(crate) async fn build(
    app: &App,
    auth: &Authorized,
    step: &str,
    timeout: Duration,
    link: Link,
) -> Result<(String, SshExec), String> {
    let (target, hops, runner) = leased(app, auth, link).await?;
    let exec = SshExec {
        target,
        hops,
        run: step.to_owned(),
        limits: ExecLimits {
            timeout_ms: Some(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            max_output_bytes: Some(KEPT as u64),
        },
    };
    Ok((runner, exec))
}

/// One `ssh.exec` of `step` on the authorised host: leases, hops, dispatch, the answer.
///
/// A stop signal ends the wait for the answer: the runner finishes the step on its own limit
/// (ponytail: no cancel op in the runner protocol yet; add one to kill the remote step at once).
async fn one(
    app: &App,
    auth: &Authorized,
    step: &str,
    link: Link,
    cancel: &Option<Cancel>,
) -> Result<ExecResult, String> {
    let fixed = |s: &str| s.to_owned();
    let (runner, exec) = build(app, auth, step, STEP_TIMEOUT, link).await?;
    let sent = app
        .hub
        .dispatch_ssh_exec(&runner, exec)
        .map_err(|e| why(e.code))?;
    let outcome = tokio::select! {
        o = sent.outcome() => o,
        () = stopped(cancel) => return Err(fixed(STOPPED)),
    };
    match outcome {
        Ok(Body::Result(Reply::SshExec(r))) => Ok(r),
        Ok(_) => Err(fixed("the runner answered something else")),
        Err(e) => Err(why(e.code)),
    }
}

pub(crate) fn why(c: ErrorCode) -> String {
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
