//! The `exec` driver (E1-11.5): `noop`, and `exec.run`, a bounded command run to its end.
//!
//! - The child leads its own process group; on timeout or cancel the group gets TERM, then
//!   KILL after `kill_grace`, and the leader is always waited for (no zombie). Whatever of
//!   the group outlives its leader is killed too, so no grandchild keeps running or holds the
//!   output pipes open.
//! - Its environment starts empty: only variables the Core sets, and those it names in
//!   `env_pass` that are also on the runner's `env_allow`.
//! - Stdout and stderr are each kept up to the limit (plus a margin, so a secret across the
//!   cut is still whole for the redactor), redacted, then cut with `TRUNCATED_MARKER`. The
//!   rest is read and dropped, so the child never blocks on a full pipe.
//! - At most `capacity` commands run at once (advertised in `Hello`); one more is `busy`.

use std::ffi::OsString;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{
    Captured, DriverInfo, ErrorCode, ExecResult, ExecRun, OP_EXEC_RUN, OP_NOOP, StreamError,
    TRUNCATED_MARKER,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

pub const DRIVER: &str = "exec";

/// Extra bytes kept past the output limit for the redactor (longer than any key shape).
const REDACT_MARGIN: usize = 4096;
/// How long the pipes may stay open after the group is gone.
const DRAIN: Duration = Duration::from_secs(2);

/// The runner's side of the limits: ceilings the Core's asks are clamped to, and what an
/// absent ask gets.
pub struct ExecConfig {
    /// Whether `exec.run` is offered at all. Off by default: whoever holds the Core's key (or
    /// a compromised Core) could otherwise run anything as the runner's user, its own key file
    /// included. E1 needs only `noop` (security review RH3); `ainkrad-runner connect
    /// --enable-exec` turns it on.
    pub run_enabled: bool,
    pub capacity: u32,
    pub max_timeout: Duration,
    pub max_output_bytes: u64,
    /// Between TERM and KILL.
    pub kill_grace: Duration,
    /// The runner's variables a command may ask for by name.
    pub env_allow: Vec<String>,
    /// The runner's environment, read once; `env_pass` is looked up here.
    pub env: Vec<(OsString, OsString)>,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            run_enabled: false,
            capacity: 4,
            max_timeout: Duration::from_secs(600),
            max_output_bytes: 1 << 20,
            kill_grace: Duration::from_secs(2),
            env_allow: ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER"]
                .map(str::to_owned)
                .to_vec(),
            env: std::env::vars_os().collect(),
        }
    }
}

pub struct ExecDriver {
    config: ExecConfig,
    slots: Arc<Semaphore>,
    redactor: Redactor,
}

impl ExecDriver {
    /// `redactor` holds the runner's own secrets (its key, at least).
    pub fn new(config: ExecConfig, redactor: Redactor) -> Self {
        let slots = Arc::new(Semaphore::new(config.capacity as usize));
        Self {
            config,
            slots,
            redactor,
        }
    }

    pub fn info(&self) -> DriverInfo {
        DriverInfo {
            name: DRIVER.to_owned(),
            commands: if self.config.run_enabled {
                vec![OP_NOOP.to_owned(), OP_EXEC_RUN.to_owned()]
            } else {
                vec![OP_NOOP.to_owned()]
            },
            capacity: self.config.capacity,
            ..DriverInfo::default()
        }
    }

    /// A slot for one `exec.run`: `unsupported_command` when `exec.run` is off, `busy` at
    /// capacity.
    pub fn slot(&self) -> Result<OwnedSemaphorePermit, StreamError> {
        if !self.config.run_enabled {
            return Err(StreamError::new(
                ErrorCode::UnsupportedCommand,
                "exec.run is off on this runner (ainkrad-runner connect --enable-exec)",
            ));
        }
        self.slots.clone().try_acquire_owned().map_err(|_| {
            let cap = self.config.capacity;
            StreamError::new(ErrorCode::Busy, format!("exec is at capacity ({cap})"))
        })
    }

    /// Runs `req` to its end, its timeout, or `cancel` (fired or dropped).
    pub async fn run(
        &self,
        req: &ExecRun,
        cancel: oneshot::Receiver<()>,
    ) -> Result<ExecResult, StreamError> {
        let invalid = |m: &str| StreamError::new(ErrorCode::InvalidArgs, m);
        if req.program.is_empty() {
            return Err(invalid("program is empty"));
        }
        if req.cwd.as_deref().is_some_and(|c| !c.starts_with('/')) {
            return Err(invalid("cwd must be absolute"));
        }
        let timeout = req
            .limits
            .timeout_ms
            .map_or(self.config.max_timeout, Duration::from_millis)
            .min(self.config.max_timeout);
        let cap = req
            .limits
            .max_output_bytes
            .unwrap_or(u64::MAX)
            .min(self.config.max_output_bytes) as usize;

        let mut cmd = Command::new(&req.program);
        cmd.args(&req.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true);
        if let Some(cwd) = &req.cwd {
            cmd.current_dir(cwd);
        }
        for (name, value) in &self.config.env {
            let wanted = |n: &String| name.to_str() == Some(n.as_str());
            if req.env_pass.iter().any(wanted) && self.config.env_allow.iter().any(wanted) {
                cmd.env(name, value);
            }
        }
        cmd.envs(&req.env);

        let started = Instant::now();
        let mut child = cmd.spawn().map_err(|e| {
            let m = format!("cannot start {}: {e}", req.program);
            StreamError::new(ErrorCode::SpawnFailed, self.redactor.text(&m))
        })?;
        let mut group = Group(
            child
                .id()
                .ok_or_else(|| StreamError::new(ErrorCode::Internal, "the child has no pid"))?,
        );
        let stdout = tokio::spawn(capture(child.stdout.take(), cap));
        let stderr = tokio::spawn(capture(child.stderr.take(), cap));

        let (status, timed_out, cancelled) = tokio::select! {
            status = child.wait() => (status.ok(), false, false),
            () = tokio::time::sleep(timeout) => (None, true, false),
            _ = cancel => (None, false, true),
        };
        let status = match status {
            Some(status) => Some(status),
            None => {
                group.signal("TERM").await;
                match tokio::time::timeout(self.config.kill_grace, child.wait()).await {
                    Ok(status) => status.ok(),
                    Err(_) => {
                        group.signal("KILL").await;
                        // The leader too, should it have left its group.
                        let _ = child.start_kill();
                        child.wait().await.ok()
                    }
                }
            }
        };
        // The leader is reaped; what is left of its group goes now, and only now (a group id
        // freed for good may be reused, so `Drop` must not signal it again).
        group.signal("KILL").await;
        group.0 = 0;
        let duration_ms = started.elapsed().as_millis() as u64;
        if cancelled {
            return Err(StreamError::new(ErrorCode::Cancelled, "cancelled"));
        }
        let stdout = self.captured(stdout).await;
        let stderr = self.captured(stderr).await;
        Ok(ExecResult {
            exit_code: status.as_ref().and_then(ExitStatus::code),
            timed_out,
            duration_ms,
            stdout,
            stderr,
        })
    }

    /// One pipe's capture, redacted and cut to its limit.
    async fn captured(&self, task: tokio::task::JoinHandle<Raw>) -> Captured {
        let raw = match tokio::time::timeout(DRAIN, task).await {
            Ok(Ok(raw)) => raw,
            _ => Raw::default(),
        };
        let mut text = self.redactor.text(&String::from_utf8_lossy(&raw.kept));
        let truncated = raw.total > raw.cap as u64;
        if truncated {
            let mut cut = raw.cap.min(text.len());
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text.push_str(TRUNCATED_MARKER);
        }
        Captured {
            text,
            bytes: raw.total,
            truncated,
        }
    }
}

#[derive(Default)]
struct Raw {
    kept: Vec<u8>,
    total: u64,
    cap: usize,
}

/// Reads `pipe` to EOF, keeping `cap + REDACT_MARGIN` bytes and counting all.
async fn capture(pipe: Option<impl AsyncRead + Unpin>, cap: usize) -> Raw {
    let mut raw = Raw {
        cap,
        ..Raw::default()
    };
    let Some(mut pipe) = pipe else { return raw };
    let keep = cap.saturating_add(REDACT_MARGIN);
    let mut buf = [0u8; 8192];
    while let Ok(n @ 1..) = pipe.read(&mut buf).await {
        raw.total += n as u64;
        let room = keep.saturating_sub(raw.kept.len()).min(n);
        raw.kept.extend_from_slice(&buf[..room]);
    }
    raw
}

/// A child's process group (its pid: it leads the group; 0 once done). Dropped before then,
/// the group is killed, so a command whose task is aborted leaves nothing behind.
struct Group(u32);

impl Group {
    async fn signal(&self, sig: &str) {
        // ponytail: `kill(1)`, as `unsafe` (libc) is forbidden here, like harness::proc.
        // A group already gone is not an error.
        let _ = Command::new("/bin/kill")
            .args([format!("-{sig}"), "--".to_owned(), format!("-{}", self.0)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if self.0 == 0 {
            return;
        }
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.0)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
pub(crate) mod tests;
