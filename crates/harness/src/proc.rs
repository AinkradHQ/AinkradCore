//! A child process speaking NDJSON on stdin/stdout, started from a cleared environment.

use std::ffi::OsStr;
use std::io;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;

use crate::Spec;

/// The bytes of a child's stderr kept for failure reasons.
const STDERR_TAIL: usize = 2048;

pub(crate) struct Proc {
    child: Child,
    /// The child's process group, which it leads: its own children inherit it, so a kill of
    /// the group reaches a build or a shell job the agent started.
    pgid: u32,
    stdin: Option<ChildStdin>,
    /// `None` once handed to `drain`.
    lines: Option<Lines<BufReader<ChildStdout>>>,
    /// The end of its stderr, which goes nowhere else: it may hold secrets, so it reaches a
    /// log only inside a failure reason the runner redacts (E3.9).
    stderr: Arc<Mutex<Vec<u8>>>,
    /// The task filling `stderr`, until `wait` has let it reach EOF.
    stderr_reader: Option<JoinHandle<()>>,
}

/// `program args…` in the spec's `process_dir` (else its `cwd`), with only its allowlisted
/// variables of this process, then its `env`, then `set`.
pub(crate) fn command(
    program: &OsStr,
    args: &[String],
    spec: &Spec,
    set: &[(&str, &OsStr)],
) -> Command {
    let mut cmd = Command::new(program);
    let dir = spec.process_dir.as_ref().unwrap_or(&spec.cwd);
    cmd.args(args).current_dir(dir).env_clear();
    for name in &spec.env_allow {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.envs(spec.env.iter().map(|(name, value)| (name, value)));
    for (name, value) in set {
        cmd.env(name, value);
    }
    cmd
}

impl Proc {
    pub(crate) fn spawn(mut cmd: Command) -> io::Result<Self> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        let pgid = child.id().ok_or_else(|| io::Error::other("no pid"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_reader = child.stderr.take().map(|mut pipe| {
            let tail = stderr.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = pipe.read(&mut buf).await {
                    let mut tail = tail.lock().expect("stderr tail");
                    tail.extend_from_slice(&buf[..n]);
                    let over = tail.len().saturating_sub(STDERR_TAIL);
                    tail.drain(..over);
                }
            })
        });
        Ok(Self {
            stdin: child.stdin.take(),
            child,
            pgid,
            lines: Some(BufReader::new(stdout).lines()),
            stderr,
            stderr_reader,
        })
    }

    /// The last `STDERR_TAIL` bytes of its stderr so far, trimmed.
    pub(crate) fn stderr_tail(&self) -> String {
        let tail = self.stderr.lock().expect("stderr tail");
        String::from_utf8_lossy(&tail).trim().to_owned()
    }

    pub(crate) async fn write(&mut self, message: &Value) -> io::Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdin closed"))?;
        stdin.write_all(format!("{message}\n").as_bytes()).await?;
        stdin.flush().await
    }

    /// The next JSON line; non-JSON lines are skipped. `None` at EOF.
    pub(crate) async fn next(&mut self) -> Option<Value> {
        loop {
            if let Ok(value) = serde_json::from_str(&self.line().await?) {
                return Some(value);
            }
        }
    }

    /// The next stdout line. `None` at EOF.
    pub(crate) async fn line(&mut self) -> Option<String> {
        self.lines.as_mut()?.next_line().await.ok()?
    }

    /// Reads the rest of stdout in the background, so a chatty child never blocks on a full
    /// pipe once its output is no longer needed.
    pub(crate) fn drain(&mut self) {
        if let Some(mut lines) = self.lines.take() {
            tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        }
    }

    /// Sends SIGINT to the whole group, the way a terminal's Ctrl-C would reach it.
    pub(crate) async fn interrupt(&self) -> io::Result<()> {
        if self.child.id().is_none() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "already exited"));
        }
        let status = Command::new("/bin/kill")
            .args(["-INT", "--", &format!("-{}", self.pgid)])
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "kill -INT -{}: {status}",
                self.pgid
            )))
        }
    }

    /// The exit code once stdout has closed, with its stderr read to the end: stdout's EOF
    /// says nothing about how much of stderr the reader has seen yet.
    pub(crate) async fn wait(&mut self) -> Option<i32> {
        let status = self.child.wait().await;
        if let Some(reader) = self.stderr_reader.take() {
            // ponytail: bounded, as a grandchild that inherited the pipe can hold it open.
            let _ = tokio::time::timeout(Duration::from_secs(2), reader).await;
        }
        status.ok()?.code()
    }

    /// Kills it and its group: for a server, which does not exit on stdin EOF.
    pub(crate) async fn kill(mut self) -> Option<i32> {
        kill_group(self.pgid);
        let _ = self.child.kill().await;
        self.child.wait().await.ok()?.code()
    }

    /// EOF on stdin, then a kill of the group if it has not exited within 5 s.
    pub(crate) async fn stop(mut self) -> Option<i32> {
        self.stdin = None;
        match tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => status.ok()?.code(),
            Err(_) => {
                kill_group(self.pgid);
                let _ = self.child.kill().await;
                None
            }
        }
    }
}

/// Whatever ends the process (a finished turn, a cancelled run whose task is aborted, the
/// runner stopping), no member of its group outlives it, even once the leader has exited.
impl Drop for Proc {
    fn drop(&mut self) {
        kill_group(self.pgid);
    }
}

/// SIGKILL to every process in group `pgid`. A group already empty is not an error.
fn kill_group(pgid: u32) {
    // ponytail: `kill(1)`, as `unsafe` (libc) is forbidden here.
    let _ = std::process::Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many processes in the group are alive; a zombie does not count. `ps -g` selects by
    /// session, so every process is filtered by its pgid.
    fn members(pgid: u32) -> usize {
        let out = std::process::Command::new("ps")
            .args(["-A", "-o", "pgid=,stat="])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| {
                let mut cols = line.split_whitespace();
                let group = cols.next().and_then(|g| g.parse::<u32>().ok());
                group == Some(pgid) && !cols.next().unwrap_or("").starts_with('Z')
            })
            .count()
    }

    /// Polls until the group has `want` live members: the shell forks its jobs after spawn.
    async fn group_has(pgid: u32, want: usize) -> bool {
        for _ in 0..100 {
            if members(pgid) >= want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// Polls until the group is gone: a SIGKILL lands asynchronously.
    async fn group_gone(pgid: u32) -> bool {
        for _ in 0..100 {
            if members(pgid) == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[tokio::test]
    async fn dropping_kills_the_whole_group() {
        let proc = Proc::spawn(sh("sleep 600 & sleep 600")).unwrap();
        let pgid = proc.pgid;
        assert!(group_has(pgid, 3).await, "the group never got its jobs");
        drop(proc);
        assert!(
            group_gone(pgid).await,
            "a member of the group outlived its harness"
        );
    }

    #[tokio::test]
    async fn kill_takes_the_whole_group() {
        let proc = Proc::spawn(sh("sleep 600 & sleep 600")).unwrap();
        let pgid = proc.pgid;
        assert!(group_has(pgid, 3).await, "the group never got its jobs");
        proc.kill().await;
        assert!(
            group_gone(pgid).await,
            "a member of the group outlived kill"
        );
    }

    #[tokio::test]
    async fn interrupt_reaches_the_agent() {
        // The sleep is a background job, which a non-interactive POSIX shell (dash too) starts
        // with SIGINT ignored, so the group's INT reaches only the shell, which then runs its
        // trap. A foreground sleep would die of the INT and take dash down before the trap.
        let mut proc = Proc::spawn(sh(
            r#"sleep 600 & pid=$!; trap 'echo got-int; kill $pid; exit 0' INT; echo ready; wait $pid"#,
        ))
        .unwrap();
        assert_eq!(proc.line().await.as_deref(), Some("ready"));
        proc.interrupt().await.unwrap();
        assert_eq!(proc.line().await.as_deref(), Some("got-int"));
        assert_eq!(proc.wait().await, Some(0));
    }
}
