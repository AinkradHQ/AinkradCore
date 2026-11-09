//! A child process speaking NDJSON on stdin/stdout, started from a cleared environment.

use std::ffi::OsStr;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines,
};
use tokio::process::Command;
use tokio::task::JoinHandle;

use crate::Spec;
use crate::exec::{ExecBackend, Exit, Launch, LocalBackend, Running, SpawnRequest, Spawned, Stdio};

/// The bytes of a child's stderr kept for failure reasons.
const STDERR_TAIL: usize = 2048;

pub(crate) struct Proc {
    /// The started process; dropping it ends its whole tree. First, so it goes before the pipes.
    running: Box<dyn Running>,
    /// The process group leader (`0` where the backend has none).
    #[cfg(test)]
    pub(crate) pgid: u32,
    stdin: Option<Box<dyn AsyncWrite + Send + Sync + Unpin>>,
    /// `None` once handed to `drain`.
    lines: Option<Lines<BufReader<Box<dyn AsyncRead + Send + Sync + Unpin>>>>,
    /// The end of its stderr, which goes nowhere else: it may hold secrets, so it reaches a
    /// log only inside a failure reason the runner redacts (E3.9).
    stderr: Arc<Mutex<Vec<u8>>>,
    /// The task filling `stderr`, until `wait` has let it reach EOF.
    stderr_reader: Option<JoinHandle<()>>,
    /// The terminating signal `wait` saw, so a sandbox kill is told apart from an exit code.
    pub(crate) signal: Option<i32>,
    /// How the last `wait` found it ended (deadline and OOM flags included).
    pub(crate) exit: Option<Exit>,
}

/// `program args…` in the spec's `process_dir` (else its `cwd`), with only its allowlisted
/// variables of this process, then its `env`, then `set`.
pub(crate) fn command(
    program: &OsStr,
    args: &[String],
    spec: &Spec,
    set: &[(&str, &OsStr)],
) -> Command {
    let mut cmd = if spec.env.iter().any(|(n, _)| n == "AINKRAD_SANDBOX") {
        crate::sandbox::command(program, args, spec)
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };
    let dir = spec.process_dir.as_ref().unwrap_or(&spec.cwd);
    cmd.current_dir(dir).env_clear();
    for name in &spec.env_allow {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.envs(spec.env.iter().filter_map(|(name, value)| {
        (!name.starts_with("AINKRAD_SANDBOX_")).then_some((name, value))
    }));
    for (name, value) in set {
        cmd.env(name, value);
    }
    if spec.env.iter().any(|(n, _)| n == "AINKRAD_SANDBOX") {
        crate::sandbox::configure_budget(&mut cmd, spec);
    }
    cmd
}

pub(crate) fn sandbox_pgid_file(spec: &Spec) -> Option<std::path::PathBuf> {
    spec.env
        .iter()
        .find(|(n, _)| n == "AINKRAD_SANDBOX_PGID_FILE")
        .map(|(_, v)| v.into())
}

impl Proc {
    /// Starts `launch` on the spec's exec backend (the local one unless the spec names another),
    /// under the spec's wall-clock cap. An `Err` means nothing was started.
    pub(crate) async fn start(spec: &Spec, launch: Launch) -> io::Result<Self> {
        let deadline = crate::exec::wall_clock(spec)?;
        let local = LocalBackend;
        let backend: &dyn ExecBackend = spec.backend.as_deref().unwrap_or(&local);
        let spawned = backend
            .spawn(SpawnRequest {
                spec,
                launch: &launch,
                stdio: Stdio::Pipes,
                deadline,
            })
            .await?;
        Ok(Self::from_spawned(spawned))
    }

    /// The local backend on a ready command (the unit tests' entry).
    #[cfg(test)]
    pub(crate) fn spawn_with_pgid_file(
        cmd: Command,
        pgid_file: Option<std::path::PathBuf>,
    ) -> io::Result<Self> {
        Ok(Self::from_spawned(crate::exec::local::spawn(
            cmd, pgid_file, None,
        )?))
    }

    fn from_spawned(spawned: Spawned) -> Self {
        let Spawned {
            stdin,
            stdout,
            stderr,
            running,
        } = spawned;
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_reader = stderr.map(|mut pipe| {
            let tail = stderr_tail.clone();
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
        Self {
            #[cfg(test)]
            pgid: running.pid().unwrap_or(0),
            running,
            stdin,
            lines: Some(BufReader::new(stdout).lines()),
            stderr: stderr_tail,
            stderr_reader,
            signal: None,
            exit: None,
        }
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
        self.running.interrupt().await
    }

    /// The exit code once stdout has closed, with its stderr read to the end: stdout's EOF
    /// says nothing about how much of stderr the reader has seen yet.
    pub(crate) async fn wait(&mut self) -> Option<i32> {
        let exit = self.running.wait().await;
        if let Some(reader) = self.stderr_reader.take() {
            // ponytail: bounded, as a grandchild that inherited the pipe can hold it open.
            let _ = tokio::time::timeout(Duration::from_secs(2), reader).await;
        }
        let exit = exit.ok()?;
        self.signal = exit.signal;
        self.exit = Some(exit);
        exit.code
    }

    /// Kills it and its group: for a server, which does not exit on stdin EOF.
    pub(crate) async fn kill(mut self) -> Option<i32> {
        self.running.kill().await?.code
    }

    /// EOF on stdin, then a kill of the group if it has not exited within 5 s.
    pub(crate) async fn stop(mut self) -> Option<i32> {
        self.stdin = None;
        match tokio::time::timeout(Duration::from_secs(5), self.running.wait()).await {
            Ok(exit) => exit.ok()?.code,
            Err(_) => {
                self.running.kill().await;
                None
            }
        }
    }
}

/// SIGKILL to every process in group `pgid`. A group already empty is not an error.
pub(crate) fn kill_group(pgid: u32) {
    // A syscall, not a forked `/bin/kill`: it must work when the host cannot fork.
    let _ = ainkrad_sys::killpg(pgid, 9);
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
        let proc = Proc::spawn_with_pgid_file(sh("sleep 600 & sleep 600"), None).unwrap();
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
        let proc = Proc::spawn_with_pgid_file(sh("sleep 600 & sleep 600"), None).unwrap();
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
        let mut proc = Proc::spawn_with_pgid_file(sh(
            r#"sleep 600 & pid=$!; trap 'echo got-int; kill $pid; exit 0' INT; echo ready; wait $pid"#,
        ), None)
        .unwrap();
        assert_eq!(proc.line().await.as_deref(), Some("ready"));
        proc.interrupt().await.unwrap();
        assert_eq!(proc.line().await.as_deref(), Some("got-int"));
        assert_eq!(proc.wait().await, Some(0));
    }
}
