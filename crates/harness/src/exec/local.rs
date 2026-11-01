//! The local backend: a process group under bubblewrap, Seatbelt or nothing, as it always was.

use std::io;
use std::process::Stdio as PipeStdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

use super::{BoxFut, ExecBackend, Exit, Running, SpawnRequest, Spawned, Stdio};
use crate::proc::kill_group;

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalBackend;

impl ExecBackend for LocalBackend {
    fn name(&self) -> &'static str {
        "local"
    }

    fn spawn<'a>(&'a self, req: SpawnRequest<'a>) -> BoxFut<'a, io::Result<Spawned>> {
        Box::pin(async move {
            if let Stdio::Pty { .. } = req.stdio {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the local exec backend has no pty (terminals use termbox)",
                ));
            }
            spawn(
                req.launch.command(req.spec),
                crate::proc::sandbox_pgid_file(req.spec),
                req.deadline,
            )
        })
    }
}

/// Starts `cmd` as the leader of its own group, with the budget watchdog, the macOS supervisor,
/// the identity file and the deadline timer when they apply.
pub(crate) fn spawn(
    mut cmd: Command,
    pgid_file: Option<std::path::PathBuf>,
    deadline: Option<Duration>,
) -> io::Result<Spawned> {
    let budget = crate::sandbox::Budget::take(&mut cmd);
    let mut child = cmd
        .stdin(PipeStdio::piped())
        .stdout(PipeStdio::piped())
        .stderr(PipeStdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let pgid = child.id().ok_or_else(|| io::Error::other("no pid"))?;
    if let Some(path) = &pgid_file {
        let persist = || -> io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, crate::sandbox::identity(pgid)?)
        };
        if let Err(error) = persist() {
            kill_group(pgid);
            let _ = child.start_kill();
            return Err(error);
        }
    }
    // Linux has `--die-with-parent`; macOS needs a supervisor outside the sandbox.
    let supervisor = (cfg!(target_os = "macos") && budget.is_some())
        .then(|| crate::sandbox::tree::supervise(pgid, std::process::id()))
        .transpose()
        .inspect_err(|_| kill_group(pgid))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let stderr = child.stderr.take();
    let stdin = child.stdin.take();
    let budget = budget.map(|b| b.start(pgid));
    let tracker = budget.as_ref().map(|w| w.tracker());
    let timed_out = Arc::new(AtomicBool::new(false));
    // The host ends the tree at the deadline: nothing inside the sandbox can lift it. The group
    // goes first; the budget watch's tracker then reaches a descendant that left it with
    // `setsid` (macOS has no pid namespace to contain one; Linux has `--unshare-pid`).
    let timer = deadline.map(|after| {
        let flag = timed_out.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            flag.store(true, Ordering::SeqCst);
            kill_group(pgid);
            if let Some(tracker) = tracker {
                tracker.kill();
            }
        })
    });
    Ok(Spawned {
        stdin: stdin.map(|s| Box::new(s) as _),
        stdout: Box::new(stdout),
        stderr: stderr.map(|s| Box::new(s) as _),
        running: Box::new(LocalProcess {
            child,
            pgid,
            budget,
            supervisor,
            pgid_file,
            timer,
            timed_out,
        }),
    })
}

struct LocalProcess {
    child: Child,
    /// The child's process group, which it leads: its own children inherit it, so a kill of
    /// the group reaches a build or a shell job the agent started.
    pgid: u32,
    budget: Option<crate::sandbox::Watch>,
    /// macOS dead-man (no parent-death signal there): kills the tree if the runner dies.
    supervisor: Option<std::process::Child>,
    pgid_file: Option<std::path::PathBuf>,
    timer: Option<JoinHandle<()>>,
    timed_out: Arc<AtomicBool>,
}

impl LocalProcess {
    fn exit(&self, status: std::process::ExitStatus) -> Exit {
        use std::os::unix::process::ExitStatusExt;
        Exit {
            code: status.code(),
            signal: status.signal(),
            deadline: self.timed_out.load(Ordering::SeqCst),
            oom: false,
        }
    }

    /// The leader is gone and reaped: its group id may be reused, so the timer must not fire.
    // ponytail: a timer that fires between the reap and this abort could `killpg` a recycled
    // group id. The window is a few microseconds, and a group id is not reused while any member
    // of the group lives; accepted until the deadline moves to a pidfd.
    fn disarm(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.abort();
        }
    }
}

impl Running for LocalProcess {
    fn pid(&self) -> Option<u32> {
        Some(self.pgid)
    }

    fn interrupt(&self) -> BoxFut<'_, io::Result<()>> {
        Box::pin(async move {
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
        })
    }

    fn wait(&mut self) -> BoxFut<'_, io::Result<Exit>> {
        Box::pin(async move {
            let status = self.child.wait().await;
            self.disarm();
            Ok(self.exit(status?))
        })
    }

    fn kill(&mut self) -> BoxFut<'_, Option<Exit>> {
        Box::pin(async move {
            self.disarm();
            kill_group(self.pgid);
            let _ = self.child.kill().await;
            let status = self.child.wait().await.ok()?;
            Some(self.exit(status))
        })
    }
}

/// Whatever ends the process (a finished turn, a cancelled run whose task is aborted, the
/// runner stopping), no member of its group outlives it, even once the leader has exited.
impl Drop for LocalProcess {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.abort();
        }
        kill_group(self.pgid);
        if let Some(budget) = self.budget.take() {
            budget.stop();
        }
        if let Some(mut s) = self.supervisor.take() {
            let _ = s.kill();
            let _ = s.wait();
        }
        if let Some(path) = &self.pgid_file {
            let _ = std::fs::remove_file(path);
        }
    }
}
