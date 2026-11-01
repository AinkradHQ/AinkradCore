//! A scripted backend standing in for a VM (E8a-06.3): no process starts anywhere. It exists to
//! exercise the refusal and failure paths of the seam (a backend that will not start, one that
//! dies mid-run, a deadline, an out-of-memory end, teardown on drop) without a hypervisor.

use std::ffi::OsString;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, watch};

use super::{BoxFut, ExecBackend, Exit, Running, SpawnRequest, Spawned, Stdio};

const KILLED: Exit = Exit {
    code: None,
    signal: Some(9),
    deadline: false,
    oom: false,
};

/// What the fake does when asked to start.
#[derive(Debug, Clone)]
pub enum Script {
    /// Refuses, as a backend does when its tier is unavailable.
    Refuse(String),
    /// Starts, prints `stdout` (one line each) and `stderr`, then ends with `exit`.
    Exit {
        stdout: Vec<String>,
        stderr: String,
        exit: Exit,
    },
    /// Starts, prints `stdout`, then runs until killed or until the request's deadline.
    Hang { stdout: Vec<String> },
}

/// What a start asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub program: OsString,
    pub args: Vec<String>,
    pub deadline: Option<Duration>,
}

#[derive(Debug)]
pub struct FakeVm {
    script: Script,
    /// Starts that got as far as a "VM".
    pub started: AtomicUsize,
    /// "VMs" destroyed (the handle was dropped).
    pub torn_down: Arc<AtomicUsize>,
    seen: Mutex<Vec<Seen>>,
}

impl FakeVm {
    pub fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script,
            started: AtomicUsize::new(0),
            torn_down: Arc::new(AtomicUsize::new(0)),
            seen: Mutex::default(),
        })
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }
}

impl ExecBackend for FakeVm {
    fn name(&self) -> &'static str {
        "fake-vm"
    }

    fn spawn<'a>(&'a self, req: SpawnRequest<'a>) -> BoxFut<'a, io::Result<Spawned>> {
        Box::pin(async move {
            self.seen.lock().expect("seen").push(Seen {
                program: req.launch.program.clone(),
                args: req.launch.args.clone(),
                deadline: req.deadline,
            });
            if let Stdio::Pty { .. } = req.stdio {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "no pty yet"));
            }
            let (stdout, stderr, scripted, hang) = match &self.script {
                Script::Refuse(why) => {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, why.clone()));
                }
                Script::Exit {
                    stdout,
                    stderr,
                    exit,
                } => (stdout.clone(), stderr.clone(), *exit, false),
                Script::Hang { stdout } => (stdout.clone(), String::new(), KILLED, true),
            };
            self.started.fetch_add(1, Ordering::SeqCst);
            let (mut tx, rx) = tokio::io::duplex(64 * 1024);
            let (done_tx, done) = watch::channel(None);
            let killed = Arc::new(Notify::new());
            let (wait_for_kill, deadline) = (killed.clone(), req.deadline);
            tokio::spawn(async move {
                for line in stdout {
                    let _ = tx.write_all(format!("{line}\n").as_bytes()).await;
                }
                let exit = match (hang, deadline) {
                    (false, _) => scripted,
                    (true, Some(after)) => {
                        match tokio::time::timeout(after, wait_for_kill.notified()).await {
                            Ok(()) => KILLED,
                            Err(_) => Exit {
                                deadline: true,
                                ..KILLED
                            },
                        }
                    }
                    (true, None) => {
                        wait_for_kill.notified().await;
                        KILLED
                    }
                };
                drop(tx);
                let _ = done_tx.send(Some(exit));
            });
            Ok(Spawned {
                stdin: Some(Box::new(tokio::io::sink())),
                stdout: Box::new(rx),
                stderr: Some(Box::new(io::Cursor::new(stderr.into_bytes()))),
                running: Box::new(FakeRunning {
                    done,
                    killed,
                    torn_down: self.torn_down.clone(),
                }),
            })
        })
    }
}

struct FakeRunning {
    done: watch::Receiver<Option<Exit>>,
    killed: Arc<Notify>,
    torn_down: Arc<AtomicUsize>,
}

impl FakeRunning {
    async fn ended(&mut self) -> Exit {
        let seen = self.done.wait_for(Option::is_some).await;
        seen.ok().and_then(|v| *v).unwrap_or(KILLED)
    }
}

impl Running for FakeRunning {
    fn pid(&self) -> Option<u32> {
        None
    }
    fn interrupt(&self) -> BoxFut<'_, io::Result<()>> {
        Box::pin(async move {
            self.killed.notify_one();
            Ok(())
        })
    }
    fn wait(&mut self) -> BoxFut<'_, io::Result<Exit>> {
        Box::pin(async move { Ok(self.ended().await) })
    }
    fn kill(&mut self) -> BoxFut<'_, Option<Exit>> {
        Box::pin(async move {
            self.killed.notify_one();
            Some(self.ended().await)
        })
    }
}

impl Drop for FakeRunning {
    fn drop(&mut self) {
        self.killed.notify_one();
        self.torn_down.fetch_add(1, Ordering::SeqCst);
    }
}
