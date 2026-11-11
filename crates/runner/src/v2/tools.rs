//! Tool install on the runner host (the `tools.install` and `tools.status` ops) and the probe of
//! what is installed. The install itself is the root helper's (`crate::toolhelper`, reached over a
//! socket); this side starts it, follows its progress lines and keeps the last operations' status
//! for the Core's polls.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, StreamError, Tool, ToolOpState, ToolsInstall, ToolsStatus};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The root helper's socket (`deploy/systemd/ainkrad-runner-tools.socket`).
pub const HELPER_SOCKET: &str = "/run/ainkrad-runner-tools.sock";

/// An install that runs longer than this is given up.
const INSTALL_LIMIT: Duration = Duration::from_secs(30 * 60);
/// Operations whose status is kept for polls.
const KEEP: usize = 16;

#[derive(Deserialize)]
struct Line {
    #[serde(default)]
    percent: Option<u8>,
    #[serde(default)]
    step: Option<String>,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    failed: Option<String>,
}

pub struct ToolsDriver {
    socket: PathBuf,
    ops: Mutex<VecDeque<ToolsStatus>>,
}

fn refuse(code: ErrorCode, why: &str) -> StreamError {
    StreamError::new(code, why)
}

impl ToolsDriver {
    pub fn new(socket: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            socket: socket.into(),
            ops: Mutex::default(),
        })
    }

    fn update(&self, op: &str, f: impl FnOnce(&mut ToolsStatus)) {
        if let Some(s) = self
            .ops
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.operation == op)
        {
            f(s);
        }
    }

    /// Starts the install and answers with its first status; `after` runs when it ended well.
    pub fn install(
        self: &Arc<Self>,
        req: ToolsInstall,
        after: impl FnOnce(Tool) + Send + 'static,
    ) -> Result<ToolsStatus, StreamError> {
        let first = ToolsStatus {
            operation: req.operation.clone(),
            tool: req.tool,
            state: ToolOpState::Running,
            percent: 0,
            step: "Starting".to_owned(),
            reason: None,
            tools: BTreeMap::new(),
        };
        {
            let mut ops = self.ops.lock().unwrap();
            if ops.iter().any(|s| s.state == ToolOpState::Running) {
                return Err(refuse(ErrorCode::Busy, "another install is running here"));
            }
            if ops.iter().any(|s| s.operation == req.operation) {
                return Err(refuse(
                    ErrorCode::InvalidArgs,
                    "that operation id is in use",
                ));
            }
            if ops.len() >= KEEP {
                ops.pop_front();
            }
            ops.push_back(first.clone());
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let ended = tokio::time::timeout(INSTALL_LIMIT, me.drive(&req)).await;
            let result = ended.unwrap_or_else(|_| Err("the install took too long".to_owned()));
            match result {
                Ok(()) => {
                    let found = tokio::task::spawn_blocking(probe_tools)
                        .await
                        .unwrap_or_default();
                    me.update(&req.operation, |s| {
                        s.state = ToolOpState::Done;
                        s.percent = 100;
                        s.step = "Installed".to_owned();
                        s.tools = found;
                    });
                    after(req.tool);
                }
                Err(why) => {
                    tracing::warn!(tool = req.tool.name(), %why, "a tool install failed");
                    me.update(&req.operation, |s| {
                        s.state = ToolOpState::Failed;
                        s.reason = Some(why);
                    });
                }
            }
        });
        Ok(first)
    }

    pub fn status(&self, op: &str) -> Result<ToolsStatus, StreamError> {
        self.ops
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.operation == op)
            .cloned()
            .ok_or_else(|| refuse(ErrorCode::InvalidArgs, "no such operation on this runner"))
    }

    /// One conversation with the helper.
    async fn drive(&self, req: &ToolsInstall) -> Result<(), String> {
        let stream = UnixStream::connect(&self.socket).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                "the tool installer is not set up on this runner (ainkrad-runner-tools.socket is missing); re-run the runner installer".to_owned()
            }
            _ => format!("the tool installer cannot be reached: {e}"),
        })?;
        let (read, mut write) = stream.into_split();
        let line = serde_json::json!({"tool": req.tool}).to_string();
        write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut lines = BufReader::new(read).lines();
        while let Some(l) = lines.next_line().await.map_err(|e| e.to_string())? {
            let Ok(l) = serde_json::from_str::<Line>(&l) else {
                continue;
            };
            if let Some(why) = l.failed {
                return Err(why.chars().take(600).collect());
            }
            if l.done {
                return Ok(());
            }
            self.update(&req.operation, |s| {
                s.percent = l.percent.unwrap_or(s.percent).min(99).max(s.percent);
                if let Some(step) = l.step {
                    s.step = step.chars().take(200).collect();
                }
            });
        }
        Err("the tool installer ended without an answer".to_owned())
    }
}

/// The first dotted version in `--version` output: `git version 2.43.0` gives `2.43.0`,
/// `go version go1.22.1 linux/amd64` gives `1.22.1`, `v22.22.1` gives `22.22.1`.
pub fn version_of(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|w| {
        let w = w.trim_matches(|c: char| c == ',' || c == '(' || c == ')');
        let w = w.strip_prefix("go").unwrap_or(w);
        let w = w.strip_prefix('v').unwrap_or(w);
        let ok = w.contains('.')
            && w.starts_with(|c: char| c.is_ascii_digit())
            && w.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+');
        ok.then(|| w.to_owned())
    })
}

/// Which program and argument tell a tool's version.
fn probe_of(t: Tool) -> (&'static str, &'static str) {
    match t {
        Tool::Python => ("python3", "--version"),
        Tool::Rust => ("rustc", "--version"),
        Tool::Go => ("go", "version"),
        t => (t.name(), "--version"),
    }
}

/// The installed tools of [`Tool::ALL`], name to version, found on this process's `PATH` (each
/// asked once, `--version`, a few seconds at most). Blocking: call it from `spawn_blocking`.
pub fn probe_tools() -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for t in Tool::ALL {
        let (program, arg) = probe_of(t);
        let Ok(mut child) = Command::new(program)
            .arg(arg)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            continue;
        };
        let started = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if started.elapsed() < Duration::from_secs(5) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        if status.is_some_and(|s| s.success())
            && let Some(out) = child.stdout.take()
        {
            use std::io::Read;
            let mut text = String::new();
            let _ = out.take(4096).read_to_string(&mut text);
            if let Some(v) = version_of(text.lines().next().unwrap_or("")) {
                found.insert(t.name().to_owned(), v);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_come_out_of_each_tools_own_wording() {
        for (text, want) in [
            ("git version 2.43.0", "2.43.0"),
            ("Python 3.14.4", "3.14.4"),
            ("go version go1.22.1 linux/amd64", "1.22.1"),
            ("rustc 1.99.1 (abc 2026-01-01)", "1.99.1"),
            ("Docker version 27.0.1, build abc", "27.0.1"),
            ("v22.22.1", "22.22.1"),
            ("2.1.318 (Claude Code)", "2.1.318"),
        ] {
            assert_eq!(version_of(text).as_deref(), Some(want), "{text}");
        }
        assert_eq!(version_of("no number here"), None);
    }

    /// A helper that answers `lines` to one request, then closes.
    fn helper(dir: &std::path::Path, lines: &'static [&'static str]) -> PathBuf {
        let sock = dir.join("h.sock");
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut req = String::new();
            BufReader::new(r).read_line(&mut req).await.unwrap();
            assert_eq!(req.trim(), r#"{"tool":"git"}"#);
            for line in lines {
                w.write_all(format!("{line}\n").as_bytes()).await.unwrap();
            }
        });
        sock
    }

    async fn settled(d: &ToolsDriver, op: &str) -> ToolsStatus {
        for _ in 0..200 {
            let s = d.status(op).unwrap();
            if s.state != ToolOpState::Running {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("still running");
    }

    fn req(op: &str) -> ToolsInstall {
        ToolsInstall {
            operation: op.to_owned(),
            tool: Tool::Git,
        }
    }

    #[tokio::test]
    async fn progress_then_done_is_kept_and_runs_after() {
        let dir = tempfile_dir();
        let sock = helper(
            &dir,
            &[
                r#"{"percent":30,"step":"Installing git"}"#,
                r#"{"percent":100,"done":true}"#,
            ],
        );
        let d = ToolsDriver::new(sock);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let first = d
            .install(req("op_1"), move |t| {
                let _ = tx.send(t);
            })
            .unwrap();
        assert_eq!(first.state, ToolOpState::Running);
        let s = settled(&d, "op_1").await;
        assert_eq!((s.state, s.percent), (ToolOpState::Done, 100));
        assert_eq!(rx.await.unwrap(), Tool::Git);
    }

    #[tokio::test]
    async fn a_failure_carries_its_reason_and_a_second_install_waits() {
        let dir = tempfile_dir();
        let sock = helper(
            &dir,
            &[
                r#"{"percent":10,"step":"x"}"#,
                r#"{"failed":"apt-get failed"}"#,
            ],
        );
        let d = ToolsDriver::new(sock);
        d.install(req("op_1"), |_| {}).unwrap();
        let busy = d.install(req("op_2"), |_| {});
        assert_eq!(busy.unwrap_err().code, ErrorCode::Busy);
        let s = settled(&d, "op_1").await;
        assert_eq!(s.state, ToolOpState::Failed);
        assert_eq!(s.reason.as_deref(), Some("apt-get failed"));
        assert_eq!(d.status("op_9").unwrap_err().code, ErrorCode::InvalidArgs);
    }

    #[tokio::test]
    async fn no_helper_says_how_to_fix_it() {
        let d = ToolsDriver::new("/nonexistent/ainkrad-tools.sock");
        d.install(req("op_1"), |_| {}).unwrap();
        let s = settled(&d, "op_1").await;
        assert_eq!(s.state, ToolOpState::Failed);
        assert!(s.reason.unwrap().contains("re-run the runner installer"));
    }

    fn tempfile_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("akt-{}", ainkrad_core_rand()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn ainkrad_core_rand() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
            ^ u64::from(std::process::id())
    }
}
