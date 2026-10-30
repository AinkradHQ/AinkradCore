//! One PTY and its child (E2-02), on `portable-pty` (P2.1).
//!
//! - The child leads its own session and process group (portable-pty calls `setsid` and makes
//!   the PTY its controlling terminal), so a signal to the group reaches the shell and its
//!   foreground job, and nothing of the host's.
//! - Its environment is built here from an allow-list ([`environment`]): nothing is inherited
//!   by accident. `TERM`, `COLORTERM` and `LANG` are set deliberately.
//! - The child is always waited for (the PTYReaper lesson): [`Pty::spawn`] hands the waiter to
//!   a thread that blocks in `wait` and reports the exit. Closing escalates HUP → TERM → KILL
//!   ([`hang_up`]), then whatever is left of the group is killed once the leader is reaped.
//! - Resizing sets the PTY's window size; the kernel sends the foreground group `SIGWINCH`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::time::Duration;

use ainkrad_proto::v2::Size;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// What the host is asked to run: the environment already resolved by the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// Absent: the user's login shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The child's whole environment.
    pub env: BTreeMap<String, String>,
    pub size: Size,
}

/// How a child ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Runner variables every terminal gets when the runner has them: who and where the user is.
pub const BASE_ENV: &[&str] = &["HOME", "LOGNAME", "PATH", "SHELL", "TMPDIR", "USER"];

/// The child's environment: [`BASE_ENV`] from the runner's own, then the runner variables
/// `pass` names that are also on `allow`, then `TERM`, `COLORTERM` and a UTF-8 `LANG`, then
/// what the Core sets (`set`) as given. Nothing else of the runner's reaches the child.
pub fn environment(
    runner: &[(OsString, OsString)],
    allow: &[String],
    pass: &[String],
    set: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let lookup = |name: &str| {
        runner
            .iter()
            .find(|(k, _)| k.to_str() == Some(name))
            .and_then(|(_, v)| v.to_str())
            .map(str::to_owned)
    };
    let passed = pass
        .iter()
        .filter(|n| allow.contains(n))
        .map(String::as_str);
    for name in BASE_ENV.iter().copied().chain(passed) {
        if let Some(v) = lookup(name) {
            env.insert(name.to_owned(), v);
        }
    }
    env.insert("TERM".to_owned(), "xterm-256color".to_owned());
    env.insert("COLORTERM".to_owned(), "truecolor".to_owned());
    let utf8 = |v: &String| {
        let v = v.to_ascii_lowercase();
        v.contains("utf-8") || v.contains("utf8")
    };
    let lang = lookup("LANG").filter(utf8);
    env.insert(
        "LANG".to_owned(),
        lang.unwrap_or_else(|| "en_US.UTF-8".to_owned()),
    );
    env.extend(set.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

fn pty_size(s: Size) -> PtySize {
    PtySize {
        rows: s.rows,
        cols: s.cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// A running PTY: its master and its child's pid (which is also its process group).
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    pub pid: u32,
}

/// The parts of a spawned PTY that go to their own threads.
pub struct Spawned {
    pub pty: Pty,
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    /// Fires once with the exit, after the child was waited for.
    pub exit: watch::Receiver<Option<Exit>>,
}

impl Pty {
    /// Starts `spec` in a new PTY. The waiter thread reaps the child whatever happens.
    pub fn spawn(spec: &Spec) -> io::Result<Spawned> {
        if !spec.size.valid() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad size"));
        }
        if spec.cwd.as_deref().is_some_and(|c| !c.starts_with('/')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cwd must be absolute",
            ));
        }
        let pair = native_pty_system()
            .openpty(pty_size(spec.size))
            .map_err(io_err)?;
        let mut cmd = match &spec.program {
            Some(p) => {
                let mut c = CommandBuilder::new(p);
                c.args(&spec.args);
                c
            }
            None => CommandBuilder::new_default_prog(),
        };
        // CommandBuilder starts from the host's environment: cleared, then only the spec's.
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        match &spec.cwd {
            Some(cwd) => cmd.cwd(cwd),
            None => {
                if let Some(home) = spec.env.get("HOME") {
                    cmd.cwd(home);
                }
            }
        }
        let mut child = pair.slave.spawn_command(cmd).map_err(io_err)?;
        // The master sees EOF only once every slave fd is closed: ours goes now.
        drop(pair.slave);
        let pid = child
            .process_id()
            .ok_or_else(|| io::Error::other("the child has no pid"))?;
        let (tx, exit) = watch::channel(None);
        std::thread::spawn(move || {
            let status = child.wait();
            let e = match status {
                Ok(s) if s.signal().is_some() => Exit {
                    code: None,
                    signal: s.signal().map(str::to_owned),
                },
                Ok(s) => Exit {
                    code: i32::try_from(s.exit_code()).ok(),
                    signal: None,
                },
                Err(e) => Exit {
                    code: None,
                    signal: Some(format!("wait failed: {e}")),
                },
            };
            let _ = tx.send(Some(e));
        });
        let reader = pair.master.try_clone_reader().map_err(io_err)?;
        let writer = pair.master.take_writer().map_err(io_err)?;
        Ok(Spawned {
            pty: Pty {
                master: pair.master,
                pid,
            },
            reader,
            writer,
            exit,
        })
    }

    /// The new window size; the child's foreground group gets `SIGWINCH`.
    pub fn resize(&self, size: Size) -> io::Result<()> {
        if !size.valid() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad size"));
        }
        self.master.resize(pty_size(size)).map_err(io_err)
    }

    /// `name` (`"INT"`) to the child's process group; `Ok(false)` once it is gone.
    pub fn signal(&self, name: &str) -> io::Result<bool> {
        let n = ainkrad_sys::signal_number(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown signal"))?;
        ainkrad_sys::killpg(self.pid, n)
    }
}

/// Ends the child: HUP, then TERM after `grace`, then KILL after another `grace`, each to its
/// process group, until `exit` reports it waited for. Once it is reaped the rest of the group
/// is killed (its id cannot be reused while a member lives).
pub async fn hang_up(pid: u32, grace: Duration, mut exit: watch::Receiver<Option<Exit>>) {
    for sig in ["HUP", "TERM", "KILL"] {
        if exit.borrow().is_some() {
            break;
        }
        if let Some(n) = ainkrad_sys::signal_number(sig) {
            let _ = ainkrad_sys::killpg(pid, n);
        }
        let _ = tokio::time::timeout(grace, exit.wait_for(Option::is_some)).await;
    }
    let _ = exit.wait_for(Option::is_some).await;
    if let Some(n) = ainkrad_sys::signal_number("KILL") {
        let _ = ainkrad_sys::killpg(pid, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    /// E2-02.3: a planted secret in the runner's environment never reaches the child.
    #[test]
    fn the_environment_is_an_allow_list() {
        let runner = os(&[
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/example"),
            ("AWS_SECRET_ACCESS_KEY", "planted"),
            ("GITHUB_TOKEN", "planted"),
            ("LC_ALL", "C"),
            ("LANG", "C"),
        ]);
        let allow = vec!["LC_ALL".to_owned()];
        let pass = vec!["LC_ALL".to_owned(), "GITHUB_TOKEN".to_owned()];
        let set = BTreeMap::from([("EDITOR".to_owned(), "vi".to_owned())]);
        let env = environment(&runner, &allow, &pass, &set);
        assert!(!env.values().any(|v| v == "planted"), "{env:?}");
        assert_eq!(env["PATH"], "/usr/bin:/bin");
        assert_eq!(env["LC_ALL"], "C");
        assert_eq!(env["TERM"], "xterm-256color");
        assert_eq!(env["COLORTERM"], "truecolor");
        assert_eq!(env["LANG"], "en_US.UTF-8", "a non-UTF-8 LANG is replaced");
        assert_eq!(env["EDITOR"], "vi");
        let env = environment(&os(&[("LANG", "C.UTF-8")]), &[], &[], &BTreeMap::new());
        assert_eq!(env["LANG"], "C.UTF-8");
    }
}
