//! One PTY and its child (E2-02), on `portable-pty` (P2.1).
//!
//! - The child leads its own session and process group (portable-pty calls `setsid` and makes
//!   the PTY its controlling terminal), so a signal to the group reaches the shell and its
//!   foreground job, and nothing of the host's.
//! - Its environment is built here from an allow-list ([`environment`]): nothing is inherited
//!   by accident. `TERM`, `COLORTERM` and `LANG` are set deliberately.
//! - The child is always waited for (the PTYReaper lesson), in two steps. A thread observes the
//!   exit **without reaping** (`ainkrad_sys::wait_exited`), so the dead leader stays a zombie
//!   and its pid, which is also its process group id, cannot be recycled while the host lives:
//!   no signal of ours can reach an unrelated process that got the same number (review H1).
//!   The host reaps it once, when it ends ([`Pty::reap`]). Signals after a known exit are
//!   refused anyway. Closing escalates HUP → TERM → KILL ([`hang_up`]).
//! - Resizing sets the PTY's window size; the kernel sends the foreground group `SIGWINCH`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::time::Duration;

use ainkrad_proto::v2::Size;
use portable_pty::{CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
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
    /// The disk cap for this terminal's scrollback (clamped to `store::CAP_MIN..=CAP_MAX`);
    /// absent: `store::CAP_DEFAULT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrollback_bytes: Option<u64>,
    /// Bytes the child gets as an inherited pipe on descriptor 3 (standard base64 here): the
    /// runner's key handoff to `ainkrad-runner ssh-pty`. Never argv, env or disk; wiped from the
    /// host's memory once the child is started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd3: Option<Hidden>,
}

/// A secret in a [`Spec`]: wiped when dropped, never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hidden(pub String);

impl std::fmt::Debug for Hidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[hidden]")
    }
}

impl Drop for Hidden {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The most bytes a serialized [`Spec`] may take (it carries the key handoff, so it is read and
/// written through one fixed buffer, never grown).
pub const SPEC_MAX: usize = 256 * 1024;

/// A writer into a `Vec` that fails rather than grow it: growing would leave an unwiped copy of
/// what was written (keys) behind in freed memory.
pub struct Capped<'a>(pub &'a mut Vec<u8>);

impl Write for Capped<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0.len() + buf.len() > self.0.capacity() {
            return Err(io::Error::other("too large"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `spec` as the host reads it on stdin, in a buffer of `SPEC_MAX` bytes that is wiped on drop.
pub fn spec_bytes(spec: &Spec) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(SPEC_MAX));
    serde_json::to_writer(Capped(&mut buf), spec).map_err(io::Error::other)?;
    Ok(buf)
}

/// The most bytes `Spec::fd3` may carry: well inside a pipe's capacity on both OSes, so filling it
/// never blocks.
pub const FD3_MAX: usize = 12 * 1024;

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

/// The pipe capacity asked for (Linux) before the key is written.
const PIPE_WANT: usize = 64 * 1024;

/// A pipe holding `bytes`, its write end closed: the child reads them, then EOF. The write end is
/// non-blocking, so bytes that do not fit fail (`key handoff did not fit`) instead of hanging the
/// host. `want` is the capacity asked for first (Linux; best effort).
fn key_pipe(bytes: &[u8], want: usize) -> io::Result<std::io::PipeReader> {
    use std::os::fd::AsFd;
    let (reader, mut writer) = std::io::pipe()?;
    ainkrad_sys::pipe_setup(writer.as_fd(), want)?;
    writer.write_all(bytes).map_err(|e| {
        if e.kind() == io::ErrorKind::WouldBlock {
            io::Error::other("key handoff did not fit")
        } else {
            e
        }
    })?;
    Ok(reader)
}

/// Starts `spec` on the PTY at `tty` with `secret` (base64) readable from an inherited pipe on
/// descriptor 3. `portable-pty`'s own spawn closes every descriptor above 2, so it cannot pass one:
/// the child is started here, the same way (own session, the PTY as controlling terminal, the
/// spec's environment only), plus the pipe. The pipe is filled and its write end closed before the
/// spawn, so the child reads the bytes and then EOF.
fn spawn_with_fd3(
    spec: &Spec,
    secret: &Hidden,
    tty: Option<std::path::PathBuf>,
) -> io::Result<std::process::Child> {
    use base64::Engine;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret.0.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd3 is not base64"))?;
    let bytes = zeroize::Zeroizing::new(bytes);
    if bytes.len() > FD3_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fd3 is too large",
        ));
    }
    let program = spec
        .program
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fd3 needs a program"))?;
    let tty = tty.ok_or_else(|| io::Error::other("the PTY has no name"))?;
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&tty)
    };
    let reader = key_pipe(&bytes, PIPE_WANT)?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(&spec.args).env_clear().envs(&spec.env);
    if let Some(dir) = spec.cwd.as_ref().or_else(|| spec.env.get("HOME")) {
        cmd.current_dir(dir);
    }
    cmd.stdin(open()?).stdout(open()?).stderr(open()?);
    ainkrad_sys::pty_child_on_exec(&mut cmd, reader.as_raw_fd());
    cmd.spawn()
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
    /// Our own slave fd, held until the exit is announced: macOS may discard output the master
    /// has not read yet when the last slave fd closes, which loses a fast child's output (an
    /// `echo` that exits at once). Held, the master never sees EOF; the host releases it once
    /// the exit is known and the output had time to drain ([`Pty::release_slave`]).
    slave: Option<Box<dyn SlavePty + Send>>,
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
        let child: Box<dyn portable_pty::Child + Send + Sync> = match &spec.fd3 {
            None => pair.slave.spawn_command(cmd).map_err(io_err)?,
            Some(secret) => Box::new(spawn_with_fd3(spec, secret, pair.master.tty_name())?),
        };
        // Our slave fd stays open until the exit is announced (see `Pty::slave`).
        let pid = child
            .process_id()
            .ok_or_else(|| io::Error::other("the child has no pid"))?;
        let (tx, exit) = watch::channel(None);
        std::thread::spawn(move || {
            // Held, never waited on through portable-pty: that would reap it (see the module).
            let _child = child;
            let e = match ainkrad_sys::wait_exited(pid) {
                Ok(ainkrad_sys::Ended::Code(c)) => Exit {
                    code: Some(c),
                    signal: None,
                },
                Ok(ainkrad_sys::Ended::Signal(n)) => Exit {
                    code: None,
                    signal: Some(
                        ainkrad_sys::signal_name(n)
                            .map_or_else(|| format!("signal {n}"), |s| format!("SIG{s}")),
                    ),
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
                slave: Some(pair.slave),
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

    /// Closes our slave fd, so the master reads EOF once the child's last fd is gone too.
    pub fn release_slave(&mut self) {
        self.slave = None;
    }

    /// Reaps the exited child, freeing its pid and group id: only once its exit was seen, and
    /// only when nothing will signal its group again (the host's end).
    pub fn reap(&self) {
        let _ = ainkrad_sys::reap(self.pid);
    }

    /// `name` (`"INT"`) to the child's process group; `Ok(false)` once it is gone. The caller
    /// refuses this after the exit is known; the zombie leader keeps the group id ours anyway.
    pub fn signal(&self, name: &str) -> io::Result<bool> {
        let n = ainkrad_sys::signal_number(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown signal"))?;
        ainkrad_sys::killpg(self.pid, n)
    }
}

/// Ends the child: HUP, then TERM after `grace`, then KILL after another `grace`, each to its
/// process group, until `exit` reports it ended; then the rest of the group is killed. Safe
/// because the leader is not reaped yet: its zombie holds the group id.
pub async fn hang_up(pid: u32, grace: Duration, mut exit: watch::Receiver<Option<Exit>>) {
    // Already over: nothing to signal, and no final sweep (review H1).
    if exit.borrow().is_some() {
        return;
    }
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

#[cfg(all(test, target_os = "linux"))]
mod key_pipe_tests {
    use super::*;

    #[test]
    fn a_key_that_does_not_fit_fails_instead_of_blocking() {
        // 4096 is the smallest pipe Linux grants: 8000 bytes cannot be written without a reader.
        let e = key_pipe(&[7u8; 8000], 4096).unwrap_err();
        assert!(e.to_string().contains("did not fit"), "{e}");
    }

    #[test]
    fn a_key_that_fits_is_read_back_then_eof() {
        use std::io::Read;
        let mut r = key_pipe(&[7u8; FD3_MAX], PIPE_WANT).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), FD3_MAX);
    }
}
