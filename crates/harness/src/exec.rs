//! The exec backend seam (E8a-06): how a harness process is started and ended.
//!
//! [`ExecBackend::spawn`] takes a [`SpawnRequest`] (argv and variables, the stdio mode, an
//! optional wall-clock deadline) and returns a [`Spawned`]: three byte streams and a
//! [`Running`] handle that can interrupt, wait for and kill the process tree. The harness
//! adapters speak NDJSON over those streams and know nothing else about where the process runs.
//!
//! - [`LocalBackend`] is the default and the only real one: today's process group under
//!   bubblewrap or Seatbelt, byte for byte (`exec/local.rs`).
//! - A backend never weakens a request. One that cannot honour it (a stdio mode it lacks, a
//!   tier it is not) returns an error from `spawn`, and nothing is started anywhere else.
//! - Terminals are not behind this yet: they stay on `termbox` until E8a-07, so `Stdio::Pty` is
//!   refused by the local backend rather than emulated.
//! - A deadline is enforced by the host killing the process tree, never by a limit the
//!   sandboxed process could lift. `None` adds no timer.

use std::ffi::OsString;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Spec;

pub(crate) mod local;
pub use local::LocalBackend;

#[doc(hidden)]
pub mod fake;
#[cfg(test)]
mod tests;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The variable of a [`Spec`]'s `env` that carries the wall-clock cap, in whole seconds.
pub const WALL_VAR: &str = "AINKRAD_SANDBOX_WALL";

/// How the process's standard streams are attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stdio {
    /// Three pipes (every harness adapter).
    Pipes,
    /// A pseudo-terminal of this size (the VM terminal, E8a-07). The local backend refuses it.
    Pty { rows: u16, cols: u16 },
}

/// What to run: the harness executable, its arguments, and the variables a harness sets for
/// itself on top of the spec's (`CLAUDE_CONFIG_DIR`, `HOME`, ...).
#[derive(Debug, Clone)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<String>,
    pub set: Vec<(String, OsString)>,
}

impl Launch {
    pub fn new(program: impl Into<OsString>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            set: vec![],
        }
    }

    pub fn set(mut self, name: &str, value: impl Into<OsString>) -> Self {
        self.set.push((name.to_owned(), value.into()));
        self
    }

    /// The local command for this launch under `spec`: the sandbox wrapping, the cleared
    /// environment, the allowlist, then the spec's variables and `set`.
    pub fn command(&self, spec: &Spec) -> tokio::process::Command {
        let set: Vec<(&str, &std::ffi::OsStr)> = self
            .set
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_os_str()))
            .collect();
        crate::proc::command(&self.program, &self.args, spec, &set)
    }
}

/// One start. `spec` carries the working directory, the variables and the `AINKRAD_SANDBOX_*`
/// settings; `launch` the command.
pub struct SpawnRequest<'a> {
    pub spec: &'a Spec,
    pub launch: &'a Launch,
    pub stdio: Stdio,
    /// The wall-clock cap: past it the host kills the process tree.
    pub deadline: Option<Duration>,
}

/// How a process ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    /// The terminating signal, so a kill is told apart from an exit code.
    pub signal: Option<i32>,
    /// The wall-clock deadline ended it.
    pub deadline: bool,
    /// The backend's memory cap ended it.
    pub oom: bool,
}

/// A started process, as the adapters need it. Dropping it ends the whole tree.
pub trait Running: Send + Sync {
    /// The process group leader, where there is one.
    fn pid(&self) -> Option<u32>;
    /// What Ctrl-C would do: SIGINT to the whole group.
    fn interrupt(&self) -> BoxFut<'_, io::Result<()>>;
    /// Waits for the leader to end.
    fn wait(&mut self) -> BoxFut<'_, io::Result<Exit>>;
    /// Kills the whole tree and waits for the leader.
    fn kill(&mut self) -> BoxFut<'_, Option<Exit>>;
}

pub struct Spawned {
    pub stdin: Option<Box<dyn AsyncWrite + Send + Sync + Unpin>>,
    pub stdout: Box<dyn AsyncRead + Send + Sync + Unpin>,
    pub stderr: Option<Box<dyn AsyncRead + Send + Sync + Unpin>>,
    pub running: Box<dyn Running>,
}

pub trait ExecBackend: Debug + Send + Sync {
    /// Shown in logs.
    fn name(&self) -> &'static str;
    /// Starts the process, or says why not. An `Err` means nothing was started.
    fn spawn<'a>(&'a self, req: SpawnRequest<'a>) -> BoxFut<'a, io::Result<Spawned>>;
}

/// The wall-clock cap in `spec`: `None` when absent. A value that is not 1 to 86400 seconds
/// refuses the start, so a typo never means "no cap".
pub(crate) fn wall_clock(spec: &Spec) -> io::Result<Option<Duration>> {
    let Some((_, value)) = spec.env.iter().find(|(n, _)| n == WALL_VAR) else {
        return Ok(None);
    };
    value
        .to_str()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (1..=86_400).contains(s))
        .map(|s| Some(Duration::from_secs(s)))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{WALL_VAR} must be 1 to 86400 seconds"),
            )
        })
}
