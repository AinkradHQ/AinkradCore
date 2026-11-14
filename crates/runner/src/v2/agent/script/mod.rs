//! Code Mode on the runner (E3): `ainkrad_run` scripts and the `ainkrad` CLI.
//!
//! A script is JavaScript run by QuickJS in a CHILD process, `ainkrad-runner __script`, spawned by
//! the stdio shim INSIDE the session's sandbox ([`shim`]). The engine has no ambient authority
//! ([`engine`]: no fs, net, process, timers or modules; `ainkrad` is frozen), its only way out is
//! the session's own tools socket, through one small client shared with the CLI ([`client`]), and
//! only the final value comes back to the model, bounded. An engine abort or a crash ends the child,
//! never the shim or the runner. Everything is behind the `quickjs` feature.
//!
//! Wire (plan P2): a script call is `tools/call ainkrad_call {op, args, run, key?}` on the socket
//! (the Core's `ainkrad.call`, named with `.` as `_` like every tool; hidden from the harness's own
//! `tools/list`, the socket is the credential either way). A script's call also carries
//! `repeat?` and `wait_ms` (its time left: the Core holds an approval no longer than that).

use std::time::Duration;

pub mod child;
pub mod cli;
pub mod client;
pub mod engine;
pub mod shim;

/// The Core's internal tools that scripts and the CLI use (MCP spelling).
pub const CALL: &str = "ainkrad_call";
pub const SCHEMA: &str = "ainkrad_schema";
pub const SEARCH: &str = "ainkrad_search";
/// Their channel names: not listed to the harness, only called.
pub const HIDDEN: [&str; 2] = ["ainkrad.call", "ainkrad.schema"];

/// The environment variable that holds the session's socket (a path, not a secret).
pub const SOCK_ENV: &str = "AINKRAD_TOOLS_SOCK";

/// The most bytes of script text.
pub const MAX_CODE: usize = 128 * 1024;
/// The most bytes of the arguments of one operation call from a script (the relay allows 384 KiB).
pub const MAX_CALL_ARGS: usize = 256 * 1024;
/// The most bytes of the final value, and of captured console output, returned to the model.
pub const MAX_VALUE: usize = 32 * 1024;
pub const MAX_CONSOLE: usize = 8 * 1024;
/// The child's whole answer to the shim.
pub const MAX_ENVELOPE: usize = 256 * 1024;

/// What one script may use. The child clamps whatever it is given to [`Limits::CEILING`].
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Bytes of JS heap.
    pub memory: usize,
    /// Bytes of JS stack (deep recursion ends with a plain error).
    pub stack: usize,
    /// The script's own running time; time spent waiting on an operation (a person's approval
    /// above all) is not counted (E6.5).
    pub time_ms: u64,
    /// Wall time for the whole script, every wait included.
    pub deadline_ms: u64,
    /// Operation calls.
    pub calls: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory: 64 << 20,
            stack: 512 << 10,
            time_ms: 60_000,
            deadline_ms: 600_000,
            calls: 100,
        }
    }
}

impl Limits {
    pub const CEILING: Limits = Limits {
        memory: 256 << 20,
        stack: 1 << 20,
        time_ms: 600_000,
        deadline_ms: 600_000,
        calls: 1000,
    };

    pub fn clamped(self) -> Self {
        let c = Self::CEILING;
        Self {
            memory: self.memory.min(c.memory),
            stack: self.stack.min(c.stack),
            time_ms: self.time_ms.min(c.time_ms),
            deadline_ms: self.deadline_ms.min(c.deadline_ms),
            calls: self.calls.min(c.calls),
        }
    }

    pub fn time(&self) -> Duration {
        Duration::from_millis(self.time_ms)
    }

    pub fn deadline(&self) -> Duration {
        Duration::from_millis(self.deadline_ms)
    }
}

/// `<dir>/bin/ainkrad`, a link to the runner executable `exe` (the shim, which is bound into the
/// sandbox at the same path): the session's CLI. Returns the bin dir, for `PATH` and a read-only bind.
pub fn install_bin(
    dir: &std::path::Path,
    exe: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let bin = dir.join("bin");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&bin)?;
    let link = bin.join("ainkrad");
    match std::fs::remove_file(&link) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::os::unix::fs::symlink(exe, &link)?;
    Ok(bin)
}

/// What a session with Code Mode is told (E3.6), after its own instructions.
pub const NOTE: &str = "\n\n## Ainkrad Code Mode\n\n\
For anything about Ainkrad itself (AI sessions, audit, health and more), call `ainkrad_search` \
first with a few words: it returns typed definitions such as \
`ainkrad.agents.listAgentSessions(args: { limit?: number }): ...`. Then do the whole task in ONE \
`ainkrad_run` call: a short JavaScript body that calls those operations (synchronous, no `await`), \
keeps what it needs in variables, and `return`s only the small answer you want. Example:\n\n\
```js\nconst l = ainkrad.agents.listAgentSessions({ limit: 20 });\n\
return l.items.filter(s => s.state === 'running').map(s => s.id);\n```\n\n\
A refused call throws an Error with a `code`; `try/catch` it. A risky operation waits for a person \
to approve it; a denial throws `ainkrad.ApprovalError` (`code` `approval_denied` or \
`approval_timeout`). A write takes options as a second argument: `{ key: 'k1' }` makes it run at \
most once per key, `{ repeat: true }` runs it again. There is no network, file or process \
access in a script, and it has a time and call budget. Use `console.log` sparingly. From a shell, \
`ainkrad search <words>`, `ainkrad schema <op>` and `ainkrad <group> <op> --json '{...}'` do the same, \
with JSON in and out.\n";

/// `value` as JSON text of at most `max` bytes: past it, a marker with the full size replaces the tail.
pub fn cap(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}... [truncated: {} of {} bytes]",
        &text[..end],
        end,
        text.len()
    )
}

#[cfg(test)]
mod tests;
