//! Terminals on protocol v2 (E2-01): the `pty` driver's ops, the terminal object and its
//! lifecycle, and the flow-control rules every hop applies to terminal output.
//!
//! **Streams.** A terminal is reached over a command stream: `pty.open` starts one and keeps the
//! stream open; `pty.attach` reaches one already running (after a runner or Core restart, or
//! from a second stream); `pty.close` ends one. On an open or attach stream the runner sends
//! `control` `opened` first, then `output` (`out`), `control` `snapshot` when it cuts to a
//! fresh screen, and finally `result` (`exit`). The Core sends `output` (`in`), `control`
//! `resize` and `signal`, and `credit`. A `close` from the Core **detaches** (the terminal keeps
//! running); only `pty.close` or the child's own exit ends it.
//!
//! **`seq` of a terminal** is a byte offset into its output since it started, not a frame
//! count: `opened.seq` and `snapshot.seq` say which output byte comes next, and `pty.attach`
//! resumes at one. A resume point the runner no longer holds gets a `snapshot` first.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The driver and its ops.
pub const DRIVER_PTY: &str = "pty";
pub const OP_PTY_OPEN: &str = "pty.open";
pub const OP_PTY_ATTACH: &str = "pty.attach";
pub const OP_PTY_CLOSE: &str = "pty.close";
/// `pty.tail`: the last rows of a terminal's screen as text; read-only, no attach.
pub const OP_PTY_TAIL: &str = "pty.tail";

/// The largest `rows` and `cols` a terminal takes.
pub const MAX_DIM: u16 = 1000;

/// The signals a client may send by name (without `SIG`). Anything else is `invalid_args`.
pub const SIGNALS: &[&str] = &[
    "HUP", "INT", "QUIT", "TERM", "KILL", "USR1", "USR2", "CONT", "STOP", "TSTP", "WINCH",
];

/// `pty.open`: a login shell, or `program args…`, in a new PTY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyOpen {
    /// Absent: the user's login shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// An absolute directory; absent, the user's home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The AI session (`as_…`) whose folder `cwd` is, set only by the Core when a client opens a
    /// terminal for a session. The runner starts the shell only when `cwd` is the folder it
    /// recorded for that session (else `invalid_args`), and its terminal sandbox then lets the
    /// shell reach that one folder although it lies in the runner's hidden state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Set in the child as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Names of the runner's own variables to pass on; only those on its allow-list are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_pass: Vec<String>,
    pub size: Size,
    /// This stream only watches for the exit (the Core's monitor): it is not a client, so it
    /// does not protect the terminal's scrollback from the disk budget.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub watch: bool,
    /// The disk cap for this terminal's scrollback; the runner clamps it to its bounds.
    /// Absent: the runner's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrollback_bytes: Option<u64>,
    /// The runner's total scrollback disk budget (E2-06.2), applied by LRU across its
    /// terminals; the runner clamps it. Absent: unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrollback_budget: Option<u64>,
    /// An interactive SSH terminal (Leyline): the runner starts its own `ssh-pty` as the terminal's
    /// program, handing it the redeemed keys over an inherited pipe. Then `program`, `args`,
    /// `cwd`, `session`, `env` and `env_pass` must be empty (`invalid_args`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<super::SshTerminal>,
    /// Where the shell lives (D-17): `home`, `project:<id>`, `session:<id>` or `real`; see
    /// [`SandboxMode`]. Absent: the runner-wide sandbox of before this field (an older Core), a
    /// `real` shell. Needs `sandbox_user` unless `real`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    /// The Core user whose persistent sandbox home the shell gets (`[a-z0-9_-]{1,32}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_user: Option<String>,
}

/// The parsed [`PtyOpen::sandbox`]. Schema compatibility: both fields are optional and skipped
/// when absent, so an old Core's `pty.open` still parses on a new runner (legacy behaviour) and a
/// new Core's on an old runner (unknown fields are ignored, so it would run the legacy sandbox:
/// the Core therefore only sends them to a runner that advertises `pty.sandbox`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxMode {
    /// A private root with only the user's persistent sandbox home writable.
    Home,
    /// `Home` plus the project's folder (`cwd`, resolved and authorized by the Core).
    Project(String),
    /// `Home` plus the AI session's folder (`cwd`, which the runner checks against its record).
    Session(String),
    /// The runner's own host view (state hidden): only for this Mac's own terminal.
    Real,
}

impl SandboxMode {
    /// The id after `kind:` is `[A-Za-z0-9_-]{1,64}`: no path or option characters.
    pub fn parse(s: &str) -> Result<Self, String> {
        let id = |v: &str| {
            let ok = (1..=64).contains(&v.len())
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
            ok.then(|| v.to_owned())
                .ok_or_else(|| format!("{s:?}: bad id in sandbox"))
        };
        match s.split_once(':') {
            None if s == "home" => Ok(Self::Home),
            None if s == "real" => Ok(Self::Real),
            Some(("project", v)) => Ok(Self::Project(id(v)?)),
            Some(("session", v)) => Ok(Self::Session(id(v)?)),
            _ => Err(format!(
                "sandbox must be home, project:<id>, session:<id> or real, not {s:?}"
            )),
        }
    }
}

/// The accounts a sandbox home may be named for: `[a-z0-9_-]{1,32}`, so it cannot be a path.
pub fn valid_sandbox_user(u: &str) -> bool {
    (1..=32).contains(&u.len())
        && u.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// The bounds the runner clamps a terminal's scrollback cap and its disk budget to; the
/// Core's settings (`terminal.scrollback_bytes`, `terminal.scrollback_budget_bytes`) use the
/// same ones.
pub const SCROLLBACK_BYTES: (u64, u64, u64) = (256 << 10, 64 << 20, 8 << 20);
pub const SCROLLBACK_BUDGET: (u64, u64, u64) = (1 << 20, 64 << 30, 256 << 20);

/// `pty.attach`: reach a running terminal and resume its output at `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyAttach {
    pub terminal: String,
    /// The next output byte the attacher wants; older than the runner keeps gets a snapshot.
    #[serde(default)]
    pub seq: u64,
    /// Only watches for the exit (the Core's monitor), not a client; see [`PtyOpen::watch`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub watch: bool,
}

/// `pty.close`: hang the terminal up (HUP, then TERM, then KILL) and answer its exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyClose {
    pub terminal: String,
}

/// `pty.tail`: the last `lines` (1 to 20) non-empty rows of the terminal's screen, as plain text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyTail {
    pub terminal: String,
    pub lines: u16,
}

/// The answer to [`PtyTail`]: rows oldest first, each at most 400 characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TerminalTail {
    pub lines: Vec<String>,
}

/// A terminal's size in cells; `control` `resize` carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    /// Both in `1..=MAX_DIM`.
    pub fn valid(self) -> bool {
        (1..=MAX_DIM).contains(&self.rows) && (1..=MAX_DIM).contains(&self.cols)
    }
}

/// `control` `signal`: deliver one of [`SIGNALS`] to the terminal's process group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignalReq {
    pub signal: String,
}

/// `control` `snapshot`: the visible screen as bytes a terminal view replays (standard
/// base64), after which output resumes at `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Snapshot {
    pub seq: u64,
    pub data: String,
}

/// A terminal as its runner sees it: `control` `opened`, and each entry of
/// `RunnerHello::terminals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TerminalInfo {
    /// `t_…`, chosen by the runner.
    pub terminal: String,
    pub state: TerminalState,
    pub size: Size,
    /// Output bytes so far: the next byte's offset.
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Set once the child exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<TerminalExit>,
}

/// The `signal` of a `TerminalExit` the runner could not read from the host: the `ainkrad-ptyhost`
/// process died (`kill -9`, a crash) so nobody waited for the child. The terminal is over.
pub const SIGNAL_HOST_LOST: &str = "host_lost";

/// How a terminal's child ended: the `result` of every `pty.*` op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TerminalExit {
    pub terminal: String,
    /// Absent when it was ended by a signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// The signal's description, when one ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    /// An interactive SSH terminal that never reached a shell because a hop's host key was not
    /// trusted (exit code `SSH_PTY_EXIT_HOST_KEY_UNKNOWN` or `_CHANGED`): which hop, and the key it
    /// presented. Reported by `ssh-pty` itself over a private descriptor, never read from the
    /// terminal's output, which a remote shell controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<super::HostKeyEvidence>,
}

/// A terminal's lifecycle (E2-01.1): created → running → exited → reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    /// Asked for; the child is not running yet.
    Created,
    Running,
    /// The child ended (it is waited for); its exit is not read yet.
    Exited,
    /// A client read the exit: the host is gone and the id is free.
    Reaped,
    /// A state from a newer peer.
    #[serde(other)]
    Unknown,
}

/// What moves a terminal along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// The child started.
    Spawned,
    /// It could not be started (counts as an exit).
    SpawnFailed,
    /// The child ended and was waited for.
    ChildExited,
    /// A client read the exit.
    ExitRead,
}

impl TerminalState {
    /// The state after `event`, or `None` when the event cannot happen in this state.
    pub fn next(self, event: Lifecycle) -> Option<Self> {
        use Lifecycle::*;
        use TerminalState::*;
        match (self, event) {
            (Created, Spawned) => Some(Running),
            (Created, SpawnFailed) | (Running, ChildExited) => Some(Exited),
            (Exited, ExitRead) => Some(Reaped),
            _ => None,
        }
    }
}

/// Output frames are coalesced for at most this long (P2.6).
pub const COALESCE: Duration = Duration::from_millis(16);
/// The most bytes one `output` frame carries.
pub const MAX_CHUNK: usize = 32 * 1024;

/// What an [`Outflow`] asks its owner to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emit {
    /// Send these bytes as one `output` frame; they used up as much credit.
    Out(Vec<u8>),
    /// The reader fell too far behind and the backlog was dropped: send a fresh `snapshot`
    /// and carry on from its `seq` (drop-to-snapshot).
    Resync,
}

/// The flow-control rules for one terminal's output on one hop (E2-01.4), with time passed in:
///
/// - **Credit window.** The sender starts with `window` bytes; a `credit` from the reader adds
///   to it. Output past the credit is never sent (the hub fails a stream that overruns).
/// - **Coalescing.** Bytes wait up to [`COALESCE`] for more, unless [`MAX_CHUNK`] is reached,
///   so a chatty program costs one frame per 16 ms, not one per write.
/// - **Drop-to-snapshot.** Unsent bytes are capped at `backlog`; past it they are dropped and
///   [`Emit::Resync`] is returned once. A slow reader costs a snapshot, never unbounded memory,
///   and never slows the producer.
/// - **A snapshot costs credit too** (review M2): it is sent only while credit is above zero
///   and takes its decoded length off it, down to zero at most (one snapshot may overdraw the
///   window, so a screen larger than the window still goes). The receiver grants it back as
///   it reads, like output. Both ends apply [`Outflow::spend`]'s rule.
#[derive(Debug)]
pub struct Outflow {
    credit: u64,
    backlog: usize,
    pending: Vec<u8>,
    since: Option<Instant>,
    behind: bool,
}

impl Outflow {
    pub fn new(window: u64, backlog: usize) -> Self {
        Self {
            credit: window,
            backlog,
            pending: Vec::new(),
            since: None,
            behind: false,
        }
    }

    /// Bytes from the producer.
    pub fn push(&mut self, bytes: &[u8], now: Instant) {
        if self.behind {
            return;
        }
        if self.pending.len() + bytes.len() > self.backlog {
            self.pending = Vec::new();
            self.since = None;
            self.behind = true;
            return;
        }
        self.since.get_or_insert(now);
        self.pending.extend_from_slice(bytes);
    }

    /// A snapshot of `bytes` went: credit drops by as much, to zero at most.
    pub fn spend(&mut self, bytes: u64) {
        self.credit = self.credit.saturating_sub(bytes);
    }

    /// Drops what waits and asks for a snapshot (`Resync`), as if the reader fell behind.
    pub fn cut(&mut self) {
        self.pending = Vec::new();
        self.since = None;
        self.behind = true;
    }

    /// The reader allows `bytes` more.
    pub fn grant(&mut self, bytes: u64) {
        self.credit = self.credit.saturating_add(bytes);
    }

    /// The owner sent the snapshot asked for by `Resync`: output flows again.
    pub fn resynced(&mut self) {
        self.behind = false;
    }

    /// Whether a `Resync` is outstanding (output is dropped until `resynced`).
    pub fn behind(&self) -> bool {
        self.behind
    }

    /// Bytes waiting (bounded by `backlog`).
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    pub fn credit(&self) -> u64 {
        self.credit
    }

    /// What to send now, if anything.
    pub fn poll(&mut self, now: Instant) -> Option<Emit> {
        if self.behind {
            return Some(Emit::Resync);
        }
        let since = self.since?;
        let due = now.duration_since(since) >= COALESCE || self.pending.len() >= MAX_CHUNK;
        if !due || self.credit == 0 {
            return None;
        }
        let n = self
            .pending
            .len()
            .min(MAX_CHUNK)
            .min(usize::try_from(self.credit).unwrap_or(usize::MAX));
        let out: Vec<u8> = self.pending.drain(..n).collect();
        self.credit -= n as u64;
        self.since = (!self.pending.is_empty()).then_some(now);
        Some(Emit::Out(out))
    }

    /// When to poll next: the end of the coalescing window, if bytes wait and credit lets them
    /// go (with none, only a `grant` can change anything; a past deadline would busy-loop).
    pub fn deadline(&self) -> Option<Instant> {
        self.since.filter(|_| self.credit > 0).map(|s| s + COALESCE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lifecycle_table() {
        use Lifecycle::*;
        use TerminalState::*;
        let all = [Spawned, SpawnFailed, ChildExited, ExitRead];
        let table: &[(TerminalState, &[(Lifecycle, TerminalState)])] = &[
            (Created, &[(Spawned, Running), (SpawnFailed, Exited)]),
            (Running, &[(ChildExited, Exited)]),
            (Exited, &[(ExitRead, Reaped)]),
            (Reaped, &[]),
            (Unknown, &[]),
        ];
        for (from, allowed) in table {
            for e in all {
                let want = allowed.iter().find(|(a, _)| *a == e).map(|(_, to)| *to);
                assert_eq!(from.next(e), want, "{from:?} + {e:?}");
            }
        }
    }

    #[test]
    fn sizes_and_signals() {
        assert!(Size { rows: 24, cols: 80 }.valid());
        assert!(!Size { rows: 0, cols: 80 }.valid());
        assert!(
            !Size {
                rows: 24,
                cols: MAX_DIM + 1
            }
            .valid()
        );
        assert!(SIGNALS.contains(&"WINCH") && !SIGNALS.contains(&"SIGTERM"));
    }

    #[test]
    fn output_waits_for_the_window_then_goes_in_one_frame() {
        let t0 = Instant::now();
        let mut f = Outflow::new(1024, 4096);
        f.push(b"ab", t0);
        f.push(b"cd", t0 + Duration::from_millis(5));
        assert_eq!(f.poll(t0 + Duration::from_millis(10)), None, "coalescing");
        assert_eq!(f.deadline(), Some(t0 + COALESCE));
        assert_eq!(f.poll(t0 + COALESCE), Some(Emit::Out(b"abcd".to_vec())));
        assert_eq!(f.poll(t0 + COALESCE * 2), None);
        assert_eq!(f.credit(), 1020);
    }

    #[test]
    fn a_full_chunk_goes_at_once_and_credit_caps_it() {
        let t0 = Instant::now();
        let mut f = Outflow::new(MAX_CHUNK as u64 + 10, 4 * MAX_CHUNK);
        f.push(&vec![1; MAX_CHUNK + 100], t0);
        let Some(Emit::Out(a)) = f.poll(t0) else {
            panic!()
        };
        assert_eq!(a.len(), MAX_CHUNK);
        let Some(Emit::Out(b)) = f.poll(t0 + COALESCE) else {
            panic!()
        };
        assert_eq!(b.len(), 10, "only the credit left");
        assert_eq!(f.poll(t0 + COALESCE * 2), None, "no credit");
        assert_eq!(f.deadline(), None, "no credit, nothing to wake for");
        f.grant(1000);
        assert_eq!(f.poll(t0 + COALESCE * 2), Some(Emit::Out(vec![1; 90])));
    }

    /// E2-01.4's simulator: a producer at 10 MB/s, a reader granting 64 KiB per 100 ms. The
    /// backlog never passes its cap, nothing past the credit is sent, the reader is resynced
    /// instead of stalling the producer, and output resumes after each snapshot.
    #[test]
    fn a_slow_reader_costs_a_snapshot_not_memory() {
        let backlog = 256 * 1024;
        let mut f = Outflow::new(64 * 1024, backlog);
        let (mut granted, mut sent, mut resyncs) = (64 * 1024u64, 0u64, 0);
        let t0 = Instant::now();
        for ms in 0..10_000u64 {
            let now = t0 + Duration::from_millis(ms);
            f.push(&[7; 10_000], now);
            assert!(f.pending() <= backlog);
            while let Some(e) = f.poll(now) {
                match e {
                    Emit::Out(b) => sent += b.len() as u64,
                    Emit::Resync => {
                        resyncs += 1;
                        f.resynced();
                    }
                }
            }
            if ms % 100 == 0 {
                f.grant(64 * 1024);
                granted += 64 * 1024;
            }
        }
        assert!(sent <= granted, "{sent} > {granted}");
        assert!(sent > granted / 2, "output keeps flowing: {sent}");
        assert!(resyncs > 10, "{resyncs}");
    }
}

#[cfg(test)]
mod sandbox_tests {
    use super::*;

    #[test]
    fn a_sandbox_mode_is_one_of_four_and_its_id_cannot_be_a_path() {
        assert_eq!(SandboxMode::parse("home"), Ok(SandboxMode::Home));
        assert_eq!(SandboxMode::parse("real"), Ok(SandboxMode::Real));
        assert_eq!(
            SandboxMode::parse("project:p_1"),
            Ok(SandboxMode::Project("p_1".into()))
        );
        assert_eq!(
            SandboxMode::parse("session:as_ab-c"),
            Ok(SandboxMode::Session("as_ab-c".into()))
        );
        for bad in [
            "",
            "Home",
            "home:x",
            "real:1",
            "project",
            "project:",
            "project:../x",
            "session:a b",
            "session:a/b",
            "other:x",
            "project:p:q",
        ] {
            assert!(SandboxMode::parse(bad).is_err(), "{bad:?}");
        }
        assert!(SandboxMode::parse(&format!("project:{}", "a".repeat(65))).is_err());
        for bad in ["", "..", "a/b", "A", "a b", &"a".repeat(33)] {
            assert!(!valid_sandbox_user(bad), "{bad:?}");
        }
        assert!(valid_sandbox_user("u-1_x"));
    }

    /// An older Core's `pty.open` (no sandbox fields) still parses, and serialises without them.
    #[test]
    fn the_new_fields_are_optional_on_the_wire() {
        let o: PtyOpen = serde_json::from_str(r#"{"size":{"rows":24,"cols":80}}"#).unwrap();
        assert!(o.sandbox.is_none() && o.sandbox_user.is_none());
        let j = serde_json::to_string(&o).unwrap();
        assert!(!j.contains("sandbox"), "{j}");
    }
}
