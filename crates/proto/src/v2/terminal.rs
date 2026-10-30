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
    /// Set in the child as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Names of the runner's own variables to pass on; only those on its allow-list are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_pass: Vec<String>,
    pub size: Size,
}

/// `pty.attach`: reach a running terminal and resume its output at `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyAttach {
    pub terminal: String,
    /// The next output byte the attacher wants; older than the runner keeps gets a snapshot.
    #[serde(default)]
    pub seq: u64,
}

/// `pty.close`: hang the terminal up (HUP, then TERM, then KILL) and answer its exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PtyClose {
    pub terminal: String,
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

    /// When to poll next: the end of the coalescing window, if bytes wait.
    pub fn deadline(&self) -> Option<Instant> {
        self.since.map(|s| s + COALESCE)
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
