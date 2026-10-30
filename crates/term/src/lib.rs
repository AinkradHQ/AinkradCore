//! Terminal screen state for reattach (E2-04): a headless VT emulator, bounded scrollback, screen
//! snapshots and diffs, and a `seq`-addressed replay window. A pure library: no I/O, no threads,
//! no `unsafe`. The PTY host (`ainkrad-ptyhost`, E2-03) owns one [`Terminal`] per session and
//! drives it through [`ScreenSink`]; persisting the replay window to disk (`0600`) is the host's
//! job, not this crate's.
//!
//! # `seq`
//!
//! `seq` is the **byte offset of the session's output stream**: the first byte the child ever
//! wrote is `seq` 0, and [`ScreenSink::feed`] returns the new head (the count of bytes fed so far).
//! An `out` frame carrying bytes `[a, b)` is "at `seq` a". A client remembers the head it has
//! applied and reattaches with it.
//!
//! # Reattach
//!
//! [`ScreenSink::attach`] with the client's last `seq`:
//! - inside the replay window (default 8 MiB) → [`Attach::Replay`]: the missing bytes, no gap;
//! - older than the window, or no `seq` (a new client) → [`Attach::Snapshot`]: escape sequences
//!   that rebuild the screen (scrollback, primary screen, alt-screen, pen, cursor, input modes)
//!   in any VT100/xterm view. The client sets its size to [`Snapshot::size`] first, resets its
//!   view, writes [`Snapshot::bytes`], then applies `out` frames from [`Snapshot::seq`] on;
//! - newer than the head → [`SeqAhead`]: the client is talking about another stream.
//!
//! Drop-to-snapshot for a slow client is the same call: when the bytes it is owed fall out of the
//! window, `attach` returns a snapshot. For a client that only lags a little, keep a
//! [`ScreenState`] of what it was last sent and send [`ScreenSink::diff`] instead of the backlog.
//!
//! # Scrollback
//!
//! Rows scrolled off the top of the primary screen are kept as rendered lines (SGR colours kept),
//! bounded by [`Limits::scrollback_lines`] **and** [`Limits::scrollback_bytes`]. Lines are numbered
//! from 0 for the session's first line and never renumbered; [`Lines::held`] says which are still
//! kept, so truncation is explicit. Alt-screen apps (vim, htop, tmux) do not add scrollback.
//!
//! # Known gaps (emulator state a snapshot does not carry)
//!
//! The scroll region (DECSTBM), origin mode, tab stops, the window
//! title and character sets are not restored, and the emulator ignores `CSI s`/`CSI u` (the
//! SCO cursor save; `ESC 7`/`ESC 8` work); full-screen apps re-emit them on their next
//! redraw, so the host should send the child a `SIGWINCH` after a snapshot attach. A width change
//! truncates or pads rows (no reflow), matching the SwiftTerm `ainkrad-no-reflow` client.
//! When the cursor waits past the last column of a row whose last cell was then erased, the
//! emulator's serialiser rebuilds that state with `ESC 7`/`ESC 8`, which overwrites the DECSC
//! slot restored before it (the slot then holds the cursor position).

mod boundary;
mod replay;

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::num::NonZeroU16;
use std::ops::Range;

use boundary::Scan;
use replay::Ring;

/// Byte offset into a session's output stream (see the crate docs).
pub type Seq = u64;

/// The largest screen accepted; bigger sizes are clamped (a size comes from an untrusted client).
pub const MAX_ROWS: u16 = 400;
/// See [`MAX_ROWS`].
pub const MAX_COLS: u16 = 800;

/// Bytes of an unfinished escape sequence held back before the emulator gets them anyway (a long
/// OSC, e.g. a clipboard write, must not grow without bound).
const MAX_PENDING: usize = 64 * 1024;

/// Screen size in character cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    /// Clamped to `1..=MAX_ROWS` × `1..=MAX_COLS`.
    pub fn clamped(self) -> Self {
        Self {
            rows: self.rows.clamp(1, MAX_ROWS),
            cols: self.cols.clamp(1, MAX_COLS),
        }
    }

    fn nonzero(self) -> (NonZeroU16, NonZeroU16) {
        let s = self.clamped();
        (
            NonZeroU16::MIN.saturating_add(s.rows - 1),
            NonZeroU16::MIN.saturating_add(s.cols - 1),
        )
    }
}

/// Per-session memory bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Scrollback lines kept (oldest dropped first).
    pub scrollback_lines: usize,
    /// Scrollback bytes kept, counting each line's rendered form.
    pub scrollback_bytes: usize,
    /// Raw output bytes kept for [`Attach::Replay`] (P2.4: 8 MiB).
    pub replay_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scrollback_lines: 10_000,
            scrollback_bytes: 4 << 20,
            replay_bytes: 8 << 20,
        }
    }
}

/// Escape sequences that rebuild a terminal's state in a fresh view (see the crate docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The stream position the snapshot reflects; `out` frames continue from here.
    pub seq: Seq,
    /// Size the client must have before replaying `bytes`.
    pub size: Size,
    /// Whether an alt-screen app (vim, htop, tmux) is in front.
    pub alt_screen: bool,
    /// Scrollback lines included, by line number (empty when none were asked for or kept).
    pub scrollback: Range<u64>,
    /// Starts with a reset (`ESC c`); UTF-8 text and VT100/xterm escape sequences only. A
    /// scrollback line wider than the current width (the screen was narrowed) wraps in the client.
    pub bytes: Vec<u8>,
}

/// Scrollback lines, as returned by [`ScreenSink::scrollback`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lines {
    /// Line number of `lines[0]`.
    pub first: u64,
    /// Rendered lines (text plus SGR, each ending in `ESC [m`), no line terminators.
    pub lines: Vec<String>,
    /// Line numbers still kept; everything below `held.start` was dropped by the limits.
    pub held: Range<u64>,
}

/// What a (re)attaching client gets first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attach {
    /// The output bytes from `from` to the head; the client's screen continues without a gap.
    Replay { from: Seq, bytes: Vec<u8> },
    /// The client's `seq` fell out of the replay window (or it had none): rebuild from this.
    Snapshot(Snapshot),
}

/// A resume `seq` beyond the head: the client holds bytes this session never produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqAhead {
    pub requested: Seq,
    pub head: Seq,
}

/// The visible screen at one `seq`, kept per client to send it a [`ScreenSink::diff`].
#[derive(Clone, Debug)]
pub struct ScreenState {
    seq: Seq,
    screen: vt100::Screen,
}

impl ScreenState {
    pub fn seq(&self) -> Seq {
        self.seq
    }
}

/// What the PTY host needs from the screen side of a terminal session. [`Terminal`] is the
/// implementation; the trait is the integration seam for the host (E2-03) and the Core (E2-05).
///
/// Every method is cheap except `snapshot` (renders the screen and the requested scrollback;
/// ~30 µs at 80×24, ~160 µs at 200×50 without scrollback) and `state` (clones the visible screen).
pub trait ScreenSink {
    /// Takes the next output bytes of the child, in order, in any chunking (a chunk may end
    /// mid-sequence or mid-character). Returns the new head `seq`.
    fn feed(&mut self, bytes: &[u8]) -> Seq;
    /// The PTY was resized (clamped to [`MAX_ROWS`] × [`MAX_COLS`]). Call it whether or not a
    /// client is attached; the next snapshot has the new size.
    fn resize(&mut self, size: Size);
    /// Current size.
    fn size(&self) -> Size;
    /// The head: bytes fed so far.
    fn head(&self) -> Seq;
    /// The `seq` range [`Attach::Replay`] can serve.
    fn replay_window(&self) -> Range<Seq>;
    /// A snapshot including up to `scrollback_lines` of the newest scrollback.
    fn snapshot(&self, scrollback_lines: usize) -> Snapshot;
    /// Scrollback lines in `range` (line numbers), clipped to what is held.
    fn scrollback(&self, range: Range<u64>) -> Lines;
    /// What to send a client resuming at `resume` (`None`: a new client). A snapshot includes up
    /// to `scrollback_lines` of scrollback.
    fn attach(&self, resume: Option<Seq>, scrollback_lines: usize) -> Result<Attach, SeqAhead>;
    /// The visible screen now, to diff against later.
    fn state(&self) -> ScreenState;
    /// Escape sequences that turn a client showing `from` into the visible screen now; `out`
    /// frames then continue from the returned `Seq`. Rows that scrolled off in between are not added to the client's scrollback. When
    /// the size or the alt-screen changed it is a full repaint (a snapshot without scrollback).
    fn diff(&self, from: &ScreenState) -> (Seq, Vec<u8>);
}

/// Rows scrolled off the primary screen, rendered, bounded by lines and bytes.
#[derive(Debug)]
struct History {
    lines: VecDeque<String>,
    bytes: usize,
    dropped: u64,
    max_lines: usize,
    max_bytes: usize,
}

impl vt100::Callbacks for History {
    fn on_scroll(&mut self, row: vt100::capture::RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        let mut line = String::new();
        // Writing into a String cannot fail.
        let _ = row.write_formatted_basic(&mut line, &mut Default::default());
        line.push_str("\x1b[m");
        self.bytes += line.len();
        self.lines.push_back(line);
        while self.lines.len() > self.max_lines || self.bytes > self.max_bytes {
            let Some(old) = self.lines.pop_front() else {
                break;
            };
            self.bytes -= old.len();
            self.dropped += 1;
        }
    }
}

impl History {
    fn held(&self) -> Range<u64> {
        self.dropped..self.dropped + self.lines.len() as u64
    }
}

/// One terminal session's screen side. See the crate docs.
pub struct Terminal {
    parser: vt100::Parser<History>,
    ring: Ring,
    /// The tail of the stream after the last ground-state point, not yet given to the emulator.
    pending: Vec<u8>,
    scan: Scan,
}

impl Terminal {
    pub fn new(size: Size, limits: Limits) -> Self {
        let (rows, cols) = size.nonzero();
        let history = History {
            lines: VecDeque::new(),
            bytes: 0,
            dropped: 0,
            max_lines: limits.scrollback_lines,
            max_bytes: limits.scrollback_bytes,
        };
        // Scrollback lives in `History` (≈ 100 B/line) rather than in the emulator's cell grid
        // (≈ 2.5 KB/line at 80 columns), so the emulator keeps none.
        Self {
            parser: vt100::Parser::new_with_callbacks(rows, cols, 0, history),
            ring: Ring::new(limits.replay_bytes),
            pending: Vec::new(),
            scan: Scan::Ground,
        }
    }

    /// The `seq` the emulator's state reflects (the head minus a held-back partial sequence).
    fn applied(&self) -> Seq {
        self.ring.window().end - self.pending.len() as Seq
    }

    fn history(&self) -> &History {
        self.parser.callbacks()
    }

    /// Both screens and the modes as formatted escape sequences, after `ESC c`; scrollback not
    /// included. The primary screen is drawn, then the alt-screen is entered with `?47h` (it
    /// saves and clears nothing) and drawn, then left again unless it is in front: each screen
    /// keeps its own cursor, DECSC slot and contents (`?47h` shows an old alt-screen again), so
    /// whichever way the app switches screens later, the client does what the host does.
    fn render_screen(&self, out: &mut String) {
        let screen = self.parser.screen();
        let alt = screen.alternate_screen();
        let (primary, alternate) = if alt {
            (primary(screen), screen.clone())
        } else {
            (screen.clone(), after(screen, b"\x1b[?47h"))
        };
        out.push_str(&saved_cursor(&primary));
        out.push_str(&primary.contents_formatted());
        out.push_str("\x1b[?47h");
        out.push_str(&saved_cursor(&alternate));
        out.push_str(&alternate.contents_formatted());
        if !alt {
            out.push_str("\x1b[?47l");
        }
        out.push_str(&screen.input_mode_formatted());
    }

    /// A stable text form of the state (size, cursor, modes, kept scrollback, visible rows with
    /// SGR shown as `\e`), for goldens and debugging. It leaves out `seq` and dropped-line counts,
    /// so a terminal rebuilt from a snapshot dumps the same as the original.
    pub fn dump(&self) -> String {
        let s = self.parser.screen();
        let (row, col) = s.cursor_position();
        let (rows, cols) = s.size();
        let esc = |t: &str| t.replace('\x1b', "\\e");
        let mut out = String::new();
        let _ = writeln!(
            out,
            "size {rows}x{cols} alt={} cursor={row},{col} hidden={} modes={}",
            s.alternate_screen(),
            s.hide_cursor(),
            esc(&s.input_mode_formatted()),
        );
        let _ = writeln!(out, "pen {}", esc(&s.attributes_formatted()));
        let _ = writeln!(out, "-- scrollback {}", self.history().lines.len());
        for l in &self.history().lines {
            let _ = writeln!(out, "{}", esc(l));
        }
        if s.alternate_screen() {
            let p = primary(s);
            let (row, col) = p.cursor_position();
            let _ = writeln!(
                out,
                "-- primary screen, under the alt-screen: cursor={row},{col}"
            );
            for r in p.rows_formatted(0, cols.get()) {
                let _ = writeln!(out, "|{}", esc(&r));
            }
        }
        let _ = writeln!(out, "-- screen");
        for r in s.rows_formatted(0, cols.get()) {
            let _ = writeln!(out, "|{}", esc(&r));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Attach, Limits, ScreenSink, Size, Terminal};

    #[test]
    fn replay_and_scrollback_are_bounded_per_terminal() {
        let mut term = Terminal::new(
            Size { rows: 2, cols: 8 },
            Limits {
                scrollback_lines: 2,
                scrollback_bytes: 32,
                replay_bytes: 8,
            },
        );
        term.feed(b"one\ntwo\nthree\nfour\n");
        assert!(term.replay_window().end - term.replay_window().start <= 8);
        let lines = term.scrollback(0..u64::MAX);
        assert!(lines.lines.len() <= 2);
        assert!(lines.lines.iter().map(String::len).sum::<usize>() <= 32);
        assert!(matches!(term.attach(Some(0), 2), Ok(Attach::Snapshot(_))));
    }

    #[test]
    fn stale_attach_snapshot_restores_alternate_screen() {
        let mut term = Terminal::new(Size { rows: 3, cols: 10 }, Limits::default());
        term.feed(b"\x1b[?1049hALT\x1b[2;1Hscreen");
        let Attach::Snapshot(snapshot) = term.attach(None, 0).unwrap() else {
            panic!("new attach must receive a snapshot")
        };
        assert!(snapshot.alt_screen);
        assert!(snapshot.bytes.windows(3).any(|w| w == b"ALT"));
    }
}

/// The primary screen while an alt-screen app is in front (the emulator only exposes the active
/// one): a copy with the alt-screen left by `?47l`, which keeps each screen's own cursor.
fn primary(screen: &vt100::Screen) -> vt100::Screen {
    after(screen, b"\x1b[?47l")
}

/// Sequences that put the active screen's DECSC slot (cursor and pen) into the client's: the slot
/// is read by restoring it in a copy, then written with `ESC 7`. The screen drawn after this
/// repositions the cursor and resets the pen.
fn saved_cursor(screen: &vt100::Screen) -> String {
    let saved = after(screen, b"\x1b8");
    let (row, col) = saved.cursor_position();
    let cols = saved.size().1.get();
    let pen = saved.attributes_formatted();
    if col >= cols {
        // Saved in the pending-wrap state (past the last column): a cursor move cannot reach it,
        // printing into the last column does (the repaint that follows overwrites the space).
        return format!("\x1b[{};{cols}H{pen} \x1b7", row + 1);
    }
    format!("\x1b[{};{}H{pen}\x1b7", row + 1, col + 1)
}

/// A copy of `screen` after `bytes` (the emulator exposes only parts of its state directly).
fn after(screen: &vt100::Screen, bytes: &[u8]) -> vt100::Screen {
    let (rows, cols) = screen.size();
    let mut p = vt100::Parser::new(rows, cols, 0);
    *p.screen_mut() = screen.clone();
    p.process(bytes);
    p.screen().clone()
}

impl ScreenSink for Terminal {
    fn feed(&mut self, bytes: &[u8]) -> Seq {
        self.ring.push(bytes);
        let (scan, ground) = self.scan.advance(bytes);
        self.scan = scan;
        let ready = if ground > 0 {
            self.pending.len() + ground
        } else {
            0
        };
        self.pending.extend_from_slice(bytes);
        let ready = if self.pending.len() > MAX_PENDING {
            self.pending.len()
        } else {
            ready
        };
        if ready > 0 {
            self.parser.process(&self.pending[..ready]);
            self.pending.drain(..ready);
        }
        self.head()
    }

    fn resize(&mut self, size: Size) {
        let (rows, cols) = size.nonzero();
        self.parser.set_size(rows, cols);
    }

    fn size(&self) -> Size {
        let (rows, cols) = self.parser.screen().size();
        Size {
            rows: rows.get(),
            cols: cols.get(),
        }
    }

    fn head(&self) -> Seq {
        self.ring.window().end
    }

    fn replay_window(&self) -> Range<Seq> {
        self.ring.window()
    }

    fn snapshot(&self, scrollback_lines: usize) -> Snapshot {
        let size = self.size();
        let h = self.history();
        let take = scrollback_lines.min(h.lines.len());
        let mut out = String::from("\x1bc");
        for line in h.lines.range(h.lines.len() - take..) {
            out.push_str(line);
            out.push_str("\r\n");
        }
        if take > 0 {
            // Scroll every written line off the screen and into the view's own scrollback: the
            // cursor is on row min(take, rows-1), so rows-1 more line feeds push exactly `take`.
            out.extend(std::iter::repeat_n('\n', usize::from(size.rows) - 1));
        }
        self.render_screen(&mut out);
        Snapshot {
            seq: self.applied(),
            size,
            alt_screen: self.parser.screen().alternate_screen(),
            scrollback: h.held().end - take as u64..h.held().end,
            bytes: out.into_bytes(),
        }
    }

    fn scrollback(&self, range: Range<u64>) -> Lines {
        let h = self.history();
        let held = h.held();
        let start = range.start.clamp(held.start, held.end);
        let end = range.end.clamp(start, held.end);
        let lines = h
            .lines
            .range((start - held.start) as usize..(end - held.start) as usize)
            .cloned()
            .collect();
        Lines {
            first: start,
            lines,
            held,
        }
    }

    fn attach(&self, resume: Option<Seq>, scrollback_lines: usize) -> Result<Attach, SeqAhead> {
        let head = self.head();
        match resume {
            Some(seq) if seq > head => Err(SeqAhead {
                requested: seq,
                head,
            }),
            Some(seq) => Ok(match self.ring.since(seq) {
                Some(bytes) => Attach::Replay { from: seq, bytes },
                None => Attach::Snapshot(self.snapshot(scrollback_lines)),
            }),
            None => Ok(Attach::Snapshot(self.snapshot(scrollback_lines))),
        }
    }

    fn state(&self) -> ScreenState {
        ScreenState {
            seq: self.applied(),
            screen: self.parser.screen().clone(),
        }
    }

    fn diff(&self, from: &ScreenState) -> (Seq, Vec<u8>) {
        let now = self.parser.screen();
        let prev = &from.screen;
        if now.size() != prev.size() || now.alternate_screen() != prev.alternate_screen() {
            let snap = self.snapshot(0);
            return (snap.seq, snap.bytes);
        }
        (self.applied(), now.state_diff(prev).into_bytes())
    }
}
