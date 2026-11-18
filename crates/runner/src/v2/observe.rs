//! The runner's side of `run.observe` (P5-04): a bounded, redacted ring of each watched run's log
//! lines, and its services' latest metrics.
//!
//! Security model. A container's output is untrusted text and may hold a secret the run was
//! given. Every line is cleaned, then redacted, then cut, in that order, before it is kept:
//! [`sanitize`] drops terminal escapes (CSI, OSC), control and bidi characters and the Podman
//! stamps `podman logs --timestamps` puts inside a line joined from partial chunks (so nothing
//! can split a secret); `Redactor` masks the values of the leases this runner redeemed for the
//! run (learnt in `RunDriver::prepare`) and key shapes, and a PEM block is dropped whole across
//! lines; only then is the text cut to [`LOG_LINE_MAX`]. The helper reads a line through a raw
//! window of [`LOG_LINE_MAX`] plus the longest secret (`crate::run::observe::raw_window`).
//! Memory is bounded whatever the containers write: that window, [`RING_BYTES`] per run and
//! [`MAX_RUNS`] runs actually watched; a flood loses the oldest lines (`lost`), never memory. A
//! run is watched only while the Core keeps asking ([`IDLE`]); Podman keeps its own capped copy
//! of the log meanwhile. A run that was forgotten (stopped, lost) is refused, not re-created.
//!
//! Limits: a secret under 8 bytes is not known to the redactor; one rotated across a runner
//! restart is only masked by the Core's second pass; a multi-line secret that is not a PEM block
//! is masked line by line only if each line matches a key shape; a secret longer than the raw
//! window cap less [`LOG_LINE_MAX`] can be cut in the window.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{
    ErrorCode, LOG_LINE_MAX, LogLine, OBSERVE_LINES_MAX, RunObserve, RunObserveReq, ServiceMetrics,
    StreamError,
};

use crate::run::helper::{self, Request};
use crate::run::observe::{Observed, RawLine, raw_window, stamp_key};

/// What one run's ring holds, in bytes of text and bookkeeping.
pub const RING_BYTES: usize = 1 << 20;
const MAX_RUNS: usize = 8;
const POLL: Duration = Duration::from_secs(2);
/// Metrics every this many polls (a `podman stats` and an inspect cost more than the logs).
const METRICS_EVERY: u32 = 3;
/// A run nobody asked about for this long is not watched any more.
const IDLE: Duration = Duration::from_secs(30);

/// Per-line bookkeeping charged against the ring (the struct and the strings' headers).
const LINE_OVERHEAD: usize = 64;
/// The redactor ignores values shorter than this (`ainkrad_proto::redact`).
const MIN_KNOWN: usize = 8;
/// A secret's longest masked form (`\uXXXX` per character) in bytes per secret byte.
const ENCODED_MAX: usize = 6;
/// Forgotten run ids remembered; past it the list starts over (a run id is not reused anyway).
// ponytail: a plain cap; an LRU if forgetting ever outruns this between restarts.
const MAX_FORGOTTEN: usize = 4096;

/// The end of a Podman stamp (`2026-11-18T10:00:00.5+00:00 `, the space included) at the start of
/// `b`, if there is one. `podman logs --timestamps` prints one before every chunk of a line that
/// was written in parts (the `P` records of the log file), so a joined line holds them inside.
fn stamp_len(b: &[u8]) -> Option<usize> {
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    let date = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if !(date.iter().all(|i| d(*i))
        && at(4, b'-')
        && at(7, b'-')
        && at(10, b'T')
        && at(13, b':')
        && at(16, b':'))
    {
        return None;
    }
    let mut i = 19;
    if at(i, b'.') {
        i += 1;
        let from = i;
        while d(i) {
            i += 1;
        }
        if i == from {
            return None;
        }
    }
    if at(i, b'Z') {
        i += 1;
    } else if (at(i, b'+') || at(i, b'-'))
        && d(i + 1)
        && d(i + 2)
        && at(i + 3, b':')
        && d(i + 4)
        && d(i + 5)
    {
        i += 6;
    } else {
        return None;
    }
    Some(i + usize::from(at(i, b' ')))
}

/// `raw` as plain text: no terminal escape sequences (CSI, OSC and the other string escapes), no
/// control characters (C0, DEL, C1; a tab stays), no bidi controls, and no Podman stamp inside
/// the line. Done before redaction, so none of it can break up a secret, and before the ring, so a
/// viewer's terminal or page cannot be driven by what a container prints.
pub fn sanitize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let b = raw.as_bytes();
    let mut chars = raw.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c.is_ascii_digit()
            && let Some(n) = stamp_len(&b[i..])
        {
            // All ASCII, so `i + n` is a boundary; skip what the stamp covered.
            while chars.peek().is_some_and(|(j, _)| *j < i + n) {
                chars.next();
            }
            continue;
        }
        match c {
            '\x1b' => match chars.peek().map(|(_, n)| *n) {
                Some('[') => {
                    chars.next();
                    skip_csi(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string(&mut chars);
                }
                // Any other escape: the ESC goes, the character after it stays text.
                _ => {}
            },
            '\u{9b}' => skip_csi(&mut chars),
            '\u{9d}' | '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}' => skip_string(&mut chars),
            '\t' => out.push(c),
            c if c.is_control() => {}
            '\u{61c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Past the parameters and intermediates of a CSI, and its final byte (0x40-0x7e).
fn skip_csi(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) {
    for (_, c) in chars {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            return;
        }
    }
}

/// Past a string escape (OSC and its kin): to BEL, ST (`ESC \` or U+009C) or the end of the line.
fn skip_string(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) {
    while let Some((_, c)) = chars.next() {
        match c {
            '\u{7}' | '\u{9c}' => return,
            '\x1b' if chars.peek().is_some_and(|(_, n)| *n == '\\') => {
                chars.next();
                return;
            }
            _ => {}
        }
    }
}

#[derive(Default)]
pub(super) struct Ring {
    lines: VecDeque<LogLine>,
    bytes: usize,
    /// The `seq` the next line gets (the first is 1).
    last: u64,
}

fn cost(l: &LogLine) -> usize {
    l.text.len() + l.service.len() + l.at.len() + LINE_OVERHEAD
}

impl Ring {
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    fn push(&mut self, service: &str, at: &str, text: String) {
        self.last += 1;
        let line = LogLine {
            seq: self.last,
            service: service.to_owned(),
            at: at.to_owned(),
            text,
        };
        self.bytes += cost(&line);
        self.lines.push_back(line);
        while self.bytes > RING_BYTES {
            match self.lines.pop_front() {
                Some(old) => self.bytes -= cost(&old),
                None => break,
            }
        }
    }

    /// The lines after `after` (of `service`, when given), at most `limit`; the `seq` to ask
    /// again from; and how many lines before the oldest held were already dropped.
    fn read(&self, after: u64, service: Option<&str>, limit: usize) -> (Vec<LogLine>, u64, u64) {
        let first = self.lines.front().map_or(self.last + 1, |l| l.seq);
        let lost = first.saturating_sub(after.saturating_add(1));
        let lines: Vec<LogLine> = self
            .lines
            .iter()
            .filter(|l| l.seq > after && service.is_none_or(|s| s == l.service))
            .take(limit)
            .cloned()
            .collect();
        // With a filter or a limit the cursor stops at the last line handed out.
        let next = match lines.last() {
            Some(l) if lines.len() == limit => l.seq,
            _ => self.last.max(after),
        };
        (lines, next, lost)
    }
}

pub(super) struct RunObs {
    pub(super) ring: Ring,
    redactor: Redactor,
    /// Services inside a PEM block: its lines are dropped until the END line.
    in_pem: HashSet<String>,
    /// The newest line seen (Podman's own stamp) and which lines at that stamp were kept.
    newest: Option<(String, u32)>,
    since: Option<String>,
    at_newest: HashSet<u64>,
    asked: Instant,
    watching: bool,
    metrics: Vec<ServiceMetrics>,
    /// The longest masked form of any secret known, in bytes: what the raw window must add.
    longest: usize,
    /// How many secrets are known (an entry that has none is dropped when idle).
    secrets: usize,
    /// The first poll of this run is in flight; no second one starts beside it.
    first_polling: bool,
    /// Until when an admin route has asked for the services' health checks to run.
    check_until: Option<Instant>,
}

impl RunObs {
    fn new() -> Self {
        Self {
            ring: Ring::default(),
            redactor: Redactor::new(),
            in_pem: HashSet::new(),
            newest: None,
            since: None,
            at_newest: HashSet::new(),
            asked: Instant::now(),
            watching: false,
            metrics: Vec::new(),
            longest: 0,
            secrets: 0,
            first_polling: false,
            check_until: None,
        }
    }

    /// Everything but the secrets: what an idle, unwatched run keeps.
    fn reset(&mut self) {
        let last = self.ring.last;
        self.ring = Ring::default();
        self.ring.last = last;
        self.in_pem.clear();
        self.newest = None;
        self.since = None;
        self.at_newest.clear();
        self.metrics.clear();
        self.check_until = None;
    }

    fn learn(&mut self, name: &str, value: &str) {
        let n = value.trim().len();
        if n >= MIN_KNOWN {
            self.secrets += 1;
            self.longest = self.longest.max(n * ENCODED_MAX);
        }
        self.redactor.known(name, value);
    }

    /// Redacts one line; `None` while inside a PEM block.
    fn clean(&mut self, service: &str, raw: &str) -> Option<String> {
        let raw = &sanitize(raw);
        if self.in_pem.contains(service) {
            if raw.contains("-----END ") {
                self.in_pem.remove(service);
            }
            return None;
        }
        if raw.contains("-----BEGIN ") && !raw.contains("-----END ") {
            self.in_pem.insert(service.to_owned());
            return Some("[redacted:pem]".to_owned());
        }
        let mut text = self.redactor.text(raw);
        if text.len() > LOG_LINE_MAX {
            let mut cut = LOG_LINE_MAX;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        Some(text)
    }

    /// Keeps the new lines of one helper answer (it may repeat the last poll's), redacted.
    pub(super) fn ingest(&mut self, got: Observed) {
        if !got.services.is_empty() {
            self.metrics = got.services;
        }
        for RawLine { service, at, text } in got.lines {
            let key = stamp_key(&at);
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (&service, &text).hash(&mut h);
            let id = h.finish();
            match (&key, &self.newest) {
                (Some(k), Some(n)) if k < n => continue,
                (Some(k), Some(n)) if k == n && !self.at_newest.insert(id) => continue,
                // After the first poll a line with no stamp cannot be told from a repeat.
                (None, Some(_)) => continue,
                _ => {}
            }
            if let Some(k) = key
                && self.newest.as_ref() != Some(&k)
            {
                self.at_newest.clear();
                self.at_newest.insert(id);
                self.since = Some(at.clone());
                self.newest = Some(k);
            }
            if let Some(text) = self.clean(&service, &text) {
                self.ring.push(&service, &at, text);
            }
        }
    }
}

pub struct Observers {
    socket: PathBuf,
    /// Lock order: `runs`, then `forgotten`.
    runs: Mutex<HashMap<String, RunObs>>,
    /// Runs that ended: `observe` refuses them, so a late or hostile ask cannot re-create one.
    forgotten: Mutex<HashSet<String>>,
}

/// Drops the unwatched, idle runs: whole when they hold no secret, else down to their secrets.
fn sweep(runs: &mut HashMap<String, RunObs>) {
    runs.retain(|_, r| {
        if r.watching || r.asked.elapsed() < IDLE {
            return true;
        }
        r.reset();
        r.secrets > 0
    });
}

/// Clears `first_polling` when the first poll ends, however it ends (an error, a cancel).
struct FirstPoll<'a>(&'a Observers, String);

impl Drop for FirstPoll<'_> {
    fn drop(&mut self) {
        if let Some(r) = self.0.runs.lock().unwrap().get_mut(&self.1) {
            r.first_polling = false;
        }
    }
}

impl Observers {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            runs: Mutex::default(),
            forgotten: Mutex::default(),
        }
    }

    /// A value the run was given: every line of it is redacted from now on. A start is the one
    /// thing that makes a forgotten run id watchable again.
    pub fn know(&self, run: &str, name: &str, value: &str) {
        let mut runs = self.runs.lock().unwrap();
        sweep(&mut runs);
        self.forgotten.lock().unwrap().remove(run);
        runs.entry(run.to_owned())
            .or_insert_with(RunObs::new)
            .learn(name, value);
    }

    /// The run is over: its ring, metrics and redaction values are dropped, and it is refused.
    pub fn forget(&self, run: &str) {
        let mut runs = self.runs.lock().unwrap();
        runs.remove(run);
        let mut gone = self.forgotten.lock().unwrap();
        if gone.len() >= MAX_FORGOTTEN {
            gone.clear();
        }
        gone.insert(run.to_owned());
    }

    /// One poll of the helper: new lines (and metrics, when asked) into the ring.
    async fn poll(&self, run: &str, metrics: bool) -> Result<(), String> {
        let (since, line_max, check) = {
            let runs = self.runs.lock().unwrap();
            let r = runs.get(run);
            (
                r.and_then(|r| r.since.clone()),
                raw_window(r.map_or(0, |r| r.longest)),
                r.and_then(|r| r.check_until)
                    .is_some_and(|t| t > Instant::now()),
            )
        };
        let req = Request::Observe {
            run: run.to_owned(),
            service: None,
            since,
            metrics,
            line_max,
            check,
        };
        let v = helper::call(&self.socket, &req, &[]).await?;
        let got: Observed = serde_json::from_value(v).map_err(|e| e.to_string())?;
        if let Some(r) = self.runs.lock().unwrap().get_mut(run) {
            r.ingest(got);
        }
        Ok(())
    }

    /// Watches `run` until nobody asks about it for [`IDLE`] or it is forgotten.
    async fn watch(self: Arc<Self>, run: String) {
        let mut tick = 0u32;
        loop {
            tokio::time::sleep(POLL).await;
            tick += 1;
            let alive = self
                .runs
                .lock()
                .unwrap()
                .get(&run)
                .is_some_and(|r| r.asked.elapsed() < IDLE);
            if !alive {
                break;
            }
            let _ = self.poll(&run, tick.is_multiple_of(METRICS_EVERY)).await;
        }
        let mut runs = self.runs.lock().unwrap();
        // Stopped watching, but keep a run that has secrets to redact for the next watch.
        if let Some(r) = runs.get_mut(&run) {
            r.watching = false;
        }
    }

    pub async fn observe(self: &Arc<Self>, req: RunObserveReq) -> Result<RunObserve, StreamError> {
        let bad = |c, m: String| StreamError::new(c, m);
        if let Some(p) = req.problem() {
            return Err(bad(ErrorCode::InvalidArgs, p));
        }
        let (start_watch, first) = {
            let mut runs = self.runs.lock().unwrap();
            sweep(&mut runs);
            if self.forgotten.lock().unwrap().contains(&req.run) {
                return Err(bad(ErrorCode::InvalidArgs, "the run has ended".to_owned()));
            }
            // Only runs being watched count; entries kept for their secrets cost no polling.
            let watched = runs.values().filter(|r| r.watching).count();
            if !runs.get(&req.run).is_some_and(|r| r.watching) && watched >= MAX_RUNS {
                return Err(bad(ErrorCode::Busy, "too many runs are watched".to_owned()));
            }
            let r = runs.entry(req.run.clone()).or_insert_with(RunObs::new);
            r.asked = Instant::now();
            if req.health {
                r.check_until = Some(r.asked + IDLE);
            }
            // One first poll in flight per run: a second ask reads what the ring holds.
            let first = r.metrics.is_empty() && r.newest.is_none() && !r.first_polling;
            r.first_polling |= first;
            (!std::mem::replace(&mut r.watching, true), first)
        };
        // Spawned before the first poll: an ask that is cancelled mid-poll still leaves a watcher.
        if start_watch {
            tokio::spawn(Arc::clone(self).watch(req.run.clone()));
        }
        if first {
            let _guard = FirstPoll(self, req.run.clone());
            self.poll(&req.run, true)
                .await
                .map_err(|e| bad(ErrorCode::Internal, e))?;
        }
        let limit = req
            .limit
            .unwrap_or(OBSERVE_LINES_MAX)
            .min(OBSERVE_LINES_MAX) as usize;
        let runs = self.runs.lock().unwrap();
        let r = runs
            .get(&req.run)
            .ok_or_else(|| bad(ErrorCode::Internal, "the run was forgotten".to_owned()))?;
        let (lines, next, lost) = r.ring.read(req.after, req.service.as_deref(), limit);
        Ok(RunObserve {
            services: r.metrics.clone(),
            lines,
            next,
            lost,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(service: &str, n: u64, text: &str) -> RawLine {
        RawLine {
            service: service.into(),
            at: format!(
                "2026-11-18T10:00:{:02}.{:09}+00:00",
                (n / 1_000_000_000) % 60,
                n % 1_000_000_000
            ),
            text: text.into(),
        }
    }

    #[test]
    fn a_10_mb_per_second_flood_stays_inside_the_ring() {
        let mut r = RunObs::new();
        // 30 s at 10 MB/s of 1 KiB lines: ~300 MB through, polled 200 lines at a time.
        let line = "x".repeat(1024);
        let total = 30 * 10_000_000 / 1024;
        let mut n = 0u64;
        while n < total {
            let lines = (0..200).map(|i| raw("web", n + i + 1, &line)).collect();
            r.ingest(Observed {
                services: Vec::new(),
                lines,
            });
            n += 200;
            assert!(r.ring.bytes() <= RING_BYTES + 2048, "{}", r.ring.bytes());
        }
        let (lines, next, lost) = r.ring.read(0, None, 500);
        assert!(lines.len() <= 500 && next >= lines.last().unwrap().seq);
        assert!(lost > 0, "the oldest lines were dropped");
        assert!(r.ring.bytes() <= RING_BYTES + 2048);
    }

    #[test]
    fn secrets_keys_and_pem_blocks_never_reach_the_ring() {
        let mut r = RunObs::new();
        r.redactor.known("db_password", "hunter2-very-secret");
        let lines = vec![
            raw("web", 1, "connecting with hunter2-very-secret now"),
            raw("web", 2, "key sk-abcdefghijklmnopqrstuvwxyz0123"),
            raw("web", 3, "-----BEGIN PRIVATE KEY-----"),
            raw("web", 4, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"),
            raw("web", 5, "-----END PRIVATE KEY-----"),
            raw("web", 6, "after"),
        ];
        r.ingest(Observed {
            services: Vec::new(),
            lines,
        });
        let (got, _, _) = r.ring.read(0, None, 50);
        let all: String = got
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("|");
        assert!(!all.contains("hunter2") && !all.contains("sk-abc") && !all.contains("MIIE"));
        assert!(
            all.contains("[redacted:db_password]") && all.ends_with("after"),
            "{all}"
        );
    }

    #[test]
    fn a_repeated_poll_adds_nothing_and_long_lines_are_cut() {
        let mut r = RunObs::new();
        let batch = || Observed {
            services: Vec::new(),
            lines: vec![
                raw("web", 1, "one"),
                raw("db", 1, "two"),
                raw("web", 2, &"y".repeat(10_000)),
            ],
        };
        r.ingest(batch());
        r.ingest(batch());
        let (got, next, lost) = r.ring.read(0, None, 50);
        assert_eq!((got.len(), next, lost), (3, 3, 0));
        assert_eq!(got[2].text.len(), LOG_LINE_MAX);
        let (only_db, ..) = r.ring.read(0, Some("db"), 50);
        assert_eq!(only_db.len(), 1);
        let (rest, ..) = r.ring.read(2, None, 50);
        assert_eq!(rest.len(), 1);
    }

    fn texts(r: &RunObs) -> Vec<String> {
        r.ring
            .read(0, None, 50)
            .0
            .into_iter()
            .map(|l| l.text)
            .collect()
    }

    #[test]
    fn terminal_escapes_controls_and_bidi_are_stripped_before_redaction() {
        let dirty = "a\x1b[31mred\x1b[0m\x1b]0;title\x07 b\x1b]8;;http://x\x1b\\link\x07\u{9b}1;2Hc\td\r\x00\u{85}\u{202e}e\u{2066}f\u{200f}";
        assert_eq!(sanitize(dirty), "ared blinkc\tdef");
        // A secret broken up by an escape, a control or a bidi mark is still found.
        let mut r = RunObs::new();
        r.learn("db", "hunter2-very-secret");
        for (n, split) in [
            "hunter2-\x1b[1mvery-secret",
            "hunter2-\x07very-secret",
            "hunter2-\u{202e}very-secret",
        ]
        .into_iter()
        .enumerate()
        {
            r.ingest(Observed {
                services: Vec::new(),
                lines: vec![raw("web", n as u64 + 1, &format!("k={split}!"))],
            });
        }
        assert_eq!(texts(&r), ["k=[redacted:db]!"; 3]);
    }

    #[test]
    fn partial_chunks_joined_by_podman_lose_their_inner_stamps() {
        // `podman logs --timestamps` of a line written in two parts (log records `P` then `F`):
        //   <stamp> <text of P><stamp> <text of F>
        // and the outer stamp is already split off, so the text still holds the inner one.
        let joined = "key=hunter2-very2026-11-18T10:00:00.250000000+00:00 -secret done";
        assert_eq!(sanitize(joined), "key=hunter2-very-secret done");
        assert_eq!(sanitize("t=2026-11-18T10:00:00Z x"), "t=x");
        // Not a stamp: no offset, or a date alone.
        assert_eq!(
            sanitize("2026-11-18T10:00:00 x 2026-11-18"),
            "2026-11-18T10:00:00 x 2026-11-18"
        );
        let mut r = RunObs::new();
        r.learn("db", "hunter2-very-secret");
        r.ingest(Observed {
            services: Vec::new(),
            lines: vec![raw("web", 1, joined)],
        });
        assert_eq!(texts(&r), ["key=[redacted:db] done"]);
    }

    #[test]
    fn a_secret_past_the_cut_is_redacted_before_the_line_is_cut() {
        let secret = "s3cr3t-".repeat(20);
        let mut r = RunObs::new();
        r.learn("tok", &secret);
        assert!(r.longest >= secret.len());
        let line = format!("{}{secret}tail", "a".repeat(LOG_LINE_MAX - 30));
        r.ingest(Observed {
            services: Vec::new(),
            lines: vec![raw("web", 1, &line)],
        });
        let got = &texts(&r)[0];
        assert!(
            got.len() <= LOG_LINE_MAX && !got.contains("s3cr3t"),
            "{got}"
        );
        assert!(got.contains("[redacted:tok]"), "{got}");
    }

    fn aged(secrets: usize) -> RunObs {
        let mut r = RunObs::new();
        r.asked = Instant::now()
            .checked_sub(IDLE + Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        r.secrets = secrets;
        r.ring.push("web", "", "x".into());
        r
    }

    #[test]
    fn idle_unwatched_runs_are_dropped_and_only_watched_ones_count() {
        let mut runs = HashMap::new();
        runs.insert("none".to_owned(), aged(0));
        runs.insert("keeps".to_owned(), aged(1));
        let mut busy = aged(0);
        busy.watching = true;
        runs.insert("busy".to_owned(), busy);
        sweep(&mut runs);
        assert!(!runs.contains_key("none"));
        // Kept for its secrets, but its lines are gone and its seq goes on.
        assert!(runs["keeps"].ring.bytes() == 0 && runs["keeps"].ring.last == 1);
        assert!(runs.contains_key("busy"));
    }

    #[tokio::test]
    async fn a_forgotten_run_is_refused_and_a_start_arms_it_again() {
        let o = Arc::new(Observers::new("/nonexistent/run.sock"));
        let ask = |run: &str| RunObserveReq {
            run: run.to_owned(),
            ..Default::default()
        };
        o.forget("r1");
        let e = o.observe(ask("r1")).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        assert!(!o.runs.lock().unwrap().contains_key("r1"));
        o.know("r1", "db", "hunter2-very-secret");
        assert!(o.runs.lock().unwrap().contains_key("r1"));
        assert_ne!(
            o.observe(ask("r1")).await.unwrap_err().code,
            ErrorCode::InvalidArgs
        );
    }

    #[tokio::test]
    async fn watched_runs_are_capped_and_one_first_poll_runs_per_run() {
        let o = Arc::new(Observers::new("/nonexistent/run.sock"));
        {
            let mut runs = o.runs.lock().unwrap();
            for n in 0..MAX_RUNS {
                let mut r = RunObs::new();
                r.watching = true;
                runs.insert(format!("w{n}"), r);
            }
            // An entry kept for secrets is not watched and does not count.
            runs.insert("kept".to_owned(), RunObs::new());
        }
        let ask = |run: &str| RunObserveReq {
            run: run.to_owned(),
            ..Default::default()
        };
        let e = o.observe(ask("another")).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::Busy);
        // A first poll is already in flight for w0: this ask does not start a second one (the
        // socket does not exist, so a started one would answer with an error).
        o.runs.lock().unwrap().get_mut("w0").unwrap().first_polling = true;
        assert!(o.observe(ask("w0")).await.is_ok());
        // Its flag is the other poll's to clear.
        assert!(o.runs.lock().unwrap()["w0"].first_polling);
    }
}
