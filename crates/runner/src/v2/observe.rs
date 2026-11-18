//! The runner's side of `run.observe` (P5-04): a bounded, redacted ring of each watched run's log
//! lines, and its services' latest metrics.
//!
//! Security model. A container's output is untrusted text and may hold a secret the run was
//! given. Every line is redacted before it is kept (`Redactor`: the values of the leases this
//! runner redeemed for the run, learnt in `RunDriver::prepare`, then key shapes, and a PEM block
//! is dropped whole across lines), and cut to [`LOG_LINE_MAX`]. Memory is bounded whatever the
//! containers write: the helper reads each service through a window of its newest lines, the ring
//! holds at most [`RING_BYTES`] per run and [`MAX_RUNS`] runs are watched; a flood loses the
//! oldest lines (`lost`), never memory. A run is watched only while the Core keeps asking
//! ([`IDLE`]); Podman keeps its own capped copy of the log meanwhile.

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
use crate::run::observe::{Observed, RawLine, stamp_key};

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
        }
    }

    /// Redacts one line; `None` while inside a PEM block.
    fn clean(&mut self, service: &str, raw: &str) -> Option<String> {
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
            if let Some(k) = key {
                if self.newest.as_ref() != Some(&k) {
                    self.at_newest.clear();
                    self.at_newest.insert(id);
                    self.since = Some(at.clone());
                    self.newest = Some(k);
                }
            }
            if let Some(text) = self.clean(&service, &text) {
                self.ring.push(&service, &at, text);
            }
        }
    }
}

pub struct Observers {
    socket: PathBuf,
    runs: Mutex<HashMap<String, RunObs>>,
}

impl Observers {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            runs: Mutex::default(),
        }
    }

    /// A value the run was given: every line of it is redacted from now on.
    pub fn know(&self, run: &str, name: &str, value: &str) {
        let mut runs = self.runs.lock().unwrap();
        runs.entry(run.to_owned())
            .or_insert_with(RunObs::new)
            .redactor
            .known(name, value);
    }

    /// The run is over: its ring, metrics and redaction values are dropped.
    pub fn forget(&self, run: &str) {
        self.runs.lock().unwrap().remove(run);
    }

    /// One poll of the helper: new lines (and metrics, when asked) into the ring.
    async fn poll(&self, run: &str, metrics: bool) -> Result<(), String> {
        let since = self
            .runs
            .lock()
            .unwrap()
            .get(run)
            .and_then(|r| r.since.clone());
        let req = Request::Observe {
            run: run.to_owned(),
            service: None,
            since,
            metrics,
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
            if !runs.contains_key(&req.run) && runs.len() >= MAX_RUNS {
                return Err(bad(ErrorCode::Busy, "too many runs are watched".to_owned()));
            }
            let r = runs.entry(req.run.clone()).or_insert_with(RunObs::new);
            r.asked = Instant::now();
            let first = r.metrics.is_empty() && r.newest.is_none();
            (!std::mem::replace(&mut r.watching, true), first)
        };
        if first {
            self.poll(&req.run, true)
                .await
                .map_err(|e| bad(ErrorCode::Internal, e))?;
        }
        if start_watch {
            tokio::spawn(Arc::clone(self).watch(req.run.clone()));
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
}
