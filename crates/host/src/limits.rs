//! `limits.json` (mutating actions): restart rate limits and the dedupe list. It lives in the
//! root-owned state directory, so a Core restart or a wiped Core home resets nothing.
//!
//! **Fail closed.** A missing file is a fresh start. A file that cannot be read, does not parse
//! (unknown fields included) or is too large is `Err`: the caller refuses every mutating action,
//! and the file is never rewritten over the bad copy.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state;

const FILE: &str = "limits.json";
const MAX_BYTES: u64 = 256 * 1024;
/// A repeated request id inside this window returns the stored answer.
pub const DEDUPE_SECS: u64 = 600;
const DEDUPE_KEEP: usize = 64;

/// `(min seconds between two, window seconds, max inside the window)`.
pub fn policy(action: &str) -> (u64, u64, usize) {
    match action {
        "restart_core" => (60, 600, 3),
        _ => (0, 600, 6),
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Done {
    pub id: String,
    pub action: String,
    pub at: u64,
    pub accepted: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    v: u32,
    /// Unix seconds of each accepted restart, by action name.
    restarts: BTreeMap<String, Vec<u64>>,
    done: Vec<Done>,
}

impl Limits {
    /// The stored outcome of request `id` within the dedupe window.
    pub fn dedupe(&self, id: &str, now: u64) -> Option<&Done> {
        self.done
            .iter()
            .find(|d| d.id == id && now.saturating_sub(d.at.min(now)) < DEDUPE_SECS)
    }

    /// `Err(retry_after)` when `action` may not run now.
    pub fn check(&self, action: &str, now: u64) -> Result<(), u64> {
        let (gap, window, max) = policy(action);
        // A timestamp from the future (the clock stepped back) counts as now.
        let times: Vec<u64> = self
            .restarts
            .get(action)
            .map(|t| t.iter().map(|t| (*t).min(now)).collect())
            .unwrap_or_default();
        let mut wait = 0;
        if let Some(last) = times.iter().max() {
            wait = wait.max((last + gap).saturating_sub(now));
        }
        let mut recent: Vec<u64> = times.into_iter().filter(|t| now - t < window).collect();
        recent.sort_unstable();
        if recent.len() >= max {
            wait = wait.max((recent[recent.len() - max] + window).saturating_sub(now));
        }
        if wait > 0 { Err(wait) } else { Ok(()) }
    }

    /// Records an accepted restart, and forgets what no window or dedupe can still see.
    pub fn record(&mut self, id: &str, action: &str, now: u64) {
        self.v = 1;
        self.restarts
            .entry(action.to_owned())
            .or_default()
            .push(now);
        for times in self.restarts.values_mut() {
            times.retain(|t| now.saturating_sub(*t) < 600);
        }
        self.done.retain(|d| now.saturating_sub(d.at) < DEDUPE_SECS);
        self.done.push(Done {
            id: id.to_owned(),
            action: action.to_owned(),
            at: now,
            accepted: true,
        });
        let excess = self.done.len().saturating_sub(DEDUPE_KEEP);
        self.done.drain(..excess);
    }

    pub fn mark_failed(&mut self, id: &str) {
        for d in self.done.iter_mut().filter(|d| d.id == id) {
            d.accepted = false;
        }
    }
}

pub fn load(dir: &Path) -> io::Result<Limits> {
    match state::read_capped(&dir.join(FILE), MAX_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Limits {
            v: 1,
            ..Limits::default()
        }),
        Err(e) => Err(e),
    }
}

pub fn save(dir: &Path, limits: &Limits) -> io::Result<()> {
    state::write_atomic(
        dir,
        FILE,
        &serde_json::to_vec(limits).map_err(io::Error::other)?,
    )
}
