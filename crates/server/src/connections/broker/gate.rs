//! Rate and concurrency limits of the broker, in memory: per session and per connection calls per
//! minute, and how many calls run at once for one session and in all. A refused call costs
//! nothing upstream. Nothing here persists: a restart starts every window empty (the upstream's
//! own limits and `connections::health` still cool a connection that is really limited).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What a session and a connection may do.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_session_per_min: usize,
    pub per_connection_per_min: usize,
    pub concurrent_per_session: usize,
    pub concurrent_total: usize,
    /// One upstream call, renewal included.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_session_per_min: 60,
            per_connection_per_min: 240,
            concurrent_per_session: 4,
            concurrent_total: 16,
            timeout: Duration::from_secs(30),
        }
    }
}

const WINDOW: Duration = Duration::from_secs(60);
/// Windows kept before the idle ones are swept.
const SWEEP_AT: usize = 512;

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, VecDeque<Instant>>,
    connections: HashMap<i64, VecDeque<Instant>>,
    running: HashMap<String, usize>,
    total: usize,
}

pub struct Gate {
    limits: Limits,
    inner: Mutex<Inner>,
}

/// A call's place in the concurrency cap; freed when dropped.
pub struct Permit {
    gate: Arc<Gate>,
    session: String,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut g = self.gate.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.total = g.total.saturating_sub(1);
        if let Some(n) = g.running.get_mut(&self.session) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.running.remove(&self.session);
            }
        }
    }
}

fn take<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, VecDeque<Instant>>,
    key: &K,
    max: usize,
    now: Instant,
) -> bool {
    if map.len() >= SWEEP_AT {
        map.retain(|_, w| w.back().is_some_and(|t| now.duration_since(*t) < WINDOW));
    }
    let w = map.entry(key.clone()).or_default();
    while w.front().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
        w.pop_front();
    }
    if w.len() >= max {
        return false;
    }
    w.push_back(now);
    true
}

impl Gate {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            inner: Mutex::default(),
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// A session's call: counted against its rate and the concurrency caps, or `None`.
    pub fn enter(self: &Arc<Self>, session: &str) -> Option<Permit> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mine = g.running.get(session).copied().unwrap_or(0);
        if g.total >= self.limits.concurrent_total || mine >= self.limits.concurrent_per_session {
            return None;
        }
        let key = session.to_owned();
        if !take(
            &mut g.sessions,
            &key,
            self.limits.per_session_per_min,
            Instant::now(),
        ) {
            return None;
        }
        g.total += 1;
        *g.running.entry(key.clone()).or_default() += 1;
        drop(g);
        Some(Permit {
            gate: Arc::clone(self),
            session: key,
        })
    }

    /// A call on connection `id`, counted against its rate.
    pub fn connection(&self, id: i64) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        take(
            &mut g.connections,
            &id,
            self.limits.per_connection_per_min,
            Instant::now(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_hold_and_a_permit_frees_its_place() {
        let g = Gate::new(Limits {
            per_session_per_min: 100,
            per_connection_per_min: 3,
            concurrent_per_session: 2,
            concurrent_total: 3,
            ..Limits::default()
        });
        let a = g.enter("as_a").unwrap();
        let _b = g.enter("as_a").unwrap();
        assert!(g.enter("as_a").is_none(), "two at once per session");
        let _c = g.enter("as_b").unwrap();
        assert!(g.enter("as_c").is_none(), "three in all");
        drop(a);
        assert!(g.enter("as_c").is_some(), "a freed place is usable");
        assert!(g.connection(1) && g.connection(1) && g.connection(1));
        assert!(!g.connection(1), "a fourth in the minute");
        assert!(g.connection(2), "another connection has its own window");
    }

    #[test]
    fn a_session_is_limited_per_minute() {
        let g = Gate::new(Limits {
            per_session_per_min: 2,
            ..Limits::default()
        });
        drop(g.enter("as_a").unwrap());
        drop(g.enter("as_a").unwrap());
        assert!(g.enter("as_a").is_none());
        assert!(g.enter("as_b").is_some());
    }
}
