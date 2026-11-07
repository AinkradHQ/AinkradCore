//! Rate, concurrency and budget limits of the broker, in memory. A refused call costs nothing
//! upstream. Nothing here persists: a restart starts every window empty (the upstream's own limits
//! and `connections::health` still cool a connection that is really limited).
//!
//! - **Rate**: every call of a session, known or not, refused or not, counts against its
//!   per-minute window FIRST. Past it a call is refused at once and costs no audit row of its own:
//!   at most one aggregated row per window per session ([`Rate::Over`]), so a flood cannot flood
//!   the audit table or the writer lock.
//! - **Concurrency**: calls past a session's, a user's or the whole broker's cap WAIT (a harness
//!   makes parallel calls) in a bounded queue per session; past the queue they are refused. The
//!   caps nest (session 4, user 8, all 16), so one user's sessions cannot take every slot.
//! - **A connection** has a per-minute window, a share of it per session, an hourly budget from its
//!   kind's descriptor (below the service's own), and a block the service's own answer sets (low
//!   remaining quota, `Retry-After`): refused locally as `connection_busy` before the service cools
//!   the connection for everyone.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What a session, a user and a connection may do.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_session_per_min: usize,
    pub per_connection_per_min: usize,
    /// One session's share of one connection's minute.
    pub per_session_connection_per_min: usize,
    pub concurrent_per_session: usize,
    pub concurrent_per_user: usize,
    pub concurrent_total: usize,
    /// Calls waiting for a place, per session, before one is refused.
    pub queue_per_session: usize,
    /// One upstream call, renewal included (counted from when it runs).
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_session_per_min: 60,
            per_connection_per_min: 240,
            per_session_connection_per_min: 60,
            concurrent_per_session: 4,
            concurrent_per_user: 8,
            concurrent_total: 16,
            queue_per_session: 32,
            timeout: Duration::from_secs(30),
        }
    }
}

const WINDOW: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
/// Windows kept before the idle ones are swept.
const SWEEP_AT: usize = 512;
/// A connection with this few calls left upstream is not called until the window resets.
const RESERVE: u64 = 20;

/// The answer of [`Gate::rate`].
#[derive(Debug, PartialEq, Eq)]
pub enum Rate {
    Ok,
    /// Over the minute: refuse. `Some(n)` when a row should be written now: `n` calls were refused
    /// since the last one.
    Over(Option<usize>),
}

/// Why a connection is not called now.
#[derive(Debug, PartialEq, Eq)]
pub enum Busy {
    /// A per-minute window (the connection's, or this session's share of it).
    Rate,
    /// The hourly budget, or the service's own answer: until this unix second, when known.
    Until(Option<i64>),
}

#[derive(Default)]
struct Over {
    dropped: usize,
    last_row: Option<Instant>,
}

struct Slot {
    sem: Arc<Semaphore>,
    waiting: AtomicUsize,
}

impl Slot {
    fn new(n: usize) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(n)),
            waiting: AtomicUsize::new(0),
        })
    }
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, VecDeque<Instant>>,
    over: HashMap<String, Over>,
    connections: HashMap<i64, VecDeque<Instant>>,
    shares: HashMap<(i64, String), VecDeque<Instant>>,
    hours: HashMap<i64, VecDeque<Instant>>,
    blocked: HashMap<i64, i64>,
    slots: HashMap<String, Arc<Slot>>,
    users: HashMap<i64, Arc<Slot>>,
}

pub struct Gate {
    limits: Limits,
    inner: Mutex<Inner>,
    total: Arc<Semaphore>,
}

/// A call's places in the concurrency caps; freed when dropped.
#[allow(dead_code)] // held for its Drop: it frees the places
pub struct Permit(Vec<OwnedSemaphorePermit>);

fn take<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, VecDeque<Instant>>,
    key: &K,
    (max, window): (usize, Duration),
    now: Instant,
) -> bool {
    if map.len() >= SWEEP_AT {
        map.retain(|_, w| w.back().is_some_and(|t| now.duration_since(*t) < window));
    }
    let w = map.entry(key.clone()).or_default();
    while w.front().is_some_and(|t| now.duration_since(*t) >= window) {
        w.pop_front();
    }
    if w.len() >= max {
        return false;
    }
    w.push_back(now);
    true
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

impl Gate {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(limits.concurrent_total)),
            limits,
            inner: Mutex::default(),
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Counts one call of `session` (whatever it turns out to be) against its minute.
    pub fn rate(&self, session: &str) -> Rate {
        let mut g = self.lock();
        let now = Instant::now();
        let key = session.to_owned();
        let max = self.limits.per_session_per_min;
        if take(&mut g.sessions, &key, (max, WINDOW), now) {
            return Rate::Ok;
        }
        if g.over.len() >= SWEEP_AT {
            g.over
                .retain(|_, o| o.last_row.is_some_and(|t| now.duration_since(t) < WINDOW));
        }
        let o = g.over.entry(key).or_default();
        o.dropped += 1;
        if o.last_row.is_none_or(|t| now.duration_since(t) >= WINDOW) {
            o.last_row = Some(now);
            return Rate::Over(Some(std::mem::take(&mut o.dropped)));
        }
        Rate::Over(None)
    }

    /// A place for one of `session`'s calls (of `user`): waits in the session's bounded queue, or
    /// `None` when the queue is full.
    pub async fn acquire(&self, session: &str, user: i64) -> Option<Permit> {
        let (s, u) = {
            let mut g = self.lock();
            if g.slots.len() >= SWEEP_AT {
                g.slots.retain(|_, s| Arc::strong_count(s) > 1);
            }
            let l = self.limits;
            let s = g
                .slots
                .entry(session.to_owned())
                .or_insert_with(|| Slot::new(l.concurrent_per_session))
                .clone();
            let u = g
                .users
                .entry(user)
                .or_insert_with(|| Slot::new(l.concurrent_per_user))
                .clone();
            (s, u)
        };
        if s.waiting.fetch_add(1, Ordering::SeqCst) >= self.limits.queue_per_session {
            s.waiting.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let mine = s.sem.clone().acquire_owned().await;
        s.waiting.fetch_sub(1, Ordering::SeqCst);
        // Always in this order (session, user, all): no two calls can wait on each other.
        let theirs = u.sem.clone().acquire_owned().await;
        let all = self.total.clone().acquire_owned().await;
        Some(Permit(vec![mine.ok()?, theirs.ok()?, all.ok()?]))
    }

    /// A call of `session` on connection `id` whose kind allows `hourly` an hour.
    pub fn connection(&self, id: i64, session: &str, hourly: u32) -> Result<(), Busy> {
        let mut g = self.lock();
        let now = Instant::now();
        if let Some(until) = g.blocked.get(&id).copied() {
            if until > unix_now() {
                return Err(Busy::Until(Some(until)));
            }
            g.blocked.remove(&id);
        }
        let hourly = (usize::try_from(hourly).unwrap_or(usize::MAX), HOUR);
        let minute = (self.limits.per_connection_per_min, WINDOW);
        let share = (self.limits.per_session_connection_per_min, WINDOW);
        // The hour first: a refused call must not use up the minute's places.
        if !take(&mut g.hours, &id, hourly, now) {
            return Err(Busy::Until(None));
        }
        if !take(&mut g.shares, &(id, session.to_owned()), share, now)
            || !take(&mut g.connections, &id, minute, now)
        {
            return Err(Busy::Rate);
        }
        Ok(())
    }

    /// What the service said about its own budget after a call on connection `id`: few calls left
    /// until `reset` (unix seconds), or a `Retry-After`. The connection is not called until then.
    pub fn note_upstream(
        &self,
        id: i64,
        remaining: Option<u64>,
        reset: Option<i64>,
        retry_after: Option<u64>,
    ) {
        let now = unix_now();
        let cap = now + 3600;
        let until = match (remaining, reset, retry_after) {
            (_, _, Some(s)) => Some(now + i64::try_from(s).unwrap_or(3600)),
            (Some(r), Some(at), _) if r <= RESERVE && at > now => Some(at),
            _ => None,
        };
        if let Some(until) = until {
            self.lock().blocked.insert(id, until.min(cap));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn calls_past_the_caps_wait_and_the_queue_is_bounded() {
        let g = Gate::new(Limits {
            concurrent_per_session: 1,
            concurrent_per_user: 8,
            queue_per_session: 1,
            ..Limits::default()
        });
        let first = g.acquire("as_a", 1).await.unwrap();
        let waiter = {
            let g = g.clone();
            tokio::spawn(async move { g.acquire("as_a", 1).await.is_some() })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            g.acquire("as_a", 1).await.is_none(),
            "past the queue: refused"
        );
        assert!(
            g.acquire("as_b", 1).await.is_some(),
            "another session is not held up"
        );
        drop(first);
        assert!(waiter.await.unwrap(), "the queued call got its place");
    }

    #[tokio::test]
    async fn one_user_cannot_take_every_slot() {
        let g = Gate::new(Limits {
            concurrent_per_session: 4,
            concurrent_per_user: 2,
            concurrent_total: 3,
            ..Limits::default()
        });
        let _a = g.acquire("as_a", 1).await.unwrap();
        let _b = g.acquire("as_b", 1).await.unwrap();
        // The user's third call waits (it would hold the last slot), a second user still gets it.
        let third = tokio::time::timeout(Duration::from_millis(100), g.acquire("as_c", 1)).await;
        assert!(third.is_err(), "the first user is held at its cap");
        assert!(
            g.acquire("as_d", 2).await.is_some(),
            "a second user's call gets a slot"
        );
    }

    #[test]
    fn a_flood_writes_one_aggregate_row_per_window() {
        let g = Gate::new(Limits {
            per_session_per_min: 3,
            ..Limits::default()
        });
        for _ in 0..3 {
            assert_eq!(g.rate("as_a"), Rate::Ok);
        }
        assert_eq!(
            g.rate("as_a"),
            Rate::Over(Some(1)),
            "the first refusal is reported"
        );
        for _ in 0..10_000 {
            assert_eq!(
                g.rate("as_a"),
                Rate::Over(None),
                "then none until the window passes"
            );
        }
        assert_eq!(g.rate("as_b"), Rate::Ok);
    }

    #[test]
    fn a_connection_has_a_minute_a_share_an_hour_and_the_services_own_block() {
        let g = Gate::new(Limits {
            per_connection_per_min: 3,
            per_session_connection_per_min: 2,
            ..Limits::default()
        });
        assert!(g.connection(1, "as_a", 100).is_ok());
        assert!(g.connection(1, "as_a", 100).is_ok());
        assert_eq!(
            g.connection(1, "as_a", 100),
            Err(Busy::Rate),
            "a session's share"
        );
        assert!(g.connection(1, "as_b", 100).is_ok());
        assert_eq!(
            g.connection(1, "as_c", 100),
            Err(Busy::Rate),
            "the connection's minute"
        );
        // The hourly budget.
        for _ in 0..2 {
            assert!(g.connection(2, "as_a", 2).is_ok());
        }
        assert_eq!(g.connection(2, "as_b", 2), Err(Busy::Until(None)));
        // The service says it is nearly out: refused until it resets.
        let reset = unix_now() + 600;
        g.note_upstream(3, Some(5), Some(reset), None);
        assert_eq!(g.connection(3, "as_a", 100), Err(Busy::Until(Some(reset))));
        g.note_upstream(4, Some(4000), Some(reset), None);
        assert!(g.connection(4, "as_a", 100).is_ok(), "plenty left");
        g.note_upstream(5, None, None, Some(30));
        assert!(matches!(
            g.connection(5, "as_a", 100),
            Err(Busy::Until(Some(_)))
        ));
    }
}
