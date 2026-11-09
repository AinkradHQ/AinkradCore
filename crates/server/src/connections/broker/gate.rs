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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What a session, a user and a connection may do.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_session_per_min: usize,
    pub per_connection_per_min: usize,
    /// The most of a connection's hourly budget (percent) one session, and one user, may use.
    pub session_share_pct: u32,
    pub user_share_pct: u32,
    pub concurrent_per_session: usize,
    pub concurrent_per_user: usize,
    pub concurrent_total: usize,
    /// Calls waiting for a place, per session, before one is refused.
    pub queue_per_session: usize,
    /// The longest a call waits for its place before it is refused `queue_timeout`.
    pub queue_wait: Duration,
    /// One upstream call, renewal included (counted from when it runs).
    pub timeout: Duration,
    /// How long refusals for rate are gathered into one audit row.
    pub flood_window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_session_per_min: 60,
            per_connection_per_min: 240,
            session_share_pct: 20,
            user_share_pct: 50,
            concurrent_per_session: 4,
            concurrent_per_user: 8,
            concurrent_total: 16,
            queue_per_session: 32,
            queue_wait: Duration::from_secs(20),
            timeout: Duration::from_secs(30),
            flood_window: Duration::from_secs(60),
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
    /// Over the minute: refuse. `first` when this is the first refusal of a flood: the caller
    /// schedules the one audit row for the window's end ([`Gate::flood`]).
    Over {
        first: bool,
    },
}

/// Why a connection is not called now.
#[derive(Debug, PartialEq, Eq)]
pub enum Busy {
    /// A per-minute window (the connection's, or this session's share of it).
    Rate,
    /// This session's (or user's) share of the connection's hour is used up.
    Share,
    /// The hourly budget, or the service's own answer: until this unix second, when known.
    Until(Option<i64>),
}

/// The refusals of one flood, gathered until its audit row is written.
#[derive(Default)]
pub struct Flood {
    pub count: usize,
    /// Calls by validated operation name (at most [`MAX_OPS`] names; the rest under `other`).
    pub ops: BTreeMap<String, usize>,
}

/// Operation names kept per flood row.
const MAX_OPS: usize = 8;

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
    over: HashMap<String, Flood>,
    connections: HashMap<i64, VecDeque<Instant>>,
    hours: HashMap<i64, VecDeque<Instant>>,
    session_hours: HashMap<(i64, String), VecDeque<Instant>>,
    user_hours: HashMap<(i64, i64), VecDeque<Instant>>,
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

fn prune<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, VecDeque<Instant>>,
    key: &K,
    window: Duration,
    now: Instant,
) -> usize {
    if map.len() >= SWEEP_AT {
        map.retain(|_, w| w.back().is_some_and(|t| now.duration_since(*t) < window));
    }
    let w = map.entry(key.clone()).or_default();
    while w.front().is_some_and(|t| now.duration_since(*t) >= window) {
        w.pop_front();
    }
    w.len()
}

/// Counts one more in the window if there is room.
fn take<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, VecDeque<Instant>>,
    key: &K,
    (max, window): (usize, Duration),
    now: Instant,
) -> bool {
    if prune(map, key, window, now) >= max {
        return false;
    }
    map.entry(key.clone()).or_default().push_back(now);
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

    /// Counts one call of `session` (whatever it turns out to be) against its minute. `op` is the
    /// call's tool name when it is a registered one (a refusal row names only those).
    pub fn rate(&self, session: &str, op: Option<&str>) -> Rate {
        let mut g = self.lock();
        let now = Instant::now();
        let key = session.to_owned();
        let max = self.limits.per_session_per_min;
        if take(&mut g.sessions, &key, (max, WINDOW), now) {
            return Rate::Ok;
        }
        Rate::Over {
            first: Self::note(&mut g, key, op),
        }
    }

    /// Counts one refused call into the flood of `key`; whether it is the first of the window.
    /// A flood being gathered is never swept: its row is still to be written.
    fn note(g: &mut Inner, key: String, op: Option<&str>) -> bool {
        let first = !g.over.contains_key(&key);
        let f = g.over.entry(key).or_default();
        f.count += 1;
        let name = op.map_or("unknown", |o| o);
        if f.ops.contains_key(name) || f.ops.len() < MAX_OPS {
            *f.ops.entry(name.to_owned()).or_default() += 1;
        } else {
            *f.ops.entry("other".to_owned()).or_default() += 1;
        }
        first
    }

    /// Whether `session` has a minute window (it has passed a lookup and is being counted).
    pub fn has_window(&self, session: &str) -> bool {
        self.lock()
            .sessions
            .get(session)
            .is_some_and(|w| !w.is_empty())
    }

    /// Counts a call about a session that does not exist, for the RUNNER that sent it: such a call
    /// has no session to attribute a row to, and a runner may invent a new name per call, so
    /// none gets a row of its own. `first` when it starts the runner's flood for the window.
    pub fn stranger(&self, runner: &str, op: Option<&str>) -> bool {
        let key = Self::runner_key(runner);
        Self::note(&mut self.lock(), key, op)
    }

    /// The flood key of a runner's calls about sessions that do not exist.
    pub fn runner_key(runner: &str) -> String {
        format!("runner:{}", runner.chars().take(48).collect::<String>())
    }

    /// Ends the flood of `session` and hands its exact counts over to be written.
    pub fn flood(&self, session: &str) -> Option<Flood> {
        self.lock().over.remove(session)
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

    /// A call of `session` (of `user`) on connection `id` whose kind allows `hourly` an hour. The
    /// cheap, local refusals come first and nothing is counted unless the call WILL run: the
    /// connection's minute, the session's share of its hour (20%), the user's (50%), the hour.
    pub fn connection(&self, id: i64, session: &str, user: i64, hourly: u32) -> Result<(), Busy> {
        let mut g = self.lock();
        let now = Instant::now();
        if let Some(until) = g.blocked.get(&id).copied() {
            if until > unix_now() {
                return Err(Busy::Until(Some(until)));
            }
            g.blocked.remove(&id);
        }
        let l = self.limits;
        let hour = usize::try_from(hourly).unwrap_or(usize::MAX);
        let share = |pct: u32| (hour * usize::try_from(pct).unwrap_or(100) / 100).max(1);
        let (sk, uk) = ((id, session.to_owned()), (id, user));
        let full = |n: usize, max: usize| n >= max;
        if full(
            prune(&mut g.connections, &id, WINDOW, now),
            l.per_connection_per_min,
        ) {
            return Err(Busy::Rate);
        }
        if full(
            prune(&mut g.session_hours, &sk, HOUR, now),
            share(l.session_share_pct),
        ) || full(
            prune(&mut g.user_hours, &uk, HOUR, now),
            share(l.user_share_pct),
        ) {
            return Err(Busy::Share);
        }
        if full(prune(&mut g.hours, &id, HOUR, now), hour) {
            return Err(Busy::Until(None));
        }
        let g = &mut *g;
        g.connections.entry(id).or_default().push_back(now);
        g.hours.entry(id).or_default().push_back(now);
        g.session_hours.entry(sk).or_default().push_back(now);
        g.user_hours.entry(uk).or_default().push_back(now);
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
    fn a_flood_is_counted_exactly_by_operation_and_reported_once() {
        let g = Gate::new(Limits {
            per_session_per_min: 3,
            ..Limits::default()
        });
        for _ in 0..3 {
            assert_eq!(g.rate("as_a", Some("github.get_issue")), Rate::Ok);
        }
        assert_eq!(
            g.rate("as_a", Some("github.get_issue")),
            Rate::Over { first: true }
        );
        for i in 1..1000 {
            let op = if i % 2 == 0 {
                Some("github.get_repo")
            } else {
                None
            };
            assert_eq!(g.rate("as_a", op), Rate::Over { first: false });
        }
        assert_eq!(g.rate("as_b", None), Rate::Ok);
        let f = g.flood("as_a").unwrap();
        assert_eq!(f.count, 1000, "the exact count");
        assert_eq!(f.ops["github.get_issue"], 1);
        assert_eq!(f.ops["github.get_repo"] + f.ops["unknown"], 999);
        assert!(g.flood("as_a").is_none(), "handed over once");
    }

    #[test]
    fn a_flood_names_at_most_eight_operations() {
        let g = Gate::new(Limits {
            per_session_per_min: 0,
            ..Limits::default()
        });
        for i in 0..20 {
            g.rate("as_a", Some(&format!("github.op_{i}")));
        }
        let f = g.flood("as_a").unwrap();
        assert_eq!((f.count, f.ops.len()), (20, 9), "eight names and `other`");
        assert_eq!(f.ops["other"], 12);
    }

    #[test]
    fn a_connection_has_a_minute_shares_an_hour_and_the_services_own_block() {
        let g = Gate::new(Limits {
            per_connection_per_min: 4,
            ..Limits::default()
        });
        // hourly 10: a session may use 2 (20%), a user 5 (50%).
        assert!(g.connection(1, "as_a", 1, 10).is_ok());
        assert!(g.connection(1, "as_a", 1, 10).is_ok());
        assert_eq!(
            g.connection(1, "as_a", 1, 10),
            Err(Busy::Share),
            "a session's share"
        );
        assert!(g.connection(1, "as_b", 1, 10).is_ok());
        assert!(g.connection(1, "as_c", 1, 10).is_ok());
        assert_eq!(
            g.connection(1, "as_d", 2, 10),
            Err(Busy::Rate),
            "the connection's minute"
        );
        // The user's share: 5 of 10.
        let g = Gate::new(Limits::default());
        for s in ["a", "a", "b", "b", "c"] {
            assert!(g.connection(1, s, 1, 10).is_ok(), "{s}");
        }
        assert_eq!(
            g.connection(1, "e", 1, 10),
            Err(Busy::Share),
            "the user used their five"
        );
        assert!(
            g.connection(1, "f", 2, 10).is_ok(),
            "a second user still gets calls"
        );
        // The hour itself.
        for n in 0..2 {
            assert!(g.connection(2, &format!("s{n}"), n, 2).is_ok());
        }
        assert_eq!(g.connection(2, "s9", 9, 2), Err(Busy::Until(None)));
        // The service says it is nearly out: refused until it resets.
        let reset = unix_now() + 600;
        g.note_upstream(3, Some(5), Some(reset), None);
        assert_eq!(
            g.connection(3, "as_a", 1, 100),
            Err(Busy::Until(Some(reset)))
        );
        g.note_upstream(4, Some(4000), Some(reset), None);
        assert!(g.connection(4, "as_a", 1, 100).is_ok(), "plenty left");
        g.note_upstream(5, None, None, Some(30));
        assert!(matches!(
            g.connection(5, "as_a", 1, 100),
            Err(Busy::Until(Some(_)))
        ));
    }

    #[test]
    fn a_refused_call_uses_none_of_the_hour() {
        let g = Gate::new(Limits {
            per_connection_per_min: 2,
            ..Limits::default()
        });
        assert!(g.connection(1, "a", 1, 100).is_ok());
        assert!(g.connection(1, "b", 2, 100).is_ok());
        for _ in 0..50 {
            assert_eq!(g.connection(1, "c", 3, 100), Err(Busy::Rate));
        }
        let hour = g.lock().hours[&1].len();
        let (s, u) = {
            let i = g.lock();
            (
                i.session_hours
                    .get(&(1, "c".to_owned()))
                    .map_or(0, |w| w.len()),
                i.user_hours.get(&(1, 3)).map_or(0, |w| w.len()),
            )
        };
        assert_eq!((hour, s, u), (2, 0, 0), "fifty refusals counted nothing");
    }
}
