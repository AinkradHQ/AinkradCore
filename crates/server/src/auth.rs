//! Device authentication state (handshake spec §5, §6, §10), all in memory and all per
//! process, so a restart forgets it: the Core identity key's public half aside, nothing here
//! survives. That is what closes replay across a restart (§6.4).
//!
//! - **Challenges** (`POST /handshake/challenge`): 32 random bytes, 60 s, single use, bound to
//!   the device id they were asked for; stored only for a usable device, at most 3 live each
//!   (review M1: a flood of made-up ids allocates nothing).
//! - **Sessions** (`POST /handshake/session`): a non-secret `s_…` handle for 15 minutes. Useless
//!   without a valid signature; there is no bearer secret and no refresh token.
//! - **Replay cache**: `(device, nonce)` for 125 s, at most 4,096 per device; when full, the
//!   device's requests are refused (never evicted: eviction would reopen replay).
//! - **Revocation fan-out**: after the revocation commits, the device's sessions are dropped
//!   and its id goes out on a broadcast; every socket of that device closes with 4001
//!   (`until_revoked`, with a 2 s database poll as the backstop).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::api::limit::Limiter;

pub mod crypto;
pub mod identity;
pub mod signed;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use identity::Identity;

/// `|now − timestamp|` allowed, seconds.
pub const SKEW: i64 = 60;
pub const REPLAY_TTL: i64 = 125;
pub const REPLAY_MAX: usize = 4096;
pub const SESSION_SECS: i64 = 15 * 60;
pub const CHALLENGE_SECS: i64 = 60;
/// A safety net only: unknown ids allocate nothing, so this holds a few per real device.
pub const CHALLENGES_MAX: usize = 10_000;
/// Live challenges per device; a new one replaces the oldest.
pub const CHALLENGES_PER_DEVICE: usize = 3;
/// Live sessions kept per device; the oldest goes first.
pub const SESSIONS_PER_DEVICE: usize = 32;
/// How often a socket re-checks its device in the database (§10 backstop).
pub const BACKSTOP: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub device: String,
    pub created: i64,
    pub expires: i64,
    /// Step-up (E1-09); always `None` until then.
    pub elevated_until: Option<i64>,
}

/// Why a nonce was not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum Replay {
    Seen,
    Full,
}

/// Failures per address in this process (§11, review M2): counted and checked under one lock,
/// so concurrent requests cannot all slip under the limit, and anything past it is refused
/// without touching the database. The persisted lockout (`store::gov::limits`) carries the
/// lock across restarts; this only gates the work and the writes.
#[derive(Default)]
pub struct AddressFailures {
    /// address → (failures in the window, window start, evaluations in flight).
    slots: Mutex<HashMap<String, (i64, i64, i64)>>,
}

/// Addresses tracked before the stale ones are dropped; past it a new address's failure is
/// refused like one over its budget.
const ADDRESSES_MAX: usize = 65_536;

impl AddressFailures {
    fn with<T>(
        &self,
        addr: &str,
        now: i64,
        f: impl FnOnce(&mut (i64, i64, i64)) -> T,
    ) -> Option<T> {
        use crate::store::gov::ADDRESS;
        let mut slots = self.slots.lock().unwrap();
        if slots.len() >= ADDRESSES_MAX && !slots.contains_key(addr) {
            slots.retain(|_, (_, start, inflight)| *inflight > 0 || now - *start < ADDRESS.window);
            if slots.len() >= ADDRESSES_MAX {
                return None;
            }
        }
        let slot = slots.entry(addr.to_owned()).or_insert((0, now, 0));
        if now - slot.1 >= ADDRESS.window {
            (slot.0, slot.1) = (0, now);
        }
        Some(f(slot))
    }

    /// Counts one failure from `addr`; `false` when the address is at its budget already (the
    /// caller refuses with 429 and writes nothing).
    pub fn count(&self, addr: &str, now: i64) -> bool {
        let threshold = crate::store::gov::ADDRESS.threshold;
        self.with(addr, now, |s| {
            let ok = s.0 < threshold;
            s.0 += i64::from(ok);
            ok
        })
        .unwrap_or(false)
    }

    /// Takes one evaluation slot for `addr` (a pairing claim): `false` when its failures plus
    /// the claims in flight reach the budget. Give it back with `release`.
    pub fn reserve(&self, addr: &str, now: i64) -> bool {
        let threshold = crate::store::gov::ADDRESS.threshold;
        self.with(addr, now, |s| {
            let ok = s.0 + s.2 < threshold;
            s.2 += i64::from(ok);
            ok
        })
        .unwrap_or(false)
    }

    /// Gives back a slot from `reserve`, counting it as a failure when `failed`.
    pub fn release(&self, addr: &str, failed: bool, now: i64) {
        self.with(addr, now, |s| {
            s.2 = (s.2 - 1).max(0);
            s.0 += i64::from(failed);
        });
    }
}

pub struct Auth {
    pub identity: Arc<Identity>,
    sessions: Mutex<HashMap<String, Session>>,
    /// challenge → (device it was issued for, expiry, issue order).
    challenges: Mutex<HashMap<String, (String, i64, u64)>>,
    issued: std::sync::atomic::AtomicU64,
    /// device → nonce → expiry.
    nonces: Mutex<HashMap<String, HashMap<String, i64>>>,
    revoked: broadcast::Sender<String>,
    /// Challenge issuance per address: 30 a minute (§11).
    pub challenge_limit: Limiter,
    /// Authentication failures per address, in memory (`AddressFailures`).
    pub failures: AddressFailures,
}

impl Auth {
    pub fn new(identity: Arc<Identity>) -> Self {
        Self {
            identity,
            sessions: Mutex::default(),
            challenges: Mutex::default(),
            issued: std::sync::atomic::AtomicU64::new(0),
            nonces: Mutex::default(),
            revoked: broadcast::channel(64).0,
            challenge_limit: Limiter::new(30, 0.5),
            failures: AddressFailures::default(),
        }
    }

    /// A new challenge for `device`. Only a `known` (usable) device gets one stored, at most
    /// `CHALLENGES_PER_DEVICE` live (a new one replaces its oldest); an unknown id gets an
    /// equally random challenge that is never stored, so a flood of made-up ids allocates
    /// nothing. `None` only when the global safety cap is full of live challenges.
    pub fn challenge(&self, device: &str, known: bool, now: i64) -> Option<String> {
        let c = crypto::b64(&crypto::random::<32>());
        if !known {
            return Some(c);
        }
        let mut live = self.challenges.lock().unwrap();
        live.retain(|_, (_, exp, _)| *exp > now);
        let mut mine: Vec<(u64, String)> = live
            .iter()
            .filter(|(_, (d, _, _))| d == device)
            .map(|(k, (_, _, n))| (*n, k.clone()))
            .collect();
        if mine.len() >= CHALLENGES_PER_DEVICE {
            mine.sort();
            for (_, k) in &mine[..=mine.len() - CHALLENGES_PER_DEVICE] {
                live.remove(k);
            }
        }
        if live.len() >= CHALLENGES_MAX {
            return None;
        }
        let n = self
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        live.insert(c.clone(), (device.to_owned(), now + CHALLENGE_SECS, n));
        Some(c)
    }

    /// Spends `challenge` if it is live and was issued for `device`. A challenge issued for
    /// another device is left alone (only its own device may spend it).
    pub fn take_challenge(&self, challenge: &str, device: &str, now: i64) -> bool {
        let mut live = self.challenges.lock().unwrap();
        match live.get(challenge) {
            Some((_, exp, _)) if *exp <= now => {
                live.remove(challenge);
                false
            }
            Some((d, _, _)) if d == device => {
                live.remove(challenge);
                true
            }
            _ => false,
        }
    }

    /// A new 15-minute session for `device`.
    pub fn issue_session(&self, device: &str, now: i64) -> Session {
        let session = Session {
            id: crypto::random_id("s_"),
            device: device.to_owned(),
            created: now,
            expires: now + SESSION_SECS,
            elevated_until: None,
        };
        let mut all = self.sessions.lock().unwrap();
        all.retain(|_, s| s.expires > now);
        let mut mine: Vec<(i64, String)> = all
            .values()
            .filter(|s| s.device == device)
            .map(|s| (s.created, s.id.clone()))
            .collect();
        if mine.len() >= SESSIONS_PER_DEVICE {
            mine.sort();
            for (_, id) in &mine[..=mine.len() - SESSIONS_PER_DEVICE] {
                all.remove(id);
            }
        }
        all.insert(session.id.clone(), session.clone());
        session
    }

    /// The live session `id` of `device`.
    pub fn session(&self, id: &str, device: &str, now: i64) -> Option<Session> {
        let all = self.sessions.lock().unwrap();
        all.get(id)
            .filter(|s| s.device == device && s.expires > now)
            .cloned()
    }

    /// Records `(device, nonce)`; refused when seen within `REPLAY_TTL`, or when the device
    /// already holds `REPLAY_MAX` live nonces.
    pub fn take_nonce(&self, device: &str, nonce: &str, now: i64) -> Result<(), Replay> {
        let mut all = self.nonces.lock().unwrap();
        let mine = all.entry(device.to_owned()).or_default();
        if mine.get(nonce).is_some_and(|exp| *exp > now) {
            return Err(Replay::Seen);
        }
        if mine.len() >= REPLAY_MAX {
            mine.retain(|_, exp| *exp > now);
            if mine.len() >= REPLAY_MAX {
                return Err(Replay::Full);
            }
        }
        mine.insert(nonce.to_owned(), now + REPLAY_TTL);
        Ok(())
    }

    /// Fans out a committed revocation: drops the device's sessions, then tells its sockets.
    pub fn revoked(&self, device: &str) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, s| s.device != device);
        // No receiver is fine: no socket is open.
        let _ = self.revoked.send(device.to_owned());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.revoked.subscribe()
    }
}

/// Resolves once `device` is revoked or otherwise no longer usable: at once on the broadcast,
/// or within `every` by polling the database (a revocation by the CLI, from another process,
/// or a broadcast that lagged). A database error keeps waiting; the next poll retries.
pub async fn until_revoked(
    pool: SqlitePool,
    mut revoked: broadcast::Receiver<String>,
    device: String,
    every: Duration,
) {
    let mut poll = tokio::time::interval(every);
    let mut open = true;
    loop {
        tokio::select! {
            got = revoked.recv(), if open => match got {
                Ok(d) if d == device => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                // The sender is gone; the poll still runs.
                Err(broadcast::error::RecvError::Closed) => open = false,
            },
            _ = poll.tick() => {
                if let Ok(false) = crate::store::gov::device_usable(&pool, &device).await {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::new(Arc::new(Identity::ephemeral()))
    }

    #[test]
    fn challenges_are_single_use_bound_and_expire() {
        let a = auth();
        let c = a.challenge("d_a", true, 100).unwrap();
        assert!(!a.take_challenge(&c, "d_b", 100), "another device's");
        assert!(a.take_challenge(&c, "d_a", 100));
        assert!(!a.take_challenge(&c, "d_a", 100), "single use");
        let c = a.challenge("d_a", true, 100).unwrap();
        assert!(!a.take_challenge(&c, "d_a", 160), "expired at 60 s");
        let unknown = a.challenge("d_x", false, 100).unwrap();
        assert!(!a.take_challenge(&unknown, "d_x", 100), "never stored");
        let first = a.challenge("d_a", true, 200).unwrap();
        for _ in 0..CHALLENGES_PER_DEVICE {
            a.challenge("d_a", true, 200).unwrap();
        }
        assert!(
            !a.take_challenge(&first, "d_a", 200),
            "the oldest was replaced"
        );
        assert_eq!(a.challenges.lock().unwrap().len(), CHALLENGES_PER_DEVICE);
    }

    #[test]
    fn sessions_expire_and_are_dropped_on_revocation() {
        let a = auth();
        let s = a.issue_session("d_a", 1000);
        assert!(a.session(&s.id, "d_a", 1000 + SESSION_SECS - 1).is_some());
        assert!(a.session(&s.id, "d_a", 1000 + SESSION_SECS).is_none());
        assert!(a.session(&s.id, "d_b", 1000).is_none(), "another device's");
        a.revoked("d_a");
        assert!(a.session(&s.id, "d_a", 1000).is_none());
        let first = a.issue_session("d_a", 1).id;
        for t in 2..=SESSIONS_PER_DEVICE as i64 + 1 {
            a.issue_session("d_a", t);
        }
        assert!(a.session(&first, "d_a", 10).is_none(), "the oldest went");
    }

    #[test]
    fn address_failures_are_counted_and_reserved_under_one_lock() {
        let f = AddressFailures::default();
        for _ in 0..20 {
            assert!(f.count("a", 0));
        }
        assert!(!f.count("a", 1), "at the budget");
        assert!(f.count("b", 1), "per address");
        assert!(f.count("a", 600), "a new window");
        for _ in 0..19 {
            assert!(f.reserve("c", 0));
        }
        assert!(f.count("c", 0));
        assert!(!f.reserve("c", 0), "19 in flight + 1 failure");
        f.release("c", false, 0);
        assert!(f.reserve("c", 0), "a slot came back");
    }

    #[test]
    fn nonces_are_refused_twice_then_free_and_capped() {
        let a = auth();
        assert_eq!(a.take_nonce("d_a", "n", 0), Ok(()));
        assert_eq!(a.take_nonce("d_a", "n", 1), Err(Replay::Seen));
        assert_eq!(a.take_nonce("d_b", "n", 1), Ok(()), "per device");
        assert_eq!(a.take_nonce("d_a", "n", REPLAY_TTL), Ok(()), "aged out");
        for i in 0..REPLAY_MAX {
            let _ = a.take_nonce("d_c", &i.to_string(), 0);
        }
        assert_eq!(a.take_nonce("d_c", "x", 1), Err(Replay::Full));
        assert_eq!(a.take_nonce("d_c", "x", REPLAY_TTL + 1), Ok(()));
    }
}
