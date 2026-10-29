//! Device authentication state (handshake spec §5, §6, §10), all in memory and all per
//! process, so a restart forgets it: the Core identity key's public half aside, nothing here
//! survives. That is what closes replay across a restart (§6.4).
//!
//! - **Challenges** (`POST /handshake/challenge`): 32 random bytes, 60 s, single use, bound to
//!   the device id they were asked for; stored only for a usable device, at most 3 per
//!   (device, address) and 256 per device, and no address evicts another's (review M1, N3).
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

pub mod budget;
pub mod crypto;
pub mod identity;
pub mod pairing;
pub mod refusals;
pub mod signed;
pub mod stepup;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod ticket;
pub mod web;

pub use budget::{AddressFailures, PairBudget};
pub use identity::Identity;
pub use stepup::{Assertion, AssertionProof, Proof, StepUpFailures};

/// `|now − timestamp|` allowed, seconds.
pub const SKEW: i64 = 60;
pub const REPLAY_TTL: i64 = 125;
pub const REPLAY_MAX: usize = 4096;
pub const SESSION_SECS: i64 = 15 * 60;
pub const CHALLENGE_SECS: i64 = 60;
/// A safety net only: unknown ids allocate nothing, so this holds a few per real device.
pub const CHALLENGES_MAX: usize = 10_000;
/// Live challenges per (device, requesting address); a new one replaces that pair's oldest.
pub const CHALLENGES_PER_PAIR: usize = 3;
/// Live challenges per device, all addresses together.
pub const CHALLENGES_PER_DEVICE: usize = 256;

/// A stored challenge: the device it was issued for and the address that asked.
struct Challenge {
    device: String,
    addr: String,
    expires: i64,
    order: u64,
}
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
    /// Until when (unix seconds) the session is elevated by a step-up (§8, `stepup`).
    pub elevated_until: Option<i64>,
    /// The session's one live step-up challenge and its expiry; a new one replaces it.
    pub stepup_challenge: Option<(String, i64)>,
    /// A web session's request key (spec §9): the browser's WebCrypto P-256 key as an SPKI,
    /// bound by the passkey sign-in. Every request of the session is signed with it; `None` for
    /// a native device, which signs with its routine key.
    pub key: Option<Vec<u8>>,
}

impl Session {
    /// Whether a step-up still holds at `now`.
    pub fn elevated(&self, now: i64) -> bool {
        self.elevated_until.is_some_and(|t| t > now)
    }
}

/// Why a nonce was not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum Replay {
    Seen,
    Full,
}

pub struct Auth {
    pub identity: Arc<Identity>,
    sessions: Mutex<HashMap<String, Session>>,
    /// challenge → who asked and until when.
    challenges: Mutex<HashMap<String, Challenge>>,
    issued: std::sync::atomic::AtomicU64,
    /// device → nonce → expiry.
    nonces: Mutex<HashMap<String, HashMap<String, i64>>>,
    revoked: broadcast::Sender<String>,
    /// Challenge issuance per address: 30 a minute (§11).
    pub challenge_limit: Limiter,
    /// Authentication failures per address, in memory (`AddressFailures`).
    pub failures: AddressFailures,
    /// The global wrong-claim budget (`PairBudget`).
    pub pair_budget: PairBudget,
    /// Failed step-up proofs per device (`stepup`).
    pub stepup_failures: StepUpFailures,
    /// Refusals counted instead of audited one row each (`refusals`).
    pub refusals: refusals::Refusals,
    /// Devices whose scopes changed: their sockets close with 4003 (§10).
    rescoped: broadcast::Sender<String>,
    /// One-time WebSocket tickets (`ticket`).
    tickets: Mutex<HashMap<String, ticket::Ticket>>,
    /// Ticket issuance per session (`ticket`).
    pub ticket_limit: Limiter,
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
            pair_budget: PairBudget::default(),
            stepup_failures: StepUpFailures::default(),
            refusals: refusals::Refusals::default(),
            rescoped: broadcast::channel(64).0,
            tickets: Mutex::default(),
            ticket_limit: Limiter::new(ticket::PER_SESSION_BURST, ticket::PER_SESSION_PER_SEC),
        }
    }

    /// A new challenge for `device`, asked from `addr`. Only a `known` (usable) device gets one
    /// stored: at most `CHALLENGES_PER_PAIR` per (device, address), a new one replacing that
    /// pair's oldest, and `CHALLENGES_PER_DEVICE` in all. At the device's total the address
    /// holding the most gives up its oldest (`evict_from_top_holder`, review R2); when none holds
    /// more than the newcomer, the newcomer's challenge is not stored, so only its own session
    /// attempt fails and no address loses its last challenge (review N3). An unknown id gets an equally random challenge that
    /// is never stored. `None` only when the global safety cap is full of live challenges.
    pub fn challenge(&self, device: &str, addr: &str, known: bool, now: i64) -> Option<String> {
        let c = crypto::b64(&crypto::random::<32>());
        if !known {
            return Some(c);
        }
        let mut live = self.challenges.lock().unwrap();
        live.retain(|_, ch| ch.expires > now);
        let mut pair: Vec<(u64, String)> = live
            .iter()
            .filter(|(_, ch)| ch.device == device && ch.addr == addr)
            .map(|(k, ch)| (ch.order, k.clone()))
            .collect();
        if pair.len() >= CHALLENGES_PER_PAIR {
            pair.sort();
            for (_, k) in &pair[..=pair.len() - CHALLENGES_PER_PAIR] {
                live.remove(k);
            }
        }
        let device_total = live.values().filter(|ch| ch.device == device).count();
        if device_total >= CHALLENGES_PER_DEVICE && !evict_from_top_holder(&mut live, device, addr)
        {
            return Some(c);
        }
        if live.len() >= CHALLENGES_MAX {
            return None;
        }
        let order = self
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ch = Challenge {
            device: device.to_owned(),
            addr: addr.to_owned(),
            expires: now + CHALLENGE_SECS,
            order,
        };
        live.insert(c.clone(), ch);
        Some(c)
    }

    /// Spends `challenge` if it is live and was issued for `device`. A challenge issued for
    /// another device is left alone (only its own device may spend it).
    pub fn take_challenge(&self, challenge: &str, device: &str, now: i64) -> bool {
        let mut live = self.challenges.lock().unwrap();
        match live.get(challenge) {
            Some(ch) if ch.expires <= now => {
                live.remove(challenge);
                false
            }
            Some(ch) if ch.device == device => {
                live.remove(challenge);
                true
            }
            _ => false,
        }
    }

    /// A new 15-minute session for `device`. It carries over the elevation of the device's
    /// newest live session (§6.2), never extended.
    pub fn issue_session(&self, device: &str, now: i64) -> Session {
        self.issue(device, None, now, now + SESSION_SECS)
    }

    /// A web session for passkey device `device` (spec §9): signed with the browser's `key`,
    /// live until `expires` (absolute, never extended). Otherwise as `issue_session`.
    pub fn issue_web_session(&self, device: &str, key: Vec<u8>, now: i64, expires: i64) -> Session {
        self.issue(device, Some(key), now, expires)
    }

    fn issue(&self, device: &str, key: Option<Vec<u8>>, now: i64, expires: i64) -> Session {
        let mut all = self.sessions.lock().unwrap();
        all.retain(|_, s| s.expires > now);
        let elevated_until = all
            .values()
            .filter(|s| s.device == device)
            .max_by_key(|s| s.created)
            .and_then(|s| s.elevated_until)
            .filter(|t| *t > now);
        let session = Session {
            id: crypto::random_id("s_"),
            device: device.to_owned(),
            created: now,
            expires,
            elevated_until,
            stepup_challenge: None,
            key,
        };
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
        self.tickets
            .lock()
            .unwrap()
            .retain(|_, t| t.device != device);
        // No receiver is fine: no socket is open.
        let _ = self.revoked.send(device.to_owned());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.revoked.subscribe()
    }

    /// Tells `device`'s sockets that its scopes changed (after the change commits).
    pub fn rescoped(&self, device: &str) {
        // No receiver is fine: no socket is open.
        let _ = self.rescoped.send(device.to_owned());
    }

    pub fn subscribe_rescoped(&self) -> broadcast::Receiver<String> {
        self.rescoped.subscribe()
    }
}

/// At `device`'s challenge cap: removes the oldest challenge of the address holding the most of
/// the device's challenges, when it holds at least 2 and more than `addr` does (review R2). So
/// addresses each asking 3 cannot starve the device's own address, and no address ever loses its
/// last challenge to another. `false` when nothing was removed (the newcomer's is not stored).
/// ponytail: about 256 addresses holding one challenge each (one IPv6 /48) still fill the cap;
/// aggregate per /48 if that is ever seen.
fn evict_from_top_holder(live: &mut HashMap<String, Challenge>, device: &str, addr: &str) -> bool {
    let mut per_addr: HashMap<&str, (usize, u64, &str)> = HashMap::new();
    for (k, ch) in live.iter().filter(|(_, ch)| ch.device == device) {
        let e = per_addr.entry(&ch.addr).or_insert((0, u64::MAX, ""));
        e.0 += 1;
        if ch.order < e.1 {
            (e.1, e.2) = (ch.order, k);
        }
    }
    let mine = per_addr.get(addr).map_or(0, |e| e.0);
    let top = per_addr
        .values()
        .max_by_key(|(n, oldest, _)| (*n, std::cmp::Reverse(*oldest)));
    match top {
        Some(&(n, _, key)) if n >= 2 && n > mine => {
            let key = key.to_owned();
            live.remove(&key);
            true
        }
        _ => false,
    }
}

/// Resolves once `device`'s scopes are no longer `scopes`: at once on the broadcast, or within
/// `every` by polling the database (a change by another process, or a lagged broadcast).
pub async fn until_rescoped(
    pool: SqlitePool,
    mut rescoped: broadcast::Receiver<String>,
    device: String,
    scopes: Vec<String>,
    every: Duration,
) {
    let mut poll = tokio::time::interval(every);
    let mut open = true;
    loop {
        tokio::select! {
            got = rescoped.recv(), if open => match got {
                Ok(d) if d == device => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => open = false,
            },
            _ = poll.tick() => {
                if let Ok(Some(d)) = crate::store::gov::get_device(&pool, &device).await
                    && d.scopes != scopes
                {
                    return;
                }
            }
        }
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
        let c = a.challenge("d_a", "ip:a", true, 100).unwrap();
        assert!(!a.take_challenge(&c, "d_b", 100), "another device's");
        assert!(a.take_challenge(&c, "d_a", 100));
        assert!(!a.take_challenge(&c, "d_a", 100), "single use");
        let c = a.challenge("d_a", "ip:a", true, 100).unwrap();
        assert!(!a.take_challenge(&c, "d_a", 160), "expired at 60 s");
        let unknown = a.challenge("d_x", "ip:a", false, 100).unwrap();
        assert!(!a.take_challenge(&unknown, "d_x", 100), "never stored");
        let first = a.challenge("d_a", "ip:a", true, 200).unwrap();
        for _ in 0..CHALLENGES_PER_PAIR {
            a.challenge("d_a", "ip:a", true, 200).unwrap();
        }
        assert!(
            !a.take_challenge(&first, "d_a", 200),
            "the pair's oldest was replaced"
        );
        assert_eq!(a.challenges.lock().unwrap().len(), CHALLENGES_PER_PAIR);
        // Other addresses never push out ip:a's challenge, however many ask.
        let mine = a.challenge("d_a", "ip:a", true, 300).unwrap();
        for i in 0..CHALLENGES_PER_DEVICE * 2 {
            a.challenge("d_a", &format!("ip:x{i}"), true, 300).unwrap();
        }
        assert!(a.take_challenge(&mine, "d_a", 300), "still live");
    }

    /// R2: 100 addresses asking 3 challenges each for a device fill its 256; the device's own
    /// address still gets one that it can spend.
    #[test]
    fn addresses_filling_a_devices_challenges_do_not_starve_it() {
        let a = auth();
        for round in 0..2 {
            for i in 0..100 {
                for _ in 0..CHALLENGES_PER_PAIR {
                    a.challenge("d_v", &format!("ip:10.0.{round}.{i}"), true, 100)
                        .unwrap();
                }
            }
        }
        let count = |a: &Auth| {
            let live = a.challenges.lock().unwrap();
            live.values().filter(|c| c.device == "d_v").count()
        };
        assert_eq!(count(&a), CHALLENGES_PER_DEVICE, "full");
        let own = a.challenge("d_v", "ip:victim", true, 100).unwrap();
        assert_eq!(count(&a), CHALLENGES_PER_DEVICE, "still capped");
        // The attackers keep asking; the victim's stays (it holds 1, they hold up to 3).
        for i in 0..100 {
            a.challenge("d_v", &format!("ip:10.0.0.{i}"), true, 101)
                .unwrap();
        }
        assert!(a.take_challenge(&own, "d_v", 101), "spendable");
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
