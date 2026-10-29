//! Device authentication state (handshake spec §5, §6, §10), all in memory and all per
//! process, so a restart forgets it: the Core identity key's public half aside, nothing here
//! survives. That is what closes replay across a restart (§6.4).
//!
//! - **Challenges** (`POST /handshake/challenge`): 32 random bytes, 60 s, single use, bound to
//!   the device id they were asked for; at most 10,000 live.
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
pub const CHALLENGES_MAX: usize = 10_000;
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

pub struct Auth {
    pub identity: Arc<Identity>,
    sessions: Mutex<HashMap<String, Session>>,
    /// challenge → (device it was issued for, expiry).
    challenges: Mutex<HashMap<String, (String, i64)>>,
    /// device → nonce → expiry.
    nonces: Mutex<HashMap<String, HashMap<String, i64>>>,
    revoked: broadcast::Sender<String>,
    /// Challenge issuance per address: 30 a minute (§11).
    pub challenge_limit: Limiter,
}

impl Auth {
    pub fn new(identity: Arc<Identity>) -> Self {
        Self {
            identity,
            sessions: Mutex::default(),
            challenges: Mutex::default(),
            nonces: Mutex::default(),
            revoked: broadcast::channel(64).0,
            challenge_limit: Limiter::new(30, 0.5),
        }
    }

    /// A new challenge for `device`; `None` while 10,000 are live.
    pub fn challenge(&self, device: &str, now: i64) -> Option<String> {
        let mut live = self.challenges.lock().unwrap();
        if live.len() >= CHALLENGES_MAX {
            live.retain(|_, (_, exp)| *exp > now);
            if live.len() >= CHALLENGES_MAX {
                return None;
            }
        }
        let c = crypto::b64(&crypto::random::<32>());
        live.insert(c.clone(), (device.to_owned(), now + CHALLENGE_SECS));
        Some(c)
    }

    /// Spends `challenge` if it is live and was issued for `device`. A challenge issued for
    /// another device is left alone (only its own device may spend it).
    pub fn take_challenge(&self, challenge: &str, device: &str, now: i64) -> bool {
        let mut live = self.challenges.lock().unwrap();
        match live.get(challenge) {
            Some((_, exp)) if *exp <= now => {
                live.remove(challenge);
                false
            }
            Some((d, _)) if d == device => {
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
        let c = a.challenge("d_a", 100).unwrap();
        assert!(!a.take_challenge(&c, "d_b", 100), "another device's");
        assert!(a.take_challenge(&c, "d_a", 100));
        assert!(!a.take_challenge(&c, "d_a", 100), "single use");
        let c = a.challenge("d_a", 100).unwrap();
        assert!(!a.take_challenge(&c, "d_a", 160), "expired at 60 s");
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
