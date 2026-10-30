//! Device authentication state (handshake spec §5, §6, §10), all in memory and all per
//! process, so a restart forgets it: the Core identity key's public half aside, nothing here
//! survives. That is what closes replay across a restart (§6.4).
//!
//! - **Challenges** (`POST /handshake/challenge`): 32 bytes, 60 s, single use, bound to the
//!   device id they were asked for. Stateless (handshake-hardening review M1): expiry, 12 random
//!   bytes and an HMAC under a per-process key over both and the device id, so issuing one stores
//!   nothing and no flood of requests can crowd out a device's own. Only a spent challenge is
//!   kept, until it expires, and only after its session signature verified.
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
/// Domain of a challenge's HMAC (nothing else uses the per-process challenge key).
const CHALLENGE_DOMAIN: &[u8] = b"AINKRAD-CHALLENGE-V1\n";
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
    /// The per-process key challenges are MACed under: a restart invalidates every challenge.
    challenge_key: ring::hmac::Key,
    /// Spent challenges → their expiry (single use); pruned as they expire.
    spent: Mutex<HashMap<String, i64>>,
    /// Issue order of WebSocket tickets (`ticket`).
    issued: std::sync::atomic::AtomicU64,
    /// device → nonce → expiry.
    nonces: Mutex<HashMap<String, HashMap<String, i64>>>,
    revoked: broadcast::Sender<String>,
    /// Challenge issuance per address: 30 a minute (§11).
    pub challenge_limit: Limiter,
    /// Authentication failures per address, in memory (`AddressFailures`).
    pub failures: AddressFailures,
    /// Token-route failures per address (`gateway::token`): apart from `failures`, so a harness
    /// guessing tokens cannot lock its own host out of the signed API.
    pub token_failures: AddressFailures,
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
            challenge_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &crypto::random::<32>()),
            spent: Mutex::default(),
            issued: std::sync::atomic::AtomicU64::new(0),
            nonces: Mutex::default(),
            revoked: broadcast::channel(64).0,
            challenge_limit: Limiter::new(30, 0.5),
            failures: AddressFailures::default(),
            token_failures: AddressFailures::default(),
            pair_budget: PairBudget::default(),
            stepup_failures: StepUpFailures::default(),
            refusals: refusals::Refusals::default(),
            rescoped: broadcast::channel(64).0,
            tickets: Mutex::default(),
            ticket_limit: Limiter::new(ticket::PER_SESSION_BURST, ticket::PER_SESSION_PER_SEC),
        }
    }

    /// A challenge for `device`: `expiry (u32 BE) ‖ 12 random bytes ‖ HMAC[..16]` over
    /// `CHALLENGE_DOMAIN ‖ expiry ‖ random ‖ device`, base64url (43 characters). Nothing is stored,
    /// so every id, known or not, gets one the same way and no requester can starve another.
    pub fn challenge(&self, device: &str, now: i64) -> String {
        let mut c = [0u8; 32];
        // ponytail: u32 unix seconds, good until 2106.
        c[..4].copy_from_slice(&((now + CHALLENGE_SECS) as u32).to_be_bytes());
        c[4..16].copy_from_slice(&crypto::random::<12>());
        let tag = self.challenge_tag(&c[..16], device);
        c[16..].copy_from_slice(&tag.as_ref()[..16]);
        crypto::b64(&c)
    }

    fn challenge_tag(&self, head: &[u8], device: &str) -> ring::hmac::Tag {
        let mut m = CHALLENGE_DOMAIN.to_vec();
        m.extend_from_slice(head);
        m.extend_from_slice(device.as_bytes());
        ring::hmac::sign(&self.challenge_key, &m)
    }

    /// Spends `challenge` if this process issued it for `device`, it is live and not spent
    /// before. Call it only after the request's signature verified: a spend is the one thing
    /// stored, so only the device itself can add to it.
    pub fn take_challenge(&self, challenge: &str, device: &str, now: i64) -> bool {
        let Some(c) = crypto::unb64(challenge, 43) else {
            return false;
        };
        let expires = i64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        let tag = self.challenge_tag(&c[..16], device);
        if !pairing::ct_eq(&crypto::b64(&c[16..]), &crypto::b64(&tag.as_ref()[..16]))
            || expires <= now
        {
            return false;
        }
        let mut spent = self.spent.lock().unwrap();
        spent.retain(|_, exp| *exp > now);
        spent.insert(challenge.to_owned(), expires).is_none()
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

/// Resolves once `device`'s scopes are no longer `scopes`: at once on the broadcast, or within
/// the backstop by the shared device snapshot (`crate::live`: a change by another process, or a
/// lagged broadcast). A device missing from the snapshot is left to `until_revoked`.
pub async fn until_rescoped(
    mut devices: crate::live::DeviceWatch,
    mut rescoped: broadcast::Receiver<String>,
    device: String,
    scopes: Vec<String>,
) {
    let (mut open, mut live) = (true, true);
    loop {
        tokio::select! {
            got = rescoped.recv(), if open => match got {
                Ok(d) if d == device => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => open = false,
            },
            changed = devices.rx.changed(), if live => match changed {
                Ok(()) => {
                    if let Some(Some(d)) = devices.current(&device)
                        && d.scopes != scopes
                    {
                        return;
                    }
                }
                Err(_) => live = false,
            },
            else => std::future::pending().await,
        }
    }
}

/// Resolves once `device` is revoked or otherwise no longer usable: at once on the broadcast,
/// or within the backstop by the shared device snapshot (`crate::live`: a revocation by the
/// CLI, from another process, or a broadcast that lagged). A device with no row counts as
/// revoked; a failed read keeps the last snapshot.
pub async fn until_revoked(
    mut devices: crate::live::DeviceWatch,
    mut revoked: broadcast::Receiver<String>,
    device: String,
) {
    let (mut open, mut live) = (true, true);
    loop {
        tokio::select! {
            got = revoked.recv(), if open => match got {
                Ok(d) if d == device => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                // The sender is gone; the snapshot still runs.
                Err(broadcast::error::RecvError::Closed) => open = false,
            },
            changed = devices.rx.changed(), if live => match changed {
                Ok(()) => {
                    if let Some(state) = devices.current(&device)
                        && !state.is_some_and(|d| d.usable)
                    {
                        return;
                    }
                }
                Err(_) => live = false,
            },
            else => std::future::pending().await,
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
        let c = a.challenge("d_a", 100);
        assert_eq!(c.len(), 43, "32 bytes");
        assert!(!a.take_challenge(&c, "d_b", 100), "another device's");
        assert!(a.take_challenge(&c, "d_a", 100));
        assert!(!a.take_challenge(&c, "d_a", 100), "single use");
        let c = a.challenge("d_a", 100);
        assert!(!a.take_challenge(&c, "d_a", 160), "expired at 60 s");
        assert!(a.take_challenge(&c, "d_a", 159));
        let c = auth().challenge("d_a", 100);
        assert!(
            !a.take_challenge(&c, "d_a", 100),
            "another process's (a restart)"
        );
        let mut raw = crypto::unb64(&a.challenge("d_a", 100), 43).unwrap();
        raw[0] ^= 1;
        assert!(
            !a.take_challenge(&crypto::b64(&raw), "d_a", 100),
            "a tampered expiry"
        );
        raw[0] ^= 1;
        raw[31] ^= 1;
        assert!(
            !a.take_challenge(&crypto::b64(&raw), "d_a", 100),
            "a tampered tag"
        );
        assert!(!a.take_challenge("x", "d_a", 100), "not a challenge");
        assert!(a.spent.lock().unwrap().len() <= 2, "only spends are kept");
        assert!(a.take_challenge(&a.challenge("d_a", 300), "d_a", 300));
        assert_eq!(a.spent.lock().unwrap().len(), 1, "expired spends pruned");
    }

    /// Review M1 (handshake hardening): any number of challenges asked for a device, from any
    /// number of addresses, store nothing; the device's own still spends.
    #[test]
    fn a_challenge_flood_stores_nothing_and_cannot_starve_the_device() {
        let a = auth();
        let own = a.challenge("d_v", 100);
        for _ in 0..100_000 {
            a.challenge("d_v", 100);
        }
        assert!(a.spent.lock().unwrap().is_empty());
        assert!(a.take_challenge(&own, "d_v", 100), "spendable");
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

    /// A socket's loop stops polling its watcher whenever another branch wins (a read, a ping).
    /// A watcher parked mid-check must not keep a pool connection: four did, and starved the
    /// pool for every socket and request (E1-19). The check now runs on the shared poller's own
    /// task (`crate::live`), so many parked watchers never hold one, and still see a change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_parked_watcher_holds_no_pool_connection() {
        let dir = std::env::temp_dir().join(format!("core-auth-park-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::store::connect(&dir.join("core.db")).await.unwrap();
        let live = crate::live::Live::default();
        let (_tx, rx) = broadcast::channel(1);
        // Watchers polled in short bursts, then parked, again and again, while the snapshot
        // is read every millisecond.
        let mut watchers: Vec<_> = (0..50)
            .map(|_| {
                let w = until_revoked(
                    live.devices(&pool, Duration::from_millis(1)),
                    rx.resubscribe(),
                    "d_x".into(),
                );
                Some(Box::pin(w))
            })
            .collect();
        // Keep all but one connection, so a check can only take the last.
        let mut held = vec![];
        while held.len() + 1 < pool.options().get_max_connections() as usize {
            held.push(pool.acquire().await.unwrap());
        }
        // An unknown device counts as revoked: each watcher resolves on a snapshot read after it
        // subscribed, polled only in short bursts.
        for _ in 0..2_000 {
            for slot in &mut watchers {
                if let Some(w) = slot
                    && tokio::time::timeout(Duration::from_micros(50), w.as_mut())
                        .await
                        .is_ok()
                {
                    *slot = None;
                }
            }
            if watchers.iter().all(Option::is_none) {
                break;
            }
        }
        assert!(
            watchers.iter().all(Option::is_none),
            "every watcher saw the snapshot"
        );
        let got = tokio::time::timeout(Duration::from_secs(2), pool.acquire()).await;
        assert!(got.is_ok(), "a parked watcher kept a connection");
        drop(got);
        drop(held);
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
