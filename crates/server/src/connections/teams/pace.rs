//! Local pacing, in memory, per connection. Two jobs, both so that what an agent does cannot take
//! the connection out of use for everyone (one shared connection serves many users and channels,
//! while Microsoft limits about one request a second PER CHANNEL):
//!
//! - **Cooling by scope.** A 429 to a call an agent drives says that CHANNEL (or that list) is
//!   asked too often. It is no verdict on the credential or the service, so it never reaches
//!   connection health and never blocks the connection: it sets a not-before for that one scope,
//!   bounded by the `Retry-After` Microsoft gave (at least one second, at most [`MAX_COOL_SECS`],
//!   [`DEFAULT_COOL_SECS`] when it said nothing). Later calls to the scope are refused here with no
//!   request while every other channel goes on. Only `/me` and the token endpoint, which no agent
//!   drives, keep a connection-wide signal.
//! - **Confirmed channels.** Every channel is confirmed once with `GET /teams/{t}/channels/{c}`
//!   (it is in that team, in the connection's tenant, and not a shared channel). A positive answer
//!   is remembered for [`CONFIRM_TTL`] (at most [`MAX_CONFIRMED`] entries), so the confirmation
//!   does not spend a request on every call.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::http::CallError;

/// A wait when Microsoft gave none.
pub const DEFAULT_COOL_SECS: u64 = 60;
/// The longest a `Retry-After` is believed here.
pub const MAX_COOL_SECS: u64 = 600;
/// How long a confirmed channel stays confirmed.
pub const CONFIRM_TTL: Duration = Duration::from_secs(300);
/// Confirmed channels remembered at most (all connections).
pub const MAX_CONFIRMED: usize = 512;
/// How long a definitive refusal of a channel is remembered, and how many (all connections).
pub const DENY_TTL: Duration = Duration::from_secs(60);
pub const MAX_DENIED: usize = 512;

/// What cools together.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `list_teams`.
    Teams,
    /// `list_channels` of one team.
    Channels(String),
    /// Everything about one channel, by its limit key (`<team>/<middle>`).
    Channel(String),
}

pub struct Pace {
    cooling: Mutex<HashMap<(i64, Scope), Instant>>,
    confirmed: Mutex<HashMap<(i64, String), Instant>>,
    denied: Mutex<HashMap<(i64, String), (Instant, CallError)>>,
    ttl: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            cooling: Mutex::default(),
            confirmed: Mutex::default(),
            denied: Mutex::default(),
            ttl: CONFIRM_TTL,
        }
    }
}

fn secs_left(until: Instant, now: Instant) -> u64 {
    let d = until.saturating_duration_since(now);
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

impl Pace {
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            ..Self::default()
        }
    }

    /// Seconds until `scope` of connection `id` may be asked again; `None` when it may.
    pub fn wait(&self, id: i64, scope: &Scope) -> Option<u64> {
        let now = Instant::now();
        let mut map = self.cooling.lock().unwrap_or_else(|e| e.into_inner());
        let key = (id, scope.clone());
        match map.get(&key).copied() {
            Some(until) if until > now => Some(secs_left(until, now)),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Cools `scope` of connection `id` for what Microsoft asked (a default when it said
    /// nothing), at least one second and at most [`MAX_COOL_SECS`]; returns the seconds. A
    /// cooling that already runs longer is kept.
    pub fn cool(&self, id: i64, scope: &Scope, retry_after: Option<u64>) -> u64 {
        let secs = retry_after
            .unwrap_or(DEFAULT_COOL_SECS)
            .clamp(1, MAX_COOL_SECS);
        let now = Instant::now();
        let until = now + Duration::from_secs(secs);
        let mut map = self.cooling.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, t| *t > now);
        let slot = map.entry((id, scope.clone())).or_insert(until);
        *slot = (*slot).max(until);
        secs_left(*slot, now)
    }

    /// The refusal remembered for `pair` (`<team>/<channel>` as asked) on connection `id`, while
    /// it lasts.
    pub fn denied(&self, id: i64, pair: &str) -> Option<CallError> {
        let now = Instant::now();
        let map = self.denied.lock().unwrap_or_else(|e| e.into_inner());
        let (until, e) = map.get(&(id, pair.to_owned()))?;
        (*until > now).then(|| e.clone())
    }

    /// Remembers a DEFINITIVE refusal (not found, forbidden, wrong team, shared): never a
    /// transient error, which the caller does not pass here.
    pub fn deny(&self, id: i64, pair: &str, e: &CallError) {
        let now = Instant::now();
        let mut map = self.denied.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (t, _)| *t > now);
        if map.len() >= MAX_DENIED {
            map.clear();
        }
        map.insert((id, pair.to_owned()), (now + DENY_TTL, e.clone()));
    }

    pub fn is_confirmed(&self, id: i64, key: &str) -> bool {
        let now = Instant::now();
        let map = self.confirmed.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&(id, key.to_owned())).is_some_and(|t| *t > now)
    }

    /// Remembers that channel `key` is a plain channel of its team for connection `id`.
    pub fn confirm(&self, id: i64, key: &str) {
        let now = Instant::now();
        let mut map = self.confirmed.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, t| *t > now);
        if map.len() >= MAX_CONFIRMED {
            map.clear();
        }
        map.insert((id, key.to_owned()), now + self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_cools_alone_and_within_bounds() {
        let p = Pace::default();
        let (a, b) = (Scope::Channel("t/a".into()), Scope::Channel("t/b".into()));
        assert_eq!(p.wait(1, &a), None);
        assert_eq!(p.cool(1, &a, Some(17)), 17);
        assert_eq!(p.wait(1, &a), Some(17));
        assert_eq!(p.wait(1, &b), None, "another channel is not held");
        assert_eq!(p.wait(2, &a), None, "another connection is not held");
        assert_eq!(p.cool(1, &b, None), DEFAULT_COOL_SECS);
        assert_eq!(p.cool(1, &Scope::Teams, Some(0)), 1, "at least a second");
        assert_eq!(p.cool(1, &Scope::Teams, Some(99_999)), MAX_COOL_SECS);
        assert_eq!(p.cool(1, &a, Some(5)), 17, "a longer cooling is kept");
    }

    #[test]
    fn a_refusal_is_remembered_per_connection_and_capped() {
        let p = Pace::default();
        assert_eq!(p.denied(1, "t/c"), None);
        p.deny(1, "t/c", &CallError::NotFound);
        assert_eq!(p.denied(1, "t/c"), Some(CallError::NotFound));
        assert_eq!(p.denied(2, "t/c"), None);
        assert_eq!(p.denied(1, "t/d"), None);
        for i in 0..=MAX_DENIED {
            p.deny(1, &format!("t/{i}"), &CallError::Forbidden);
        }
        assert!(p.denied.lock().unwrap().len() <= MAX_DENIED);
    }

    #[test]
    fn confirmations_expire_and_are_capped() {
        let p = Pace::with_ttl(Duration::from_millis(30));
        p.confirm(1, "t/a");
        assert!(p.is_confirmed(1, "t/a") && !p.is_confirmed(2, "t/a"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!p.is_confirmed(1, "t/a"));
        let p = Pace::default();
        for i in 0..=MAX_CONFIRMED {
            p.confirm(1, &format!("t/{i}"));
        }
        let held = p.confirmed.lock().unwrap().len();
        assert!(held <= MAX_CONFIRMED, "{held}");
    }
}
