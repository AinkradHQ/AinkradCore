//! Local pacing, in memory, per connection. Two jobs, both so that what an agent does cannot take
//! the connection out of use for everyone:
//!
//! - **Cooling by family.** A 429 or `ratelimited` from a method says the BOT is asked too often
//!   for that method (`conversations.history` and `.replies` are one request a minute for a
//!   distributed app outside Slack's Marketplace). It is no verdict on the credential or the
//!   service, so it never reaches connection health. It sets a `not before` for that method's
//!   family on that connection, bounded by the `Retry-After` Slack gave (at most [`MAX_COOL_SECS`]);
//!   later calls to the family are refused here with no request, while the other families (posting,
//!   reacting, listing) go on. Only `auth.test` and `oauth.v2.access`, which no agent drives, keep
//!   a connection-wide signal.
//! - **Confirmed channels.** Every channel id is confirmed once with `conversations.info` (a
//!   channel, not a direct message or a group DM). A positive answer is remembered for
//!   [`CONFIRM_TTL`], so the confirmation does not spend the info tier on every call.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::http::Method;

/// A wait when Slack gave none.
pub const DEFAULT_COOL_SECS: u64 = 60;
/// The longest a `Retry-After` is believed here.
pub const MAX_COOL_SECS: u64 = 600;
/// How long a confirmed channel stays confirmed.
pub const CONFIRM_TTL: Duration = Duration::from_secs(300);
/// Confirmed channels remembered at most (all connections).
const MAX_CONFIRMED: usize = 512;

/// Methods that share a rate limit as far as this adapter cares. One family cooling never stops
/// another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// `conversations.history` and `conversations.replies`: the Tier 1 pair.
    History,
    /// `conversations.list`.
    List,
    /// `conversations.info`: the channel confirmation.
    Info,
    Users,
    Post,
    React,
}

impl Family {
    /// The family of `m`; `None` for the methods no agent drives (`auth.test`, `oauth.v2.access`).
    pub fn of(m: Method) -> Option<Self> {
        Some(match m {
            Method::ConversationsHistory | Method::ConversationsReplies => Self::History,
            Method::ConversationsList => Self::List,
            Method::ConversationsInfo => Self::Info,
            Method::UsersInfo => Self::Users,
            Method::ChatPostMessage => Self::Post,
            Method::ReactionsAdd => Self::React,
            Method::AuthTest | Method::OauthV2Access => return None,
        })
    }
}

pub struct Pace {
    cooling: Mutex<HashMap<(i64, Family), Instant>>,
    confirmed: Mutex<HashMap<(i64, String), Instant>>,
    ttl: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            cooling: Mutex::default(),
            confirmed: Mutex::default(),
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

    /// Seconds until `family` of connection `id` may be asked again; `None` when it may.
    pub fn wait(&self, id: i64, family: Family) -> Option<u64> {
        let now = Instant::now();
        let mut map = self.cooling.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&(id, family)).copied() {
            Some(until) if until > now => Some(secs_left(until, now)),
            Some(_) => {
                map.remove(&(id, family));
                None
            }
            None => None,
        }
    }

    /// Cools `family` of connection `id` for what Slack asked (a default when it said nothing),
    /// at least one second and at most [`MAX_COOL_SECS`]; returns the seconds. A cooling that
    /// already runs longer is kept.
    pub fn cool(&self, id: i64, family: Family, retry_after: Option<u64>) -> u64 {
        let secs = retry_after
            .unwrap_or(DEFAULT_COOL_SECS)
            .clamp(1, MAX_COOL_SECS);
        let now = Instant::now();
        let until = now + Duration::from_secs(secs);
        let mut map = self.cooling.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, t| *t > now);
        let slot = map.entry((id, family)).or_insert(until);
        *slot = (*slot).max(until);
        secs_left(*slot, now)
    }

    pub fn is_confirmed(&self, id: i64, channel: &str) -> bool {
        let now = Instant::now();
        let map = self.confirmed.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&(id, channel.to_owned())).is_some_and(|t| *t > now)
    }

    /// Remembers that `channel` is a channel for connection `id`.
    pub fn confirm(&self, id: i64, channel: &str) {
        let now = Instant::now();
        let mut map = self.confirmed.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, t| *t > now);
        if map.len() >= MAX_CONFIRMED {
            map.clear();
        }
        map.insert((id, channel.to_owned()), now + self.ttl);
    }
}
