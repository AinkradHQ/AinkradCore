//! The account allocator (KAN-437, S4; design `2026-11-06-core-account-scheduler` §5): which
//! account a session draws from its chain's pools. [`pick_in`] runs inside the write transaction
//! that also holds the session's row, so the cap count, the choice, the budget hold and the
//! assignment are ONE write: two sessions cannot take the last slot of a cap (I4), and a pick that
//! rolls back takes its hold with it.
//!
//! - **Order.** The chain from `from_pos`; the first entry with an account to give wins. In a pool:
//!   least loaded, then least recently used (never used first), then seat order.
//! - **A candidate** is in no `used_accounts`, belongs to the session's user (I5), is leasable to
//!   its runner (the broker secret's scope), is `active` (a window that has ended is recovered
//!   first, audited: [`recover_in`](super::health::recover_in)), has no pending auth signal, is under
//!   its cap, and for an API key has the budget room for one turn. An unhealthy account with no end
//!   (`auth_suspected`), a disabled one or an admin's own state never comes back by itself, so it
//!   is no reason to wait.
//! - **A subscription's plan limit** needs no check of its own here: S3 cools the account until the
//!   window resets when the snapshot arrives, so it is `cooling` with that `state_until`.
//! - **Wait or give up.** When no entry has an account but one has an account that cools, the pick
//!   is `Wait(until)` if the earliest window ends within `wait_max_secs`, else `Exhausted` with one
//!   reason per entry (counts only: never an account's label or key).
//! - **Nothing here starts a session.** The assignment writes the row; the supervisor launches it.

use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

use super::agents::SessionSecret;
use super::gateway::{self as gw, Hold};
use crate::scheduler::{iso_of_unix, unix_secs};

mod assign;
mod candidates;
mod live;
pub use assign::*;
pub use candidates::room_in;
pub use live::*;

/// A pick waits at most this long for a cooling account: the default of `scheduler.wait_max_secs`.
pub const WAIT_MAX_SECS: i64 = 15 * 60;

/// One step of a chain: a pool, and the harness and model its accounts run. (Chains themselves, and
/// how a session names one, are S5; the snapshot is the JSON of these in `core_agent_sessions.chain`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub pool: i64,
    pub provider: String,
    pub harness: String,
    #[serde(default)]
    pub model: Option<String>,
}

/// What to pick for.
pub struct Ask<'a> {
    /// The session the pick is for (its hold is keyed by it; its row, if it exists, is written).
    pub session: &'a str,
    pub runner: &'a str,
    /// The session's user: only this user's accounts are candidates.
    pub user: i64,
    pub chain: &'a [Entry],
    pub from_pos: usize,
    pub used_accounts: &'a [i64],
    pub skip_pools: &'a [i64],
    /// What one turn of the entry's model needs, in micro-dollars (`gateway::min_turn_usd`).
    pub min_turn: &'a (dyn Fn(&Entry) -> u64 + Sync),
    /// Why the runner cannot serve the entry, if it cannot (`placement_refusal_with`).
    pub serves: &'a (dyn Fn(&Entry) -> Option<String> + Sync),
    pub wait_max_secs: i64,
}

/// The account chosen, and what the session runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picked {
    pub account: i64,
    pub pool: i64,
    pub pos: usize,
    pub provider: String,
    pub harness: String,
    pub model: Option<String>,
    /// The account's own secret, as the session names it.
    pub secret: SessionSecret,
    /// An API key: served by the gateway (`gateway_account_id` is set, its hold is taken).
    pub gateway: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Picked(Picked),
    /// Nothing now; the earliest window ends at this unix second, within `wait_max_secs`.
    Wait {
        until: i64,
        why: String,
    },
    /// The session is not `starting` any more (it ended or was stopped): nothing was taken.
    Gone,
    /// Nothing, and nothing soon: one reason per entry that was looked at (chain position, why).
    Exhausted(Vec<(usize, String)>),
}

const WAITING: &str = "every account the chain can use is cooling, limited or at its cap";

/// Picks an account for `ask.session`, in the caller's write transaction. A session that already
/// holds an account (a retry after a commit) gets it back, with no second hold.
pub async fn pick_in(
    conn: &mut SqliteConnection,
    ask: &Ask<'_>,
    now: &str,
) -> Result<Outcome, sqlx::Error> {
    let Some(now_u) = unix_secs(now) else {
        return Ok(Outcome::Exhausted(vec![(
            0,
            "the clock is unreadable".into(),
        )]));
    };
    if let Some(p) = assign::existing_in(conn, ask).await? {
        return Ok(Outcome::Picked(p));
    }
    // A session stopped since the caller read it takes no hold and no account.
    if assign::state_in(conn, ask.session)
        .await?
        .is_some_and(|s| s != "starting")
    {
        return Ok(Outcome::Gone);
    }
    let (mut reasons, mut earliest, mut full) = (Vec::new(), None::<i64>, false);
    for pos in ask.from_pos..ask.chain.len() {
        let e = &ask.chain[pos];
        if let Some(why) = (ask.serves)(e) {
            reasons.push((pos, format!("the runner cannot serve it: {why}")));
            continue;
        }
        if ask.skip_pools.contains(&e.pool) {
            reasons.push((pos, "its pool's budget is spent".to_owned()));
            continue;
        }
        let auth_var = match candidates::auth_var(conn, e).await? {
            Ok(v) => v,
            Err(why) => {
                reasons.push((pos, why));
                continue;
            }
        };
        let mut found = candidates::of_entry(conn, ask, e, now, now_u).await?;
        earliest = [earliest, found.until].into_iter().flatten().min();
        full |= found.full;
        found
            .ready
            .sort_by(|a, b| (a.live, &a.last, a.seat).cmp(&(b.live, &b.last, b.seat)));
        let gateway = !super::account_keys::subscription_provider(&e.provider);
        for c in std::mem::take(&mut found.ready) {
            // An API key takes its hold with the pick; a denial (a session limit, a race of two
            // budgets) leaves the next account a turn.
            if gateway {
                let min = (ask.min_turn)(e);
                match gw::reserve_in(conn, ask.session, c.id, min, now).await {
                    Ok(Hold::Granted(_)) => {}
                    Ok(Hold::Denied(_)) | Err(super::secrets::Error::Refused { .. }) => {
                        found.tally.hold_denied += 1;
                        continue;
                    }
                    Err(super::secrets::Error::Db(e)) => return Err(e),
                }
            }
            sqlx::query("UPDATE core_accounts SET last_used_at = ? WHERE id = ?")
                .bind(now)
                .bind(c.id)
                .execute(&mut *conn)
                .await?;
            let picked = Picked {
                account: c.id,
                pool: e.pool,
                pos,
                provider: e.provider.clone(),
                harness: e.harness.clone(),
                model: e.model.clone(),
                secret: SessionSecret {
                    name: c.secret,
                    var: auth_var,
                },
                gateway,
            };
            assign::assign_in(conn, ask.session, &picked).await?;
            return Ok(Outcome::Picked(picked));
        }
        reasons.push((pos, found.tally.text()));
    }
    // However often the supervisor asks, a session waits at most `wait_max` in all, counted from
    // its first wait.
    let since = assign::waiting_since_in(conn, ask.session).await?;
    let spent = since.is_some_and(|s| now_u - s >= ask.wait_max_secs);
    if spent {
        reasons.push((ask.from_pos, "it has waited as long as it may".to_owned()));
    }
    // A cap that is full frees when a session ends, which nothing here can say when: it waits
    // too, but only as long as `wait_max` allows in all.
    let soon = earliest.filter(|t| t - now_u <= ask.wait_max_secs);
    let waiting = !spent && (soon.is_some() || full);
    match waiting.then(|| soon.unwrap_or_else(|| since.unwrap_or(now_u) + ask.wait_max_secs)) {
        Some(until) => {
            let since = since.unwrap_or(now_u);
            assign::waiting_in(conn, ask.session, &iso_of_unix(until), WAITING, since).await?;
            Ok(Outcome::Wait {
                until,
                why: WAITING.to_owned(),
            })
        }
        None => Ok(Outcome::Exhausted(reasons)),
    }
}
