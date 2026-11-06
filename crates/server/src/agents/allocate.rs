//! The allocator as the supervisor drives it (KAN-437 S4; design §5). A session that draws from a
//! chain (`core_agent_sessions.chain` set) has no account until [`ready`] has picked one; until
//! then it stays `starting` and never launches, so a harness cannot start on the runner's own
//! login. A session that names its account itself has no chain, and none of this touches it.
//!
//! - **One write.** The pick, its budget hold and the assignment are one `begin_write`
//!   transaction (`store::alloc::pick_in`).
//! - **A re-pick** ([`repick`]) is a launch refusing the account the pick chose (it was disabled,
//!   cooled or out of budget in between): the hold goes back, the account is left out and the pick
//!   runs again, at most twice. It is not a failover hop.

use ainkrad_proto::v2::ModelPrice;

use super::*;
use crate::store::alloc::{self, Ask, Entry, Outcome};
use crate::store::gateway as gw;
use crate::store::prices;

fn offline() -> Refusal {
    Refusal::Runner(StreamError::new(
        ErrorCode::Offline,
        "the runner is not connected",
    ))
}

/// Why `runner` cannot serve `e`, if it cannot: no slot for the harness, or the placement rules of
/// the entry's delivery (a gateway for an API key; the egress filter, the tier and the
/// subscription command for a subscription).
fn serves(runner: &RunnerState, s: &Session, e: &Entry) -> Option<String> {
    let Some(d) = runner.drivers.iter().find(|d| d.name == AGENT_DRIVER) else {
        return Some("the runner offers no agent sessions".to_owned());
    };
    if !d.slots.is_empty() && !d.slots.contains_key(&e.harness) {
        return Some("the runner offers no slot for that harness".to_owned());
    }
    let probe = [store::SessionSecret {
        name: format!("acct.{}.1", e.provider),
        var: "ACCOUNT".to_owned(),
    }];
    placement_refusal_with(runner, &probe, &s.policy, false)
}

/// The row to launch now: `s` itself for a session with no chain or that has its account;
/// otherwise the pick runs, and the row it leaves (the account is on it) is returned. `None` means
/// it waits (the supervisor asks again), or has ended.
pub(super) async fn ready(app: &App, s: &Session) -> Result<Option<Session>, Refusal> {
    match alloc::view(&app.pool, &s.id).await? {
        Some(v) if v.chain.is_some() && v.account.is_none() => match pick(app, s, false).await? {
            Next::Launch => Ok(store::get(&app.pool, &s.id).await?),
            _ => Ok(None),
        },
        _ => Ok(Some(s.clone())),
    }
}

/// A launch refused the account of a chain session: leaves it out and picks again. Whether it did
/// (the supervisor goes round again); `false` for a session with no chain or no account, or with
/// its re-picks used.
pub(super) async fn repick(app: &App, s: &Session) -> Result<bool, Refusal> {
    app.agents.leases.lock().unwrap().remove(&s.id);
    match alloc::view(&app.pool, &s.id).await? {
        Some(v) if v.chain.is_some() && v.account.is_some() => {
            pick(app, s, true).await.map(|p| p != Next::Refused)
        }
        _ => Ok(false),
    }
}

#[derive(PartialEq, Eq)]
enum Next {
    Launch,
    Wait,
    Ended,
    /// A re-pick with none left.
    Refused,
}

async fn pick(app: &App, s: &Session, retreat: bool) -> Result<Next, Refusal> {
    let live = app.hub.runners();
    let Some(runner) = live.get(&s.runner).filter(|r| r.online) else {
        return Err(offline());
    };
    let book = prices::list(&app.pool).await?;
    let min_turn = |e: &Entry| {
        let rate = |n: i64| u64::try_from(n).unwrap_or(0);
        let ps: Vec<ModelPrice> = book
            .iter()
            .filter(|p| p.provider == e.provider)
            .map(|p| ModelPrice {
                model: p.model.clone(),
                input: rate(p.input_per_mtok_micro),
                output: rate(p.output_per_mtok_micro),
                cache_read: rate(p.cache_per_mtok_micro),
                cache_write: rate(p.cache_per_mtok_micro),
            })
            .collect();
        gw::min_turn_usd(&ps, e.model.as_deref())
    };
    let now = app.clock.now();
    let mut tx = crate::store::begin_write(&app.pool).await?;
    if retreat && alloc::retreat_in(&mut tx, &s.id).await?.is_none() {
        return Ok(Next::Refused);
    }
    let Some(v) = alloc::view_in(&mut tx, &s.id).await? else {
        return Ok(Next::Ended);
    };
    let chain = v.chain.unwrap_or_default();
    let placed = |e: &Entry| serves(runner, s, e);
    let ask = Ask {
        session: &s.id,
        runner: &s.runner,
        user: v.user,
        chain: &chain,
        from_pos: v.pos.unwrap_or(0),
        used_accounts: &v.tried,
        skip_pools: &[],
        min_turn: &min_turn,
        serves: &placed,
        wait_max_secs: alloc::WAIT_MAX_SECS,
        lost_after_secs: i64::try_from(app.agents.config.lost_after.as_secs()).unwrap_or(i64::MAX),
    };
    let outcome = alloc::pick_in(&mut tx, &ask, &now).await?;
    // Committed whatever it says: the recoveries it audited and the wait it recorded stay.
    tx.commit().await?;
    Ok(match outcome {
        Outcome::Picked(_) => Next::Launch,
        Outcome::Wait { .. } => Next::Wait,
        Outcome::Exhausted(reasons) => {
            let said: Vec<String> = reasons
                .iter()
                .map(|(pos, why)| format!("entry {}: {why}", pos + 1))
                .collect();
            fail(
                app,
                s,
                &format!("no account is available ({})", said.join("; ")),
            )
            .await;
            Next::Ended
        }
    })
}
