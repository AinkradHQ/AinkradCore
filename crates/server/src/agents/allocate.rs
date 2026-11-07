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

use std::collections::HashMap;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::ModelPrice;

use super::*;
use crate::store::alloc::{self, Ask, Entry, Outcome};
use crate::store::gateway as gw;
use crate::store::prices;

/// The entries of the session's chain snapshot.
async fn chain_of(app: &App, s: &Session) -> Result<Vec<Entry>, Refusal> {
    Ok(alloc::view(&app.pool, &s.id)
        .await?
        .and_then(|v| v.chain)
        .unwrap_or_default())
}

fn offline() -> Refusal {
    Refusal::Runner(StreamError::new(
        ErrorCode::Offline,
        "the runner is not connected",
    ))
}

/// Why `runner` cannot serve `e`, if it cannot: no slot for the harness, or the placement rules of
/// the entry's delivery (a gateway for an API key; the egress filter, the tier and the
/// subscription command for a subscription).
pub(super) fn serves(runner: &RunnerState, s: &Session, e: &Entry) -> Option<String> {
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

/// Prices a turn per provider of the chain from the grant's own source (`prices::book_of`).
pub(super) async fn books(
    app: &App,
    chain: &[Entry],
) -> Result<HashMap<String, Vec<ModelPrice>>, Refusal> {
    let all = prices::list(&app.pool).await?;
    let mut books = HashMap::new();
    for e in chain {
        if let Ok(def) = crate::store::providers::get(&app.pool, &e.provider).await {
            let book = prices::book_of(all.clone(), &e.provider, &def);
            books.insert(e.provider.clone(), prices::model_prices(&book));
        }
    }
    Ok(books)
}

pub(super) fn min_turn(books: &HashMap<String, Vec<ModelPrice>>, e: &Entry) -> u64 {
    let none = Vec::new();
    gw::min_turn_usd(books.get(&e.provider).unwrap_or(&none), e.model.as_deref())
}

/// Whether the account the pick chose is refused for a reason of its own state, which a race
/// between the pick and the launch can cause: gone, no longer startable (disabled, cooling,
/// limited, unhealthy) or out of budget room. An unpriced model, a harness that is not the
/// provider's, a bad base URL or a vanished provider are the entry's, and ending beats moving.
async fn account_refused(app: &App, s: &Session, v: &alloc::View) -> Result<bool, Refusal> {
    let (Some(account), Some(pos)) = (v.account, v.pos) else {
        return Ok(false);
    };
    let now = app.clock.now();
    crate::store::health::recover(&app.pool, account, &now).await?;
    let a = match crate::store::accounts::get(&app.pool, account).await {
        Ok(a) => a,
        Err(crate::store::secrets::Error::Refused {
            code: "not_found", ..
        }) => return Ok(true),
        Err(crate::store::secrets::Error::Db(e)) => return Err(e.into()),
        Err(_) => return Ok(false),
    };
    if !crate::store::health::startable(&a.state, a.state_reason.as_deref(), false) {
        return Ok(true);
    }
    let Some(e) = v.chain.as_ref().and_then(|c| c.get(pos)) else {
        return Ok(false);
    };
    let books = books(app, std::slice::from_ref(e)).await?;
    let plan = crate::store::account_keys::subscription_provider(&a.provider);
    let mut conn = app.pool.acquire().await?;
    let room = alloc::room_in(&mut conn, account, &s.id, plan, min_turn(&books, e), &now).await?;
    Ok(!room)
}

/// A launch refused the account of a chain session: leaves it out and picks again. Whether it did
/// (the supervisor goes round again); `false` when the refusal is not about the account's state
/// or budget, for a session with no chain or no account, or with its re-picks used, or whose
/// start was ever sent (see `alloc::retreat_in`).
pub(super) async fn repick(app: &App, s: &Session) -> Result<bool, Refusal> {
    app.agents.leases.lock().unwrap().remove(&s.id);
    match alloc::view(&app.pool, &s.id).await? {
        Some(v) if v.chain.is_some() && v.account.is_some() => {
            if !account_refused(app, s, &v).await? {
                return Ok(false);
            }
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
    let books = books(app, &chain_of(app, s).await?).await?;
    let price = |e: &Entry| min_turn(&books, e);
    let now = app.clock.now();
    // `scheduler.wait_max_secs`, read at each pick; an unreadable setting falls back to its default.
    let (key, at) = (Key::SchedulerWaitMaxSecs, Scope::Server);
    let wait_max_secs = crate::store::settings::value(&app.pool, key, at)
        .await
        .unwrap_or(alloc::WAIT_MAX_SECS);
    let mut tx = crate::store::begin_write(&app.pool).await?;
    let before = alloc::view_in(&mut tx, &s.id).await?;
    if retreat && alloc::retreat_in(&mut tx, &s.id).await?.is_none() {
        return Ok(Next::Refused);
    }
    let Some(v) = alloc::view_in(&mut tx, &s.id).await? else {
        return Ok(Next::Ended);
    };
    let chain = v.chain.unwrap_or_default();
    // A failover's attempt leaves out every account its run has used, and the pools a budget stop
    // took out (I3); a refused pick adds its own `tried`.
    let (mut used, skip) = crate::store::failover::context_in(&mut tx, &s.id).await?;
    let more: Vec<i64> = v
        .tried
        .iter()
        .filter(|t| !used.contains(t))
        .copied()
        .collect();
    used.extend(more);
    let successor = crate::store::failover::has_predecessor_in(&mut tx, &s.id).await?;
    let placed = |e: &Entry| serves(runner, s, e);
    let ask = Ask {
        session: &s.id,
        runner: &s.runner,
        user: v.user,
        chain: &chain,
        from_pos: v.pos.unwrap_or(0),
        used_accounts: &used,
        skip_pools: &skip,
        min_turn: &price,
        serves: &placed,
        wait_max_secs,
    };
    let outcome = alloc::pick_in(&mut tx, &ask, &now).await?;
    // A re-pick, or the first pick of a failover's attempt, that crosses provider or harness is said
    // in the session's own state event (a successor's position is the old attempt's until then).
    if let (true, Outcome::Picked(p), Some(was)) = (
        retreat || (successor && before.as_ref().is_some_and(|b| b.account.is_none())),
        &outcome,
        before
            .and_then(|b| b.pos.zip(b.chain))
            .and_then(|(i, c)| c.get(i).cloned()),
    ) && (was.provider != p.provider || was.harness != p.harness)
    {
        let reason = if retreat { "repicked" } else { "failover" };
        let note = serde_json::json!({"session": s.id, "state": "starting", "reason": reason,
            "from": {"provider": was.provider, "harness": was.harness},
            "to": {"provider": p.provider, "harness": p.harness}});
        crate::store::events::append(&mut tx, "agent.state", &note).await?;
    }
    // Committed whatever it says: the recoveries it audited and the wait it recorded stay.
    tx.commit().await?;
    Ok(match outcome {
        Outcome::Picked(_) => Next::Launch,
        Outcome::Wait { .. } => Next::Wait,
        Outcome::Gone => Next::Ended,
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
