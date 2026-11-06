//! Failover as the supervisor drives it (KAN-438 part B, S6; design `2026-11-06-core-account-scheduler`
//! §8). The rows and the decision are `store::failover`; this is the part that needs the runner.
//!
//! - **When.** The supervisor calls [`after_end`] when a session it watched is over, and [`live`] on
//!   a running gateway session whose own reports (or budgets) say its account cannot go on.
//! - **A live stop is not a cancel.** [`live`] writes the decision (`failover_class`) first, then
//!   orders the stop the way a budget stop does; the runner reports it as `Cancelled`, which the
//!   decision reads as a move because of the class, not as a person's cancel.
//! - **One account at a time (I2).** The move starts only after the old attempt is over. It is one
//!   write (`store::failover::move_in`): claim, successor, pick and hold. A runner that is away
//!   when the attempt ends is waited for (bounded by `lost_after`); a restart finds the unsettled
//!   attempt ([`resume_unfinished`]) and finishes the same move.
//! - **The successor is supervised like any session:** its own wait is bounded by the allocator, its
//!   launch takes fresh leases, and nothing of the old attempt's leases is reused.

use super::*;
use crate::store::alloc::{Entry, WAIT_MAX_SECS};
use crate::store::failover::{self as rows, Ctx, Decision, Moved};

/// An attempt is over: finishes its failover (once; a settled attempt does nothing).
pub(super) async fn after_end(app: &App, s: &Session) {
    if let Err(e) = settle(app, &s.id).await {
        tracing::warn!(session = s.id, why = describe(&e), "settling a failover");
    }
}

async fn settle(app: &App, id: &str) -> Result<(), Refusal> {
    let began = tokio::time::Instant::now();
    loop {
        let Some(v) = rows::view(&app.pool, id).await? else {
            return Ok(());
        };
        if v.done || !matches!(v.state.as_str(), "ended" | "lost") {
            return Ok(());
        }
        let class = match rows::decide(&v) {
            Decision::End(_) => return Ok(rows::settle(&app.pool, id).await?),
            Decision::Move(class) => class,
        };
        match try_move(app, id, &class).await {
            Ok(()) => return Ok(()),
            // The runner is away (or a read failed): the run waits for it, I2, but not for ever.
            Err(Refusal::Runner(_) | Refusal::Db(_)) => {
                if began.elapsed() >= app.agents.config.lost_after {
                    let why = "the runner never came back, so the run could not move";
                    return Ok(rows::settle_with(&app.pool, id, why).await?);
                }
                tokio::time::sleep(app.agents.config.retry).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn try_move(app: &App, id: &str, class: &str) -> Result<(), Refusal> {
    let Some(old) = store::get(&app.pool, id).await? else {
        return Ok(());
    };
    let live = app.hub.runners();
    let Some(runner) = live.get(&old.runner).filter(|r| r.online) else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::Offline,
            "the runner is not connected",
        )));
    };
    let chain: Vec<Entry> = rows::view(&app.pool, id)
        .await?
        .and_then(|v| v.chain)
        .unwrap_or_default();
    let books = allocate::books(app, &chain).await?;
    let price = |e: &Entry| allocate::min_turn(&books, e);
    let placed = |e: &Entry| allocate::serves(runner, &old, e);
    let now = app.clock.now();
    let cx = Ctx {
        now: &now,
        min_turn: &price,
        serves: &placed,
        wait_max_secs: WAIT_MAX_SECS,
    };
    let mut tx = crate::store::begin_write(&app.pool).await?;
    let moved = rows::move_in(&mut tx, id, class, &cx).await?;
    tx.commit().await?;
    match moved {
        Moved::To { session, .. } => {
            // No cached lease of the old attempt is ever reused; the new one gets its own at launch.
            app.agents.leases.lock().unwrap().remove(id);
            // The create's step-up covers every attempt of the chain it named (§12 rule 6).
            app.agents
                .elevated
                .lock()
                .unwrap()
                .insert(session.clone(), app.hub.continue_agent_elevation());
            supervise(app, &session);
        }
        Moved::Ended { why, .. } => {
            tracing::info!(session = id, why, "a run ended: its chain has nothing left");
        }
        Moved::Skipped => {}
    }
    Ok(())
}

/// A running gateway session whose own reports or budgets say its account cannot go on is stopped
/// for a move: the decision is written first, then the stop is ordered (and ordered again, then
/// killed after the grace, on each pass until it is over). Whether the session is being stopped
/// for a move.
pub(super) async fn live(app: &App, s: &Session) -> bool {
    if s.state != "running" {
        return false;
    }
    let v = match rows::view(&app.pool, &s.id).await {
        Ok(Some(v)) => v,
        _ => return false,
    };
    if v.done || v.module || v.chain.is_none() || v.account.is_none() {
        return false;
    }
    // A stop of the Core's own that is no budget (a ceiling, a session limit) ends the run: no move.
    if v.gw_stop.is_some() && v.budget.is_none() {
        return false;
    }
    let class = match (&v.class, v.budget, v.upstream.as_deref()) {
        (Some(c), _, _) => c.clone(),
        (_, Some(_), _) => "budget_pool".to_owned(),
        (_, _, Some("quota")) => "quota".to_owned(),
        (_, _, Some("auth_failed")) => "auth".to_owned(),
        _ => return false,
    };
    if v.class.is_none() && !matches!(rows::set_class(&app.pool, &s.id, &class).await, Ok(true)) {
        return false;
    }
    let details = json!({"reason": "failover", "class": class});
    if let Err(e) = gateway::enforce(app, s, details).await {
        tracing::warn!(
            session = s.id,
            why = describe(&e),
            "stopping a session for a move"
        );
    }
    true
}

/// What a starting Core finishes: every attempt that is over and whose failover was never
/// settled (the Core went down between the end and the move).
pub(super) async fn resume_unfinished(app: &App) -> Result<usize, sqlx::Error> {
    // Only what ended within the last `lost_after`: an older attempt is not moved by a restart.
    let since = crate::scheduler::iso_of_unix(
        app.clock.unix() - i64::try_from(app.agents.config.lost_after.as_secs()).unwrap_or(3600),
    );
    let ids = rows::unfinished_since(&app.pool, &since).await?;
    for id in &ids {
        let (app, id) = (app.clone(), id.clone());
        tokio::spawn(async move {
            let mut closing = app.closing.subscribe();
            tokio::select! {
                r = settle(&app, &id) => if let Err(e) = r {
                    tracing::warn!(session = id, why = describe(&e), "settling a failover");
                },
                () = crate::api::stopping(&mut closing) => {}
            }
        });
    }
    Ok(ids.len())
}
