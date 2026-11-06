//! A gateway at its ceiling while its budgets still have room (KAN-435 G5). The ceiling a session
//! starts with is a hold, at most 20M tokens or US$50 of what its budgets leave. A session that has
//! spent nearly all of it would be refused (`429 gateway_ceiling`) on every request while the budgets
//! still have headroom, and nothing would end it. So when what the gateway has left (its ceiling less
//! what the ledger holds for this epoch) cannot admit one turn, the Core reserves again:
//!
//! - **Room:** a positive `agent.limit`, absolute for this gateway instance: this epoch's ledger
//!   spend plus the new hold (the runner's ceiling counts spent, and spent starts at 0 at each start).
//! - **No room:** the session is stopped, with the reason, as a budget stop is (decision 7).

use ainkrad_proto::v2::{AgentLimit, Ceiling};

use super::*;
use crate::store::gateway as gw;

/// `spent` plus a new hold, where `u64::MAX` (no limit) stays no limit.
fn absolute(spent: u64, hold: u64) -> u64 {
    if hold == u64::MAX {
        u64::MAX
    } else {
        spent.saturating_add(hold)
    }
}

/// The ceiling to send: this epoch's spend plus `hold`.
fn raised(spent: (u64, u64), hold: Ceiling) -> Ceiling {
    Ceiling {
        tokens: absolute(spent.0, hold.tokens),
        usd_micros: absolute(spent.1, hold.usd_micros),
    }
}

pub(super) async fn run(app: &App, s: &Session) {
    if let Err(e) = topup(app, s).await {
        tracing::warn!(
            session = s.id,
            why = describe(&e),
            "topping up a gateway's ceiling"
        );
    }
}

async fn topup(app: &App, s: &Session) -> Result<(), Refusal> {
    let Some(account) = s.gateway_account_id else {
        return Ok(());
    };
    let Some((ceiling, prices)) = gw::granted(&app.pool, &s.id).await? else {
        return Ok(());
    };
    let spent = gw::spent_in_epoch(&app.pool, &s.id, s.resumes).await?;
    let min_usd = gw::min_turn_usd(&prices, s.model.as_deref());
    let short = (ceiling.tokens != u64::MAX
        && ceiling.tokens.saturating_sub(spent.0) < gw::MIN_CEILING_TOKENS)
        || (ceiling.usd_micros != u64::MAX && ceiling.usd_micros.saturating_sub(spent.1) < min_usd);
    if !short {
        return Ok(());
    }
    let hold = match gw::reserve(&app.pool, &s.id, account, min_usd, &app.clock.now())
        .await
        .map_err(Refusal::Secrets)?
    {
        gw::Hold::Granted(hold) => hold,
        gw::Hold::Denied(why) => {
            let why =
                format!("the gateway's ceiling is used up and the budgets leave too little: {why}");
            // A budget that is short is a budget stop (the run moves); anything else (the account's
            // session limit) ends the run.
            let now = app.clock.now();
            let mut conn = app.pool.acquire().await?;
            let budget = gw::short_budget(&mut conn, account, &s.id, min_usd, &now).await?;
            drop(conn);
            gw::stop(&app.pool, &s.id, &why, budget.as_deref()).await?;
            return Ok(());
        }
    };
    let Some(proof) = app.agents.elevated.lock().unwrap().get(&s.id).copied() else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::InvalidArgs,
            "a ceiling raise needs the session's elevation",
        )));
    };
    let new = raised(spent, hold);
    let limit = Command::AgentLimit(AgentLimit {
        session: s.id.clone(),
        ceiling: new,
    });
    let ev = ask(app, &s.runner, limit, app.agents.config.answer, Some(proof)).await?;
    store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    gw::set_ceiling(&app.pool, &s.id, new).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_ceiling_is_the_epochs_spend_plus_the_hold_and_no_limit_stays_none() {
        let hold = Ceiling {
            tokens: 5_000_000,
            usd_micros: u64::MAX,
        };
        let new = raised((19_900_000, 40_000_000), hold);
        assert_eq!((new.tokens, new.usd_micros), (24_900_000, u64::MAX));
    }
}
