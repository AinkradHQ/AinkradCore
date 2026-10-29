//! A run's token cap and its usage while it works (#15, E3.8). Tokens are what a cap counts:
//! input, output and cache together, as the ledger stores them. Dollars are not available
//! for every harness, so caps never use them.

use citadel_core::exec::{CostEvent, Run, Usage};
use citadel_core::gov::{AccountId, Billing};
use ainkrad_proto::runner::TokenCaps;

use super::*;
use crate::store::gov::{billing_in, price_in};

/// The tokens `run` may use, least of `run_token_caps`: every hard-stop budget and the issue
/// cap counted in full, and `default` (`run.token_cap`) counted every token in full too.
pub async fn run_token_cap(
    pool: &SqlitePool,
    run: &Run,
    default: u64,
    now: &str,
) -> Result<u64, Error> {
    Ok(run_token_caps(pool, run, default, 1, now).await?.least())
}

/// The caps `run` works under (1.27). `exact` is the least left, now, of every hard-stop budget
/// that applies to it (its agent's, its agent's company's and departments', its issue's
/// project's and sprint's), and the issue's `issue.token_cap` left, counted in full: what is
/// left comes from the budgets' spend counters for the period containing `now`
/// (`gov::standings`), the same ones admission reads: the cap plus approved raises, less the
/// spend. An exhausted budget leaves 0. `run` is `default` (`run.token_cap`), which the runner
/// counts with cache reads and writes at `1 / divisor`, so a long run is capped by the work it
/// does rather than the context it re-reads.
pub async fn run_token_caps(
    pool: &SqlitePool,
    run: &Run,
    default: u64,
    divisor: u64,
    now: &str,
) -> Result<TokenCaps, Error> {
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(pool)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")));
    }
    let standings = crate::store::gov::standings(pool, run.agent_id, run.issue_id, now, true);
    let mut exact = standings
        .await?
        .iter()
        .map(|s| s.left())
        .min()
        .map(|left| left.max(0) as u64);
    if let Some(issue) = run.issue_id
        && let Some(left) = issue_tokens_left(pool, issue, run.id).await?
    {
        exact = Some(exact.map_or(left, |exact| exact.min(left)));
    }
    Ok(TokenCaps {
        exact,
        run: default,
        cache_weight_divisor: divisor,
    })
}

/// What is left of the issue's `issue.token_cap` (its project's) for `run`: the cap less every
/// other run of the issue's tokens; `None` when the issue has no cap (0).
pub async fn issue_tokens_left(
    pool: &SqlitePool,
    issue: IssueId,
    run: RunId,
) -> Result<Option<u64>, Error> {
    let (cap, used): (i64, i64) = issue_tokens(pool, issue, Some(run)).await?;
    Ok((cap > 0).then(|| (cap - used).max(0) as u64))
}

/// The issue's effective `issue.token_cap` (0: none) and the tokens its runs used, but `except`.
pub async fn issue_tokens(
    pool: &SqlitePool,
    issue: IssueId,
    except: Option<RunId>,
) -> Result<(i64, i64), Error> {
    let project: Option<i64> = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(issue.0)
        .fetch_optional(pool)
        .await?;
    let Some(project) = project else {
        return Ok((0, 0));
    };
    let at = citadel_core::settings::Scope::Project(citadel_core::work::ProjectId(project));
    let cap = crate::store::settings::value(pool, citadel_core::settings::Key::IssueTokenCap, at);
    let used: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) FROM runs \
         WHERE issue_id = ? AND id IS NOT ?",
    )
    .bind(issue.0)
    .bind(except.map(|r| r.0))
    .fetch_one(pool)
    .await?;
    Ok((cap.await?, used))
}

/// Records report `seq` of the run's token totals so far, attributed to the account the run
/// works as now (E15.1): the growth since what the ledger
/// already holds for the run goes in as one cost event (key `run:<id>:usage:<seq>`, stamped
/// `now`), and the run's own usage becomes the totals. Totals, not deltas, so a repeated
/// report adds nothing and a lost one loses nothing; a stale one (below the ledger) and one
/// with no growth (in tokens, or in a reported cost not yet in the ledger) are skipped (`None`). The event counts toward the budgets that apply (the
/// `budget_spend` trigger), and any that reach their warning threshold warn
/// (`gov::warn_in`), in the same transaction; so do the limits of the run's account (E15.2,
/// `gov::check_limits_in`).
///
/// Dollars (E7.3, `gov::price_in`): the event costs what the harness reported for the run
/// (`totals.cost_usd_micros`) less what the ledger already holds, else its tokens at the latest
/// price of the run's harness and model, else nothing known (NULL, `priced = 0`); a
/// subscription harness records no dollars. The run's own cost is the sum of its events' once
/// every one is priced, or once the harness reported the whole run's; NULL otherwise.
pub async fn record_run_usage(
    pool: &SqlitePool,
    run: &Run,
    seq: u64,
    totals: &Usage,
    now: &str,
) -> Result<Option<CostEvent>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let key = format!("run:{}:usage:{seq}", run.id.0);
    let seen: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cost_events WHERE idempotency_key = ?)")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await?;
    let (input, output, cache, held): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), \
         coalesce(sum(cache_tokens), 0), coalesce(sum(cost_usd_micros), 0) \
         FROM cost_events WHERE run_id = ?",
    )
    .bind(run.id.0)
    .fetch_one(&mut *tx)
    .await?;
    let delta = [
        totals.input_tokens - input,
        totals.output_tokens - output,
        totals.cache_tokens - cache,
    ];
    // A harness's cost often arrives after its tokens (at the turn's close): a report whose
    // only news is the cost still goes in, as an event of no tokens, until the run is priced.
    let run_priced: bool = sqlx::query_scalar("SELECT priced FROM runs WHERE id = ?")
        .bind(run.id.0)
        .fetch_one(&mut *tx)
        .await?;
    let metered = billing_in(&mut tx, run).await? == Billing::Metered;
    let news = metered
        && totals
            .cost_usd_micros
            .is_some_and(|r| r != held || !run_priced);
    if seen || delta.iter().any(|d| *d < 0) || (delta.iter().all(|d| *d == 0) && !news) {
        return Ok(None);
    }
    let growth = Usage {
        input_tokens: delta[0],
        output_tokens: delta[1],
        cache_tokens: delta[2],
        cost_usd_micros: None,
    };
    let reported = totals.cost_usd_micros.map(|r| r - held);
    let (billing, cost, price) = price_in(&mut tx, run, &growth, reported).await?;
    let event = sqlx::query(concat!(
        "INSERT INTO cost_events (run_id, agent_id, issue_id, input_tokens, output_tokens, \
         cache_tokens, cost_usd_micros, priced, idempotency_key, created_at, price_id, \
         billing, account_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
         (SELECT account_id FROM runs WHERE id = ?1)) RETURNING ",
        cost_columns!()
    ))
    .bind(run.id.0)
    .bind(run.agent_id.0)
    .bind(run.issue_id.map(|i| i.0))
    .bind(delta[0])
    .bind(delta[1])
    .bind(delta[2])
    .bind(cost)
    .bind(cost.is_some())
    .bind(&key)
    .bind(now)
    .bind(price.map(|p| p.0))
    .bind(billing.as_str())
    .fetch_one(&mut *tx)
    .await
    .and_then(cost_event)?;
    // The whole run is priced once the harness reported it, or every event is.
    let whole = billing == Billing::Metered && reported.is_some();
    let run_cost: Option<i64> = sqlx::query_scalar(
        "SELECT iif(?2 OR NOT EXISTS (SELECT 1 FROM cost_events WHERE run_id = ?1 \
             AND priced = 0), (SELECT sum(cost_usd_micros) FROM cost_events \
             WHERE run_id = ?1), NULL)",
    )
    .bind(run.id.0)
    .bind(whole)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE runs SET input_tokens = ?, output_tokens = ?, cache_tokens = ?, \
         cost_usd_micros = ?, priced = ? WHERE id = ?",
    )
    .bind(totals.input_tokens)
    .bind(totals.output_tokens)
    .bind(totals.cache_tokens)
    .bind(run_cost)
    .bind(run_cost.is_some())
    .bind(run.id.0)
    .execute(&mut *tx)
    .await?;
    crate::store::gov::warn_in(&mut tx, run.agent_id, run.issue_id, now).await?;
    let account: Option<i64> = sqlx::query_scalar("SELECT account_id FROM runs WHERE id = ?")
        .bind(run.id.0)
        .fetch_one(&mut *tx)
        .await?;
    if let Some(account) = account {
        crate::store::gov::check_limits_in(&mut tx, AccountId(account), now).await?;
    }
    tx.commit().await?;
    Ok(Some(event))
}
