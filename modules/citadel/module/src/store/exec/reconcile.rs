//! Reconcile: live runs follow their sessions. The platform supervises a session (reads its
//! runner, stores its transcript, resumes it after a runner restart or a Core restart), so there
//! is no lease and no heartbeat here: the engine only looks at what the session became.
//!
//! One pass, idempotent, safe to run any number of times and after a restart (it keeps no state
//! of its own but the rows):
//! - a run whose session is `running` (or `interrupted`, which the platform resumes) is
//!   `running`; one whose session ended or was lost ends with the session's outcome;
//! - usage: the session's totals become cost events (idempotent), which move the budgets;
//! - the cap: an exhausted hard-stop budget, the run's or the issue's token cap, stops the run;
//! - tool approvals the harness asks become `permission_escalation` approvals, and a decided
//!   one is relayed to the harness once;
//! - a stop the runner did not take is asked again; a claimed run whose session never started
//!   fails; a session of the engine's that no live run owns is killed.

use ainkrad_core_server::api::App;
use ainkrad_core_server::store::agents::{self as sessions, Session};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;

use super::*;
use crate::domain::exec::RunEvent;
use crate::domain::gov::{ApprovalKind, NewApproval};
use crate::store::audit::{self, Event};
use crate::store::gov::{open_approval_in, standings};

/// What a pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub ended: usize,
    pub capped: usize,
    pub cost_events: usize,
    pub approvals: usize,
    pub relayed: usize,
    pub orphans: usize,
}

/// How long a claimed run may wait for its session to be recorded (a crash between claiming it
/// and starting the session leaves one without) before it fails and is retried.
const CLAIM_GRACE_SECS: i64 = 120;

/// How long a session of the engine's may exist before a run must own it.
const ORPHAN_GRACE_SECS: i64 = 60;

pub async fn reconcile<H: Host>(app: &App, host: &H, now: &str) -> Result<Report, Error> {
    let mut report = Report::default();
    let live: Vec<Run> = sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM citadel_runs WHERE state IN ('claimed', 'running') ORDER BY id"
    ))
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .map(run)
    .collect::<Result<_, _>>()?;
    for r in live {
        follow(app, host, r, now, &mut report).await?;
    }
    relay_decisions(app, host, &mut report).await?;
    sweep_orphans(app, host, now, &mut report).await?;
    Ok(report)
}

async fn older_than(pool: &SqlitePool, then: &str, secs: i64, now: &str) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT (julianday(?) - julianday(?)) * 86400 >= ?")
        .bind(now)
        .bind(then)
        .bind(secs)
        .fetch_one(pool)
        .await
}

/// Moves a claimed run to running, for the terminal event that needs it.
async fn running(pool: &SqlitePool, r: &Run, now: &str) -> Result<Run, Error> {
    if r.state != RunState::Claimed {
        return Ok(r.clone());
    }
    transition_run(
        pool,
        r.id,
        SYSTEM,
        &RunEvent::Start {
            session: r.session_id.clone(),
        },
        now,
    )
    .await
    .map_err(into_db)
}

async fn end(
    pool: &SqlitePool,
    r: &Run,
    event: RunEvent,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let r = if matches!(
        event,
        RunEvent::Succeed | RunEvent::TokenCap | RunEvent::Stall
    ) {
        running(pool, r, now).await?
    } else {
        r.clone()
    };
    match transition_run(pool, r.id, SYSTEM, &event, now).await {
        Ok(_) => report.ended += 1,
        // Another pass (or the admin's cancel) ended it first.
        Err(TransitionError::Conflict | TransitionError::Illegal(_)) => {}
        Err(e) => return Err(into_db(e)),
    }
    Ok(())
}

fn outcome_event(s: &Session) -> RunEvent {
    let why = |s: &str| match s.trim() {
        "" => "no reason given".to_owned(),
        r => r.chars().take(500).collect(),
    };
    let o = s.outcome.clone().unwrap_or(Value::Null);
    let reason = why(o["reason"].as_str().unwrap_or_default());
    match o["kind"].as_str() {
        Some("succeeded") => RunEvent::Succeed,
        Some("cancelled") => RunEvent::Cancel { reason },
        Some("token_cap") => RunEvent::TokenCap,
        Some("stalled") => RunEvent::Stall,
        Some("failed") => RunEvent::Fail {
            reason,
            fingerprint: o["fingerprint"].as_str().map(str::to_owned),
        },
        _ => RunEvent::Fail {
            reason: "the session ended without an outcome".to_owned(),
            fingerprint: None,
        },
    }
}

async fn follow<H: Host>(
    app: &App,
    host: &H,
    r: Run,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let pool = &app.pool;
    let Some(session) = r.session_id.clone() else {
        let since = r.claimed_at.clone().unwrap_or_else(|| r.queued_at.clone());
        if older_than(pool, &since, CLAIM_GRACE_SECS, now).await? {
            let why = "the session never started".to_owned();
            end(
                pool,
                &r,
                RunEvent::Fail {
                    reason: why,
                    fingerprint: None,
                },
                now,
                report,
            )
            .await?;
        }
        return Ok(());
    };
    let Some(s) = sessions::get(pool, &session).await? else {
        return end(pool, &r, RunEvent::RunnerLost, now, report).await;
    };
    // Usage that cannot be recorded is logged and tried again next pass; it must not stop this run's
    // cancel, cap or end, nor the other runs.
    let r = match record_usage(pool, &r, &s, now, report).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(run = r.id.0, error = ?e, "a run's usage was not recorded");
            r.clone()
        }
    };
    if r.cancel_requested_at.is_some() {
        // A stop the runner did not take (or a session ended meanwhile): the admin's word stands.
        if s.live()
            && host
                .instruct(app, &session, Instruction::Stop { kill: true })
                .await
                .is_err()
        {
            return Ok(());
        }
        let cancel = RunEvent::Cancel {
            reason: "cancelled by the admin".to_owned(),
        };
        return end(pool, &r, cancel, now, report).await;
    }
    match s.state.as_str() {
        "ended" => end(pool, &r, outcome_event(&s), now, report).await,
        "lost" => end(pool, &r, RunEvent::RunnerLost, now, report).await,
        "starting" => Ok(()),
        _ => {
            let r = running(pool, &r, now).await?;
            if let Some(why) = over_cap(pool, &r, now).await? {
                // Kill first: the run is over only once the harness is, so a budget that ran out
                // never leaves a live harness spending on a run marked ended.
                if s.live()
                    && host
                        .instruct(app, &session, Instruction::Stop { kill: true })
                        .await
                        .is_err()
                {
                    tracing::warn!(
                        run = r.id.0,
                        why,
                        "the cap's kill was not taken; asking again"
                    );
                    return Ok(());
                }
                report.capped += 1;
                return end(pool, &r, RunEvent::TokenCap, now, report).await;
            }
            scan_approvals(app, host, &r, &s, now, report).await
        }
    }
}

/// Why the run may not go on: an exhausted hard-stop budget (its agent's, its company's, its
/// issue's project's, ...), its own cap (`run.token_cap`), or its issue's (`issue.token_cap`).
async fn over_cap(pool: &SqlitePool, r: &Run, now: &str) -> Result<Option<String>, Error> {
    if let Some(s) = standings(pool, r.agent_id, r.issue_id, now, true)
        .await?
        .into_iter()
        .find(|s| s.exhausted())
    {
        return Ok(Some(format!("budget {} is exhausted", s.budget.id.0)));
    }
    // The run's own cap counts cache reads and writes at a fraction, so a long run is capped by
    // the work it does rather than the context it re-reads; budgets and the issue's cap count all.
    let divisor = crate::settings::value(pool, "run.cache_weight_divisor").await?;
    let weighted = r.usage.input_tokens + r.usage.output_tokens + r.usage.cache_tokens / divisor;
    if weighted >= crate::settings::value(pool, "run.token_cap").await? {
        return Ok(Some("the run's token cap".to_owned()));
    }
    let cap = crate::settings::value(pool, "issue.token_cap").await?;
    if let (true, Some(issue)) = (cap > 0, r.issue_id) {
        let used: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) FROM citadel_runs \
             WHERE issue_id = ?",
        )
        .bind(issue.0)
        .fetch_one(pool)
        .await?;
        if used >= cap {
            return Ok(Some("the issue's token cap".to_owned()));
        }
    }
    Ok(None)
}

/// Turns the session's token totals into one cost event for what grew since the ledger last saw
/// the run (idempotent: the key names the totals, so a repeated report adds nothing and a lost
/// one loses nothing), prices it, moves the run's totals and lets the budgets warn. The ledger and
/// the budgets are the Core's (KAN-449, KAN-448): the event is recorded there, in this transaction,
/// as the session `run:<id>`, naming what it counts against (`subjects_in`).
///
/// Dollars: a subscription harness records tokens only; a metered one costs what the harness
/// reported (less what the ledger holds) or else its tokens at the latest price of its harness and
/// model in Citadel's price book, or else nothing known (NULL, never 0).
pub async fn record_usage(
    pool: &SqlitePool,
    r: &Run,
    s: &Session,
    now: &str,
    report: &mut Report,
) -> Result<Run, Error> {
    use ainkrad_core_server::store::costs::{self, Pricing};
    use ainkrad_core_server::store::{prices::Rates, secrets::Error as CoreError};
    let total = [
        s.usage.input,
        s.usage.output,
        s.usage.cache_read + s.usage.cache_write,
    ]
    .map(|t| i64::try_from(t).unwrap_or(i64::MAX));
    let reported = s.usage.cost_usd_micros.and_then(|c| i64::try_from(c).ok());
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let session = format!("run:{}", r.id.0);
    let [input, output, cache, held] = costs::session_totals(&mut tx, &session).await?;
    let delta = [total[0] - input, total[1] - output, total[2] - cache];
    let subscription: bool = sqlx::query_scalar(
        "SELECT coalesce((SELECT billing FROM citadel_harness_billing WHERE harness = ?), 'metered') \
         = 'subscription'",
    )
    .bind(r.harness.as_str())
    .fetch_one(&mut *tx)
    .await?;
    let news = !subscription && reported.is_some_and(|c| c > held);
    if delta.iter().any(|d| *d < 0) || (delta.iter().all(|d| *d == 0) && !news) {
        tx.commit().await?;
        return Ok(r.clone());
    }
    let model: Option<String> =
        sqlx::query_scalar("SELECT coalesce(?1, (SELECT model FROM citadel_agents WHERE id = ?2))")
            .bind(&r.model_used)
            .bind(r.agent_id.0)
            .fetch_one(&mut *tx)
            .await?;
    // The price book keeps the name as given; the Core ledger takes only a clean one.
    let model = model
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let core_model = crate::store::gov::core_model(&model);
    let (cost, pricing): (Option<i64>, Pricing) = match (subscription, reported) {
        (true, _) => (None, Pricing::Unpriced),
        (false, Some(c)) => (Some((c - held).max(0)), Pricing::Unpriced),
        (false, None) => {
            let p: Option<(i64, i64, i64, String)> = sqlx::query_as(
                "SELECT input_micros_per_mtok, output_micros_per_mtok, cache_micros_per_mtok, \
                 created_at FROM citadel_prices WHERE harness = ?1 AND model = ?2 \
                 ORDER BY version DESC LIMIT 1",
            )
            .bind(r.harness.as_str())
            .bind(&model)
            .fetch_optional(&mut *tx)
            .await?;
            let own = p.map(|(input, output, cache, priced_at)| Rates {
                input,
                output,
                cache,
                priced_at,
            });
            (None, own.map_or(Pricing::Unpriced, Pricing::Own))
        }
    };
    let owned = crate::store::gov::subjects_in(&mut tx, r.agent_id, r.issue_id).await?;
    let subjects: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let provider = match r.harness.as_str() {
        "claude" => "anthropic",
        "codex" => "openai",
        "agy" => "google",
        other => other,
    };
    let key = format!(
        "run:{}:usage:{}:{}:{}:{held}",
        r.id.0, total[0], total[1], total[2]
    );
    let new = costs::NewCost {
        session: &session,
        epoch: 0,
        account_id: None,
        legacy_account_id: None,
        provider,
        harness: r.harness.as_str(),
        model: &core_model,
        input_tokens: delta[0],
        output_tokens: delta[1],
        cache_tokens: delta[2],
        reported_usd_micros: cost,
        approximate: false,
        subjects: &subjects,
        idempotency_key: &key,
        occurred_at: now,
    };
    let recorded = costs::record_priced_in(&mut tx, &new, pricing, now)
        .await
        .map_err(|e| match e {
            CoreError::Db(e) => e,
            CoreError::Refused { message, .. } => Error::InvalidArgument(message),
        })?;
    if recorded.duplicate {
        tx.commit().await?;
        return Ok(r.clone());
    }
    // The run is priced once every one of its events is.
    let run_cost = costs::session_cost(&mut tx, &session).await?;
    let updated = sqlx::query(concat!(
        "UPDATE citadel_runs SET input_tokens = ?, output_tokens = ?, cache_tokens = ?, \
         cost_usd_micros = ?, priced = ? WHERE id = ? RETURNING ",
        run_columns!()
    ))
    .bind(total[0])
    .bind(total[1])
    .bind(total[2])
    .bind(run_cost)
    .bind(run_cost.is_some())
    .bind(r.id.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(run)?;
    crate::store::gov::wake_for_warnings(&mut tx, &recorded.guard.warned, r.issue_id).await?;
    tx.commit().await?;
    report.cost_events += 1;
    Ok(updated)
}

mod approvals;
use approvals::{relay_decisions, scan_approvals, sweep_orphans};
