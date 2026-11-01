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
use crate::store::gov::{open_approval_in, standings, warn_in};

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
    let r = record_usage(pool, &r, &s, now, report).await?;
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
/// one loses nothing), prices it, moves the run's totals and lets the budgets warn.
///
/// Dollars: a subscription harness records tokens only; a metered one costs what the harness
/// reported (less what the ledger holds) or else its tokens at the latest price of its harness and
/// model, or else nothing known (NULL, never 0).
pub async fn record_usage(
    pool: &SqlitePool,
    r: &Run,
    s: &Session,
    now: &str,
    report: &mut Report,
) -> Result<Run, Error> {
    let total = [
        s.usage.input,
        s.usage.output,
        s.usage.cache_read + s.usage.cache_write,
    ]
    .map(|t| i64::try_from(t).unwrap_or(i64::MAX));
    let reported = s.usage.cost_usd_micros.and_then(|c| i64::try_from(c).ok());
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (input, output, cache, held): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), \
         coalesce(sum(cache_tokens), 0), coalesce(sum(cost_usd_micros), 0) \
         FROM citadel_cost_events WHERE run_id = ?",
    )
    .bind(r.id.0)
    .fetch_one(&mut *tx)
    .await?;
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
    let (cost, price): (Option<i64>, Option<i64>) = match (subscription, reported) {
        (true, _) => (None, None),
        (false, Some(c)) => (Some((c - held).max(0)), None),
        (false, None) => {
            let p: Option<(i64, i64, i64, i64)> = sqlx::query_as(
                "SELECT id, input_micros_per_mtok, output_micros_per_mtok, cache_micros_per_mtok \
                 FROM citadel_prices WHERE harness = ?1 AND model = coalesce(?2, \
                 (SELECT model FROM citadel_agents WHERE id = ?3)) ORDER BY version DESC LIMIT 1",
            )
            .bind(r.harness.as_str())
            .bind(&r.model_used)
            .bind(r.agent_id.0)
            .fetch_optional(&mut *tx)
            .await?;
            match p {
                Some((id, i, o, c)) => {
                    let micros = i128::from(delta[0]) * i128::from(i)
                        + i128::from(delta[1]) * i128::from(o)
                        + i128::from(delta[2]) * i128::from(c);
                    (
                        Some(i64::try_from((micros + 500_000) / 1_000_000).unwrap_or(i64::MAX)),
                        Some(id),
                    )
                }
                None => (None, None),
            }
        }
    };
    let key = format!(
        "run:{}:usage:{}:{}:{}:{held}",
        r.id.0, total[0], total[1], total[2]
    );
    let inserted = sqlx::query(
        "INSERT INTO citadel_cost_events (run_id, agent_id, issue_id, input_tokens, output_tokens, \
         cache_tokens, cost_usd_micros, priced, idempotency_key, created_at, price_id, billing) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(r.id.0)
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .bind(delta[0])
    .bind(delta[1])
    .bind(delta[2])
    .bind(cost)
    .bind(cost.is_some())
    .bind(&key)
    .bind(now)
    .bind(price)
    .bind(if subscription {
        "subscription"
    } else {
        "metered"
    })
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        tx.commit().await?;
        return Ok(r.clone());
    }
    // The run is priced once every one of its events is.
    let run_cost: Option<i64> = sqlx::query_scalar(
        "SELECT iif(NOT EXISTS (SELECT 1 FROM citadel_cost_events WHERE run_id = ?1 AND priced = 0), \
         (SELECT sum(cost_usd_micros) FROM citadel_cost_events WHERE run_id = ?1), NULL)",
    )
    .bind(r.id.0)
    .fetch_one(&mut *tx)
    .await?;
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
    warn_in(&mut tx, r.agent_id, r.issue_id, now).await?;
    tx.commit().await?;
    report.cost_events += 1;
    Ok(updated)
}

/// The tool approvals the harness asked since the last look become `permission_escalation`
/// approvals (one per request, whatever the number of passes). The harness waits on the decision.
async fn scan_approvals<H: Host>(
    app: &App,
    host: &H,
    r: &Run,
    s: &Session,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let pool = &app.pool;
    if s.last_seq <= 0 {
        return Ok(());
    }
    let entries = sessions::transcript(pool, &s.id, r.approval_seq(pool).await?, 200).await?;
    let Some(last) = entries.last().map(|e| e.seq) else {
        return Ok(());
    };
    // A call an "allow for this issue" rule still covers goes ahead without a reviewer, with
    // these guards. (1) Fail closed: a rule must be a legal rule (`rule_problem`) and cover the
    // call in full (`allows`: every command and pattern, one simple command, nothing destructive);
    // a request id is allowed only when EVERY entry that carries it is covered, so a repeated id
    // can never hide an uncovered call. (2) One transaction audits `run.allowed_by_rule`,
    // escalates every other call and advances the cursor, and it commits BEFORE the harness is
    // told: an approval never exists without its row, a decision is never sent twice, and a crash
    // before it is sent leaves a request the runner denies on its own timeout. (3) A decision the
    // runner does not take is escalated like any other call and audited with outcome `unapplied`. The rows
    // carry the rule's id, never its text or the command.
    let rules = match r.issue_id {
        Some(issue) => crate::store::gov::issue_allow_rules(pool, issue, now).await?,
        None => vec![],
    };
    let mut verdicts: Vec<(&str, &str, Option<i64>)> = vec![];
    for e in entries
        .iter()
        .filter(|e| e.body["type"] == "approval_request")
    {
        let (Some(request), Some(tool)) = (e.body["id"].as_str(), e.body["tool"].as_str()) else {
            continue;
        };
        let sane =
            !request.is_empty() && request.len() <= 256 && !request.contains(char::is_control);
        let covered = rules
            .iter()
            .find(|(_, rule)| {
                sane && ainkrad_proto::runner::rule_problem(rule).is_none()
                    && ainkrad_proto::runner::allows(rule, tool, &e.body["input"])
            })
            .map(|(id, _)| *id);
        match verdicts.iter_mut().find(|v| v.0 == request) {
            Some(v) if v.1 == tool && v.2 == covered => {}
            Some(v) => v.2 = None,
            None => verdicts.push((request, tool, covered)),
        }
    }
    let matched: Vec<(&str, &str, i64)> = verdicts
        .iter()
        .filter_map(|&(q, t, id)| id.map(|id| (q, t, id)))
        .collect();
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(r.agent_id.0)
        .fetch_one(pool)
        .await?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    for &m in &matched {
        audit_rule(&mut tx, r, company, m, "allowed").await?;
    }
    for e in entries
        .iter()
        .filter(|e| e.body["type"] == "approval_request")
    {
        if e.body["id"]
            .as_str()
            .is_some_and(|q| matched.iter().any(|m| m.0 == q))
        {
            continue;
        }
        escalate_in(&mut tx, r, s, company, e, now, report).await?;
    }
    sqlx::query("UPDATE citadel_runs SET approval_seq = ? WHERE id = ?")
        .bind(last as i64)
        .bind(r.id.0)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut unapplied = vec![];
    for &m in &matched {
        let told = Instruction::Decide {
            request: m.0.to_owned(),
            approved: true,
            reply: Some("allowed for this issue".to_owned()),
        };
        if host.instruct(app, &s.id, told).await.is_err() {
            unapplied.push(m);
        }
    }
    if unapplied.is_empty() {
        return Ok(());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    for m in unapplied {
        audit_rule(&mut tx, r, company, m, "unapplied").await?;
        for e in entries
            .iter()
            .filter(|e| e.body["id"].as_str() == Some(m.0))
        {
            escalate_in(&mut tx, r, s, company, e, now, report).await?;
        }
    }
    tx.commit().await
}

/// Opens the `permission_escalation` for one `approval_request` entry, once per request.
async fn escalate_in(
    tx: &mut sqlx::SqliteConnection,
    r: &Run,
    s: &Session,
    company: i64,
    e: &ainkrad_proto::v2::TranscriptEntry,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let Some(request) = e.body["id"].as_str() else {
        return Ok(());
    };
    let asked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_approvals WHERE kind = 'permission_escalation' \
         AND json_extract(payload, '$.session') = ?1 AND json_extract(payload, '$.request') = ?2)",
    )
    .bind(&s.id)
    .bind(request)
    .fetch_one(&mut *tx)
    .await?;
    if asked {
        return Ok(());
    }
    // The tool and a cut of what it was asked to do: the transcript is already redacted, and
    // what is kept here is shown on a phone, so it stays short.
    let tool = e.body["tool"].as_str().unwrap_or("a tool");
    let mut input = e.body["input"].clone();
    ainkrad_core_server::store::redact::json(&mut input);
    let input: String = input.to_string().chars().take(300).collect();
    let payload = json!({"run": r.id.0, "session": s.id, "request": request, "tool": tool,
                         "input": input, "summary": format!("{tool} needs a decision")});
    let new = NewApproval {
        company_id: crate::domain::org::CompanyId(company),
        kind: ApprovalKind::PermissionEscalation,
        issue_id: r.issue_id,
        sprint_id: None,
        agent_id: None,
        requested_by: r.agent_id,
        payload: payload.to_string(),
    };
    open_approval_in(tx, &new, None, now).await?;
    report.approvals += 1;
    Ok(())
}

/// One audit row for a rule that covered a call: ids and the tool name only, never the rule's text
/// or the command.
async fn audit_rule(
    conn: &mut sqlx::SqliteConnection,
    r: &Run,
    company: i64,
    (request, tool, rule_id): (&str, &str, i64),
    outcome: &str,
) -> Result<(), Error> {
    audit::append(
        conn,
        Event::new(SYSTEM, "run.allowed_by_rule")
            .entity("run", r.id.0)
            .company(company)
            .run(r.id.0)
            .details(
                json!({"outcome": outcome, "rule_id": rule_id, "request": request,
                            "tool": tool, "issue": r.issue_id.map(|i| i.0)}),
            ),
    )
    .await
}

impl Run {
    async fn approval_seq(&self, pool: &SqlitePool) -> Result<i64, Error> {
        sqlx::query_scalar("SELECT approval_seq FROM citadel_runs WHERE id = ?")
            .bind(self.id.0)
            .fetch_one(pool)
            .await
    }
}

/// A decided (or expired) `permission_escalation` is told to its harness once. Expired means no:
/// a tool nobody allowed does not run.
async fn relay_decisions<H: Host>(app: &App, host: &H, report: &mut Report) -> Result<(), Error> {
    let decided: Vec<(i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, status, reply, payload FROM citadel_approvals \
         WHERE kind = 'permission_escalation' AND status IN ('approved', 'rejected', 'expired') \
         AND json_extract(payload, '$.session') IS NOT NULL \
         AND json_extract(payload, '$.relayed') IS NULL ORDER BY id LIMIT 50",
    )
    .fetch_all(&app.pool)
    .await?;
    for (id, status, reply, payload) in decided {
        let p: Value = serde_json::from_str(&payload).unwrap_or_default();
        let (Some(session), Some(request)) = (p["session"].as_str(), p["request"].as_str()) else {
            continue;
        };
        let live = sessions::get(&app.pool, session)
            .await?
            .is_some_and(|s| s.live());
        if live {
            let what = Instruction::Decide {
                request: request.to_owned(),
                approved: status == "approved",
                reply,
            };
            if let Err(why) = host.instruct(app, session, what).await {
                tracing::warn!(approval = id, why, "a decision was not taken; asking again");
                continue;
            }
        }
        sqlx::query(
            "UPDATE citadel_approvals SET payload = json_set(payload, '$.relayed', 1) WHERE id = ?",
        )
        .bind(id)
        .execute(&app.pool)
        .await?;
        report.relayed += 1;
        let mut tx = ainkrad_core_server::store::begin_write(&app.pool).await?;
        audit::append(
            &mut tx,
            Event::new(SYSTEM, "run.decided")
                .entity("approval", id)
                .run(p["run"].as_i64().unwrap_or(0))
                .details(json!({"status": status, "session_live": live})),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// A live session of the engine's that no live run owns (a crash between starting it and
/// recording it, a cancel that raced the start) is killed: nothing may work unaccounted.
async fn sweep_orphans<H: Host>(
    app: &App,
    host: &H,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    for s in sessions::live(&app.pool).await? {
        if s.owner_module.as_deref() != Some(crate::MODULE) {
            continue;
        }
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_runs WHERE session_id = ? \
             AND state IN ('claimed', 'running'))",
        )
        .bind(&s.id)
        .fetch_one(&app.pool)
        .await?;
        if owned || !older_than(&app.pool, &s.created_at, ORPHAN_GRACE_SECS, now).await? {
            continue;
        }
        if host
            .instruct(app, &s.id, Instruction::Stop { kill: true })
            .await
            .is_ok()
        {
            report.orphans += 1;
        }
    }
    Ok(())
}
