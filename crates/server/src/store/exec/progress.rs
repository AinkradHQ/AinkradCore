//! The progress watchdog (E15.7, pain #3: stalled agents, and agents pretending to work).
//!
//! - **Progress**: a run's runner reports it (`record_progress`): a tool call, a file change in
//!   the worktree, a new assistant message or more tokens, with how many files the worktree
//!   differs from its base in. The lease heartbeat only proves the process is alive. The runner
//!   itself stops a run with no progress for `run.stall_after_secs` and ends it `stalled`, which
//!   escalates its issue at once (`stop_in`) and counts for the loop breaker like any failure.
//! - **Empty done**: an agent's `done` on an issue with nothing to show for it (`done_evidence`:
//!   no diff reported by any run of the issue or by the calling run, no PR, no comment from the
//!   calling run) is refused with the reason, and a second one by the same agent escalates the
//!   issue up the chain (`refuse_empty_done`). Every refusal is audited as `issue.done_refused`.
//!
//! The diff comes from the runner's last `Progress`, which can trail a tool call by a moment;
//! a done refused in that gap passes when the agent tries again.
// ponytail: refusals count per (issue, agent) for ever; a window or a reset on reopen if an
// agent's old refusal ever escalates a later, honest one.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::WakeSource;
use ainkrad_core::org::CompanyId;
use ainkrad_core::work::NextActor;
use serde_json::json;

use super::*;
use crate::store::audit;
use crate::store::org::escalation_target_in;
use crate::store::work::{IssueTransitionError, reassign_in};

/// Records that `run`, held by `runner`, progressed at `now`, with its worktree's diff when
/// measured: its files, and each repo's (`repos`, 1.18; empty, not measured). `false` when the
/// run is not live on that runner (ended, or another's).
pub async fn record_progress(
    pool: &SqlitePool,
    run: RunId,
    runner: RunnerId,
    diff_files: Option<u32>,
    repos: &[ainkrad_proto::runner::RepoDiff],
    now: &str,
) -> Result<bool, Error> {
    let mut conn = pool.acquire().await?;
    check_time(&mut conn, now).await?;
    let repos = (!repos.is_empty()).then_some(Json(repos));
    sqlx::query(
        "UPDATE runs SET last_progress_at = ?1, diff_files = coalesce(?2, diff_files), \
         diff_repos = coalesce(?5, diff_repos) \
         WHERE id = ?3 AND runner_id = ?4 AND state IN ('claimed', 'running')",
    )
    .bind(now)
    .bind(diff_files.map(i64::from))
    .bind(run.0)
    .bind(runner.0)
    .bind(repos)
    .execute(&mut *conn)
    .await
    .map(affected)
}

/// The run was stopped for making no progress (E15.7).
pub(super) fn stalled(r: &Run) -> bool {
    r.terminal_reason.as_deref() == Some("stalled")
}

/// Whether `issue` has something to show for a `done` from `run`: a diff reported by any run
/// of the issue or by `run` itself (a subtask is worked by its parent's run), a PR, or a comment
/// `run` wrote.
pub async fn done_evidence(pool: &SqlitePool, issue: IssueId, run: RunId) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM runs WHERE (issue_id = ?1 OR id = ?2) AND diff_files > 0) \
         OR EXISTS (SELECT 1 FROM issue_prs WHERE issue_id = ?1) \
         OR EXISTS (SELECT 1 FROM comments WHERE run_id = ?2)",
    )
    .bind(issue.0)
    .bind(run.0)
    .fetch_one(pool)
    .await
}

/// What an empty done did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptyDone {
    /// Refused; the agent may try again with something to show.
    Refused,
    /// The agent's second empty done on the issue: it went up the chain to this actor.
    Escalated(NextActor),
}

/// Refuses `run`'s `done` on `issue` at `now`: audits `issue.done_refused`, and when its agent
/// had already been refused on this issue, escalates the issue up the chain from that agent.
pub async fn refuse_empty_done(
    pool: &SqlitePool,
    issue: IssueId,
    run: &Run,
    now: &str,
) -> Result<EmptyDone, IssueTransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let agent = run.agent_id;
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'issue.done_refused' \
         AND entity_kind = 'issue' AND entity_id = ? AND json_extract(details, '$.agent') = ?",
    )
    .bind(issue.0)
    .bind(agent.0)
    .fetch_one(&mut *tx)
    .await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_one(&mut *tx)
        .await?;
    let mut done = EmptyDone::Refused;
    if before > 0 {
        let to = escalation_target_in(&mut tx, issue, agent).await?;
        let by = AuditActor::System;
        if reassign_in(&mut tx, issue, to.clone(), by, WakeSource::Escalation)
            .await?
            .is_some()
        {
            done = EmptyDone::Escalated(to);
        }
    }
    let escalated_to = match &done {
        EmptyDone::Escalated(to) => Some(super::breaker::actor_text(to)),
        EmptyDone::Refused => None,
    };
    let event = NewAuditEvent {
        actor: AuditActor::Agent(agent),
        action: "issue.done_refused".to_owned(),
        entity: Some(AuditEntity {
            kind: "issue".to_owned(),
            id: issue.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(run.id),
        details: json!({"agent": agent.0, "run": run.id.0, "refusal": before + 1,
            "escalated_to": escalated_to, "at": now})
        .to_string(),
    };
    audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    Ok(done)
}
