//! The empty-done check (E15.7, pain #3: agents pretending to work). An agent's `done` on an
//! issue with nothing to show for it is refused with the reason, and a second one by the same
//! agent escalates the issue up the chain. Every refusal is audited as `issue.done_refused`.
//!
//! What counts as something to show: a pull request on the issue, or a comment this run wrote.
//! The monolith also counted the diff the runner measured in the run's worktree; the Core's
//! runner does not report one yet, so an agent that only changed files says what it did in a
//! comment first.
// ponytail: refusals count per (issue, agent) for ever; a window or a reset on reopen if an
// agent's old refusal ever escalates a later, honest one.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::Run;
use crate::domain::work::{IssueId, NextActor, RunId, WakeSource};
use crate::store::audit::{self, Event};
use crate::store::org::escalation_target_in;
use crate::store::work::{IssueTransitionError, reassign_in};

/// Whether `issue` has something to show for a `done` from `run`.
pub async fn done_evidence(
    pool: &SqlitePool,
    issue: IssueId,
    run: RunId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_issue_prs WHERE issue_id = ?1) \
         OR EXISTS (SELECT 1 FROM citadel_comments WHERE run_id = ?2)",
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

/// Refuses `run`'s `done` on `issue`: audits `issue.done_refused`, and when its agent had
/// already been refused on this issue, escalates the issue up the chain from that agent.
pub async fn refuse_empty_done(
    pool: &SqlitePool,
    issue: IssueId,
    run: &Run,
    now: &str,
) -> Result<EmptyDone, IssueTransitionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let agent = run.agent_id;
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.issue.done_refused' \
         AND entity_kind = 'issue' AND entity_id = ? AND json_extract(details, '$.agent') = ?",
    )
    .bind(issue.0)
    .bind(agent.0)
    .fetch_one(&mut *tx)
    .await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(agent.0)
        .fetch_one(&mut *tx)
        .await?;
    let mut done = EmptyDone::Refused;
    if before > 0 {
        let to = escalation_target_in(&mut tx, issue, agent).await?;
        if reassign_in(
            &mut tx,
            issue,
            to.clone(),
            AuditActor::System,
            WakeSource::Escalation,
        )
        .await?
        .is_some()
        {
            done = EmptyDone::Escalated(to);
        }
    }
    let escalated = matches!(done, EmptyDone::Escalated(_));
    let event = Event::new(AuditActor::System, "issue.done_refused")
        .entity("issue", issue.0)
        .company(company)
        .run(run.id.0)
        .details(
            json!({"agent": agent.0, "refusal": before + 1, "escalated": escalated, "at": now}),
        );
    audit::append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(done)
}
