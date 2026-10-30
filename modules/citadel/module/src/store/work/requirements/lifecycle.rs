//! A requirement's life after it is filed: cancel, pause, resume, finish, and what holds an
//! agent's work on the plan.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::{Error, SqlitePool};

use super::*;
use crate::domain::work::IssueTransition;
use crate::store::work::{IssueTransitionError, transition_issue_in};

/// Cancels the requirement as `actor`, with an optional `reason`: each of its open issues is
/// cancelled through the issue rules (unblocking what waited on it), then the requirement
/// (`requirement.cancelled`, naming them), in one transaction. Refused when it is done or
/// cancelled already. (The monolith also refused while a run works on one of its issues and
/// signalled the wake loop afterwards: both come with the run engine, S7.)
pub async fn cancel_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    reason: Option<&str>,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if matches!(
        r.state,
        RequirementState::Done | RequirementState::Cancelled
    ) {
        return Err(RequirementError::State(r.state));
    }
    // S7: refuse with `RequirementError::Busy` while a run (queued, claimed, running) works on
    // one of its issues; the module has no `runs` table yet.
    let open: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_issues WHERE requirement_id = ? \
         AND state NOT IN ('done', 'cancelled') ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    for &issue in &open {
        let cancel = &IssueTransition::Cancel;
        // An issue an earlier one's cancel closed already is skipped by the rules' own check.
        match transition_issue_in(&mut tx, IssueId(issue), cancel, actor).await {
            Ok(_) | Err(IssueTransitionError::Illegal(_)) => {}
            Err(IssueTransitionError::Db(e)) => return Err(e.into()),
            Err(e) => return Err(Error::Protocol(e.to_string()).into()),
        }
    }
    sqlx::query("UPDATE citadel_requirements SET state = 'cancelled' WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"reason": reason, "from": r.state.as_str(), "issues": open});
    event_in(&mut tx, &r, actor, "requirement.cancelled", details).await?;
    let cancelled = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(cancelled)
}

/// Pauses the requirement as `actor` (`requirement.paused`): no wake for its issues is dispatched
/// until it is resumed; runs already working go on. Already paused changes and audits nothing.
/// Refused once it is done or cancelled.
pub async fn pause_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    hold(pool, id, actor, true).await
}

/// Resumes a paused requirement as `actor` (`requirement.resumed`). Not paused changes and
/// audits nothing. (Letting its held wakes go is the run engine's, S7.)
pub async fn resume_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    hold(pool, id, actor, false).await
}

async fn hold(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
    pause: bool,
) -> Result<Requirement, RequirementError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if matches!(
        r.state,
        RequirementState::Done | RequirementState::Cancelled
    ) {
        return Err(RequirementError::State(r.state));
    }
    if r.paused_at.is_some() == pause {
        return Ok(r);
    }
    sqlx::query(
        "UPDATE citadel_requirements SET paused_at = CASE WHEN ? THEN \
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END WHERE id = ?",
    )
    .bind(pause)
    .bind(id.0)
    .execute(&mut *tx)
    .await?;
    let action = if pause {
        "requirement.paused"
    } else {
        "requirement.resumed"
    };
    event_in(
        &mut tx,
        &r,
        actor,
        action,
        json!({"state": r.state.as_str()}),
    )
    .await?;
    let held = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(held)
}

/// Marks the requirement done as `actor` (`requirement.done`): it must be `in_progress` with none
/// of its issues open (`RequirementError::Open`); a pause ends with it.
pub async fn finish_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if r.state != RequirementState::InProgress {
        return Err(RequirementError::State(r.state));
    }
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM citadel_issues WHERE requirement_id = ? \
         AND state NOT IN ('done', 'cancelled')",
    )
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    if open > 0 {
        return Err(RequirementError::Open(open as usize));
    }
    sqlx::query("UPDATE citadel_requirements SET state = 'done', paused_at = NULL WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    event_in(
        &mut tx,
        &r,
        actor,
        "requirement.done",
        json!({"from": r.state.as_str()}),
    )
    .await?;
    let done = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(done)
}

/// SQL: whether agent `$agent`'s work on issue `$issue` waits on the plan of the issue's
/// requirement (plan-first, E15.10): the requirement is `planning`, `plan_review` or `cancelled`,
/// and the agent does not plan the issue's project (its product owner or team lead, the CEO or
/// the CTO), or the requirement is paused (`paused_at`, for everyone). The monolith's
/// `plan_held!`; the run engine's dispatch (S7) needs it too.
macro_rules! plan_held {
    ($agent:literal, $issue:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM citadel_issues ph_i \
             JOIN citadel_requirements ph_q ON ph_q.id = ph_i.requirement_id \
             JOIN citadel_projects ph_p ON ph_p.id = ph_i.project_id \
             JOIN citadel_agents ph_a ON ph_a.id = ",
            $agent,
            " WHERE ph_i.id = ",
            $issue,
            " AND (ph_q.paused_at IS NOT NULL \
             OR (ph_q.state IN ('planning', 'plan_review', 'cancelled') \
             AND ph_a.org_role NOT IN ('ceo', 'cto') \
             AND NOT EXISTS (SELECT 1 FROM citadel_team_memberships ph_m \
                 WHERE ph_m.team_id = ph_p.team_id AND ph_m.agent_id = ph_a.id \
                 AND ph_m.team_role IN ('product_owner', 'team_lead')))))"
        )
    };
}
pub(crate) use plan_held;

/// Why `agent`'s work on `issue` waits on the issue's requirement's plan (plan-first,
/// `plan_held!`), in words; `None` when it does not.
pub async fn plan_hold(
    pool: &SqlitePool,
    issue: IssueId,
    agent: AgentId,
) -> Result<Option<String>, Error> {
    let held: Option<(i64, String, Option<String>)> = sqlx::query_as(concat!(
        "SELECT q.number, q.state, q.paused_at FROM citadel_issues i \
         JOIN citadel_requirements q ON q.id = i.requirement_id WHERE i.id = ?2 AND ",
        plan_held!("?1", "?2")
    ))
    .bind(agent.0)
    .bind(issue.0)
    .fetch_optional(pool)
    .await?;
    Ok(held.map(|(n, state, paused)| match state.as_str() {
        _ if paused.is_some() => format!("requirement R-{n} is paused: no work on its issues"),
        "cancelled" => format!("requirement R-{n} is cancelled: no work on its issues"),
        state => format!(
            "requirement R-{n}'s plan is not approved yet ({state}): no dev work starts until \
             its full plan (every epic with tasks, every task estimated and assigned) is \
             approved"
        ),
    }))
}
