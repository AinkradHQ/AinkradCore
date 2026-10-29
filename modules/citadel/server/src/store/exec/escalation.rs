//! Permission escalations (E3.10): a harness's tool call outside its project's policy becomes
//! a `permission_escalation` approval, one per `(run, request id)`, which a reviewer decides.

use citadel_core::gov::{ApprovalId, ApprovalKind, NewApproval};
use citadel_core::org::CompanyId;
use serde_json::{Value, json};

use super::*;
use crate::store::gov::open_approval_in;

/// The approval for request `request` of `run`, opened at `now` or found from an earlier
/// send. Its payload names the run, the request, the tool and its (already redacted) input.
/// It expires when the runner gives up on it: `timeout_secs` after `now` (the runner's own
/// approval timeout, sent with the request), or the `permission_escalation` deadline for an
/// older runner that does not send one; and when the run ends (`expire_approvals`).
pub async fn escalate(
    pool: &SqlitePool,
    run: &Run,
    request: &str,
    tool: &str,
    input: &Value,
    timeout_secs: Option<u64>,
    now: &str,
) -> Result<ApprovalId, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM approvals WHERE kind = 'permission_escalation' \
         AND json_extract(payload, '$.run') = ? AND json_extract(payload, '$.request') = ?",
    )
    .bind(run.id.0)
    .bind(request)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(id) = found {
        return Ok(ApprovalId(id));
    }
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(run.agent_id.0)
        .fetch_one(&mut *tx)
        .await?;
    let payload = json!({"run": run.id.0, "request": request, "tool": tool, "input": input});
    let new = NewApproval {
        company_id: CompanyId(company),
        kind: ApprovalKind::PermissionEscalation,
        issue_id: run.issue_id,
        sprint_id: None,
        agent_id: Some(run.agent_id),
        requested_by: run.agent_id,
        payload: payload.to_string(),
    };
    let a = open_approval_in(&mut tx, &new, timeout_secs, now).await?;
    tx.commit().await?;
    Ok(a.id)
}

/// The issue's live "allow for this issue" rule (`gov::allow_for_issue`) covering the run's
/// escalated call, if one does; then audited as `run.allowed_by_rule` by the system, and the
/// call goes ahead without a reviewer.
pub async fn allowed_by_rule(
    pool: &SqlitePool,
    run: &Run,
    request: &str,
    tool: &str,
    input: &Value,
    now: &str,
) -> Result<Option<String>, Error> {
    let Some(issue) = run.issue_id else {
        return Ok(None);
    };
    let rules = crate::store::gov::issue_allow_rules(pool, issue, now).await?;
    let Some(rule) = rules
        .into_iter()
        .find(|r| ainkrad_proto::runner::allows(r, tool, input))
    else {
        return Ok(None);
    };
    let mut tx = crate::store::begin_write(pool).await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(run.agent_id.0)
        .fetch_one(&mut *tx)
        .await?;
    let event = citadel_core::audit::NewAuditEvent {
        actor: citadel_core::audit::AuditActor::System,
        action: "run.allowed_by_rule".to_owned(),
        entity: Some(citadel_core::audit::AuditEntity {
            kind: "run".to_owned(),
            id: run.id.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(run.id),
        details: json!({"rule": rule, "request": request, "tool": tool, "issue": issue.0})
            .to_string(),
    };
    crate::store::audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    Ok(Some(rule))
}
