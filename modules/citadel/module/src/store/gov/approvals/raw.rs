//! Raw approval writers, test-only (`cfg(test)` or the `test-support` feature): they skip the
//! deadline, the decision's effects and the audit. Production code opens approvals with
//! `open_approval_in` and decides them with `decide_approval`.

use super::*;
use crate::store::org::affected;

/// Opens a `pending` approval with no deadline. `payload` must be valid JSON.
pub async fn create_approval(
    pool: impl sqlx::SqliteExecutor<'_>,
    a: &NewApproval,
) -> Result<Approval, Error> {
    sqlx::query(concat!(
        "INSERT INTO citadel_approvals (company_id, kind, issue_id, sprint_id, agent_id, \
         requested_by_agent_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ",
        approval_columns!()
    ))
    .bind(a.company_id.0)
    .bind(a.kind.as_str())
    .bind(a.issue_id.map(|i| i.0))
    .bind(a.sprint_id.map(|s| s.0))
    .bind(a.agent_id.map(|g| g.0))
    .bind(a.requested_by.0)
    .bind(&a.payload)
    .fetch_one(pool)
    .await
    .and_then(approval)
}

/// Records status, decider and reply as given. A decided approval needs a decider; a pending
/// one has none.
pub async fn update_approval(
    pool: impl sqlx::SqliteExecutor<'_>,
    a: &Approval,
) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_approvals SET status = ?1, decided_by_user_id = ?2, reply = ?3, \
         decided_at = iif(?1 = 'pending', NULL, coalesce(decided_at, \
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))) WHERE id = ?4",
    )
    .bind(a.status.as_str())
    .bind(a.decided_by.map(|u| u.0))
    .bind(&a.reply)
    .bind(a.id.0)
    .execute(pool)
    .await
    .map(affected)
}

pub async fn delete_approval(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: ApprovalId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_approvals WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}
