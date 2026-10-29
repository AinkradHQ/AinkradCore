//! The sprint commit gate (E5.4, decision #10): the only way a sprint starts.
//!
//! The project's product owner commits a planned sprint (`commit_sprint`). Under the
//! `product_owner` policy that starts it at once; under `owner` it opens a `sprint_commit`
//! approval holding the sprint's summary (issues, points against capacity, goal), and the sprint
//! stays planned, its scope frozen, until a human decides (`gov::decide_approval`, which calls
//! `sprint_decided_in`): approving starts it, rejecting hands it back to the product owner with
//! the reply. Committing more points than the team's capacity needs an override reason, kept in
//! the approval and the audit.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{Approval, ApprovalKind, NewApproval};
use ainkrad_core::work::{Sprint, SprintApproval};
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::checkout::append_issue_event;
use super::sprints::{append_sprint_event, not_awaiting, sprint_in, start_in, startable};
use super::*;
use crate::store::gov::open_approval_in;

/// What a commit did.
#[derive(Debug)]
pub enum Commit {
    /// The product owner commits alone: the sprint is active.
    Started(Sprint),
    /// The owner decides: the sprint stays planned until this approval is.
    Pending(Approval),
}

/// The sprint's summary as the approval carries it: its issues, points against capacity,
/// goal and dates, and the override reason if any.
async fn summary(
    conn: &mut SqliteConnection,
    s: &Sprint,
    override_reason: Option<&str>,
) -> Result<(Value, u32, Option<u32>), Error> {
    let issues: Vec<(i64, String, String, Option<u32>)> = sqlx::query_as(
        "SELECT i.id, p.key || '-' || i.number, i.title, i.points FROM issues i \
         JOIN projects p ON p.id = i.project_id WHERE i.sprint_id = ? AND i.parent_id IS NULL \
         ORDER BY i.rank, i.id",
    )
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    let (points, capacity): (u32, Option<u32>) = sqlx::query_as(
        "SELECT (SELECT coalesce(sum(points), 0) FROM issues WHERE sprint_id = ?1), \
         (SELECT sum(m.capacity) FROM team_memberships m JOIN projects p \
             ON p.team_id = m.team_id WHERE p.id = ?2)",
    )
    .bind(s.id.0)
    .bind(s.project_id.0)
    .fetch_one(&mut *conn)
    .await?;
    let issues: Vec<Value> = issues
        .into_iter()
        .map(|(id, key, title, points)| json!({"id": id, "key": key, "title": title, "points": points}))
        .collect();
    let v = json!({"sprint": s.id.0, "name": s.name, "goal": s.goal, "starts_on": s.starts_on,
                   "ends_on": s.ends_on, "issues": issues, "points": points,
                   "capacity": capacity, "override_reason": override_reason});
    Ok((v, points, capacity))
}

/// Commits the planned sprint as the project team's product owner `po`, in one `BEGIN
/// IMMEDIATE` transaction: under the `product_owner` policy it starts (`sprint.started`, gate
/// `product_owner`); under `owner` it opens a `sprint_commit` approval (about `from_issue`,
/// the product owner's planning issue, when given) and appends `sprint.commit_requested`.
/// Points over the team's capacity need a non-blank `override_reason`. The approval opens at
/// `now`, with the `sprint_commit` deadline.
pub async fn commit_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    po: AgentId,
    from_issue: Option<IssueId>,
    override_reason: Option<&str>,
    now: &str,
) -> Result<Commit, SprintError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    startable(&mut tx, &s).await?;
    not_awaiting(&mut tx, sprint).await?;
    let (policy, is_po): (String, bool) = sqlx::query_as(
        "SELECT p.sprint_approval, EXISTS (SELECT 1 FROM team_memberships m \
             WHERE m.team_id = p.team_id AND m.agent_id = ? AND m.team_role = 'product_owner') \
         FROM projects p WHERE p.id = ?",
    )
    .bind(po.0)
    .bind(s.project_id.0)
    .fetch_one(&mut *tx)
    .await?;
    if !is_po {
        return Err(SprintError::NotProductOwner);
    }
    let reason = override_reason.map(str::trim).filter(|r| !r.is_empty());
    let (payload, points, capacity) = summary(&mut tx, &s, reason).await?;
    if let Some(capacity) = capacity
        && points > capacity
        && reason.is_none()
    {
        return Err(SprintError::OverCapacity { points, capacity });
    }
    let by = AuditActor::Agent(po);
    let policy: SprintApproval = policy.parse().map_err(|e| Error::Decode(Box::new(e)))?;
    let done = match policy {
        SprintApproval::ProductOwner => {
            let gate = json!({"by": "product_owner", "points": points, "capacity": capacity,
                              "override_reason": reason});
            Commit::Started(start_in(&mut tx, &s, by, gate).await?)
        }
        SprintApproval::Owner => {
            let company: i64 = sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
                .bind(s.project_id.0)
                .fetch_one(&mut *tx)
                .await?;
            let new = NewApproval {
                company_id: ainkrad_core::org::CompanyId(company),
                kind: ApprovalKind::SprintCommit,
                issue_id: from_issue,
                sprint_id: Some(sprint),
                agent_id: None,
                requested_by: po,
                payload: payload.to_string(),
            };
            let a = open_approval_in(&mut tx, &new, None, now).await?;
            let id = a.id.0;
            let details = json!({"approval": id, "points": points, "capacity": capacity,
                                 "override_reason": reason});
            append_sprint_event(&mut tx, &s, by, "sprint.commit_requested", details).await?;
            Commit::Pending(a)
        }
    };
    tx.commit().await?;
    Ok(done)
}

/// Commits the planned sprint as the admin `by`, who is the owner the `owner` policy waits on
/// (decision #10): it starts at once under either policy (`sprint.started`, gate `owner`), with
/// the same checks as the product owner's commit: scope not waiting on an approval (decide that
/// instead), points within the team's capacity or a non-blank `override_reason`.
pub async fn owner_commit_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    by: UserId,
    override_reason: Option<&str>,
) -> Result<Sprint, SprintError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    startable(&mut tx, &s).await?;
    not_awaiting(&mut tx, sprint).await?;
    let reason = override_reason.map(str::trim).filter(|r| !r.is_empty());
    let (_, points, capacity) = summary(&mut tx, &s, reason).await?;
    if let Some(capacity) = capacity
        && points > capacity
        && reason.is_none()
    {
        return Err(SprintError::OverCapacity { points, capacity });
    }
    let gate = json!({"by": "owner", "points": points, "capacity": capacity,
                      "override_reason": reason});
    let started = start_in(&mut tx, &s, AuditActor::User(by), gate).await?;
    tx.commit().await?;
    Ok(started)
}

/// What a decided `sprint_commit` does, inside the deciding transaction: approved, the sprint
/// starts (gate `owner`, by the decider); rejected, it stays planned. The product owner hears
/// of it from the approvals service (`gov::decide_approval`). A start that fails (another sprint active, an issue
/// without points, points that differ from the approval's) fails the decision, which stays
/// pending.
pub(crate) async fn sprint_decided_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: UserId,
) -> Result<(), SprintError> {
    let Some(sprint) = a.sprint_id else {
        return Ok(());
    };
    let s = sprint_in(conn, sprint).await?;
    let approved = a.status == ainkrad_core::gov::ApprovalStatus::Approved;
    if approved {
        // What is approved is what the approval holds: the points of each issue and the total.
        let (current, ..) = summary(conn, &s, None).await?;
        let held: Value = serde_json::from_str(&a.payload).unwrap_or_default();
        let estimates = |v: &Value| {
            let issues = v["issues"].as_array().map(|issues| {
                let pairs = issues
                    .iter()
                    .map(|i| (i["id"].clone(), i["points"].clone()));
                pairs.collect::<Vec<_>>()
            });
            (v["points"].clone(), issues)
        };
        if estimates(&current) != estimates(&held) {
            return Err(SprintError::EstimatesChanged);
        }
        let gate = json!({"by": "owner", "approval": a.id.0, "reply": a.reply});
        start_in(conn, &s, AuditActor::User(by), gate).await?;
    }
    Ok(())
}

/// Posts `body` as `by`'s comment on the approval's issue (key `approval:<id>`, so once) and
/// appends `issue.commented`; nothing when it has no issue or the issue is gone.
pub(crate) async fn approval_comment_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: UserId,
    body: &str,
) -> Result<(), Error> {
    let Some(issue) = a.issue_id else {
        return Ok(());
    };
    let Some(i) = super::checkout::issue_in(conn, issue).await? else {
        return Ok(());
    };
    let added = sqlx::query(
        "INSERT INTO comments (issue_id, author_user_id, body, idempotency_key) \
         VALUES (?, ?, ?, ?) ON CONFLICT (issue_id, idempotency_key) DO NOTHING",
    )
    .bind(issue.0)
    .bind(by.0)
    .bind(body)
    .bind(format!("approval:{}", a.id.0))
    .execute(&mut *conn)
    .await
    .map(affected)?;
    if added {
        let details = json!({"approval": a.id.0}).to_string();
        let by = AuditActor::User(by);
        append_issue_event(conn, &i, by, "issue.commented", None, details).await?;
    }
    Ok(())
}

/// Sets the project's spec, the text its planners plan from (read with `get_context`), and
/// appends `project.spec_set` by `actor`; `false` when there is no such project.
pub async fn set_project_spec(
    pool: &SqlitePool,
    project: ProjectId,
    spec: &str,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let company: Option<i64> =
        sqlx::query_scalar("UPDATE projects SET spec = ? WHERE id = ? RETURNING company_id")
            .bind(spec)
            .bind(project.0)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let event = ainkrad_core::audit::NewAuditEvent {
        actor,
        action: "project.spec_set".to_owned(),
        entity: Some(ainkrad_core::audit::AuditEntity {
            kind: "project".to_owned(),
            id: project.0,
        }),
        company_id: Some(ainkrad_core::org::CompanyId(company)),
        run_id: None,
        details: json!({"bytes": spec.len()}).to_string(),
    };
    crate::store::audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    Ok(true)
}

/// The project's spec; `None` when there is no such project.
pub async fn project_spec(pool: &SqlitePool, project: ProjectId) -> Result<Option<String>, Error> {
    sqlx::query_scalar("SELECT spec FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(pool)
        .await
}
