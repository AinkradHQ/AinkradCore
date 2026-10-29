//! Plan-first (E15.10, decision #40): a requirement's plan is its epics and their tasks (its
//! top-level issues filed under an epic; cancelled ones left out). It is complete when it has an
//! epic, every epic has a task, and every task has points and an assignee (its owner). A planner
//! submits it (`submit_plan`):
//!
//! - under the `product_owner` sprint policy of every project it spans, it is approved at once;
//! - under `owner` (any project), a `plan_approval` approval opens about the submitter's issue and
//!   the requirement waits in `plan_review` until a person decides (`plan_decided_in`, from the
//!   approvals service): approved, the plan is recorded as the next version and work may start;
//!   rejected or expired, it goes back to `planning`. The submitter hears the reply (the
//!   approvals service wakes it), as with a sprint commit.
//!
//! An approved plan's tasks are stored as its version (`requirement_plans`); later changes show
//! as a diff against it in the tree (`tree::plan_diff`), never silently.

use ainkrad_core::gov::{Approval, ApprovalKind, ApprovalStatus, NewApproval};
use ainkrad_core::work::{EpicId, IssueKind, IssueState, NewIssue, NextActor};
use serde_json::Value;

use super::*;
use crate::store::exec::signal_wakes;
use crate::store::gov::open_approval_in;

/// What a submitted plan became.
#[derive(Debug)]
pub enum Submitted {
    /// Approved at once (`product_owner` policy): this version.
    Approved(i64),
    /// Waiting on this `plan_approval`.
    Pending(Box<Approval>),
}

/// Whether `agent` plans `requirement`: the CEO or CTO of its company, or a product owner or
/// team lead of a project it spans (made for it, or holding an epic or an issue of it: an
/// existing project it was routed to carries it on its kickoff issue).
pub(crate) async fn plans_in(
    conn: &mut SqliteConnection,
    requirement: &Requirement,
    agent: AgentId,
) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agents a WHERE a.id = ?1 AND a.company_id = ?3 AND \
         (a.org_role IN ('ceo', 'cto') OR EXISTS (SELECT 1 FROM team_memberships m \
             JOIN projects p ON p.team_id = m.team_id WHERE m.agent_id = a.id \
             AND m.team_role IN ('product_owner', 'team_lead') AND (p.requirement_id = ?2 \
             OR p.id IN (SELECT project_id FROM epics WHERE requirement_id = ?2) \
             OR p.id IN (SELECT project_id FROM issues WHERE requirement_id = ?2)))))",
    )
    .bind(agent.0)
    .bind(requirement.id.0)
    .bind(requirement.company_id.0)
    .fetch_one(&mut *conn)
    .await
}

/// The plan's tasks as an approval and a version hold them: `[{id, key, title, epic_id,
/// points, assignee_agent_id}]`, by epic then rank.
pub(crate) async fn plan_tasks_in(
    conn: &mut SqliteConnection,
    requirement: RequirementId,
) -> Result<Vec<Value>, Error> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT json_object('id', i.id, 'key', p.key || '-' || i.number, 'title', i.title, \
         'epic_id', i.epic_id, 'points', i.points, 'assignee_agent_id', i.owner_agent_id) \
         FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE i.requirement_id = ? AND i.parent_id IS NULL AND i.epic_id IS NOT NULL \
         AND i.state <> 'cancelled' ORDER BY i.epic_id, i.rank, i.id",
    )
    .bind(requirement.0)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .iter()
        .map(|r| serde_json::from_str(r).unwrap_or_default())
        .collect())
}

/// What keeps the plan from being complete, in words; empty when it is.
pub async fn plan_problems_in(
    conn: &mut SqliteConnection,
    requirement: RequirementId,
) -> Result<Vec<String>, Error> {
    let epics: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT e.id, e.title, (SELECT count(*) FROM issues i WHERE i.epic_id = e.id \
             AND i.parent_id IS NULL AND i.state <> 'cancelled') \
         FROM epics e WHERE e.requirement_id = ? AND e.status <> 'cancelled' ORDER BY e.id",
    )
    .bind(requirement.0)
    .fetch_all(&mut *conn)
    .await?;
    let mut problems = vec![];
    if epics.is_empty() {
        problems.push("it has no epic".to_owned());
    }
    for (id, title, tasks) in &epics {
        if *tasks == 0 {
            problems.push(format!("epic {id} ({title}) has no task"));
        }
    }
    let unready: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT p.key || '-' || i.number, i.points IS NULL, \
         i.owner_agent_id IS NULL AND i.owner_user_id IS NULL \
         FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE i.requirement_id = ? AND i.parent_id IS NULL AND i.epic_id IS NOT NULL \
         AND i.state <> 'cancelled' AND (i.points IS NULL OR (i.owner_agent_id IS NULL \
             AND i.owner_user_id IS NULL)) ORDER BY i.id",
    )
    .bind(requirement.0)
    .fetch_all(&mut *conn)
    .await?;
    for (key, unpointed, unassigned) in unready {
        if unpointed {
            problems.push(format!("{key} has no estimate"));
        }
        if unassigned {
            problems.push(format!("{key} has no assignee"));
        }
    }
    Ok(problems)
}

/// Files an epic for the requirement in `project` (of its company) as `by`, with `epic.created`.
pub(crate) async fn add_epic_in(
    conn: &mut SqliteConnection,
    requirement: &Requirement,
    project: ProjectId,
    title: &str,
    by: AuditActor,
) -> Result<EpicId, RequirementError> {
    let company: Option<i64> = sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(&mut *conn)
        .await?;
    if company != Some(requirement.company_id.0) {
        return Err(
            Error::InvalidArgument(format!("no project {} in this company", project.0)).into(),
        );
    }
    if title.trim().is_empty() {
        return Err(Error::InvalidArgument("an epic needs a title".to_owned()).into());
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO epics (project_id, title, requirement_id) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(project.0)
    .bind(title.trim())
    .bind(requirement.id.0)
    .fetch_one(&mut *conn)
    .await?;
    let details = json!({"project": project.0, "title": title.trim(),
                         "requirement": requirement.id.0});
    let company = requirement.company_id;
    append_org_event(conn, company, by, "epic.created", ("epic", id), details).await?;
    Ok(EpicId(id))
}

/// A task of a plan: under an epic of the requirement, in the backlog, owned by `assignee`,
/// waiting on the planner, points as given. Nobody is woken: work starts once the plan is
/// approved and the planner hands the task over (`assign_issue`).
#[derive(Clone, Copy)]
pub struct PlannedTask<'a> {
    /// `None` inside a `NewPlanEpic`: the new epic.
    pub epic: Option<EpicId>,
    pub title: &'a str,
    pub body: &'a str,
    pub points: Option<u32>,
    pub assignee: Option<AgentId>,
}

/// Files the task as `planner`, with `issue.created`.
pub(crate) async fn add_task_in(
    conn: &mut SqliteConnection,
    requirement: &Requirement,
    t: &PlannedTask<'_>,
    planner: AgentId,
) -> Result<Issue, RequirementError> {
    let epic = t
        .epic
        .ok_or_else(|| Error::InvalidArgument("a task needs an epic".to_owned()))?;
    let project: Option<(i64, Option<i64>)> =
        sqlx::query_as("SELECT project_id, requirement_id FROM epics WHERE id = ?")
            .bind(epic.0)
            .fetch_optional(&mut *conn)
            .await?;
    let not_ours =
        || Error::InvalidArgument(format!("epic {} is not one of this requirement's", epic.0));
    let Some((project, Some(of))) = project else {
        return Err(not_ours().into());
    };
    if of != requirement.id.0 {
        return Err(not_ours().into());
    }
    if let Some(a) = t.assignee {
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM agents WHERE id = ? AND company_id = ?)",
        )
        .bind(a.0)
        .bind(requirement.company_id.0)
        .fetch_one(&mut *conn)
        .await?;
        if !ok {
            return Err(Error::InvalidArgument(format!("no agent {} in this company", a.0)).into());
        }
    }
    let new = NewIssue {
        project_id: ProjectId(project),
        epic_id: Some(epic),
        parent_id: None,
        kind: IssueKind::Task,
        title: t.title.trim().to_owned(),
        body: t.body.to_owned(),
        state: IssueState::Backlog,
        owner: t.assignee.map(Actor::Agent),
        next_actor: Some(NextActor::Agent(planner)),
        points: t.points,
        sprint_id: None,
    };
    if new.title.is_empty() {
        return Err(Error::InvalidArgument("a task needs a title".to_owned()).into());
    }
    let i = create_issue_in(conn, &new).await?;
    let details = json!({"title": i.title, "requirement": requirement.id.0}).to_string();
    let by = AuditActor::Agent(planner);
    crate::store::work::append_issue_event(conn, &i, by, "issue.created", None, details).await?;
    Ok(i)
}

/// A new epic of a plan, with its tasks.
pub struct NewPlanEpic<'a> {
    pub project: ProjectId,
    pub title: &'a str,
    pub tasks: Vec<PlannedTask<'a>>,
}

/// What `plan_requirement` filed, and what still keeps the plan from being complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub epics: Vec<EpicId>,
    pub tasks: Vec<IssueId>,
    pub problems: Vec<String>,
}

/// Files epics (with their tasks) and tasks under existing epics into the requirement's plan, as
/// the planner `by`, in one transaction. While its plan is reviewed nothing is added; once it is
/// approved, what is added shows in the tree's diff.
pub async fn plan_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    by: AgentId,
    epics: &[NewPlanEpic<'_>],
    tasks: &[PlannedTask<'_>],
) -> Result<Planned, RequirementError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if !plans_in(&mut tx, &r, by).await? {
        return Err(RequirementError::NotPlanner);
    }
    if !matches!(
        r.state,
        RequirementState::Planning | RequirementState::InProgress
    ) {
        return Err(RequirementError::State(r.state));
    }
    let mut planned = Planned {
        epics: vec![],
        tasks: vec![],
        problems: vec![],
    };
    let actor = AuditActor::Agent(by);
    for e in epics {
        let epic = add_epic_in(&mut tx, &r, e.project, e.title, actor).await?;
        planned.epics.push(epic);
        for t in &e.tasks {
            let t = PlannedTask {
                epic: Some(epic),
                ..*t
            };
            planned
                .tasks
                .push(add_task_in(&mut tx, &r, &t, by).await?.id);
        }
    }
    for t in tasks {
        planned
            .tasks
            .push(add_task_in(&mut tx, &r, t, by).await?.id);
    }
    planned.problems = plan_problems_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(planned)
}

/// Submits the requirement's plan as `by` (a planner), from its issue `from_issue`, at `now`;
/// see the module docs. Refused unless the requirement is `planning` and its plan complete.
pub async fn submit_plan(
    pool: &SqlitePool,
    id: RequirementId,
    by: AgentId,
    from_issue: Option<IssueId>,
    now: &str,
) -> Result<Submitted, RequirementError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if !plans_in(&mut tx, &r, by).await? {
        return Err(RequirementError::NotPlanner);
    }
    if r.state != RequirementState::Planning {
        return Err(RequirementError::State(r.state));
    }
    let problems = plan_problems_in(&mut tx, id).await?;
    if !problems.is_empty() {
        return Err(RequirementError::Incomplete(problems));
    }
    // The strictest policy of the projects it spans (not the intake, where the request is):
    // one asking the owner decides.
    let owner_decides: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM projects WHERE sprint_approval = 'owner' AND intake = 0 \
         AND (requirement_id = ?1 OR id IN (SELECT project_id FROM epics WHERE requirement_id = ?1) \
         OR id IN (SELECT project_id FROM issues WHERE requirement_id = ?1)))",
    )
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let tasks = plan_tasks_in(&mut tx, id).await?;
    let done = if owner_decides {
        let points: i64 = tasks.iter().filter_map(|t| t["points"].as_i64()).sum();
        let payload = json!({"requirement": id.0, "key": r.key(), "title": r.title,
                             "tasks": tasks, "points": points});
        let new = NewApproval {
            company_id: r.company_id,
            kind: ApprovalKind::PlanApproval,
            issue_id: from_issue,
            sprint_id: None,
            agent_id: None,
            requested_by: by,
            payload: payload.to_string(),
        };
        let a = open_approval_in(&mut tx, &new, None, now).await?;
        sqlx::query("UPDATE approvals SET requirement_id = ? WHERE id = ?")
            .bind(id.0)
            .bind(a.id.0)
            .execute(&mut *tx)
            .await?;
        set_state_in(&mut tx, &r, RequirementState::PlanReview).await?;
        let details = json!({"approval": a.id.0, "tasks": tasks.len(), "points": points});
        event_in(
            &mut tx,
            &r,
            AuditActor::Agent(by),
            "requirement.plan_submitted",
            details,
        )
        .await?;
        Submitted::Pending(Box::new(a))
    } else {
        let v = approve_in(&mut tx, &r, None, AuditActor::Agent(by), now).await?;
        Submitted::Approved(v)
    };
    tx.commit().await?;
    if matches!(done, Submitted::Approved(_)) {
        signal_wakes();
    }
    Ok(done)
}

async fn set_state_in(
    conn: &mut SqliteConnection,
    r: &Requirement,
    state: RequirementState,
) -> Result<(), Error> {
    sqlx::query("UPDATE requirements SET state = ? WHERE id = ?")
        .bind(state.as_str())
        .bind(r.id.0)
        .execute(&mut *conn)
        .await
        .map(drop)
}

/// Appends `action` about the requirement.
pub(crate) async fn event_in(
    conn: &mut SqliteConnection,
    r: &Requirement,
    actor: AuditActor,
    action: &str,
    details: Value,
) -> Result<(), Error> {
    let entity = ("requirement", r.id.0);
    append_org_event(conn, r.company_id, actor, action, entity, details).await
}

/// Records the plan as it stands as the next version, approved by `approval` (else by the
/// product owner's policy), and starts the work (`in_progress`); `requirement.plan_approved`.
async fn approve_in(
    conn: &mut SqliteConnection,
    r: &Requirement,
    approval: Option<&Approval>,
    by: AuditActor,
    now: &str,
) -> Result<i64, Error> {
    let tasks = plan_tasks_in(conn, r.id).await?;
    let version = r.plan_version + 1;
    let gate = match approval {
        Some(_) => "owner",
        None => "product_owner",
    };
    sqlx::query(
        "INSERT INTO requirement_plans (requirement_id, version, tasks, approval_id, \
         approved_by, approved_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(r.id.0)
    .bind(version)
    .bind(Value::from(tasks.clone()).to_string())
    .bind(approval.map(|a| a.id.0))
    .bind(gate)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE requirements SET state = 'in_progress', plan_version = ? WHERE id = ?")
        .bind(version)
        .bind(r.id.0)
        .execute(&mut *conn)
        .await?;
    let details = json!({"version": version, "by": gate, "tasks": tasks.len(),
                         "approval": approval.map(|a| a.id.0)});
    event_in(conn, r, by, "requirement.plan_approved", details).await?;
    Ok(version)
}

/// What a decided (or expired) `plan_approval` does, inside its transaction: approved, the plan
/// becomes the next version and work may start; otherwise the requirement goes back to planning.
pub(crate) async fn plan_decided_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: AuditActor,
    now: &str,
) -> Result<(), Error> {
    let id: Option<i64> = sqlx::query_scalar("SELECT requirement_id FROM approvals WHERE id = ?")
        .bind(a.id.0)
        .fetch_one(&mut *conn)
        .await?;
    let Some(r) = (match id {
        Some(id) => requirement_in(conn, RequirementId(id)).await?,
        None => None,
    }) else {
        return Ok(());
    };
    if r.state != RequirementState::PlanReview {
        return Ok(());
    }
    if a.status == ApprovalStatus::Approved {
        approve_in(conn, &r, Some(a), by, now).await?;
        return Ok(());
    }
    set_state_in(conn, &r, RequirementState::Planning).await?;
    let details = json!({"approval": a.id.0, "status": a.status.as_str(), "reply": a.reply});
    event_in(conn, &r, by, "requirement.plan_returned", details).await
}
