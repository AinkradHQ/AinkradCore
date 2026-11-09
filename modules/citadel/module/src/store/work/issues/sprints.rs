//! Sprints (E5.2): plan, fill, start and close, each audited in one `BEGIN IMMEDIATE`
//! transaction. Agents change a sprint's scope only while it is planned and its commit is not
//! waiting on an approval; the admin (a user: the CLI and `/api/v1`) may also change an active
//! sprint's scope, moving its committed points, and delete an empty planned sprint (`scope`).
//! A closed sprint's scope is fixed. Starting, only through the commit gate (`gate`, E5.4),
//! freezes the committed points; closing moves the open issues out (to the backlog or a planned
//! sprint) and freezes the completed points. Sprints are scrum only: kanban is refused (E5.3).

use crate::domain::gov::ApprovalId;
use crate::domain::work::WakeSource;
use crate::domain::work::{NewSprint, ProjectMode, Sprint, SprintState};
use crate::store::exec::{NewWakeRequest, enqueue_in};
use ainkrad_core::audit::AuditActor;
use sqlx::SqliteConnection;

use super::checkout::{append_issue_event, issue_in};
use super::kanban::project_mode;
use super::*;
use crate::store::audit::{self, Event};

/// Why a sprint operation was refused.
#[derive(Debug)]
pub enum SprintError {
    /// No such sprint or issue.
    NotFound,
    /// Not allowed while the sprint is in this state.
    State(SprintState),
    /// The issue or sprint belongs to another project.
    OtherProject,
    /// The issue is closed: it neither joins a sprint nor is estimated.
    IssueClosed(IssueState),
    /// Subtasks go with their parent.
    Subtask,
    /// A sprint starts only when every issue in it has points.
    Unpointed(Vec<IssueId>),
    /// Sprints are for scrum projects; this one is kanban (E5.3).
    WrongMode(ProjectMode),
    /// The project already has an active sprint.
    ActiveExists(SprintId),
    /// Only the product owner of the project's team commits its sprint (E5.4).
    NotProductOwner,
    /// The sprint holds more points than the team's capacity; committing it needs an
    /// override reason.
    OverCapacity {
        points: u32,
        capacity: u32,
    },
    /// The sprint's commit waits on this approval: its scope is frozen until it is decided.
    AwaitingApproval(ApprovalId),
    /// The sprint's issues or points differ from what its pending commit approval holds: the
    /// approval cannot start it.
    EstimatesChanged,
    /// The sprint still holds this many issues: it is deleted only empty.
    NotEmpty(i64),
    Db(Error),
}

impl From<Error> for SprintError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for SprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such sprint or issue"),
            Self::State(s) => write!(f, "not allowed on a {} sprint", s.as_str()),
            Self::OtherProject => f.write_str("the issue and sprint are in different projects"),
            Self::IssueClosed(s) => write!(
                f,
                "the issue is {}: it neither joins a sprint nor is estimated",
                s.as_str()
            ),
            Self::Subtask => f.write_str("a subtask goes with its parent"),
            Self::Unpointed(ids) => write!(f, "{} issue(s) without points", ids.len()),
            Self::WrongMode(m) => write!(f, "a {} project has no sprints", m.as_str()),
            Self::ActiveExists(id) => write!(f, "sprint {} is already active", id.0),
            Self::NotProductOwner => {
                f.write_str("only the product owner of the project's team commits its sprint")
            }
            Self::OverCapacity { points, capacity } => write!(
                f,
                "{points} points is over the team's capacity of {capacity}; give an \
                 override_reason to commit it anyway"
            ),
            Self::AwaitingApproval(id) => {
                write!(f, "the sprint's commit waits on approval {}", id.0)
            }
            Self::EstimatesChanged => {
                f.write_str("the sprint's issues or points changed since its commit was requested")
            }
            Self::NotEmpty(n) => write!(f, "{n} issue(s) still in it: `sprint remove` them first"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SprintError {}

macro_rules! sprint_columns {
    () => {
        "id, project_id, name, goal, state, starts_on, ends_on"
    };
}

pub(super) async fn sprint_in(
    conn: &mut SqliteConnection,
    id: SprintId,
) -> Result<Sprint, SprintError> {
    let row = sqlx::query(concat!(
        "SELECT ",
        sprint_columns!(),
        " FROM citadel_sprints WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(SprintError::NotFound)?;
    let s = crate::store::work::sprint(row)?;
    scrum_only(conn, s.project_id).await?;
    Ok(s)
}

/// Sprints are for scrum projects (E5.3).
async fn scrum_only(conn: &mut SqliteConnection, project: ProjectId) -> Result<(), SprintError> {
    match project_mode(conn, project).await? {
        None => Err(SprintError::NotFound),
        Some((ProjectMode::Scrum, _)) => Ok(()),
        Some((mode, _)) => Err(SprintError::WrongMode(mode)),
    }
}

/// Appends an event about the sprint, attributed to its project's company.
pub(super) async fn append_sprint_event(
    conn: &mut SqliteConnection,
    s: &Sprint,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(s.project_id.0)
        .fetch_one(&mut *conn)
        .await?;
    let event = Event::new(actor, action)
        .entity("sprint", s.id.0)
        .company(company)
        .details(details);
    audit::append(conn, event).await
}

/// Plans a sprint (state `planned`) with its goal and both dates (`YYYY-MM-DD`, end not
/// before start) and appends `sprint.planned` by `actor`. Any other state, or a missing or
/// malformed date, is `Error::InvalidArgument`.
pub async fn plan_sprint(
    pool: &SqlitePool,
    s: &NewSprint,
    actor: AuditActor,
) -> Result<Sprint, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let planned = plan_sprint_in(&mut tx, s, actor).await?;
    tx.commit().await?;
    Ok(planned)
}

/// `plan_sprint` inside the caller's transaction.
pub async fn plan_sprint_in(
    tx: &mut SqliteConnection,
    s: &NewSprint,
    actor: AuditActor,
) -> Result<Sprint, SprintError> {
    if s.state != SprintState::Planned {
        return Err(SprintError::State(s.state));
    }
    scrum_only(&mut *tx, s.project_id).await?;
    let (Some(starts), Some(ends)) = (&s.starts_on, &s.ends_on) else {
        return Err(Error::InvalidArgument("a sprint needs a start and an end date".into()).into());
    };
    let valid: bool = sqlx::query_scalar("SELECT date(?1) IS ?1 AND date(?2) IS ?2 AND ?2 >= ?1")
        .bind(starts)
        .bind(ends)
        .fetch_one(&mut *tx)
        .await?;
    if !valid {
        let why = format!("bad sprint dates {starts}..{ends}");
        return Err(Error::InvalidArgument(why).into());
    }
    let name = scope::free_name(&mut *tx, s.project_id, &s.name).await?;
    let row = sqlx::query(concat!(
        "INSERT INTO citadel_sprints (project_id, name, goal, state, starts_on, ends_on) \
         VALUES (?, ?, ?, 'planned', ?, ?) RETURNING ",
        sprint_columns!()
    ))
    .bind(s.project_id.0)
    .bind(&name)
    .bind(&s.goal)
    .bind(starts)
    .bind(ends)
    .fetch_one(&mut *tx)
    .await?;
    let planned = crate::store::work::sprint(row)?;
    let details = serde_json::json!({"goal": s.goal, "starts_on": starts, "ends_on": ends});
    append_sprint_event(tx, &planned, actor, "sprint.planned", details).await?;
    Ok(planned)
}

/// Moves `issue` to `to` (or out of any sprint) and appends `issue.sprint_set` by `actor`.
pub(super) async fn set_sprint_in(
    conn: &mut SqliteConnection,
    issue: &Issue,
    to: Option<SprintId>,
    actor: AuditActor,
) -> Result<Issue, Error> {
    let row = sqlx::query(concat!(
        "UPDATE citadel_issues SET sprint_id = ? WHERE id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(to.map(|s| s.0))
    .bind(issue.id.0)
    .fetch_one(&mut *conn)
    .await?;
    let moved = super::issue(row)?;
    let details = serde_json::json!({"from": issue.sprint_id.map(|s| s.0), "to": to.map(|s| s.0)});
    append_issue_event(
        conn,
        &moved,
        actor,
        "issue.sprint_set",
        None,
        details.to_string(),
    )
    .await?;
    Ok(moved)
}

/// The sprint the issue is in must be planned (or none) for it to move, or active and the
/// move the admin's: then it is a scope change, recorded here.
async fn leaving_ok(
    conn: &mut SqliteConnection,
    issue: &Issue,
    actor: AuditActor,
) -> Result<(), SprintError> {
    let Some(from) = issue.sprint_id else {
        return Ok(());
    };
    let s = sprint_in(conn, from).await?;
    match s.state {
        SprintState::Planned => not_awaiting(conn, from).await,
        SprintState::Active if scope::may_change(actor) => {
            Ok(scope::changed(conn, &s, issue, false, actor).await?)
        }
        state => Err(SprintError::State(state)),
    }
}

/// A sprint whose commit waits on an approval keeps the scope it was submitted with.
pub(super) async fn not_awaiting(
    conn: &mut SqliteConnection,
    sprint: SprintId,
) -> Result<(), SprintError> {
    let pending: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_approvals WHERE sprint_id = ? AND kind = 'sprint_commit' \
         AND status = 'pending'",
    )
    .bind(sprint.0)
    .fetch_optional(&mut *conn)
    .await?;
    match pending {
        Some(id) => Err(SprintError::AwaitingApproval(ApprovalId(id))),
        None => Ok(()),
    }
}

/// Adds an open top-level issue of the sprint's project to the planned sprint (or, for the
/// admin, an active one: a pointed issue, as a scope change), from the backlog or another
/// sprint it may leave, and appends `issue.sprint_set` by `actor`.
pub async fn add_to_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    issue: IssueId,
    actor: AuditActor,
) -> Result<Issue, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let added = add_to_sprint_in(&mut tx, sprint, issue, actor).await?;
    tx.commit().await?;
    Ok(added)
}

/// `add_to_sprint` inside the caller's transaction.
pub async fn add_to_sprint_in(
    tx: &mut SqliteConnection,
    sprint: SprintId,
    issue: IssueId,
    actor: AuditActor,
) -> Result<Issue, SprintError> {
    let s = sprint_in(&mut *tx, sprint).await?;
    let i = issue_in(&mut *tx, issue)
        .await?
        .ok_or(SprintError::NotFound)?;
    let scope_change = match s.state {
        SprintState::Planned => false,
        SprintState::Active if scope::may_change(actor) => true,
        state => return Err(SprintError::State(state)),
    };
    if i.project_id != s.project_id {
        return Err(SprintError::OtherProject);
    }
    if i.state.is_terminal() {
        return Err(SprintError::IssueClosed(i.state));
    }
    if i.parent_id.is_some() {
        return Err(SprintError::Subtask);
    }
    if i.sprint_id == Some(sprint) {
        return Ok(i);
    }
    if scope_change && i.points.is_none() {
        return Err(SprintError::Unpointed(vec![i.id]));
    }
    not_awaiting(&mut *tx, sprint).await?;
    leaving_ok(&mut *tx, &i, actor).await?;
    if scope_change {
        scope::changed(&mut *tx, &s, &i, true, actor).await?;
    }
    Ok(set_sprint_in(tx, &i, Some(sprint), actor).await?)
}

/// Takes the issue out of its planned sprint (or, for the admin, its active one: a scope
/// change), back to the backlog, and appends
/// `issue.sprint_set` by `actor`; an issue in no sprint is returned unchanged.
pub async fn remove_from_sprint(
    pool: &SqlitePool,
    issue: IssueId,
    actor: AuditActor,
) -> Result<Issue, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let i = issue_in(&mut tx, issue)
        .await?
        .ok_or(SprintError::NotFound)?;
    if i.sprint_id.is_none() {
        return Ok(i);
    }
    leaving_ok(&mut tx, &i, actor).await?;
    let removed = set_sprint_in(&mut tx, &i, None, actor).await?;
    tx.commit().await?;
    Ok(removed)
}

/// Makes `issues` exactly the planned sprint's issues, in one transaction: the listed ones
/// join (`add_to_sprint_in`'s rules), the others leave for the backlog. Any refusal rolls
/// everything back. Returns `(added, removed)` issue ids.
pub async fn set_sprint_issues(
    pool: &SqlitePool,
    sprint: SprintId,
    issues: &[IssueId],
    actor: AuditActor,
) -> Result<(Vec<IssueId>, Vec<IssueId>), SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    if s.state != SprintState::Planned {
        return Err(SprintError::State(s.state));
    }
    let current: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_issues WHERE sprint_id = ? ORDER BY id")
            .bind(sprint.0)
            .fetch_all(&mut *tx)
            .await?;
    let (mut added, mut removed) = (vec![], vec![]);
    for id in current
        .into_iter()
        .filter(|id| !issues.iter().any(|i| i.0 == *id))
    {
        let i = issue_in(&mut tx, IssueId(id))
            .await?
            .ok_or(SprintError::NotFound)?;
        leaving_ok(&mut tx, &i, actor).await?;
        set_sprint_in(&mut tx, &i, None, actor).await?;
        removed.push(i.id);
    }
    for &id in issues {
        let before = issue_in(&mut tx, id).await?.ok_or(SprintError::NotFound)?;
        add_to_sprint_in(&mut tx, sprint, id, actor).await?;
        if before.sprint_id != Some(sprint) {
            added.push(id);
        }
    }
    tx.commit().await?;
    Ok((added, removed))
}

/// Why the planned sprint `s` cannot start now: another sprint of the project is active, or
/// an issue in it has no points.
pub(super) async fn startable(conn: &mut SqliteConnection, s: &Sprint) -> Result<(), SprintError> {
    if s.state != SprintState::Planned {
        return Err(SprintError::State(s.state));
    }
    let active: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_sprints WHERE project_id = ? AND state = 'active'",
    )
    .bind(s.project_id.0)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = active {
        return Err(SprintError::ActiveExists(SprintId(id)));
    }
    let unpointed: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_issues WHERE sprint_id = ? AND points IS NULL ORDER BY id",
    )
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    if !unpointed.is_empty() {
        return Err(SprintError::Unpointed(
            unpointed.into_iter().map(IssueId).collect(),
        ));
    }
    Ok(())
}

/// Starts the planned sprint inside the caller's `BEGIN IMMEDIATE` transaction, freezing its
/// committed points, and appends `sprint.started` by `actor` with `gate` (how the commit was
/// approved) in its details. Only the sprint commit gate (`gate`) calls this (E5.4): a
/// sprint never starts without it.
pub(super) async fn start_in(
    conn: &mut SqliteConnection,
    s: &Sprint,
    actor: AuditActor,
    gate: serde_json::Value,
) -> Result<Sprint, SprintError> {
    startable(conn, s).await?;
    let committed: i64 = sqlx::query_scalar(
        "UPDATE citadel_sprints SET state = 'active', committed_points = \
         (SELECT coalesce(sum(points), 0) FROM citadel_issues WHERE sprint_id = ?1) \
         WHERE id = ?1 RETURNING committed_points",
    )
    .bind(s.id.0)
    .fetch_one(&mut *conn)
    .await?;
    let started = Sprint {
        state: SprintState::Active,
        ..s.clone()
    };
    let details = serde_json::json!({"committed": committed, "gate": gate});
    append_sprint_event(conn, &started, actor, "sprint.started", details).await?;
    // The owners of the committed work that waits on them are woken to start it (R7a), once per
    // issue; one already working, or waiting on a person, is not woken.
    let owned: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT id, owner_agent_id FROM citadel_issues WHERE sprint_id = ? \
         AND owner_agent_id IS NOT NULL AND next_agent_id = owner_agent_id \
         AND state NOT IN ('done', 'cancelled') ORDER BY id",
    )
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    for (issue, owner) in owned {
        let wake = NewWakeRequest {
            agent_id: AgentId(owner),
            issue_id: Some(IssueId(issue)),
            source: WakeSource::Assignment,
            reason: format!("sprint {} started", started.name),
            idempotency_key: format!("sprint:{}:started:issue:{issue}", s.id.0),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    Ok(started)
}

/// Starts the sprint past the gate: tests of the metrics only.
#[cfg(test)]
pub(crate) async fn start_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    actor: AuditActor,
) -> Result<Sprint, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    let started = start_in(&mut tx, &s, actor, serde_json::json!("test")).await?;
    tx.commit().await?;
    Ok(started)
}
