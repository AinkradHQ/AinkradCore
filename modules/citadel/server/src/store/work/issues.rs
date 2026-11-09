//! Issues (with their labels), blocker links and comments.

use std::fmt;

use citadel_core::exec::RunId;
use citadel_core::org::AgentId;
use citadel_core::work::{
    Actor, BlockerLink, Comment, CommentId, Criterion, EpicId, Issue, IssueId, IssueState, Label,
    LabelId, NewComment, NewIssue, NextActor, ProjectId, RequirementId, SprintId, UserId,
};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use super::label;
use crate::store::org::{affected, text};

/// Reads an actor stored as an (agent, user) column pair, at most one set.
fn actor(row: &SqliteRow, agent: &str, user: &str) -> Result<Option<Actor>, Error> {
    let agent = row.try_get::<Option<i64>, _>(agent)?.map(AgentId);
    let user = row.try_get::<Option<i64>, _>(user)?.map(UserId);
    Ok(agent.map(Actor::Agent).or(user.map(Actor::Human)))
}

fn actor_columns(a: Option<Actor>) -> (Option<i64>, Option<i64>) {
    match a {
        Some(Actor::Agent(id)) => (Some(id.0), None),
        Some(Actor::Human(id)) => (None, Some(id.0)),
        None => (None, None),
    }
}

fn next_actor_columns(n: &Option<NextActor>) -> (Option<i64>, Option<i64>, Option<&str>) {
    match n {
        Some(NextActor::Agent(id)) => (Some(id.0), None, None),
        Some(NextActor::Human(id)) => (None, Some(id.0), None),
        Some(NextActor::Timer(at)) => (None, None, Some(at)),
        None => (None, None, None),
    }
}

// --- issues -----------------------------------------------------------------

macro_rules! issue_columns {
    () => {
        "id, project_id, number, epic_id, parent_id, kind, title, body, state, \
         owner_agent_id, owner_user_id, next_agent_id, next_user_id, next_at, points, \
         sprint_id, rank, checkout_run_id, requirement_id, priority, priority_level, criteria"
    };
}

fn issue(row: SqliteRow) -> Result<Issue, Error> {
    let next_at: Option<String> = row.try_get("next_at")?;
    let next_actor = match actor(&row, "next_agent_id", "next_user_id")? {
        Some(Actor::Agent(id)) => Some(NextActor::Agent(id)),
        Some(Actor::Human(id)) => Some(NextActor::Human(id)),
        None => next_at.map(NextActor::Timer),
    };
    Ok(Issue {
        id: IssueId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        number: row.try_get("number")?,
        epic_id: row.try_get::<Option<i64>, _>("epic_id")?.map(EpicId),
        parent_id: row.try_get::<Option<i64>, _>("parent_id")?.map(IssueId),
        kind: text(&row, "kind")?,
        title: row.try_get("title")?,
        body: row.try_get("body")?,
        state: text(&row, "state")?,
        owner: actor(&row, "owner_agent_id", "owner_user_id")?,
        next_actor,
        points: row.try_get("points")?,
        sprint_id: row.try_get::<Option<i64>, _>("sprint_id")?.map(SprintId),
        rank: row.try_get("rank")?,
        checkout_run_id: row.try_get::<Option<i64>, _>("checkout_run_id")?.map(RunId),
        requirement_id: row
            .try_get::<Option<i64>, _>("requirement_id")?
            .map(RequirementId),
        priority: row.try_get("priority")?,
        priority_level: text(&row, "priority_level")?,
        criteria: criteria(&row.try_get::<String, _>("criteria")?)?,
    })
}

/// The criteria column: a JSON array of `{text, done}`.
pub(crate) fn criteria(json: &str) -> Result<Vec<Criterion>, Error> {
    let items: Vec<serde_json::Value> =
        serde_json::from_str(json).map_err(|e| Error::Decode(e.into()))?;
    Ok(items
        .iter()
        .map(|c| Criterion {
            text: c["text"].as_str().unwrap_or_default().to_owned(),
            done: c["done"].as_bool().unwrap_or(false),
        })
        .collect())
}

pub(crate) fn criteria_json(all: &[Criterion]) -> String {
    let items: Vec<_> = all
        .iter()
        .map(|c| serde_json::json!({"text": c.text, "done": c.done}))
        .collect();
    serde_json::Value::Array(items).to_string()
}

mod backlog;
mod chat;
mod checkout;
mod comments;
mod edit;
mod flow;
mod gate;
mod kanban;
mod review;
mod scope;
mod sprints;
pub use backlog::*;
pub use chat::*;
pub(crate) use checkout::issue_in;
pub use checkout::*;
pub use comments::*;
pub use edit::*;
pub use flow::*;
pub use gate::*;
pub use kanban::*;
pub use review::*;
pub use scope::delete_empty_sprint;
pub use sprints::*;

/// Allocates the next number in the project and appends the issue to the end of the
/// backlog, in one transaction; it inherits its parent's requirement, else its epic's, else its
/// project's (E15.10). A missing project yields `Error::RowNotFound`. An issue
/// starts in `backlog` or `todo` (or arrives already `done` / `cancelled`); `in_progress`,
/// `in_review` and `blocked` are reached only through `transition_issue`, which checks the
/// reviewer and blocker rules, so any other state is `Error::InvalidArgument`. Likewise a
/// top-level issue joins only a planned sprint, and a subtask only its parent's sprint: an
/// active sprint's scope is frozen (E5.2).
pub async fn create_issue(pool: &SqlitePool, i: &NewIssue) -> Result<Issue, Error> {
    if matches!(
        i.state,
        IssueState::InProgress | IssueState::InReview | IssueState::Blocked
    ) {
        return Err(Error::InvalidArgument(format!(
            "an issue cannot be created {}",
            i.state.as_str()
        )));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let created = create_issue_in(&mut tx, i).await?;
    tx.commit().await?;
    Ok(created)
}

/// `create_issue` inside the caller's `BEGIN IMMEDIATE` transaction (past its state check).
pub(crate) async fn create_issue_in(
    conn: &mut sqlx::SqliteConnection,
    i: &NewIssue,
) -> Result<Issue, Error> {
    if let Some(sprint) = i.sprint_id {
        sprint_ok(conn, i, sprint).await?;
    }
    let number: i64 = sqlx::query_scalar(
        "UPDATE projects SET next_issue_number = next_issue_number + 1 WHERE id = ? \
         RETURNING next_issue_number - 1",
    )
    .bind(i.project_id.0)
    .fetch_one(&mut *conn)
    .await?;
    let (owner_agent, owner_user) = actor_columns(i.owner);
    let (next_agent, next_user, next_at) = next_actor_columns(&i.next_actor);
    sqlx::query(concat!(
        "INSERT INTO issues (project_id, number, epic_id, parent_id, kind, title, body, state, \
         owner_agent_id, owner_user_id, next_agent_id, next_user_id, next_at, points, \
         sprint_id, rank, requirement_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
         (SELECT coalesce(max(rank), 0) + 1 FROM issues WHERE project_id = ?1), \
         coalesce((SELECT requirement_id FROM issues WHERE id = ?4), \
             (SELECT requirement_id FROM epics WHERE id = ?3), \
             (SELECT requirement_id FROM projects WHERE id = ?1))) RETURNING ",
        issue_columns!()
    ))
    .bind(i.project_id.0)
    .bind(number)
    .bind(i.epic_id.map(|e| e.0))
    .bind(i.parent_id.map(|p| p.0))
    .bind(i.kind.as_str())
    .bind(&i.title)
    .bind(&i.body)
    .bind(i.state.as_str())
    .bind(owner_agent)
    .bind(owner_user)
    .bind(next_agent)
    .bind(next_user)
    .bind(next_at)
    .bind(i.points)
    .bind(i.sprint_id.map(|s| s.0))
    .fetch_one(&mut *conn)
    .await
    .and_then(issue)
}

/// A new issue may be created in `sprint` only if it is planned, or for a subtask, if it is
/// its parent's.
async fn sprint_ok(
    conn: &mut sqlx::SqliteConnection,
    i: &NewIssue,
    sprint: SprintId,
) -> Result<(), Error> {
    let allowed: Option<bool> = match i.parent_id {
        Some(parent) => {
            sqlx::query_scalar("SELECT sprint_id IS ? FROM issues WHERE id = ?")
                .bind(sprint.0)
                .bind(parent.0)
                .fetch_optional(&mut *conn)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT state = 'planned' FROM sprints WHERE id = ?")
                .bind(sprint.0)
                .fetch_optional(&mut *conn)
                .await?
        }
    };
    // A missing parent or sprint falls through to its foreign key error.
    match allowed {
        Some(false) => Err(Error::InvalidArgument(format!(
            "an issue cannot be created in sprint {}: only a planned sprint (or a subtask's \
             parent's) takes new issues",
            sprint.0
        ))),
        _ => Ok(()),
    }
}

pub async fn get_issue(pool: &SqlitePool, id: IssueId) -> Result<Option<Issue>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        issue_columns!(),
        " FROM issues WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(issue)
    .transpose()
}

/// Every issue in the project, by number.
/// The issue's key, `<project key>-<number>`, e.g. `CIT-12`.
pub async fn issue_key(pool: &SqlitePool, id: IssueId) -> Result<Option<String>, Error> {
    sqlx::query_scalar(
        "SELECT p.key || '-' || i.number FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE i.id = ?",
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
}

pub async fn list_issues(pool: &SqlitePool, project_id: ProjectId) -> Result<Vec<Issue>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        issue_columns!(),
        " FROM issues WHERE project_id = ? ORDER BY number"
    ))
    .bind(project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(issue)
    .collect()
}

/// Updates the issue's details: epic, parent, kind, title, body, owner, points and rank.
/// State, next actor, checkout and sprint are not written: they change only through
/// `transition_issue`, checkout / release and the sprint operations, so no edit can bypass
/// the next-actor, blocker and sprint rules. Schema constraints still apply.
pub async fn update_issue(pool: &SqlitePool, i: &Issue) -> Result<bool, Error> {
    let (owner_agent, owner_user) = actor_columns(i.owner);
    sqlx::query(
        "UPDATE issues SET epic_id = ?, parent_id = ?, kind = ?, title = ?, body = ?, \
         owner_agent_id = ?, owner_user_id = ?, points = ?, rank = ? \
         WHERE id = ?",
    )
    .bind(i.epic_id.map(|e| e.0))
    .bind(i.parent_id.map(|p| p.0))
    .bind(i.kind.as_str())
    .bind(&i.title)
    .bind(&i.body)
    .bind(owner_agent)
    .bind(owner_user)
    .bind(i.points)
    .bind(i.rank)
    .bind(i.id.0)
    .execute(pool)
    .await
    .map(affected)
}

// --- issue labels -----------------------------------------------------------

pub async fn list_issue_labels(pool: &SqlitePool, issue_id: IssueId) -> Result<Vec<Label>, Error> {
    sqlx::query(
        "SELECT l.id, l.project_id, l.name FROM labels l \
         JOIN issue_labels il ON il.label_id = l.id WHERE il.issue_id = ? ORDER BY l.name",
    )
    .bind(issue_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(label)
    .collect()
}

// --- blocker links ----------------------------------------------------------

/// Why a blocker link was not added.
#[derive(Debug)]
pub enum BlockerError {
    /// `blocked` already (transitively) blocks `blocker`.
    Cycle,
    Db(Error),
}

impl From<Error> for BlockerError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for BlockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cycle => f.write_str("blocker link would create a cycle"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BlockerError {}

/// Rejects a link that closes a cycle; a self-link or duplicate pair is a constraint error.
/// `BEGIN IMMEDIATE`, so two racing links cannot both pass the cycle check. Linking does
/// not change either issue's state: blocking is the `Block` transition.
pub async fn add_blocker(pool: &SqlitePool, link: BlockerLink) -> Result<(), BlockerError> {
    let mut tx = crate::store::begin_write(pool).await?;
    add_blocker_in(&mut tx, link).await?;
    tx.commit().await?;
    Ok(())
}

/// `add_blocker` inside the caller's `BEGIN IMMEDIATE` transaction.
pub(crate) async fn add_blocker_in(
    tx: &mut sqlx::SqliteConnection,
    link: BlockerLink,
) -> Result<(), BlockerError> {
    let cycle: bool = sqlx::query_scalar(
        "WITH RECURSIVE downstream(id) AS ( \
             SELECT blocked_id FROM blocker_links WHERE blocker_id = ? \
             UNION SELECT l.blocked_id FROM blocker_links l JOIN downstream d \
             ON l.blocker_id = d.id) \
         SELECT EXISTS (SELECT 1 FROM downstream WHERE id = ?)",
    )
    .bind(link.blocked.0)
    .bind(link.blocker.0)
    .fetch_one(&mut *tx)
    .await?;
    if cycle {
        return Err(BlockerError::Cycle);
    }
    sqlx::query("INSERT INTO blocker_links (blocker_id, blocked_id) VALUES (?, ?)")
        .bind(link.blocker.0)
        .bind(link.blocked.0)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// Issues that block `issue`.
pub async fn list_blockers(pool: &SqlitePool, issue: IssueId) -> Result<Vec<IssueId>, Error> {
    sqlx::query_scalar(
        "SELECT blocker_id FROM blocker_links WHERE blocked_id = ? ORDER BY blocker_id",
    )
    .bind(issue.0)
    .fetch_all(pool)
    .await
    .map(|ids| ids.into_iter().map(IssueId).collect())
}

/// Issues that `issue` blocks.
pub async fn list_dependants(pool: &SqlitePool, issue: IssueId) -> Result<Vec<IssueId>, Error> {
    sqlx::query_scalar(
        "SELECT blocked_id FROM blocker_links WHERE blocker_id = ? ORDER BY blocked_id",
    )
    .bind(issue.0)
    .fetch_all(pool)
    .await
    .map(|ids| ids.into_iter().map(IssueId).collect())
}
