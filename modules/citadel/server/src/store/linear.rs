//! Linear sync records (E9.4): which project syncs with which Linear team, which issue is
//! linked to which Linear issue, and the snapshot of what both sides held at the last sync.
//! Every write here is audited; an issue's own changes go through the engine
//! (`transition_issue_in`), so the next-actor and WIP rules still hold.

use std::path::PathBuf;

use citadel_core::audit::AuditActor;
use citadel_core::work::{
    Actor, Issue, IssueId, IssueKind, IssueState, IssueTransition, NewIssue, NextActor, ProjectId,
};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::exec::ESCALATION_USER;
use super::forge::append;
use super::work::{IssueTransitionError, create_issue_in, issue_in, transition_issue_in};

/// The public GraphQL API.
pub const LINEAR_API: &str = "https://api.linear.app/graphql";

/// A project synced with a Linear team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLinear {
    pub project_id: ProjectId,
    pub team_id: String,
    pub api_url: String,
    pub token_file: PathBuf,
    /// The latest `updatedAt` read from Linear.
    pub cursor: Option<String>,
}

/// What a synced issue held on both sides at the last sync. `state` is a Linear state type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    pub title: String,
    pub body: String,
    pub state: String,
    pub assignee: Option<String>,
}

/// An issue linked to a Linear issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub issue_id: IssueId,
    pub linear_id: String,
    pub identifier: String,
    pub synced: Synced,
}

/// The Linear state type an issue in `state` is in.
pub fn state_kind(state: IssueState) -> &'static str {
    match state {
        IssueState::Backlog => "backlog",
        IssueState::Todo => "unstarted",
        IssueState::InProgress | IssueState::InReview | IssueState::Blocked => "started",
        IssueState::Done => "completed",
        IssueState::Cancelled => "canceled",
    }
}

/// The transitions that take an issue in `from` to Linear state type `to`; `None` when the
/// engine has no way there (e.g. back to the backlog, or done straight from blocked).
pub fn path(from: IssueState, to: &str) -> Option<Vec<IssueTransition>> {
    use IssueState as S;
    use IssueTransition as T;
    if state_kind(from) == to {
        return Some(vec![]);
    }
    let reopen = || T::Reopen {
        next: NextActor::Human(ESCALATION_USER),
    };
    Some(match (from, to) {
        (S::Backlog, "unstarted") => vec![T::Ready],
        (S::Done | S::Cancelled, "unstarted") => vec![reopen()],
        (S::Backlog | S::Todo, "started") => vec![T::Start],
        (S::Done | S::Cancelled, "started") => vec![reopen(), T::Start],
        (S::InProgress, "completed") => vec![T::Done],
        (S::InReview, "completed") => vec![T::Approve],
        (S::Backlog | S::Todo, "completed") => vec![T::Start, T::Done],
        (S::Cancelled, "completed") => vec![reopen(), T::Start, T::Done],
        (s, "canceled") if !s.is_terminal() => vec![T::Cancel],
        _ => return None,
    })
}

fn config(row: SqliteRow) -> Result<ProjectLinear, Error> {
    Ok(ProjectLinear {
        project_id: ProjectId(row.try_get("project_id")?),
        team_id: row.try_get("team_id")?,
        api_url: row.try_get("api_url")?,
        token_file: PathBuf::from(row.try_get::<String, _>("token_file")?),
        cursor: row.try_get("cursor")?,
    })
}

fn link(row: SqliteRow) -> Result<Link, Error> {
    Ok(Link {
        issue_id: IssueId(row.try_get("issue_id")?),
        linear_id: row.try_get("linear_id")?,
        identifier: row.try_get("identifier")?,
        synced: Synced {
            title: row.try_get("title")?,
            body: row.try_get("body")?,
            state: row.try_get("state")?,
            assignee: row.try_get("assignee")?,
        },
    })
}

async fn company_of(conn: &mut SqliteConnection, project: ProjectId) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_one(&mut *conn)
        .await
}

/// Syncs the project with Linear team `team_id` from now on (or changes how), audited as
/// `project.linear_set`; the cursor starts over. A bad value is `Error::InvalidArgument`;
/// `false` when there is no such project.
pub async fn set_project_linear(
    pool: &SqlitePool,
    l: &ProjectLinear,
    actor: AuditActor,
) -> Result<bool, Error> {
    let api_ok = l.api_url.starts_with("https://") || l.api_url.starts_with("http://");
    if !api_ok || l.api_url.contains('@') || l.team_id.trim().is_empty() {
        return Err(Error::InvalidArgument(
            "bad Linear API URL or team".to_owned(),
        ));
    }
    if !l.token_file.is_absolute() {
        let why = "the token file path must be absolute".to_owned();
        return Err(Error::InvalidArgument(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let Ok(company) = company_of(&mut tx, l.project_id).await else {
        return Ok(false);
    };
    let token_file = l.token_file.to_string_lossy();
    sqlx::query(
        "INSERT INTO project_linear (project_id, team_id, api_url, token_file) \
         VALUES (?, ?, ?, ?) ON CONFLICT (project_id) DO UPDATE SET team_id = excluded.team_id, \
         api_url = excluded.api_url, token_file = excluded.token_file, cursor = NULL",
    )
    .bind(l.project_id.0)
    .bind(&l.team_id)
    .bind(&l.api_url)
    .bind(&*token_file)
    .execute(&mut *tx)
    .await?;
    let details = json!({"team": l.team_id, "api_url": l.api_url, "token_file": token_file});
    let entity = ("project", l.project_id.0);
    append(
        &mut tx,
        company,
        actor,
        "project.linear_set",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn project_linear(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<ProjectLinear>, Error> {
    sqlx::query("SELECT * FROM project_linear WHERE project_id = ?")
        .bind(project.0)
        .fetch_optional(pool)
        .await?
        .map(config)
        .transpose()
}

pub async fn linear_projects(pool: &SqlitePool) -> Result<Vec<ProjectLinear>, Error> {
    sqlx::query("SELECT * FROM project_linear ORDER BY project_id")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(config)
        .collect()
}

pub async fn set_cursor(pool: &SqlitePool, project: ProjectId, cursor: &str) -> Result<(), Error> {
    sqlx::query("UPDATE project_linear SET cursor = ? WHERE project_id = ?")
        .bind(cursor)
        .bind(project.0)
        .execute(pool)
        .await
        .map(drop)
}

/// The project's links, by issue.
pub async fn links(pool: &SqlitePool, project: ProjectId) -> Result<Vec<Link>, Error> {
    sqlx::query(
        "SELECT l.* FROM linear_issues l JOIN issues i ON i.id = l.issue_id \
         WHERE i.project_id = ? ORDER BY l.issue_id",
    )
    .bind(project.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(link)
    .collect()
}

/// An issue as the sync sees it: the issue, its last change time and its assignee's name (its
/// next actor, when an agent).
pub async fn local(
    pool: &SqlitePool,
    issue: IssueId,
) -> Result<Option<(Issue, Option<String>, Option<String>)>, Error> {
    let Some(i) = super::work::get_issue(pool, issue).await? else {
        return Ok(None);
    };
    let (updated_at, assignee): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT i.updated_at, a.name FROM issues i LEFT JOIN agents a ON a.id = i.next_agent_id \
         WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_one(pool)
    .await?;
    Ok(Some((i, updated_at, assignee)))
}

/// Links `issue` to Linear issue `linear_id`/`identifier`, with `synced` as both sides' state.
pub async fn link_issue(
    pool: &SqlitePool,
    issue: IssueId,
    linear_id: &str,
    identifier: &str,
    synced: &Synced,
    action: &str,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    insert_link(&mut tx, issue, linear_id, identifier, synced).await?;
    let project: i64 = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(issue.0)
        .fetch_one(&mut *tx)
        .await?;
    let company = company_of(&mut tx, ProjectId(project)).await?;
    let details = json!({"linear": identifier});
    append(
        &mut tx,
        company,
        AuditActor::System,
        action,
        ("issue", issue.0),
        details,
    )
    .await?;
    tx.commit().await
}

async fn insert_link(
    conn: &mut SqliteConnection,
    issue: IssueId,
    linear_id: &str,
    identifier: &str,
    s: &Synced,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO linear_issues (issue_id, linear_id, identifier, title, body, state, \
         assignee) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(issue.0)
    .bind(linear_id)
    .bind(identifier)
    .bind(&s.title)
    .bind(&s.body)
    .bind(&s.state)
    .bind(&s.assignee)
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// Records `synced` as both sides' state of `issue` after a push, audited `linear.pushed` with
/// the `fields` it changed in Linear.
pub async fn pushed(
    pool: &SqlitePool,
    issue: IssueId,
    synced: &Synced,
    fields: &[&str],
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    snapshot(&mut tx, issue, synced).await?;
    let (company, linear) = linked(&mut tx, issue).await?;
    let details = json!({"linear": linear, "fields": fields});
    append(
        &mut tx,
        company,
        AuditActor::System,
        "linear.pushed",
        ("issue", issue.0),
        details,
    )
    .await?;
    tx.commit().await
}

async fn snapshot(conn: &mut SqliteConnection, issue: IssueId, s: &Synced) -> Result<(), Error> {
    sqlx::query(
        "UPDATE linear_issues SET title = ?, body = ?, state = ?, assignee = ?, \
         synced_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE issue_id = ?",
    )
    .bind(&s.title)
    .bind(&s.body)
    .bind(&s.state)
    .bind(&s.assignee)
    .bind(issue.0)
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// The issue's company and its Linear identifier.
async fn linked(conn: &mut SqliteConnection, issue: IssueId) -> Result<(i64, String), Error> {
    sqlx::query_as(
        "SELECT p.company_id, l.identifier FROM linear_issues l JOIN issues i ON i.id = l.issue_id \
         JOIN projects p ON p.id = i.project_id WHERE l.issue_id = ?",
    )
    .bind(issue.0)
    .fetch_one(&mut *conn)
    .await
}

mod pull;
pub use pull::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_states_map_to_engine_paths() {
        use IssueState as S;
        let names = |from, to| {
            path(from, to).map(|p| p.iter().map(IssueTransition::name).collect::<Vec<_>>())
        };
        assert_eq!(names(S::Todo, "unstarted"), Some(vec![]));
        assert_eq!(names(S::Backlog, "started"), Some(vec!["start"]));
        assert_eq!(names(S::InReview, "completed"), Some(vec!["approve"]));
        assert_eq!(names(S::Done, "started"), Some(vec!["reopen", "start"]));
        assert_eq!(names(S::Blocked, "canceled"), Some(vec!["cancel"]));
        assert_eq!(
            names(S::InProgress, "backlog"),
            None,
            "never back to the backlog"
        );
        assert_eq!(names(S::Blocked, "completed"), None);
        assert_eq!(names(S::Done, "canceled"), None);
        assert_eq!(state_kind(S::InReview), "started");
    }
}
