//! Forges (E9.1): a project repository's git host, and its issues' pull requests, one per repo
//! the issue touches (E15.16), all from the issue's one branch name.
//!
//! An agent asks for its issue's PR on a repo (`request_pr`, the agent tool `open_pr`); the
//! forge poller (`crate::forge`) opens it once the run that asked has ended (the runner pushes
//! the issue's branch as the run ends), then follows its head and checks, recording each change
//! here (`follow`): on the PR row, as a comment on the issue, and in the audit log. Only these
//! functions write `citadel_issue_prs`.
//!
//! Waking the issue's next actor after a change (failing checks, a closed PR, a merge) is the
//! run engine's wake queue (S7); until it lands the change is on the issue as a comment and in
//! the audit log, which is what the engine will read.

use std::fmt;

use crate::domain::org::AgentId;
use crate::domain::work::{IssueId, ProjectId};
use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use crate::store::work::{ProjectForge, append};

mod done;
mod follow;
mod hosts;
mod push;
pub use done::*;
pub use follow::*;
pub use hosts::*;
pub use push::*;

/// Where an issue's pull request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrPhase {
    /// Asked for; opened once the run that asked has ended.
    Requested,
    Open,
    /// Approved for merge (E9.3); the poller merges it.
    Merging,
    Merged,
    /// Closed without merging.
    Closed,
}

impl PrPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Open => "open",
            Self::Merging => "merging",
            Self::Merged => "merged",
            Self::Closed => "closed",
        }
    }

    fn parse(s: &str) -> Result<Self, Error> {
        [
            Self::Requested,
            Self::Open,
            Self::Merging,
            Self::Merged,
            Self::Closed,
        ]
        .into_iter()
        .find(|p| p.as_str() == s)
        .ok_or_else(|| Error::Decode(format!("unknown PR state {s:?}").into()))
    }

    /// Open, or on its way to open or merged: the issue has a live PR.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Requested | Self::Open | Self::Merging)
    }
}

/// An issue's pull request on one of its repos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuePr {
    pub issue_id: IssueId,
    /// The project repo (`store::work::Repo`) it is on.
    pub repo_id: i64,
    pub phase: PrPhase,
    pub number: Option<u64>,
    pub url: Option<String>,
    pub title: String,
    pub body: String,
    pub head: String,
    pub base: String,
    pub head_sha: Option<String>,
    /// `none`, `pending`, `success` or `failure`.
    pub checks: String,
    pub author: Option<AgentId>,
    pub last_error: Option<String>,
    /// Set when the forge token cannot read every check (`PrStatus::note`): what `checks` is
    /// made of instead. QA may still pass the PR; its merge approval says so.
    pub checks_note: Option<String>,
    /// Set when the runner's push of its branch was refused for good (#103): the refusal. The
    /// request then opens once the branch is on the forge, never re-armed by later runs.
    pub push_held: Option<String>,
}

macro_rules! pr_columns {
    () => {
        "issue_id, repo_id, state, number, url, title, body, head, base, head_sha, checks, \
         author_agent_id, last_error, checks_note, push_held"
    };
}

pub(crate) fn issue_pr_row(row: SqliteRow) -> Result<IssuePr, Error> {
    Ok(IssuePr {
        issue_id: IssueId(row.try_get("issue_id")?),
        repo_id: row.try_get("repo_id")?,
        phase: PrPhase::parse(&row.try_get::<String, _>("state")?)?,
        number: row.try_get::<Option<i64>, _>("number")?.map(|n| n as u64),
        url: row.try_get("url")?,
        title: row.try_get("title")?,
        body: row.try_get("body")?,
        head: row.try_get("head")?,
        base: row.try_get("base")?,
        head_sha: row.try_get("head_sha")?,
        checks: row.try_get("checks")?,
        author: row
            .try_get::<Option<i64>, _>("author_agent_id")?
            .map(AgentId),
        last_error: row.try_get("last_error")?,
        checks_note: row.try_get("checks_note")?,
        push_held: row.try_get("push_held")?,
    })
}

/// The issue's PRs, in its project's repo order.
pub async fn issue_prs(
    pool: impl sqlx::SqliteExecutor<'_>,
    issue: IssueId,
) -> Result<Vec<IssuePr>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        pr_columns!(),
        " FROM citadel_issue_prs WHERE issue_id = ? ORDER BY \
         (SELECT position FROM citadel_project_repos r WHERE r.id = citadel_issue_prs.repo_id), repo_id"
    ))
    .bind(issue.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(issue_pr_row)
    .collect()
}

/// The issue's first PR in its project's repo order: on a single-repo project, its PR.
pub async fn issue_pr(
    pool: impl sqlx::SqliteExecutor<'_>,
    issue: IssueId,
) -> Result<Option<IssuePr>, Error> {
    Ok(issue_prs(pool, issue).await?.into_iter().next())
}

/// Why a PR was not requested.
#[derive(Debug)]
pub enum PrError {
    /// The issue's project has no repo, or no forge.
    NoForge,
    NotFound,
    /// Not a repo the issue touches, or the repo must be named.
    Refused(String),
    Db(Error),
}

impl From<Error> for PrError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for PrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoForge => f.write_str("the issue's project has no repo on a forge"),
            Self::NotFound => f.write_str("no such issue"),
            Self::Refused(why) => f.write_str(why),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PrError {}

/// Asks for a PR of the issue's branch (`work::issue_branch`) into `repo`'s default branch (one
/// of the repos the issue touches on a forge; may be left out when it touches one), by `agent`,
/// and appends `pr.requested`. A request still waiting takes the new title and body; a PR
/// already open (or being merged) is returned as it is; after a merged or closed one, a new one
/// is requested.
pub async fn request_pr(
    pool: &SqlitePool,
    issue: IssueId,
    repo: Option<&str>,
    agent: AgentId,
    (title, body): (&str, &str),
) -> Result<IssuePr, PrError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let found: Option<(i64, String)> = sqlx::query_as(
        "SELECT p.company_id, p.key || '-' || i.number FROM citadel_issues i \
         JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *tx)
    .await?;
    let (company, key) = found.ok_or(PrError::NotFound)?;
    let on_forge: Vec<_> = crate::store::work::issue_repos_in(&mut tx, issue)
        .await?
        .into_iter()
        .filter(|r| r.forge.is_some())
        .collect();
    let names = || {
        on_forge
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let target = match repo {
        Some(name) => on_forge.iter().find(|r| r.name == name).ok_or_else(|| {
            PrError::Refused(format!(
                "{name} is not a repo of {key} on a forge (they are: {}); ask for another repo \
                 with request_repo",
                names()
            ))
        })?,
        None => match on_forge.as_slice() {
            [] => return Err(PrError::NoForge),
            [one] => one,
            _ => {
                let why = format!("{key} touches several repos; name one: {}", names());
                return Err(PrError::Refused(why));
            }
        },
    };
    let branch = crate::store::work::issue_branch_in(&mut tx, issue)
        .await?
        .ok_or(PrError::NotFound)?;
    let current = issue_prs(&mut *tx, issue).await?;
    if let Some(live) = current.into_iter().find(|p| p.repo_id == target.id)
        && matches!(live.phase, PrPhase::Open | PrPhase::Merging)
    {
        return Ok(live);
    }
    let pr = sqlx::query(concat!(
        "INSERT INTO citadel_issue_prs (issue_id, repo_id, title, body, head, base, author_agent_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (issue_id, repo_id) DO UPDATE SET \
         state = 'requested', number = NULL, url = NULL, head_sha = NULL, checks = 'none', \
         last_error = NULL, checks_note = NULL, unpushed_at = NULL, \
         pushed_sha = CASE WHEN state = 'requested' THEN pushed_sha END, \
         title = excluded.title, \
         body = excluded.body, head = excluded.head, \
         base = excluded.base, author_agent_id = excluded.author_agent_id, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') RETURNING ",
        pr_columns!()
    ))
    .bind(issue.0)
    .bind(target.id)
    .bind(title)
    .bind(body)
    .bind(&branch)
    .bind(&target.default_branch)
    .bind(agent.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(issue_pr_row)?;
    let details = json!({"repo": target.name, "head": pr.head, "base": pr.base, "title": title});
    let entity = ("issue", issue.0);
    let by = AuditActor::System;
    append(&mut tx, company, by, "pr.requested", entity, details).await?;
    tx.commit().await?;
    Ok(pr)
}

/// The PRs the poller has work on, with their repo's forge, by issue and in each issue's repo
/// order: those open, those approved for merge, and those requested whose branch is confirmed
/// pushed (`pushed_sha`) or whose push was refused for good (`push_held`, tried every pass,
/// opening once the branch is there). A request whose branch was found missing (`pr_unpushed`)
/// waits for the next confirmed push. The run engine (S7) adds "requested, and its issue has no
/// live run left" to this once runs exist.
pub async fn due_prs(pool: &SqlitePool) -> Result<Vec<(IssuePr, ProjectForge)>, Error> {
    let rows = sqlx::query(
        "SELECT p.issue_id, p.repo_id, p.state, p.number, p.url, p.title, p.body, p.head, \
         p.base, p.head_sha, p.checks, p.author_agent_id, p.last_error, p.checks_note, \
         p.push_held, f.project_id, f.forge_kind, f.forge_api_url, f.forge_repo, f.forge_secret \
         FROM citadel_issue_prs p JOIN citadel_project_repos f ON f.id = p.repo_id \
         WHERE f.forge_kind IS NOT NULL AND (p.state IN ('open', 'merging') OR \
             (p.state = 'requested' AND (p.pushed_sha IS NOT NULL OR p.push_held IS NOT NULL))) \
         ORDER BY p.issue_id, f.position, f.id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let forge = ProjectForge {
                project_id: ProjectId(row.try_get("project_id")?),
                kind: row.try_get("forge_kind")?,
                api_url: row.try_get("forge_api_url")?,
                repo: row.try_get("forge_repo")?,
                secret: row.try_get("forge_secret")?,
            };
            Ok((issue_pr_row(row)?, forge))
        })
        .collect()
}
