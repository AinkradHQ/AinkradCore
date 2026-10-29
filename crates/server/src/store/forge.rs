//! Forges (E9.1): a project repository's git host, and its issues' pull requests, one per repo
//! the issue touches (E15.16), all from the issue's one branch name.
//!
//! An agent asks for its issue's PR on a repo (`request_pr`, MCP `open_pr`); the forge poller
//! (`crate::forge`) opens it once the run that asked has ended (the runner pushes the issue's
//! branch as the run ends), then follows its head and checks, recording each change here
//! (`follow`): on the PR row, as a comment on the issue, and in the audit log. Only these
//! functions write `issue_prs`.

use std::fmt;
use std::path::PathBuf;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::org::{AgentId, CompanyId};
use ainkrad_core::work::{IssueId, ProjectId};
use ainkrad_providers::Kind;
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::audit;

mod done;
mod follow;
mod push;
pub use done::*;
pub use follow::*;
pub use push::*;

/// A project's repository on a forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectForge {
    pub project_id: ProjectId,
    pub kind: Kind,
    /// The API's base URL, e.g. `https://api.github.com`.
    pub api_url: String,
    /// The repository's path on the forge: `owner/name`, or a GitLab project path.
    pub repo: String,
    /// The server-side file holding the API token.
    pub token_file: PathBuf,
}

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

/// Why `f` cannot be stored: an API URL that is not http(s), a repository path with anything
/// but `[A-Za-z0-9._/-]` (or an empty or absolute one), or a token file path that is not
/// absolute.
pub(crate) fn forge_problem(f: &ProjectForge) -> Option<String> {
    let api = &f.api_url;
    if !(api.starts_with("https://") || api.starts_with("http://")) || api.contains('@') {
        return Some(format!(
            "the API URL {api:?} must be http(s) and hold no credentials"
        ));
    }
    let repo_ok = !f.repo.is_empty()
        && !f.repo.starts_with('/')
        && !f.repo.contains("..")
        && f.repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b));
    if !repo_ok {
        return Some(format!("bad repository path {:?}", f.repo));
    }
    if !f.token_file.is_absolute() {
        return Some("the token file path must be absolute".to_owned());
    }
    None
}

/// Appends `action` about `entity` (`(kind, id)`) of `company` by `actor`; its sequence number.
pub(crate) async fn append(
    conn: &mut SqliteConnection,
    company: i64,
    actor: AuditActor,
    action: &str,
    entity: (&str, i64),
    details: serde_json::Value,
) -> Result<i64, Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: entity.0.to_owned(),
            id: entity.1,
        }),
        company_id: Some(CompanyId(company)),
        run_id: None,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(|e| e.seq.0)
}

/// Puts the project's primary repo on `f`'s forge (E15.16: each repo has its own; this is the
/// single-repo call) and appends `project.forge_set` by `actor` (the token file's path, never a
/// token). A bad value, or a project with no repo, is `Error::InvalidArgument`; `false` when
/// there is no such project.
pub async fn set_project_forge(
    pool: &SqlitePool,
    f: &ProjectForge,
    actor: AuditActor,
) -> Result<bool, Error> {
    if let Some(why) = forge_problem(f) {
        return Err(Error::InvalidArgument(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(company) =
        sqlx::query_scalar::<_, i64>("SELECT company_id FROM projects WHERE id = ?")
            .bind(f.project_id.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    let token_file = f.token_file.to_string_lossy();
    let set = sqlx::query(
        "UPDATE project_repos SET forge_kind = ?, forge_api_url = ?, forge_repo = ?, \
         forge_token_file = ? WHERE project_id = ? AND is_primary = 1",
    )
    .bind(f.kind.as_str())
    .bind(&f.api_url)
    .bind(&f.repo)
    .bind(&*token_file)
    .bind(f.project_id.0)
    .execute(&mut *tx)
    .await?;
    if set.rows_affected() == 0 {
        let why = "the project has no repo to put on a forge; add one first".to_owned();
        return Err(Error::InvalidArgument(why));
    }
    let details = json!({"kind": f.kind.as_str(), "api_url": f.api_url, "repo": f.repo,
                         "token_file": token_file});
    let entity = ("project", f.project_id.0);
    append(
        &mut tx,
        company,
        actor,
        "project.forge_set",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The forge of the project's primary repo.
pub async fn project_forge(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<ProjectForge>, Error> {
    let all = crate::store::work::list_repos(pool, project).await?;
    Ok(all.into_iter().find(|r| r.primary).and_then(|r| r.forge))
}

/// The issue's PRs, in its project's repo order.
pub async fn issue_prs(
    pool: impl sqlx::SqliteExecutor<'_>,
    issue: IssueId,
) -> Result<Vec<IssuePr>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        pr_columns!(),
        " FROM issue_prs WHERE issue_id = ? ORDER BY \
         (SELECT position FROM project_repos r WHERE r.id = issue_prs.repo_id), repo_id"
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
    let mut tx = crate::store::begin_write(pool).await?;
    let found: Option<(i64, String)> = sqlx::query_as(
        "SELECT p.company_id, p.key || '-' || i.number FROM issues i \
         JOIN projects p ON p.id = i.project_id WHERE i.id = ?",
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
        "INSERT INTO issue_prs (issue_id, repo_id, title, body, head, base, author_agent_id) \
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
    let by = AuditActor::Agent(agent);
    append(&mut tx, company, by, "pr.requested", entity, details).await?;
    tx.commit().await?;
    Ok(pr)
}

/// The PRs the poller has work on, with their repo's forge, by issue and in each issue's repo
/// order: those requested whose branch the runner confirmed pushed (`pushed_sha`), those
/// requested whose issue has no live run left (its branches are pushed), those open, and those
/// approved for merge. A request found with its branch not pushed
/// (`pr_unpushed`) waits until a later run on its issue has ended, which pushes it; one whose
/// push was refused for good (`push_held`) is tried every pass, opening once the branch is there.
pub async fn due_prs(pool: &SqlitePool) -> Result<Vec<(IssuePr, ProjectForge)>, Error> {
    let rows = sqlx::query(
        "SELECT issue_prs.issue_id, repo_id, state, number, issue_prs.url, title, body, head, \
         base, head_sha, checks, author_agent_id, last_error, checks_note, push_held, \
         f.project_id, \
         f.forge_kind, f.forge_api_url, f.forge_repo, f.forge_token_file \
         FROM issue_prs JOIN project_repos f ON f.id = issue_prs.repo_id \
         WHERE f.forge_kind IS NOT NULL AND (state IN ('open', 'merging') OR \
             (state = 'requested' AND (pushed_sha IS NOT NULL OR (NOT EXISTS (SELECT 1 FROM runs r \
              WHERE r.issue_id = issue_prs.issue_id \
              AND r.state IN ('queued', 'claimed', 'running')) \
             AND (push_held IS NOT NULL OR unpushed_at IS NULL OR EXISTS (SELECT 1 FROM runs r \
              WHERE r.issue_id = issue_prs.issue_id AND r.ended_at > unpushed_at))))))\
         ORDER BY issue_prs.issue_id, f.position, f.id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let forge = ProjectForge {
                project_id: ProjectId(row.try_get("project_id")?),
                kind: row
                    .try_get::<String, _>("forge_kind")?
                    .parse()
                    .map_err(|e: String| Error::Decode(e.into()))?,
                api_url: row.try_get("forge_api_url")?,
                repo: row.try_get("forge_repo")?,
                token_file: PathBuf::from(row.try_get::<String, _>("forge_token_file")?),
            };
            Ok((issue_pr_row(row)?, forge))
        })
        .collect()
}
