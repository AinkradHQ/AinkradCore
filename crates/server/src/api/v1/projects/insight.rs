//! What the project's pages show beyond its rows (Core 0.10, E11-3): the Code cards (read from the
//! Core's repo copies with git plumbing, never a checkout), the AI usage (the cost ledger joined
//! to sessions by project) and who changed what in the last week. All `read`.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, ApiResult};
use super::num;
use crate::api::App;
use crate::mirrors::{self, Commit};
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::project_usage as usage_store;
use crate::store::projects as store;

#[derive(Debug, Serialize, ToSchema)]
pub struct CommitInfo {
    pub sha: String,
    pub author: String,
    pub message: String,
    pub at: Timestamp,
}

fn commit(c: &Commit) -> CommitInfo {
    CommitInfo {
        sha: c.sha.clone(),
        author: c.author.clone(),
        message: c.message.clone(),
        at: ts(&utc(&c.at)),
    }
}

/// A git author date (ISO 8601 with an offset) as stored UTC.
fn utc(at: &str) -> String {
    iso_of_unix(unix_secs(at).unwrap_or(0))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepoCode {
    pub repo: String,
    /// Files in the branch shown; 0 before the first fetch.
    pub files: i64,
    /// The most recently updated branch (the default one when it is the only one).
    pub branch: String,
    /// Commits that branch has beyond the default branch.
    pub ahead: i64,
    /// Commits the default branch has beyond that branch.
    pub behind: i64,
    /// The branch's newest commit; null before the first fetch.
    pub last_commit: Option<CommitInfo>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/code", operation_id = "getProjectCode",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "One card per repo, primary first, read from the \
        Core's copy with git plumbing (no checkout, no hook runs). A repo with no copy yet has \
        zeros and no last commit. 404 for no such project", body = Vec<RepoCode>)))]
pub async fn code(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Vec<RepoCode>> {
    let project = num(&id, "project")?;
    let mut conn = app.pool.acquire().await?;
    store::get(&mut conn, project).await?;
    let repos = store::repos(&mut conn, project).await?;
    drop(conn);
    let mut out = Vec::new();
    for r in repos {
        let info = match app.mirrors.as_ref() {
            Some(m) => m
                .code(
                    r.id,
                    &mirrors::key(project, &r.remote_url),
                    &r.default_branch,
                )
                .await
                .ok(),
            None => None,
        };
        out.push(match info {
            Some(i) => RepoCode {
                repo: r.name,
                files: i.files,
                branch: i.branch,
                ahead: i.ahead,
                behind: i.behind,
                last_commit: i.last.as_ref().map(commit),
            },
            None => RepoCode {
                repo: r.name,
                files: 0,
                branch: r.default_branch,
                ahead: 0,
                behind: 0,
                last_commit: None,
            },
        });
    }
    Ok(Json(out))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionUsage {
    pub id: String,
    pub title: Option<String>,
    /// `starting`, `running`, `interrupted`, `ended` or `lost`.
    pub state: String,
    /// All-time cost in USD micros.
    pub cost: i64,
    /// Cost per day, last 7 days, oldest first, USD micros.
    pub spark: Vec<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectUsage {
    /// Cost of the last 7 days in USD micros (millionths), as the cost ledger stores it.
    pub week_cost: i64,
    /// The 7 days before that.
    pub prev_week_cost: i64,
    /// Sessions started in the last 7 days.
    pub sessions_week: i64,
    /// Cost per day, last 7 days, oldest first, USD micros.
    pub by_day: Vec<i64>,
    /// The project's sessions, newest first (at most 30).
    pub sessions: Vec<SessionUsage>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/usage", operation_id = "getProjectUsage",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "AI usage of the project: the cost ledger joined to \
        its sessions. Money is USD micros. 404 for no such project", body = ProjectUsage)))]
pub async fn usage(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProjectUsage> {
    let project = num(&id, "project")?;
    store::get(&mut *app.pool.acquire().await?, project).await?;
    let u = usage_store::usage(&app.pool, project, &app.clock.now()).await?;
    Ok(Json(ProjectUsage {
        week_cost: u.week_cost,
        prev_week_cost: u.prev_week_cost,
        sessions_week: u.sessions_week,
        by_day: u.by_day.to_vec(),
        sessions: u
            .sessions
            .into_iter()
            .map(|s| SessionUsage {
                id: s.id,
                title: s.title,
                state: s.state,
                cost: s.cost,
                spark: s.spark.to_vec(),
            })
            .collect(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorCount {
    pub who: String,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Change {
    pub who: String,
    /// `commit` or `session`.
    pub kind: String,
    pub summary: String,
    pub at: Timestamp,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectChanges {
    /// Commit authors, and `AI sessions` for the sessions, by count, most first.
    pub by_author: Vec<AuthorCount>,
    /// Newest first, at most 50.
    pub recent: Vec<Change>,
}

/// Counts per author, most first, ties by name; and the newest `max` changes. Pure.
pub fn tally(mut all: Vec<(String, String, String, i64)>, max: usize) -> ProjectChanges {
    let mut by: BTreeMap<String, i64> = BTreeMap::new();
    for (who, ..) in &all {
        *by.entry(who.clone()).or_default() += 1;
    }
    let mut by_author: Vec<AuthorCount> = by
        .into_iter()
        .map(|(who, count)| AuthorCount { who, count })
        .collect();
    by_author.sort_by(|a, b| b.count.cmp(&a.count).then(a.who.cmp(&b.who)));
    all.sort_by(|a, b| b.3.cmp(&a.3));
    ProjectChanges {
        by_author,
        recent: all
            .into_iter()
            .take(max)
            .map(|(who, kind, summary, at)| Change {
                who,
                kind,
                summary,
                at: ts(&iso_of_unix(at)),
            })
            .collect(),
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/changes", operation_id = "getProjectChanges",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "Who changed what in the last 7 days: commits on any \
        branch of the Core's copies, plus the project's AI sessions (as `AI sessions`; their \
        file edits are not itemised). 404 for no such project", body = ProjectChanges)))]
pub async fn changes(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProjectChanges> {
    let project = num(&id, "project")?;
    let mut conn = app.pool.acquire().await?;
    store::get(&mut conn, project).await?;
    let repos = store::repos(&mut conn, project).await?;
    drop(conn);
    let mut all = Vec::new();
    if let Some(m) = app.mirrors.as_ref() {
        for r in repos {
            let key = mirrors::key(project, &r.remote_url);
            for c in m
                .commits_since(r.id, &key, 7, 100)
                .await
                .unwrap_or_default()
            {
                let at = unix_secs(&c.at).unwrap_or(0);
                all.push((c.author, "commit".to_owned(), c.message, at));
            }
        }
    }
    let now = app.clock.now();
    for (title, at) in usage_store::recent_sessions(&app.pool, project, &now)
        .await
        .map_err(ApiError::from)?
    {
        let at = unix_secs(&at).unwrap_or(0);
        let summary = title.unwrap_or_else(|| "AI session".to_owned());
        all.push(("AI sessions".to_owned(), "session".to_owned(), summary, at));
    }
    Ok(Json(tally(all, 50)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_are_counted_per_author_and_sorted_newest_first() {
        let a = |w: &str, at| (w.to_owned(), "commit".to_owned(), "m".to_owned(), at);
        let t = tally(vec![a("Sam", 1), a("Mia", 3), a("Mia", 2)], 2);
        assert_eq!(t.by_author[0].who, "Mia");
        assert_eq!(t.by_author[0].count, 2);
        assert_eq!(t.recent.len(), 2);
        assert_eq!(t.recent[0].who, "Mia");
        assert_eq!(utc("2026-11-19T10:00:00+02:00"), "2026-11-19T08:00:00.000Z");
    }
}
