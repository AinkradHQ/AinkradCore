//! The Linear sync (E9.4, #26): each pass, for every project synced with a Linear team, pull
//! then push.
//!
//! - Pull: the team's issues updated since the cursor. A linked one is compared field by field
//!   (title, description, state type, assignee) with the snapshot of the last sync: a field
//!   Linear changed and Citadel did not is applied (`store::linear::pull`); a field both
//!   changed goes to the later writer (Linear's `updatedAt` against the issue's
//!   `updated_at`), audited as a conflict. An unlinked one is imported. The cursor moves to the
//!   latest `updatedAt` read.
//! - Push: each top-level issue of the project. A linked one whose fields differ from the
//!   snapshot is updated in Linear; an unlinked one is created there. The snapshot then holds
//!   what was written.
//!
//! No echo: a write either side made from the other is in the snapshot, so reading it back
//! changes nothing and writes nothing. The assignee is best-effort: an agent and a Linear
//! member with the same name are the same person; anyone else is left alone on each side.

use std::collections::HashMap;

use citadel_core::org::AgentId;
use citadel_core::work::{IssueState, ProjectId};
use ainkrad_providers::linear::{Changes, Issue as Remote, Linear, Team};
use ainkrad_providers::{Client, Secret};
use sqlx::SqlitePool;

use crate::store::linear::{
    ProjectLinear, Pull, Synced, import, linear_projects, link_issue, links, local, pull, pushed,
    set_cursor, state_kind,
};
use crate::store::work::list_issues;

/// One pass over every synced project. A project whose Linear cannot be reached is logged and
/// tried again next pass.
pub async fn sync(pool: &SqlitePool, client: &Client) -> Result<(), sqlx::Error> {
    for config in linear_projects(pool).await? {
        let token = match Secret::from_file(&config.token_file) {
            Ok(token) => token,
            Err(why) => {
                tracing::warn!(project = config.project_id.0, %why, "Linear sync skipped");
                continue;
            }
        };
        let linear = Linear::new(client.clone(), &config.api_url, token);
        if let Err(e) = project(pool, &linear, &config).await {
            match e {
                Failed::Db(e) => return Err(e),
                Failed::Linear(e) => {
                    tracing::warn!(project = config.project_id.0, error = %e, "Linear sync failed");
                }
            }
        }
    }
    Ok(())
}

enum Failed {
    Db(sqlx::Error),
    Linear(ainkrad_providers::Error),
}

impl From<sqlx::Error> for Failed {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<ainkrad_providers::Error> for Failed {
    fn from(e: ainkrad_providers::Error) -> Self {
        Self::Linear(e)
    }
}

/// Linear's state types Citadel knows; triage counts as not started.
fn kind(remote: &Remote) -> String {
    match remote.state.kind.as_str() {
        "triage" => "unstarted".to_owned(),
        other => other.to_owned(),
    }
}

/// The team's state for an issue in `state`: of its type, and "In Review" for one in review
/// when the team has such a state.
fn state_id(team: &Team, state: IssueState) -> Option<String> {
    let wanted = state_kind(state);
    let mut of_kind = team.states.iter().filter(|s| s.kind == wanted);
    let review = (state == IssueState::InReview)
        .then(|| {
            of_kind
                .clone()
                .find(|s| s.name.eq_ignore_ascii_case("in review"))
        })
        .flatten();
    review.or_else(|| of_kind.next()).map(|s| s.id.clone())
}

async fn project(pool: &SqlitePool, linear: &Linear, config: &ProjectLinear) -> Result<(), Failed> {
    let team = linear.team(&config.team_id).await?;
    let agents: HashMap<String, AgentId> = sqlx::query_as(
        "SELECT a.name, a.id FROM agents a JOIN projects p ON p.company_id = a.company_id \
         WHERE p.id = ?",
    )
    .bind(config.project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|(name, id): (String, i64)| (name, AgentId(id)))
    .collect();

    let changed = linear
        .issues_since(&config.team_id, config.cursor.as_deref())
        .await?;
    let linked: HashMap<String, _> = links(pool, config.project_id)
        .await?
        .into_iter()
        .map(|l| (l.linear_id.clone(), l))
        .collect();
    for remote in &changed {
        let body = &remote.description;
        match linked.get(&remote.id) {
            None => {
                let p = config.project_id;
                let (id, ident, title) = (&remote.id, &remote.identifier, &remote.title);
                import(pool, p, id, ident, title, body, &kind(remote)).await?;
            }
            Some(l) => {
                let Some((issue, updated_at, _)) = local(pool, l.issue_id).await? else {
                    continue;
                };
                // Linear wrote last if the issue has not changed since, or changed earlier.
                let linear_later = updated_at.is_none_or(|at| remote.updated_at > at);
                let mut p = Pull::default();
                let s = &l.synced;
                let mine = state_kind(issue.state).to_owned();
                let theirs = kind(remote);
                p.title = pick(
                    "title",
                    &remote.title,
                    &issue.title,
                    &s.title,
                    linear_later,
                    &mut p.conflicts,
                );
                p.body = pick(
                    "body",
                    body,
                    &issue.body,
                    &s.body,
                    linear_later,
                    &mut p.conflicts,
                );
                p.state = pick(
                    "state",
                    &theirs,
                    &mine,
                    &s.state,
                    linear_later,
                    &mut p.conflicts,
                );
                let name = remote.assignee.as_ref().map(|(_, name)| name);
                if let Some(name) = name.filter(|n| Some(*n) != s.assignee.as_ref())
                    && let Some(agent) = agents.get(name)
                {
                    p.assignee = Some((*agent, name.clone()));
                }
                if p != Pull::default() {
                    pull(pool, l.issue_id, &p).await?;
                }
            }
        }
    }
    if let Some(latest) = changed.iter().map(|r| r.updated_at.as_str()).max() {
        set_cursor(pool, config.project_id, latest).await?;
    }
    push(pool, linear, config.project_id, &config.team_id, &team).await
}

/// The field Linear's value `theirs` should set, given Citadel's `mine` and what both held at
/// the last sync: theirs when only Linear changed it, or both did and Linear wrote last (a
/// conflict either way, recorded in `conflicts`).
fn pick(
    field: &'static str,
    theirs: &str,
    mine: &str,
    synced: &str,
    linear_later: bool,
    conflicts: &mut Vec<(&'static str, &'static str)>,
) -> Option<String> {
    if theirs == synced || theirs == mine {
        return None;
    }
    if mine != synced {
        conflicts.push((field, if linear_later { "linear" } else { "citadel" }));
        if !linear_later {
            return None;
        }
    }
    Some(theirs.to_owned())
}

/// Creates the project's unlinked top-level issues in Linear, and writes the fields of linked
/// ones that changed in Citadel since the last sync.
async fn push(
    pool: &SqlitePool,
    linear: &Linear,
    project: ProjectId,
    team_id: &str,
    team: &Team,
) -> Result<(), Failed> {
    let linked: HashMap<_, _> = links(pool, project)
        .await?
        .into_iter()
        .map(|l| (l.issue_id, l))
        .collect();
    for issue in list_issues(pool, project).await? {
        if issue.parent_id.is_some() {
            // ponytail: subtasks stay in Citadel; Linear sub-issues are the upgrade.
            continue;
        }
        let Some((issue, _, assignee)) = local(pool, issue.id).await? else {
            continue;
        };
        let member = |name: &Option<String>| {
            let name = name.as_ref()?;
            team.members
                .iter()
                .find(|(_, n)| n == name)
                .map(|(id, _)| id.clone())
        };
        let mine = Synced {
            title: issue.title.clone(),
            body: issue.body.clone(),
            state: state_kind(issue.state).to_owned(),
            assignee: assignee.clone(),
        };
        let Some(l) = linked.get(&issue.id) else {
            let c = Changes {
                title: Some(mine.title.clone()),
                description: Some(mine.body.clone()),
                state_id: state_id(team, issue.state),
                assignee_id: member(&assignee),
            };
            let made = linear.create(team_id, &c).await?;
            link_issue(
                pool,
                issue.id,
                &made.id,
                &made.identifier,
                &mine,
                "linear.exported",
            )
            .await?;
            continue;
        };
        let s = &l.synced;
        let mut c = Changes::default();
        let mut fields = vec![];
        if mine.title != s.title {
            c.title = Some(mine.title.clone());
            fields.push("title");
        }
        if mine.body != s.body {
            c.description = Some(mine.body.clone());
            fields.push("body");
        }
        if mine.state != s.state {
            c.state_id = state_id(team, issue.state);
            fields.push("state");
        }
        // Only an agent Linear also knows is pushed; any other assignee stays as it is.
        let mut next = mine.clone();
        match member(&assignee) {
            Some(id) if assignee != s.assignee => {
                c.assignee_id = Some(id);
                fields.push("assignee");
            }
            _ => next.assignee = s.assignee.clone(),
        }
        if !fields.is_empty() {
            linear.update(&l.linear_id, &c).await?;
            pushed(pool, issue.id, &next, &fields).await?;
        }
    }
    Ok(())
}
