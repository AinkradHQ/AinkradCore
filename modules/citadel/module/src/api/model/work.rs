//! Projects and what is planned in them: epics, sprints, issues, their labels and comments
//! (ported from the monolith's `api/v1/model/work_items.rs` and its `Comment`). Response and
//! request models of the work seam (ToSchema; names unique across the Core contract).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::types::*;
use crate::domain::work;

#[derive(Debug, Serialize, ToSchema)]
pub struct Project {
    pub id: i64,
    pub company_id: i64,
    pub team_id: Option<i64>,
    pub name: String,
    pub key: String,
    pub mode: ProjectMode,
    pub sprint_approval: SprintApproval,
    /// A symbol or emoji (API minor 18); absent when unset, as every field below.
    pub icon: Option<String>,
    /// `#rrggbb`.
    pub color: Option<String>,
    /// Its uploaded logo (`getProjectLogo`).
    pub logo_url: Option<String>,
    /// Every team on it, the owner first; `team_id` is the first.
    #[schema(required = false)]
    pub team_ids: Vec<i64>,
    /// Runtime: the tags a runner needs for its runs, the cap on parallel runs, the run timeout
    /// in seconds and how many days worktrees are kept. Stored and shown; not yet applied by
    /// dispatch.
    #[schema(required = false)]
    pub runner_tags: Vec<String>,
    pub max_parallel_runs: Option<u32>,
    pub run_timeout_secs: Option<u32>,
    pub worktree_keep_days: Option<u32>,
}

impl From<work::Project> for Project {
    fn from(p: work::Project) -> Self {
        Self {
            logo_url: p
                .logo_sha256
                .map(|_| format!("/modules/citadel/v1/projects/{}/logo", p.id.0)),
            icon: p.icon,
            color: p.color,
            team_ids: p.team_ids.iter().map(|t| t.0).collect(),
            runner_tags: p.runner_tags,
            max_parallel_runs: p.max_parallel_runs,
            run_timeout_secs: p.run_timeout_secs,
            worktree_keep_days: p.worktree_keep_days,
            id: p.id.0,
            company_id: p.company_id.0,
            team_id: p.team_ids.first().map(|t| t.0),
            name: p.name,
            key: p.key,
            mode: p.mode.into(),
            sprint_approval: p.sprint_approval.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Epic {
    pub id: i64,
    /// `KEY-E3`: its project's key and its number there, never reused.
    pub key: String,
    pub number: i64,
    pub project_id: i64,
    pub title: String,
    pub status: EpicStatus,
    /// `#rrggbb` (API minor 18); absent when unset.
    pub color: Option<String>,
    /// `YYYY-MM-DD` (API minor 18).
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
    /// The requirement it serves (API minor 18).
    pub requirement_id: Option<i64>,
}

impl Epic {
    /// The epic, keyed by its project's `key`.
    pub fn new(e: work::Epic, project_key: &str) -> Self {
        Self {
            id: e.id.0,
            key: format!("{project_key}-E{}", e.number),
            number: e.number,
            project_id: e.project_id.0,
            title: e.title,
            status: e.status.into(),
            color: e.color,
            starts_on: e.starts_on,
            ends_on: e.ends_on,
            requirement_id: e.requirement_id.map(|r| r.0),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Sprint {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub goal: String,
    pub state: SprintState,
    /// `YYYY-MM-DD`.
    pub starts_on: Option<String>,
    /// `YYYY-MM-DD`.
    pub ends_on: Option<String>,
}

impl From<work::Sprint> for Sprint {
    fn from(s: work::Sprint) -> Self {
        Self {
            id: s.id.0,
            project_id: s.project_id.0,
            name: s.name,
            goal: s.goal,
            state: s.state.into(),
            starts_on: s.starts_on,
            ends_on: s.ends_on,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Issue {
    pub id: i64,
    /// `KEY-12`.
    pub key: String,
    pub project_id: i64,
    pub number: i64,
    pub epic_id: Option<i64>,
    pub parent_id: Option<i64>,
    pub kind: IssueKind,
    pub title: String,
    pub body: String,
    pub state: IssueState,
    pub owner: Option<Actor>,
    pub next_actor: Option<NextActor>,
    pub points: Option<u32>,
    pub sprint_id: Option<i64>,
    /// Backlog order within the project: lower first.
    pub rank: f64,
    /// The run holding the issue, while one does.
    pub checkout_run_id: Option<i64>,
    /// The requirement it serves (E15.10), Quest's requirement tag.
    pub requirement_id: Option<i64>,
    /// Bumped by the admin (`bumpIssue`): its wakes go first.
    pub priority: bool,
    /// `none` ... `urgent` (API minor 18); `priority` is true from `high` up.
    #[schema(required = false)]
    pub priority_level: PriorityLevel,
    /// The acceptance criteria, in order (API minor 18).
    #[schema(required = false)]
    pub criteria: Vec<Criterion>,
    /// Its labels, by name.
    pub labels: Vec<Label>,
    /// True when the issue has no explicit repo and its project has several, so it works in the
    /// primary one (API minor 20). Set on a single-issue read; omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[schema(required = false)]
    pub repo_implicit: bool,
}

/// One acceptance criterion of an issue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Criterion {
    pub text: String,
    #[serde(default)]
    pub done: bool,
}

/// A label of a project, put on its issues.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Label {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
}

impl From<work::Label> for Label {
    fn from(l: work::Label) -> Self {
        Self {
            id: l.id.0,
            project_id: l.project_id.0,
            name: l.name,
        }
    }
}

impl Issue {
    /// The issue, keyed by its project's `key`.
    pub fn new(i: work::Issue, project_key: &str) -> Self {
        Self {
            id: i.id.0,
            key: format!("{project_key}-{}", i.number),
            project_id: i.project_id.0,
            number: i.number,
            epic_id: i.epic_id.map(|e| e.0),
            parent_id: i.parent_id.map(|p| p.0),
            kind: i.kind.into(),
            title: i.title,
            body: i.body,
            state: i.state.into(),
            owner: i.owner.map(Into::into),
            next_actor: i.next_actor.map(Into::into),
            points: i.points,
            sprint_id: i.sprint_id.map(|s| s.0),
            rank: i.rank,
            checkout_run_id: i.checkout_run_id.map(|r| r.0),
            requirement_id: i.requirement_id.map(|r| r.0),
            priority: i.priority,
            priority_level: i.priority_level.into(),
            criteria: i
                .criteria
                .into_iter()
                .map(|c| Criterion {
                    text: c.text,
                    done: c.done,
                })
                .collect(),
            labels: vec![],
            repo_implicit: false,
        }
    }
}

/// A comment on an issue.
#[derive(Debug, Serialize, ToSchema)]
pub struct Comment {
    pub id: i64,
    pub issue_id: i64,
    pub author: Actor,
    pub body: String,
    /// The run it was written from, for an agent's comment.
    pub run_id: Option<i64>,
}

impl From<work::Comment> for Comment {
    fn from(c: work::Comment) -> Self {
        Self {
            id: c.id.0,
            issue_id: c.issue_id.0,
            author: c.author.into(),
            body: c.body,
            run_id: c.run_id.map(|r| r.0),
        }
    }
}
