//! Response models of the planning seam (ToSchema; names unique across the Core contract):
//! requirements and their tree, the hub's questions and thread, the project profile and its
//! history. Each is built from its store type; nothing here reads the database.

use serde::Serialize;
use utoipa::ToSchema;

use super::governance::{Approval, Artifact};
use super::work::{Comment, Criterion};
use crate::api::types::{
    Actor, IssueState, PermissionMode, PriorityLevel, QuestionState, RequirementState,
    SprintApproval, Timestamp, opt_ts, ts,
};
use crate::profile::Profile;
use crate::store::work;

#[derive(Debug, Serialize, ToSchema)]
pub struct Requirement {
    pub id: i64,
    pub company_id: i64,
    /// `R-12`.
    pub key: String,
    pub number: i64,
    pub title: String,
    pub body: String,
    pub requested_by_user_id: i64,
    /// The intake request; its comments are the requirement's thread.
    pub intake_issue_id: Option<i64>,
    /// Who answers in the thread: the CEO, then the product owner it was handed to.
    pub owner_agent_id: Option<i64>,
    pub state: RequirementState,
    /// The approved plan's version; 0 before the first approval.
    pub plan_version: i64,
    pub created_at: Timestamp,
    /// When the admin paused it (API minor 18); absent unless it is paused.
    pub paused_at: Option<Timestamp>,
    /// The project it was filed for (API minor 18).
    pub project_id: Option<i64>,
    #[schema(required = false)]
    pub priority_level: PriorityLevel,
    #[schema(required = false)]
    pub criteria: Vec<Criterion>,
}

impl From<work::Requirement> for Requirement {
    fn from(r: work::Requirement) -> Self {
        Self {
            key: r.key(),
            id: r.id.0,
            company_id: r.company_id.0,
            number: r.number,
            title: r.title,
            body: r.body,
            requested_by_user_id: r.requested_by.0,
            intake_issue_id: r.intake_issue_id.map(|i| i.0),
            owner_agent_id: r.owner_agent_id.map(|a| a.0),
            state: r.state.into(),
            plan_version: r.plan_version,
            created_at: ts(&r.created_at),
            paused_at: opt_ts(r.paused_at.as_deref()),
            project_id: r.project_id.map(|p| p.0),
            priority_level: r.priority_level.into(),
            criteria: r
                .criteria
                .into_iter()
                .map(|c| Criterion {
                    text: c.text,
                    done: c.done,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TreeTask {
    pub issue_id: i64,
    /// `CIT-61`.
    pub key: String,
    pub title: String,
    pub state: IssueState,
    pub epic_id: Option<i64>,
    /// Its owner, else the agent it waits on.
    pub assignee: Option<Actor>,
    pub points: Option<u32>,
    pub sprint_id: Option<i64>,
    /// Seconds its ended runs took (0 until the run engine, S7).
    pub time_secs: i64,
    pub tokens: i64,
    /// Its pull requests, one per repo it touches.
    pub prs: i64,
}

impl From<work::TreeTask> for TreeTask {
    fn from(t: work::TreeTask) -> Self {
        Self {
            issue_id: t.id.0,
            key: t.key,
            title: t.title,
            state: t.state.into(),
            epic_id: t.epic_id.map(|e| e.0),
            assignee: t.assignee.map(Into::into),
            points: t.points,
            sprint_id: t.sprint_id.map(|s| s.0),
            time_secs: t.time_secs,
            tokens: t.tokens,
            prs: t.prs,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TreeEpic {
    pub epic_id: i64,
    pub project_id: i64,
    pub title: String,
    pub status: String,
    pub points: u32,
    pub done_points: u32,
    pub tasks: Vec<TreeTask>,
}

/// A task as a plan version holds it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlanTask {
    pub issue_id: i64,
    pub key: String,
    pub title: String,
    pub points: Option<i64>,
}

impl From<work::PlannedTaskRef> for PlanTask {
    fn from(t: work::PlannedTaskRef) -> Self {
        Self {
            issue_id: t.id,
            key: t.key,
            title: t.title,
            points: t.points,
        }
    }
}

/// The plan now against its approved version: scope added or removed since.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlanDiff {
    pub version: i64,
    pub approved_at: Timestamp,
    /// `owner`, or `product_owner` under that sprint policy.
    pub approved_by: String,
    pub added: Vec<PlanTask>,
    pub removed: Vec<PlanTask>,
    pub points_approved: i64,
    pub points_now: i64,
}

/// Points left at the end of a day, and that day's scope.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlanBurndownDay {
    pub day: String,
    pub left: u32,
    pub scope: Option<u32>,
}

/// A requirement's plan, live. (The monolith's `cost` comes with the run engine, S7.)
#[derive(Debug, Serialize, ToSchema)]
pub struct RequirementTree {
    pub requirement: Requirement,
    pub epics: Vec<TreeEpic>,
    /// Its issues outside the plan: the intake request, the kickoff.
    pub other: Vec<TreeTask>,
    pub points: u32,
    pub done_points: u32,
    /// By points, rounded; leaf product tasks only (documentation tasks are left out).
    pub percent_done: u32,
    pub tasks: u32,
    pub done_tasks: u32,
    /// Points left at the end of each day since the plan's approval (or the requirement's
    /// creation).
    pub burndown: Vec<PlanBurndownDay>,
    pub points_per_day: f64,
    /// `YYYY-MM-DD` the rest is done at the pace so far; absent before anything is done or
    /// before three days of data.
    pub eta: Option<String>,
    /// Absent before the plan's first approval.
    pub diff: Option<PlanDiff>,
}

impl From<work::RequirementTree> for RequirementTree {
    fn from(t: work::RequirementTree) -> Self {
        Self {
            requirement: t.requirement.into(),
            epics: t
                .epics
                .into_iter()
                .map(|e| TreeEpic {
                    epic_id: e.id.0,
                    project_id: e.project_id.0,
                    title: e.title,
                    status: e.status,
                    points: e.points,
                    done_points: e.done_points,
                    tasks: e.tasks.into_iter().map(Into::into).collect(),
                })
                .collect(),
            other: t.other.into_iter().map(Into::into).collect(),
            points: t.points,
            done_points: t.done_points,
            percent_done: t.percent_done,
            tasks: t.tasks,
            done_tasks: t.done_tasks,
            burndown: t
                .burndown
                .into_iter()
                .map(|(day, left, scope)| PlanBurndownDay {
                    day,
                    left,
                    scope: Some(scope),
                })
                .collect(),
            points_per_day: t.points_per_day,
            eta: t.eta,
            diff: t.diff.map(|d| PlanDiff {
                version: d.version,
                approved_at: ts(&d.approved_at),
                approved_by: d.approved_by,
                added: d.added.into_iter().map(Into::into).collect(),
                removed: d.removed.into_iter().map(Into::into).collect(),
                points_approved: d.points_approved,
                points_now: d.points_now,
            }),
        }
    }
}

/// An agent's question for the admin: a card while open, a receipt once answered.
#[derive(Debug, Serialize, ToSchema)]
pub struct Question {
    pub id: i64,
    pub requirement_id: Option<i64>,
    /// The asker's issue, where the answer goes.
    pub issue_id: i64,
    pub issue_key: String,
    pub asked_by_agent_id: i64,
    pub run_id: Option<i64>,
    pub question: String,
    pub options: Vec<String>,
    pub state: QuestionState,
    pub answer: Option<String>,
    /// `requirement` or `issue`: where it was answered.
    pub answered_in: Option<String>,
    pub created_at: Timestamp,
    pub answered_at: Option<Timestamp>,
}

pub fn question(q: work::Question, issue_key: String) -> Question {
    Question {
        id: q.id.0,
        requirement_id: q.requirement_id.map(|r| r.0),
        issue_id: q.issue_id.0,
        issue_key,
        asked_by_agent_id: q.agent_id.0,
        run_id: q.run_id.map(|r| r.0),
        question: q.question,
        options: q.options,
        state: q.state.into(),
        answer: q.answer,
        answered_in: q.answered_in,
        created_at: ts(&q.created_at),
        answered_at: opt_ts(q.answered_at.as_deref()),
    }
}

/// One item of a requirement's thread.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThreadItem {
    Message {
        comment: Comment,
        at: Timestamp,
    },
    Question {
        question: Question,
    },
    Approval {
        approval: Approval,
        at: Timestamp,
    },
    /// Published on the requirement's issues (E15.12); opens on the artifacts screen.
    Artifact {
        artifact: Artifact,
    },
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Thread {
    pub requirement_id: i64,
    /// Who a message to the owner wakes: the CEO, then the product owner (#45).
    pub owner_agent_id: Option<i64>,
    /// What a post answers unless it says otherwise: the newest open question (#44).
    pub to_question_id: Option<i64>,
    pub items: Vec<ThreadItem>,
}

/// An agent's pending proposal of a new value for one field.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileProposal {
    /// The knowledge entry; decided with `decideProfileProposal` (a person only, #48).
    pub id: i64,
    pub field: String,
    pub title: String,
    /// The new value: JSON, or plain text for a text field.
    pub body: String,
    pub proposed_by: Option<i64>,
    /// Why the agent proposes it, in one line, when it said.
    pub rationale: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectProfile {
    pub project_id: i64,
    pub profile: Profile,
    pub sprint_approval: SprintApproval,
    pub permission_mode: PermissionMode,
    /// Bytes of the profile a run is given in its instructions, of `budget_bytes` (the
    /// `profile.budget_bytes` setting).
    pub injected_bytes: u64,
    pub budget_bytes: u64,
    /// Sections the budget leaves out of a run's instructions (named there).
    pub dropped: Vec<String>,
    pub proposals: Vec<ProfileProposal>,
    /// Absent while the profile was never changed.
    pub updated_at: Option<Timestamp>,
}

/// Who made a profile change: a person, or the system (an agent's rows are the system's, its
/// id in `details.agent_id`).
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileActor {
    User { user_id: i64 },
    System {},
}

/// One step of a profile's history.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileChange {
    /// Its audit sequence number: the cursor of the next page.
    pub seq: i64,
    pub at: Timestamp,
    pub actor: ProfileActor,
    /// `project.profile_set` (a change), or `knowledge.proposed`, `knowledge.accepted` or
    /// `knowledge.rejected` (an agent's proposal of one).
    pub action: String,
    /// A change: `fields` changed and their new `values` (absent on changes made before values
    /// were recorded), `knowledge_entry` when a proposal made it. A proposal step: its
    /// `profile_field`, `title`, `rationale` or decision `reason`.
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
}
