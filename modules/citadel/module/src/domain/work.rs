//! Work model: project → epic → story / task / bug → subtask, plus sprints, blockers,
//! comments and labels (brainstorm §5). Issue transitions and the next-actor invariant
//! are in `machine` (E2.4).
//!
//! Timestamps and dates are ISO-8601 text, as stored.

use std::str::FromStr;

use crate::domain::org::{AgentId, CompanyId, TeamId, UnknownVariant, id, text_enum};

// A run belongs to the run engine (agent sessions, E2-08); the domain only points at it.
id!(RunId);

pub mod aggregate;
mod machine;
pub use machine::*;

id!(
    UserId,
    ProjectId,
    EpicId,
    IssueId,
    SprintId,
    LabelId,
    CommentId,
    RequirementId,
    QuestionId
);

// A requirement's life (E15.10): its plan is drafted, reviewed, then worked; no dev work runs
// before `in_progress` (plan-first).
text_enum!(RequirementState {
    Planning => "planning",
    PlanReview => "plan_review",
    InProgress => "in_progress",
    Done => "done",
    Cancelled => "cancelled",
});

text_enum!(ProjectMode {
    Scrum => "scrum",
    Kanban => "kanban",
});

// Who approves a sprint commit (#10): the owner (Ahmed), or the product owner alone.
text_enum!(SprintApproval {
    Owner => "owner",
    ProductOwner => "product_owner",
});

text_enum!(EpicStatus {
    Open => "open",
    InProgress => "in_progress",
    Done => "done",
    Cancelled => "cancelled",
});

text_enum!(IssueKind {
    Story => "story",
    Task => "task",
    Bug => "bug",
    Chore => "chore",
    Spike => "spike",
    Subtask => "subtask",
});

// How much an issue matters (API minor 18); `high` and `urgent` are what the bool
// `Issue.priority` has always meant.
text_enum!(PriorityLevel {
    None => "none",
    Low => "low",
    Medium => "medium",
    High => "high",
    Urgent => "urgent",
});

impl PriorityLevel {
    /// Whether the issue's wakes are dispatched first.
    pub fn is_high(self) -> bool {
        matches!(self, Self::High | Self::Urgent)
    }
}

/// One line of an issue's acceptance criteria.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    pub text: String,
    pub done: bool,
}

text_enum!(IssueState {
    Backlog => "backlog",
    Todo => "todo",
    InProgress => "in_progress",
    InReview => "in_review",
    Blocked => "blocked",
    Done => "done",
    Cancelled => "cancelled",
});

impl IssueState {
    /// Terminal issues are the only ones allowed to have no next actor.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Cancelled)
    }
}

// An agent's question for a person (E15.11): open until answered, in the requirement's thread
// or the asker's issue thread.
text_enum!(QuestionState {
    Open => "open",
    Answered => "answered",
    Cancelled => "cancelled",
});

text_enum!(SprintState {
    Planned => "planned",
    Active => "active",
    Closed => "closed",
});

/// Who owns an issue or wrote a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    Agent(AgentId),
    Human(UserId),
}

/// Who moves an issue forward next (decision #4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NextActor {
    Agent(AgentId),
    Human(UserId),
    /// A system timer due at this timestamp.
    Timer(String),
}

impl From<Actor> for NextActor {
    fn from(a: Actor) -> Self {
        match a {
            Actor::Agent(id) => Self::Agent(id),
            Actor::Human(id) => Self::Human(id),
        }
    }
}

/// A project before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProject {
    pub company_id: CompanyId,
    /// The owning team; must be in the same company.
    pub team_id: Option<TeamId>,
    pub name: String,
    /// Issue-number prefix, e.g. `CIT` for `CIT-12`; unique within the company.
    pub key: String,
    pub mode: ProjectMode,
    pub sprint_approval: SprintApproval,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: ProjectId,
    pub company_id: CompanyId,
    pub team_id: Option<TeamId>,
    pub name: String,
    pub key: String,
    pub mode: ProjectMode,
    pub sprint_approval: SprintApproval,
    /// A symbol or emoji (API minor 18).
    pub icon: Option<String>,
    /// `#rrggbb`.
    pub color: Option<String>,
    /// An uploaded logo: its SHA-256.
    pub logo_sha256: Option<String>,
    /// Every team on it, the owner (`team_id`) first.
    pub team_ids: Vec<TeamId>,
    /// Runtime limits; stored and shown, dispatch does not apply them yet.
    pub runner_tags: Vec<String>,
    pub max_parallel_runs: Option<u32>,
    pub run_timeout_secs: Option<u32>,
    pub worktree_keep_days: Option<u32>,
}

/// A project's git repository (E3.7): each issue's runs work in a worktree of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRepo {
    pub project_id: ProjectId,
    /// A URL or path git can clone; never holds credentials.
    pub url: String,
    /// The branch issue branches are cut from.
    pub default_branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic {
    pub id: EpicId,
    pub project_id: ProjectId,
    pub title: String,
    pub status: EpicStatus,
    /// Per project, from 1, never reused: `<KEY>-E<number>`.
    pub number: i64,
    /// `#rrggbb` (API minor 18).
    pub color: Option<String>,
    /// `YYYY-MM-DD`.
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
    /// The requirement it serves: its project's at creation, or set by the admin.
    pub requirement_id: Option<RequirementId>,
}

/// Whether `c` is `#rrggbb`.
pub fn is_hex_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A sprint before it is stored. A project has at most one active sprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSprint {
    pub project_id: ProjectId,
    pub name: String,
    pub goal: String,
    pub state: SprintState,
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sprint {
    pub id: SprintId,
    pub project_id: ProjectId,
    pub name: String,
    pub goal: String,
    pub state: SprintState,
    pub starts_on: Option<String>,
    pub ends_on: Option<String>,
}

/// An issue before it is stored; the store allocates its number and appends it to the
/// backlog. A subtask is an issue with a parent, and only a subtask has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIssue {
    pub project_id: ProjectId,
    pub epic_id: Option<EpicId>,
    pub parent_id: Option<IssueId>,
    pub kind: IssueKind,
    pub title: String,
    pub body: String,
    pub state: IssueState,
    pub owner: Option<Actor>,
    /// Required unless `state` is terminal.
    pub next_actor: Option<NextActor>,
    pub points: Option<u32>,
    pub sprint_id: Option<SprintId>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub id: IssueId,
    pub project_id: ProjectId,
    /// Sequential per project, from 1.
    pub number: i64,
    pub epic_id: Option<EpicId>,
    pub parent_id: Option<IssueId>,
    pub kind: IssueKind,
    pub title: String,
    pub body: String,
    pub state: IssueState,
    pub owner: Option<Actor>,
    pub next_actor: Option<NextActor>,
    pub points: Option<u32>,
    pub sprint_id: Option<SprintId>,
    /// Backlog order, ascending; fractional so an issue can move between two others.
    pub rank: f64,
    /// The run that checked the issue out (E2.3). A run that has since ended no longer
    /// holds it, even while its id is still here. Set only by checkout and release.
    pub checkout_run_id: Option<RunId>,
    /// The requirement it was derived from (E15.10): set at insert from its parent, epic or
    /// project, and never by an edit.
    pub requirement_id: Option<RequirementId>,
    /// Bumped by the admin: its wakes are dispatched before others'. True from `high` up.
    pub priority: bool,
    pub priority_level: PriorityLevel,
    pub criteria: Vec<Criterion>,
}

/// Where an issue goes in its project's order (E5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Top,
    Bottom,
    /// Just before this issue of the same project.
    Before(IssueId),
    /// Just after this issue of the same project.
    After(IssueId),
}

/// Narrows a backlog listing; a `None` field matches every issue.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BacklogFilter {
    pub epic_id: Option<EpicId>,
    pub label_id: Option<LabelId>,
    pub kind: Option<IssueKind>,
    pub state: Option<IssueState>,
    /// The owner.
    pub assignee: Option<Actor>,
}

/// A sprint's numbers (E5.2), from the points its issues carry now.
#[derive(Debug, Clone, PartialEq)]
pub struct SprintReport {
    pub sprint_id: SprintId,
    pub state: SprintState,
    /// Points in the sprint when it started; `None` while planned.
    pub committed: Option<u32>,
    /// Points of its done issues: as of the close once closed, so far while active.
    pub completed: u32,
    /// The owning team's capacity: the sum of its members' set capacities, if any is set.
    pub capacity: Option<u32>,
    /// Points left at the end of each day (`YYYY-MM-DD`), from the start date to the end
    /// date or today, whichever is earlier. Empty until the sprint starts.
    pub burndown: Vec<(String, u32)>,
}

/// Completed points over a project's last closed sprints.
#[derive(Debug, Clone, PartialEq)]
pub struct Velocity {
    /// `(sprint, committed, completed)`, newest first.
    pub sprints: Vec<(SprintId, u32, u32)>,
    /// The mean completed points; 0 with no closed sprint.
    pub average: f64,
}

/// How fast a project's issues flow (E5.3), over the issues done in a window.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowMetrics {
    /// `(issue, cycle, lead)` in seconds, by when it was done: cycle from its first
    /// `in_progress` (`None` if it never was), lead from its creation, both to its last
    /// `done`.
    pub issues: Vec<(IssueId, Option<i64>, i64)>,
    pub mean_cycle_secs: Option<f64>,
    pub mean_lead_secs: Option<f64>,
}

/// `blocker` must close before `blocked` can proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockerLink {
    pub blocker: IssueId,
    pub blocked: IssueId,
}

/// A comment before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewComment {
    pub issue_id: IssueId,
    pub author: Actor,
    pub body: String,
    /// The run that wrote it, if any.
    pub run_id: Option<RunId>,
    /// Posting twice with the same key on one issue yields the first comment.
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub id: CommentId,
    pub issue_id: IssueId,
    pub author: Actor,
    pub body: String,
    pub run_id: Option<RunId>,
    pub idempotency_key: Option<String>,
}

/// Labels are scoped to a project; names are unique within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub id: LabelId,
    pub project_id: ProjectId,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_text() {
        for s in [
            IssueState::InProgress,
            IssueState::InReview,
            IssueState::Cancelled,
        ] {
            assert_eq!(s.as_str().parse::<IssueState>(), Ok(s));
        }
        assert_eq!("subtask".parse::<IssueKind>(), Ok(IssueKind::Subtask));
        assert_eq!(
            "product_owner".parse::<SprintApproval>(),
            Ok(SprintApproval::ProductOwner)
        );
        assert_eq!("kanban".parse::<ProjectMode>(), Ok(ProjectMode::Kanban));
        assert!("epic".parse::<IssueKind>().is_err());
    }

    #[test]
    fn only_done_and_cancelled_are_terminal() {
        let terminal: Vec<_> = [
            IssueState::Backlog,
            IssueState::Todo,
            IssueState::InProgress,
            IssueState::InReview,
            IssueState::Blocked,
            IssueState::Done,
            IssueState::Cancelled,
        ]
        .into_iter()
        .filter(|s| s.is_terminal())
        .collect();
        assert_eq!(terminal, vec![IssueState::Done, IssueState::Cancelled]);
    }
}
