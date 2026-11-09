//! The contract's shared shapes (ported from the monolith's `api/v1/types.rs`): timestamps,
//! pages, the enums and the actor unions. Each enum mirrors a domain enum variant for variant
//! (a new domain variant fails to compile here) and is on the wire as the domain's snake_case
//! text. The error body is the Core's own (`ainkrad_core_server::api::v1::ApiError`).
//!
//! The enums of the run engine, accounts, settings and forge (`RunState`, `StuckKind`,
//! `AccountStatus`, `PrState`, ...) come with their slices.
//!
//! Versioning follows the Core's rule: an added enum value, union variant or optional field is
//! additive; the contract marks every enum open.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// RFC 3339 UTC with exactly milliseconds, `2026-10-21T12:00:00.250Z`: one shape, so a
/// client's date parser never meets a second one (E0.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = DateTime)]
pub struct Timestamp(String);

impl Timestamp {
    /// A stored ISO-8601 UTC time in the wire shape: the fraction padded or cut to
    /// milliseconds. Stored times already are, except a few written without a fraction.
    pub fn new(stored: &str) -> Self {
        let body = stored.strip_suffix('Z').unwrap_or(stored);
        let (secs, frac) = body.split_once('.').unwrap_or((body, ""));
        let ms: String = frac.chars().chain("000".chars()).take(3).collect();
        Self(format!("{secs}.{ms}Z"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn ts(stored: &str) -> Timestamp {
    Timestamp::new(stored)
}

pub fn opt_ts(stored: Option<&str>) -> Option<Timestamp> {
    stored.map(Timestamp::new)
}

/// A page of a list. `next_after` is the cursor of the next page, absent on the last.
#[derive(Debug, Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_after: Option<i64>,
}

impl<T> Page<T> {
    /// `items` as fetched with one extra row: the extra one only says there is more.
    pub fn of(mut items: Vec<T>, limit: u32, cursor: impl Fn(&T) -> i64) -> Self {
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_after = more.then(|| items.last().map(&cursor)).flatten();
        Self { items, next_after }
    }
}

macro_rules! api_enum {
    ($(#[$doc:meta])* $name:ident = $core:ty { $($v:ident),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($v),* }

        impl From<$core> for $name {
            fn from(v: $core) -> Self {
                match v { $(<$core>::$v => Self::$v),* }
            }
        }

        impl From<$name> for $core {
            fn from(v: $name) -> Self {
                match v { $($name::$v => Self::$v),* }
            }
        }
    };
}

use crate::domain::{gov, org, work};

api_enum!(ProjectMode = work::ProjectMode { Scrum, Kanban });
api_enum!(
    /// The admin's own company, or a client's (E15.14).
    CompanyKind = org::CompanyKind { Own, Client }
);
api_enum!(
    SprintApproval = work::SprintApproval {
        Owner,
        ProductOwner
    }
);
api_enum!(
    PermissionMode = ainkrad_proto::runner::PermissionMode {
        Ask,
        AcceptEdits,
        Sandboxed
    }
);
api_enum!(
    EpicStatus = work::EpicStatus {
        Open,
        InProgress,
        Done,
        Cancelled
    }
);
api_enum!(
    IssueKind = work::IssueKind {
        Story,
        Task,
        Bug,
        Chore,
        Spike,
        Subtask
    }
);
api_enum!(
    /// How much an issue matters (API minor 18).
    PriorityLevel = work::PriorityLevel {
        None,
        Low,
        Medium,
        High,
        Urgent
    }
);
api_enum!(
    IssueState = work::IssueState {
        Backlog,
        Todo,
        InProgress,
        InReview,
        Blocked,
        Done,
        Cancelled
    }
);
api_enum!(
    RequirementState = work::RequirementState {
        Planning,
        PlanReview,
        InProgress,
        Done,
        Cancelled
    }
);
api_enum!(
    QuestionState = work::QuestionState {
        Open,
        Answered,
        Cancelled
    }
);
api_enum!(
    SprintState = work::SprintState {
        Planned,
        Active,
        Closed
    }
);
api_enum!(
    TeamRole = org::TeamRole {
        ProductOwner,
        TeamLead,
        Member
    }
);
api_enum!(OrgRole = org::OrgRole { Ceo, Cto, None });
api_enum!(
    /// How hard an agent thinks (API minor 17).
    Effort = org::Effort { Low, Medium, High }
);
/// What an agent's harness may touch (API minor 17): `read-only`, `workspace-write` or
/// `full-access`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Sandbox {
    ReadOnly,
    WorkspaceWrite,
    FullAccess,
}

impl From<org::Sandbox> for Sandbox {
    fn from(v: org::Sandbox) -> Self {
        match v {
            org::Sandbox::ReadOnly => Self::ReadOnly,
            org::Sandbox::WorkspaceWrite => Self::WorkspaceWrite,
            org::Sandbox::FullAccess => Self::FullAccess,
        }
    }
}

impl From<Sandbox> for org::Sandbox {
    fn from(v: Sandbox) -> Self {
        match v {
            Sandbox::ReadOnly => Self::ReadOnly,
            Sandbox::WorkspaceWrite => Self::WorkspaceWrite,
            Sandbox::FullAccess => Self::FullAccess,
        }
    }
}
api_enum!(
    Harness = org::Harness {
        Claude,
        Codex,
        Opencode,
        Agy
    }
);
api_enum!(
    Tier = org::Tier {
        Small,
        Standard,
        Large
    }
);
api_enum!(
    AgentStatus = org::AgentStatus {
        Active,
        Paused,
        PendingApproval,
        Terminated
    }
);
api_enum!(
    ApprovalKind = gov::ApprovalKind {
        SprintCommit,
        PrMerge,
        BudgetOverrun,
        HireAgent,
        PermissionEscalation,
        PlanApproval,
        WorkflowPush
    }
);
api_enum!(
    ArtifactKind = gov::ArtifactKind {
        Report,
        File,
        Screenshot,
        Other
    }
);
api_enum!(
    ApprovalStatus = gov::ApprovalStatus {
        Pending,
        Approved,
        Rejected,
        Expired
    }
);
api_enum!(
    Billing = gov::Billing {
        Metered,
        Subscription
    }
);
api_enum!(
    KnowledgeKind = gov::KnowledgeKind {
        Decision,
        Landmine,
        State,
        Retro
    }
);
api_enum!(
    KnowledgeStatus = gov::KnowledgeStatus {
        Proposed,
        Accepted,
        Rejected,
        Retired
    }
);
api_enum!(
    BudgetPeriod = gov::BudgetPeriod {
        Day,
        Week,
        Month,
        Total
    }
);

/// An agent or a person: who owns an issue, wrote a comment, reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    Agent { agent_id: i64 },
    Human { user_id: i64 },
}

impl From<work::Actor> for Actor {
    fn from(a: work::Actor) -> Self {
        match a {
            work::Actor::Agent(id) => Self::Agent { agent_id: id.0 },
            work::Actor::Human(id) => Self::Human { user_id: id.0 },
        }
    }
}

impl From<Actor> for work::Actor {
    fn from(a: Actor) -> Self {
        match a {
            Actor::Agent { agent_id } => Self::Agent(org::AgentId(agent_id)),
            Actor::Human { user_id } => Self::Human(work::UserId(user_id)),
        }
    }
}

/// Who moves an issue next: an agent, a person, or a timer at `at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NextActor {
    Agent { agent_id: i64 },
    Human { user_id: i64 },
    Timer { at: String },
}

impl From<work::NextActor> for NextActor {
    fn from(a: work::NextActor) -> Self {
        match a {
            work::NextActor::Agent(id) => Self::Agent { agent_id: id.0 },
            work::NextActor::Human(id) => Self::Human { user_id: id.0 },
            work::NextActor::Timer(at) => Self::Timer { at },
        }
    }
}

impl From<NextActor> for work::NextActor {
    fn from(a: NextActor) -> Self {
        match a {
            NextActor::Agent { agent_id } => Self::Agent(org::AgentId(agent_id)),
            NextActor::Human { user_id } => Self::Human(work::UserId(user_id)),
            NextActor::Timer { at } => Self::Timer(at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_exactly_milliseconds() {
        for (stored, wire) in [
            ("2026-10-21T12:00:00Z", "2026-10-21T12:00:00.000Z"),
            ("2026-10-21T12:00:00.25Z", "2026-10-21T12:00:00.250Z"),
            ("2026-10-21T12:00:00.250Z", "2026-10-21T12:00:00.250Z"),
            ("2026-10-21T12:00:00.123456789Z", "2026-10-21T12:00:00.123Z"),
        ] {
            assert_eq!(Timestamp::new(stored).as_str(), wire);
        }
    }

    fn s<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    #[test]
    fn enums_speak_the_core_text() {
        assert_eq!(
            s(&IssueState::from(work::IssueState::InReview)),
            "\"in_review\""
        );
        assert_eq!(s(&AgentStatus::PendingApproval), "\"pending_approval\"");
        assert_eq!(s(&OrgRole::None), "\"none\"");
        assert_eq!(
            s(&Actor::Agent { agent_id: 3 }),
            r#"{"kind":"agent","agent_id":3}"#
        );
    }

    #[test]
    fn a_page_says_whether_there_is_more() {
        let p = Page::of(vec![1, 2, 3], 2, |n| *n);
        assert_eq!((p.items, p.next_after), (vec![1, 2], Some(2)));
        let p = Page::of(vec![1, 2], 2, |n| *n);
        assert_eq!((p.items, p.next_after), (vec![1, 2], None));
    }
}
