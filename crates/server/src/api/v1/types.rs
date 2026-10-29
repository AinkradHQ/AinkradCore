//! The contract's shared shapes (E10.1): timestamps, pages, errors, the enums and the actor
//! unions. Each enum mirrors a core enum variant for variant (a new core variant fails to
//! compile here) and is on the wire as the core's snake_case text.
//!
//! Versioning (E0.4): adding an enum value, a union variant or an optional field is allowed
//! within `/api/v1`; clients must tolerate values they do not know. The spec marks every
//! enum open (`spec::normalise`), so generated clients keep an unknown value as a string
//! instead of failing the whole response. Removing or renaming anything is a new `/api/v2`.
//!
//! [`API_MINOR`] counts those additions: every change to `api/openapi.json` within `/api/v1`
//! bumps it by one (the contract's `info.version` is `1.<minor>.0`). A client reads it from
//! `GET /api/v1/me` and knows a server below the minor it was built for lacks something.

/// The `/api/v1` minor version: bumped by one on every additive change to the contract.
/// 1: `GET /api/v1/me` and `GET /api/v1/events/latest`.
/// 2: transcript `tool_result` chunks documented (runner protocol 1.18).
/// 3: the admin's controls (pause, resume, stop, message, wake, nudge, reassign, allow for an
/// issue); `Agent.paused_at`, `Runner.wake_requested_at`.
/// 4: reads for the home, agent, run, stuck and cost screens (agent skills, company runs, open
/// questions, spend by hour or day, spend by agent and department, issue diff);
/// `Agent.hired_at`, `run_token_cap`, `issue_token_cap`; `Run.diff_repos`;
/// `StuckIssue.stuck_since`.
/// 5: prices and budget caps set from the app, move an issue to the backlog (the `shelve`
/// transition), "run when I'm back" (`wakeRunner` `when`, `Runner.wake_mode`).
/// 6: runner admin (register, drain, undrain, remove, log tail, Power Nap) and what a runner
/// reports (`Runner.harnesses`, `slots`, `uptime_secs`, `reported_at`, `logins`, `asleep`,
/// `last_slept_secs`, `drained_at`, `power_nap`, `power_nap_applied`); `Account.plan_tier`
/// (`setAccountPlan`); `AccountUsage.drops_window_secs`, `recent_drops`,
/// `recent_drops_window_secs`; `ErrorBody.error_id`; `Run.transcript_gone_reason`,
/// `transcript_pruned_at`.
/// 7: staffing and planning from the app: apply the Engineering template, propose an agent
/// (a hire), create a project, decide a profile proposal and read the profile's history
/// (`ProfileProposal.rationale`), rename and cancel a requirement, attach a file to its thread.
/// 8: the stuck list's actions (release a dead checkout, retry a run on a runner, bump an issue;
/// `Issue.priority`), budget create and delete, price history, a company's overridden settings.
/// 9: Quest from the app: the owner's sprint commit, project labels and labels on issues
/// (`Issue.labels`), team capacity, project and issue flow times, a sprint's review and retro
/// proposals, project settings (`updateProject`), epic keys (`Epic.key`, `Epic.number`), and
/// `project_id` in every `issue.*` event's details.
/// 10: harness versions against the tested ones (`Runner.harness_status`: `status`,
/// `tested_up_to`, `offered`, `reason`); the `version` setting unit (`harness.*.max_version`).
/// 12: `setIssueSprint` changes an active sprint's scope (audited `sprint.scope_added` /
/// `sprint.scope_removed`, committed points moved).
/// 13: `deleteSprint` (`DELETE /api/v1/sprints/{id}`) deletes an empty planned sprint
/// (audited `sprint.deleted`).
/// 14: the admin's blocker links (`listBlockers`, `linkBlocker`, `unlinkBlocker`; the `block`
/// transition's `blocker_issue_id`), and `NewComment.wake_agent_id` (a comment's wake otherwise
/// goes to the agent it `@mentions`, else the issue's working agent).
/// 15: the `workflow_push` approval kind (a branch push refused for its workflow files waits for
/// a human to push it; approving lets its PR open).
/// 16: an issue's pull requests (`listIssuePrs`), the audit log newest first (`listAudit`,
/// `before`, `kind`, `target`), a project's knowledge (`listKnowledge`) and a human's
/// decision on a proposal (`acceptKnowledge`, `rejectKnowledge`); `Knowledge.created_at`,
/// `updated_at`, `superseded_by`, `body_truncated`, `reason`, `rationale`, `target`,
/// `proposed_by_agent_id`.
/// 17: the prototype's first server tranche: a company's profile (`Company.color`,
/// `description`, `industries`, `website`, `timezone`, `work_start`, `work_end`, `work_days`,
/// `logo_url`; `getCompanyLogo`, `uploadCompanyLogo`, `resetCompanyLogo`); `Approval.created_at`
/// and `decided_at`; an agent's profile (`Agent.description`, `effort`, `sandbox`, `instructions`,
/// `guidelines`; `updateAgent`, `wakeAgent`, `terminateAgent`; `AgentProposal` takes the profile,
/// a team seat and a palette, applied when the hire is approved); departments and teams shaped over
/// HTTP (`createDepartment`, `updateDepartment`, `deleteDepartment`, `createTeam`, `updateTeam`,
/// `deleteTeam`, `seatAgent`, `unseatAgent`; `Department.about`, `head_agent_id`); `Runner.os`,
/// `arch` and `probeRunner` (runner protocol 1.25); `listAudit`'s `actor`; `deleteAccount`; the
/// settings `cost.daily_warn_usd_micros` and `agent.wip_max`, and `account.at_limit` per account.
/// 18: the prototype's second server tranche (B2): dollar budgets (`BudgetBody.usd_cap_micros`,
/// `BudgetStanding.usd_*`) and the `issue` budget scope, unpriced models (`listUnpriced`) and
/// `NewPrice.apply_from`.
/// 20: `Issue.repo_implicit` (R19), true on a single-issue read when it has no explicit repo in a
/// project with several.
pub const API_MINOR: u32 = 20;

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

/// A JSON error: a stable `code` and a message for people.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    /// `err_` and a ULID, unique to this answer: logged with it (and, for a refused write,
    /// audited as `api.refused`), for the app's "Copy error".
    pub error_id: String,
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

use ainkrad_core::{exec, gov, org, settings, work};

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
    RunnerStatus = exec::RunnerStatus {
        Online,
        Offline,
        Unhealthy
    }
);
api_enum!(
    RunState = exec::RunState {
        Queued,
        Claimed,
        Running,
        Succeeded,
        Failed,
        Cancelled,
        TimedOut,
        RunnerLost
    }
);
api_enum!(
    WakeSource = exec::WakeSource {
        Assignment,
        Comment,
        BlockerClosed,
        Timer,
        Manual,
        Approval,
        Escalation,
        Retry
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
api_enum!(LimitUnit = gov::LimitUnit { Tokens, Messages });
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
    /// Where an issue's pull request is: `requested` (opened once the run that asked ends),
    /// `open`, `merging` (approved; the poller merges it), `merged`, `closed` (not merged).
    PrState = crate::store::forge::PrPhase {
        Requested,
        Open,
        Merging,
        Merged,
        Closed
    }
);
api_enum!(
    /// Where a setting may be set (E15.17).
    SettingScope = settings::ScopeKind {
        Server,
        Company,
        Project,
        Runner,
        Account
    }
);
api_enum!(
    SettingUnit = settings::Unit {
        Seconds,
        Milliseconds,
        Percent,
        Count,
        Tokens,
        Bytes,
        PerMinute,
        Version
    }
);
api_enum!(
    AccountStatus = gov::AccountStatus {
        Active,
        Limited,
        Unhealthy,
        Disabled
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
api_enum!(
    StuckKind = exec::StuckKind {
        NoNextActor,
        BlockedNoBlocker,
        BlockedBlockersClosed,
        AgentPausedByBreaker,
        ReviewerInactive,
        NextActorInactive,
        ReviewNoReviewer,
        InProgressIdle,
        TodoIdle,
        WakeNoRunner,
        RunQueuedNoLease,
        CheckoutDead,
        RunnerDiskFull
    }
);
api_enum!(
    RepairAction = exec::RepairAction {
        Rewake,
        ReassignToLead,
        Escalate,
        Unblock,
        ReleaseCheckout,
        Requeue,
        DropWake,
        Notify
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
        assert_eq!(s(&StuckKind::RunQueuedNoLease), "\"run_queued_no_lease\"");
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
