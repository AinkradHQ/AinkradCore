//! Response and request models of the org_admin seam (ToSchema; names unique across the Core
//! contract). Request-body enums are `String`s parsed by hand (`org_admin::parse`), so a bad
//! value is a 400, not a serde 422; `schema(value_type)` still documents the enum.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{Agent, Company};
use crate::api::types::{Effort, Harness, OrgRole, Sandbox, TeamRole, Tier};
use crate::domain::org;
use crate::store::org::avatars::Activity;

/// `Option<Option<T>>` from JSON: absent is `None`, `null` is `Some(None)`.
pub mod serde_with_none {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

/// What an agent's figure shows, first match wins:
///
/// | state | when |
/// |---|---|
/// | `sleepy` | the agent is paused |
/// | `rest` | it waits on its hire approval, or is terminated |
/// | `listening` | it has an open question to the admin, or an approval it asked for is pending |
/// | `working` | its run is running and has produced output |
/// | `thinking` | its run is running, no output yet |
/// | `loading` | its run is queued or claimed by a runner, not yet started |
/// | `confused` | its last run failed, timed out, lost its runner or stalled |
/// | `success` | its last run succeeded in the last five minutes |
/// | `idle` | otherwise |
///
/// Until the run engine is ported only the first three and `idle` occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FigureState {
    Rest,
    Idle,
    Listening,
    Thinking,
    Working,
    Success,
    Confused,
    Sleepy,
    Loading,
}

impl FigureState {
    pub fn of(status: org::AgentStatus, a: &Activity) -> Self {
        match status {
            org::AgentStatus::Paused => Self::Sleepy,
            org::AgentStatus::PendingApproval | org::AgentStatus::Terminated => Self::Rest,
            org::AgentStatus::Active => match a.live.as_deref() {
                _ if a.waiting => Self::Listening,
                Some("running") if a.speaking => Self::Working,
                Some("running") => Self::Thinking,
                Some(_) => Self::Loading,
                None if a.failed => Self::Confused,
                None if a.succeeded => Self::Success,
                None => Self::Idle,
            },
        }
    }
}

/// A seat on a team.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrgSeat {
    pub agent_id: i64,
    pub team_role: TeamRole,
    /// Points per sprint, when set.
    pub capacity: Option<u32>,
}

/// A team with its seats (the org chart's; `Team` is the flat one).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrgTeam {
    pub id: i64,
    pub name: String,
    pub members: Vec<OrgSeat>,
}

/// A department with its teams (the org chart's; `Department` is the flat one).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrgDepartment {
    pub id: i64,
    pub name: String,
    /// What it does (API minor 17).
    #[serde(default)]
    pub about: String,
    /// The agent that heads it; absent when it has none.
    #[serde(default)]
    pub head_agent_id: Option<i64>,
    pub teams: Vec<OrgTeam>,
}

/// A company's agents (with `reports_to`, the chart's edges) and its departments and teams.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgChart {
    pub company: Company,
    pub agents: Vec<Agent>,
    pub departments: Vec<OrgDepartment>,
}

/// What to change about an agent; absent fields stay, `null` clears `effort`, `sandbox` and
/// `reports_to`. At least one field is needed.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentUpdate {
    /// Free-text job title, 1-100 characters.
    pub role: Option<String>,
    /// At most 4000 characters.
    pub description: Option<String>,
    #[schema(value_type = Option<Harness>)]
    pub harness: Option<String>,
    /// 1-200 characters.
    pub model: Option<String>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<Effort>)]
    pub effort: Option<Option<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<Sandbox>)]
    pub sandbox: Option<Option<String>>,
    /// At most 20 tags, each 1-64 characters without spaces.
    pub runner_tags: Option<Vec<String>>,
    /// An agent of the company that does not report to this one; `null`: nobody.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub reports_to: Option<Option<i64>>,
    /// At most 20000 characters.
    pub instructions: Option<String>,
    /// At most 50, each 1-500 characters; replaces the list.
    pub guidelines: Option<Vec<String>>,
}

/// What applying a template left in place.
#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateApplied {
    pub department_id: i64,
    pub team_id: i64,
    /// Its agents, the CTO first, then the team in seat order; new ones `pending_approval`.
    pub agents: Vec<Agent>,
    /// The hire approvals this apply opened, for the admin to decide (none on a re-apply).
    pub hire_approval_ids: Vec<i64>,
    pub skills_published: usize,
}

/// An agent the admin proposes; it is hired only once its approval is approved.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentProposal {
    /// Unique within the company.
    pub name: String,
    /// Free-text job title ("QA", "Designer"...).
    pub role: String,
    /// Absent: none (`ceo` and `cto` at most once per company).
    #[schema(value_type = Option<OrgRole>)]
    pub org_role: Option<String>,
    #[schema(value_type = Harness)]
    pub harness: String,
    pub model: String,
    /// Capabilities a runner must offer, e.g. `macos`.
    #[serde(default)]
    pub runner_tags: Vec<String>,
    /// An agent of the company it reports to.
    pub reports_to: Option<i64>,
    /// Why the company needs it: shown on the hire approval.
    pub justification: String,
    /// What it is (API minor 17); like the fields below, applied when the hire is approved.
    #[serde(default)]
    pub description: String,
    #[schema(value_type = Option<Effort>)]
    pub effort: Option<String>,
    #[schema(value_type = Option<Sandbox>)]
    pub sandbox: Option<String>,
    #[serde(default)]
    pub instructions: String,
    #[serde(default)]
    pub guidelines: Vec<String>,
    /// A team of the company to seat it on (with `team_role`, default `member`); a product
    /// owner or lead seat the team has filled is a 409.
    pub team_id: Option<i64>,
    #[schema(value_type = Option<TeamRole>)]
    pub team_role: Option<String>,
    /// One of `listPalettes`; absent: the company's least used.
    pub palette_id: Option<String>,
}

/// A proposed agent and the approval that hires it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProposedAgent {
    /// `pending_approval` until the approval is decided.
    pub agent: Agent,
    pub hire_approval_id: i64,
}

/// A department to add.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewDepartment {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// At most 2000 characters.
    #[serde(default)]
    pub about: String,
    /// An agent of the company.
    pub head_agent_id: Option<i64>,
}

/// What to change about a department; absent fields stay, `null` clears the head.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DepartmentUpdate {
    pub name: Option<String>,
    pub about: Option<String>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub head_agent_id: Option<Option<i64>>,
}

/// What a delete removed.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgRemoved {
    pub id: i64,
}

/// What to change about a team; absent fields stay.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TeamUpdate {
    pub name: Option<String>,
    /// Move it to another department of the same company.
    pub department_id: Option<i64>,
}

/// A seat on a team.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SeatRequest {
    #[schema(value_type = TeamRole)]
    pub team_role: String,
    /// Points per sprint.
    pub capacity: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleOut {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub purpose: String,
    /// A glyph name the client draws; free text.
    pub icon: String,
    /// What a new agent of the role starts on; absent: the client's choice.
    pub harness: Option<Harness>,
    pub model: Option<String>,
    /// Its token budget per month, when the role has a default.
    pub budget_tokens: Option<i64>,
    /// Skill names.
    pub skills: Vec<String>,
    pub instructions: String,
}

/// A role to store; `PUT` replaces all of it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RoleBody {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub purpose: String,
    /// At most 40 characters.
    #[serde(default)]
    pub icon: String,
    #[schema(value_type = Option<Harness>)]
    pub harness: Option<String>,
    /// 1-200 characters.
    pub model: Option<String>,
    /// 0 or more.
    pub budget_tokens: Option<i64>,
    /// At most 50 skill names.
    #[serde(default)]
    pub skills: Vec<String>,
    /// At most 20000 characters.
    #[serde(default)]
    pub instructions: String,
}

/// One entry of a chain, tried in order.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChainEntryBody {
    #[schema(value_type = Harness)]
    pub harness: String,
    pub model: String,
    /// Pin the entry to one account of the company's pool; absent: any. (No account is in a
    /// pool until the accounts slice, so a pin is refused for now.)
    pub account_id: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainPresetOut {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    /// `#rrggbb`.
    pub color: Option<String>,
    pub description: String,
    /// The chain agents with no chain of their own use.
    pub is_default: bool,
    pub entries: Vec<ChainEntryBody>,
}

/// A preset to store; `PUT` replaces all of it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChainPresetBody {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// `#rrggbb`.
    pub color: Option<String>,
    /// At most 2000 characters.
    #[serde(default)]
    pub description: String,
    /// Make it the company's default chain (the old default stops being it).
    #[serde(default)]
    pub is_default: bool,
    /// At most 20; an account pin must be in the company's pool.
    pub entries: Vec<ChainEntryBody>,
}

/// How an agent gets its chain: a preset, or entries of its own. Exactly one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentChainBody {
    /// Use this preset of the agent's company.
    pub preset_id: Option<i64>,
    /// Use these fallbacks of its own and no preset (no account pins: pin in a preset); an empty
    /// list clears them.
    pub entries: Option<Vec<ChainEntryBody>>,
}

/// The agent's effective chain after its own entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentChainOut {
    /// The preset the agent has set; absent when it uses its own entries (or the default).
    pub preset_id: Option<i64>,
    pub entries: Vec<ChainEntryBody>,
}

/// One entry of the fallback chain, tried in order after the agent's own harness and model.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelFallback {
    #[schema(value_type = Harness)]
    pub harness: String,
    pub model: String,
}

/// The (harness, model) an agent's tasks of `tier` start on. Its own harness and model are
/// its standard tier, so only `small` and `large` are set here.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelTier {
    #[schema(value_type = Tier)]
    pub tier: String,
    #[schema(value_type = Harness)]
    pub harness: String,
    pub model: String,
}

/// One routing rule: issues with this label (`label:chore`) or kind (`kind:subtask`) run on
/// `tier`. A matching rule wins over points.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TierRule {
    pub rule: String,
    #[schema(value_type = Tier)]
    pub tier: String,
}

/// A project's routing rules; `defaults` when it has set none and the built-in ones apply.
#[derive(Debug, Serialize, ToSchema)]
pub struct TierRules {
    pub rules: Vec<TierRule>,
    pub defaults: bool,
}

/// A palette the client colours a figure with.
#[derive(Debug, Serialize, ToSchema)]
pub struct Palette {
    /// E.g. `neon-tide`.
    pub id: String,
    pub name: String,
}

/// A new look: a palette, and a figure version when it changes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AppearanceChange {
    pub palette_id: String,
    pub figure_version: Option<String>,
}
