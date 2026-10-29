//! The contract's resources (E10.1): what the store returns, as the client sees it. Each is
//! built from its core type; nothing here reads the database.

use ainkrad_core::{exec, gov, org, work};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use super::reads::RepoDiff;
use utoipa::ToSchema;

use super::avatars::{Appearance, FigureState};
use super::types::*;
use crate::store;

mod work_items;
pub use work_items::*;

#[derive(Debug, Serialize, ToSchema)]
pub struct Company {
    pub id: i64,
    pub name: String,
    pub kind: super::types::CompanyKind,
    /// The pool accounts its runs may use (E15.1).
    pub account_ids: Vec<i64>,
    /// Its colour, `#rrggbb` (API minor 17); absent when unset, as every optional field here.
    pub color: Option<String>,
    /// What it does, for its agents (empty when unset).
    #[schema(required = false)]
    pub description: String,
    #[schema(required = false)]
    pub industries: Vec<String>,
    pub website: Option<String>,
    /// An IANA time zone, e.g. `Europe/Berlin`.
    pub timezone: Option<String>,
    /// Working hours: minutes from midnight, 0–1440.
    pub work_start: Option<u16>,
    pub work_end: Option<u16>,
    /// Working days as a bitmask: bit 0 Monday … bit 6 Sunday (31 = Monday to Friday).
    pub work_days: Option<u8>,
    /// Its uploaded logo (`getCompanyLogo`); absent when it has none.
    pub logo_url: Option<String>,
}

impl From<org::Company> for Company {
    fn from(c: org::Company) -> Self {
        let p = c.profile;
        Self {
            logo_url: p
                .logo_sha256
                .map(|_| format!("/api/v1/companies/{}/logo", c.id.0)),
            id: c.id.0,
            name: c.name,
            kind: c.kind.into(),
            account_ids: vec![],
            color: p.color,
            description: p.description,
            industries: p.industries,
            website: p.website,
            timezone: p.timezone,
            work_start: p.work_start,
            work_end: p.work_end,
            work_days: p.work_days,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Agent {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub role: String,
    pub org_role: OrgRole,
    pub reports_to: Option<i64>,
    pub harness: Harness,
    pub model: String,
    pub runner_tags: Vec<String>,
    pub status: AgentStatus,
    /// What the admin wrote about it (API minor 17).
    #[schema(required = false)]
    pub description: String,
    /// Absent: the harness default. Stored and shown; not yet applied by dispatch.
    pub effort: Option<super::types::Effort>,
    /// Absent: the harness default. Stored and shown; not yet applied by dispatch.
    pub sandbox: Option<super::types::Sandbox>,
    /// Its standing instructions.
    #[schema(required = false)]
    pub instructions: String,
    /// Short rules, in order.
    #[schema(required = false)]
    pub guidelines: Vec<String>,
    /// How the client draws its figure (decision #61).
    pub appearance: Appearance,
    /// Its uploaded image, shown instead of the figure; absent when it has none.
    pub avatar_url: Option<String>,
    /// What its figure shows now.
    pub figure_state: FigureState,
    /// When the admin paused it (decision #34); absent unless it is paused by the admin.
    pub paused_at: Option<Timestamp>,
    /// When it was hired.
    pub hired_at: Timestamp,
    /// Its company's effective `run.token_cap` and `issue.token_cap` (0: none); a project
    /// may set its own.
    pub run_token_cap: i64,
    pub issue_token_cap: i64,
    /// The chain preset it uses in place of its own fallbacks (API minor 18); absent when it has
    /// none.
    pub chain_preset_id: Option<i64>,
    /// Wakes waiting for it (API minor 18), e.g. while it is paused.
    #[schema(required = false)]
    pub queued_wakes: i64,
}

impl Agent {
    /// `a` as the client sees it, doing `activity`, with its company's (run, issue) token caps.
    pub fn of(a: org::Agent, activity: &store::org::avatars::Activity, caps: (i64, i64)) -> Self {
        Self {
            hired_at: ts(&a.created_at),
            run_token_cap: caps.0,
            issue_token_cap: caps.1,
            chain_preset_id: None,
            queued_wakes: 0,
            figure_state: FigureState::of(a.status, activity),
            paused_at: match a.status {
                org::AgentStatus::Paused => opt_ts(a.paused_at.as_deref()),
                _ => None,
            },
            avatar_url: a
                .avatar_sha256
                .as_ref()
                .map(|_| format!("/api/v1/agents/{}/avatar", a.id.0)),
            appearance: Appearance {
                figure_version: a.figure_version,
                palette_id: a.palette_id,
            },
            id: a.id.0,
            company_id: a.company_id.0,
            name: a.name,
            role: a.role,
            org_role: a.org_role.into(),
            reports_to: a.reports_to.map(|r| r.0),
            harness: a.harness.into(),
            model: a.model,
            runner_tags: a.runner_tags,
            status: a.status.into(),
            description: a.profile.description,
            effort: a.profile.effort.map(Into::into),
            sandbox: a.profile.sandbox.map(Into::into),
            instructions: a.profile.instructions,
            guidelines: a.profile.guidelines,
        }
    }
}

/// A seat on a team.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Seat {
    pub agent_id: i64,
    pub team_role: TeamRole,
    /// Points per sprint, when set.
    pub capacity: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Team {
    pub id: i64,
    pub name: String,
    pub members: Vec<Seat>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Department {
    pub id: i64,
    pub name: String,
    /// What it does (API minor 17).
    #[serde(default)]
    pub about: String,
    /// The agent that heads it; absent when it has none.
    #[serde(default)]
    pub head_agent_id: Option<i64>,
    pub teams: Vec<Team>,
}

/// A company's agents (with `reports_to`, the chart's edges) and its departments and teams.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgChart {
    pub company: Company,
    pub agents: Vec<Agent>,
    pub departments: Vec<Department>,
}

pub use super::runners::Runner;

#[derive(Debug, Serialize, ToSchema)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    /// Absent when the run is not priced.
    pub cost_usd_micros: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Run {
    pub id: i64,
    pub agent_id: i64,
    pub issue_id: Option<i64>,
    pub runner_id: Option<i64>,
    pub state: RunState,
    pub terminal_reason: Option<String>,
    pub harness: Harness,
    pub harness_version: Option<String>,
    pub usage: Usage,
    pub queued_at: Timestamp,
    pub claimed_at: Option<Timestamp>,
    pub started_at: Option<Timestamp>,
    pub ended_at: Option<Timestamp>,
    /// The provider account it works as (E15.1).
    pub account_id: Option<i64>,
    /// The model it works with (E15.3).
    pub model_used: Option<String>,
    /// Why it is not on its agent's first (harness, model): every reason, in order (E15.3).
    pub fallback_reason: Option<String>,
    /// The tier its task was routed to (E15.5); absent on runs from before.
    pub tier: Option<Tier>,
    /// Its first turn's input tokens, cache included: the context it started with (E15.5).
    pub context_tokens: Option<i64>,
    /// Stage timings (E15.6): when its wake was due, its harness first reported and its model
    /// first answered. With `claimed_at`, `started_at` (its workspace ready) and `ended_at`:
    /// wake → claim → workspace → harness → first token → end.
    pub woken_at: Option<Timestamp>,
    pub harness_started_at: Option<Timestamp>,
    pub first_token_at: Option<Timestamp>,
    /// When its runner last saw it progress (E15.7): a tool call, a file change, a new message
    /// or more tokens. With the project's `run.stall_after_secs`, how close it is to stalling.
    pub last_progress_at: Option<Timestamp>,
    /// Files its worktree differs from the base in, as last measured (E15.7).
    pub diff_files: Option<i64>,
    /// Each repo's diff against its base, as last measured (runner protocol 1.18), in the
    /// issue's repo order; empty before any measure.
    pub diff_repos: Vec<RepoDiff>,
    /// Why its transcript is gone, when it is: `pruned` (`transcript.retention_secs`).
    pub transcript_gone_reason: Option<String>,
    pub transcript_pruned_at: Option<Timestamp>,
}

impl From<exec::Run> for Run {
    fn from(r: exec::Run) -> Self {
        Self {
            id: r.id.0,
            agent_id: r.agent_id.0,
            issue_id: r.issue_id.map(|i| i.0),
            runner_id: r.runner_id.map(|i| i.0),
            state: r.state.into(),
            terminal_reason: r.terminal_reason,
            harness: r.harness.into(),
            harness_version: r.harness_version,
            usage: Usage {
                input_tokens: r.usage.input_tokens,
                output_tokens: r.usage.output_tokens,
                cache_tokens: r.usage.cache_tokens,
                cost_usd_micros: r.usage.cost_usd_micros,
            },
            queued_at: ts(&r.queued_at),
            claimed_at: opt_ts(r.claimed_at.as_deref()),
            started_at: opt_ts(r.started_at.as_deref()),
            ended_at: opt_ts(r.ended_at.as_deref()),
            account_id: r.account_id.map(|a| a.0),
            model_used: r.model_used,
            fallback_reason: r.fallback_reason,
            tier: r.tier.map(Into::into),
            context_tokens: r.context_tokens,
            woken_at: opt_ts(r.woken_at.as_deref()),
            harness_started_at: opt_ts(r.harness_started_at.as_deref()),
            first_token_at: opt_ts(r.first_token_at.as_deref()),
            last_progress_at: opt_ts(r.last_progress_at.as_deref()),
            diff_files: r.diff_files,
            // A malformed column (never written so) reads as no measure.
            diff_repos: r
                .diff_repos
                .as_deref()
                .and_then(|j| serde_json::from_str(j).ok())
                .unwrap_or_default(),
            transcript_gone_reason: r.transcript_pruned_at.as_ref().map(|_| "pruned".to_owned()),
            transcript_pruned_at: opt_ts(r.transcript_pruned_at.as_deref()),
        }
    }
}

/// One chunk of a run's transcript, as the runner sent it (redacted).
#[derive(Debug, Serialize, ToSchema)]
pub struct TranscriptChunk {
    /// Increasing within the run: the transcript's own cursor.
    pub seq: i64,
    pub at: Timestamp,
    /// The payload's `type`: `session_started`, `assistant_text`, `tool_use`, `tool_result`,
    /// `approval_requested`, `usage`, `turn_ended`, … — open: new kinds may appear. A
    /// `tool_result` (runner protocol 1.18) ends the `tool_use` with its `id`: `name`, `status`
    /// (`ok` or `error`), `exit_code` (when known), `output` (redacted, cut to its head and tail
    /// at `run.tool_output_bytes`), `output_bytes` (the full size) and `duration_ms`.
    pub kind: String,
    #[schema(value_type = Object)]
    pub payload: Value,
}

impl From<store::exec::TranscriptChunk> for TranscriptChunk {
    fn from(c: store::exec::TranscriptChunk) -> Self {
        Self {
            seq: c.seq,
            at: ts(&c.at),
            kind: c.kind,
            payload: c.payload,
        }
    }
}

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

#[derive(Debug, Serialize, ToSchema)]
pub struct Approval {
    pub id: i64,
    pub company_id: i64,
    pub kind: ApprovalKind,
    pub issue_id: Option<i64>,
    pub sprint_id: Option<i64>,
    pub agent_id: Option<i64>,
    pub requested_by: i64,
    pub status: ApprovalStatus,
    pub decided_by: Option<i64>,
    pub reply: Option<String>,
    /// What is asked, by kind (the sprint's issues, the command, the overrun, …).
    #[schema(value_type = Object)]
    pub payload: Value,
    pub expires_at: Option<Timestamp>,
    /// When it was asked (API minor 17).
    #[schema(required = false)]
    pub created_at: Timestamp,
    /// When it was approved, rejected or expired; absent while pending.
    pub decided_at: Option<Timestamp>,
}

impl From<gov::Approval> for Approval {
    fn from(a: gov::Approval) -> Self {
        Self {
            id: a.id.0,
            company_id: a.company_id.0,
            kind: a.kind.into(),
            issue_id: a.issue_id.map(|i| i.0),
            sprint_id: a.sprint_id.map(|s| s.0),
            agent_id: a.agent_id.map(|g| g.0),
            requested_by: a.requested_by.0,
            status: a.status.into(),
            decided_by: a.decided_by.map(|u| u.0),
            reply: a.reply,
            payload: serde_json::from_str(&a.payload).unwrap_or(Value::String(a.payload)),
            expires_at: opt_ts(a.expires_at.as_deref()),
            created_at: ts(&a.created_at),
            decided_at: opt_ts(a.decided_at.as_deref()),
        }
    }
}

pub use super::stuck::StuckIssue;
