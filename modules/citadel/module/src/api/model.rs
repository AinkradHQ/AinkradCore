//! The contract's resources (ported from the monolith's `api/v1/model.rs`): what the store
//! returns, as the client sees it. Each is built from its domain type; nothing here reads the
//! database. The org resources are here; the work and governance resources come with their
//! slices, in `model/` next to this file.

use crate::domain::org;
use serde::Serialize;
use utoipa::ToSchema;

use super::types::*;

pub mod governance;
pub mod org_admin;
pub mod planning;
pub mod work;

#[derive(Debug, Serialize, ToSchema)]
pub struct Company {
    pub id: i64,
    pub name: String,
    pub kind: CompanyKind,
    /// The pool accounts its runs may use (E15.1); empty until the accounts slice.
    #[schema(required = false)]
    pub account_ids: Vec<i64>,
    /// Its colour, `#rrggbb`; absent when unset, as every optional field here.
    pub color: Option<String>,
    /// What it does, for its agents (empty when unset).
    #[schema(required = false)]
    pub description: String,
    #[schema(required = false)]
    pub industries: Vec<String>,
    pub website: Option<String>,
    /// An IANA time zone, e.g. `Europe/Berlin`.
    pub timezone: Option<String>,
    /// Working hours: minutes from midnight, 0-1440.
    pub work_start: Option<u16>,
    pub work_end: Option<u16>,
    /// Working days as a bitmask: bit 0 Monday ... bit 6 Sunday (31 = Monday to Friday).
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
                .map(|_| format!("/modules/citadel/v1/companies/{}/logo", c.id.0)),
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

/// How the client draws an agent's figure (decision #61).
#[derive(Debug, Serialize, ToSchema)]
pub struct Appearance {
    pub figure_version: String,
    pub palette_id: String,
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
    /// What the admin wrote about it.
    #[schema(required = false)]
    pub description: String,
    /// Absent: the harness default.
    pub effort: Option<Effort>,
    /// Absent: the harness default.
    pub sandbox: Option<Sandbox>,
    /// Its standing instructions.
    #[schema(required = false)]
    pub instructions: String,
    /// Short rules, in order.
    #[schema(required = false)]
    pub guidelines: Vec<String>,
    /// How the client draws its figure.
    pub appearance: Appearance,
    /// Its uploaded image, shown instead of the figure; absent when it has none.
    pub avatar_url: Option<String>,
    /// When the admin paused it; absent unless it is paused by the admin.
    pub paused_at: Option<Timestamp>,
    /// When it was hired.
    pub hired_at: Timestamp,
    /// What its figure shows now. Until the run engine is ported it follows the agent's status
    /// and its open questions and approvals only (never `working`, `thinking`, `loading`,
    /// `confused` or `success`).
    pub figure_state: Option<org_admin::FigureState>,
    /// The chain preset it uses in place of its own fallbacks (API minor 18); absent when it
    /// has none. (`run_token_cap`, `issue_token_cap` and `queued_wakes` come with the run
    /// engine.)
    pub chain_preset_id: Option<i64>,
}

impl From<org::Agent> for Agent {
    fn from(a: org::Agent) -> Self {
        Self {
            hired_at: ts(&a.created_at),
            figure_state: Some(org_admin::FigureState::of(
                a.status,
                &crate::store::org::avatars::Activity::default(),
            )),
            chain_preset_id: None,
            paused_at: match a.status {
                org::AgentStatus::Paused => opt_ts(a.paused_at.as_deref()),
                _ => None,
            },
            avatar_url: a
                .avatar_sha256
                .as_ref()
                .map(|_| format!("/modules/citadel/v1/agents/{}/avatar", a.id.0)),
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

#[derive(Debug, Serialize, ToSchema)]
pub struct Department {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    /// What it does.
    #[schema(required = false)]
    pub about: String,
    /// The agent that heads it; absent when it has none.
    pub head_agent_id: Option<i64>,
}

impl From<org::Department> for Department {
    fn from(d: org::Department) -> Self {
        Self {
            id: d.id.0,
            company_id: d.company_id.0,
            name: d.name,
            about: d.about,
            head_agent_id: d.head_agent_id.map(|a| a.0),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Team {
    pub id: i64,
    pub department_id: i64,
    pub name: String,
}

impl From<org::Team> for Team {
    fn from(t: org::Team) -> Self {
        Self {
            id: t.id.0,
            department_id: t.department_id.0,
            name: t.name,
        }
    }
}

/// The answer to a delete: the id that is gone.
#[derive(Debug, Serialize, ToSchema)]
pub struct Deleted {
    pub deleted: i64,
}
