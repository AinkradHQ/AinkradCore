//! Response models of the governance seam (ToSchema; names unique across the Core contract):
//! approvals, budgets, prices, skills, knowledge and artifacts. Request bodies live next to
//! their handlers in `api/governance/`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::api::types::{
    ApprovalKind, ApprovalStatus, ArtifactKind, BudgetPeriod, Harness, KnowledgeKind,
    KnowledgeStatus, Timestamp, opt_ts, ts,
};
use crate::domain::gov::{self, BudgetScope as CoreScope, SkillAttach};
use crate::store::artifacts::{self, Preview, preview_of};
use crate::store::gov as store;

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
    /// What is asked, by kind (the sprint's issues, the command, the overrun, ...).
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

/// What a budget caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetScope {
    Company {
        company_id: i64,
    },
    Department {
        department_id: i64,
    },
    Project {
        project_id: i64,
    },
    Agent {
        agent_id: i64,
    },
    Sprint {
        sprint_id: i64,
    },
    /// API minor 18.
    Issue {
        issue_id: i64,
    },
}

/// A budget and its spend in the current period.
#[derive(Debug, Serialize, ToSchema)]
pub struct BudgetStanding {
    pub budget_id: i64,
    pub scope: BudgetScope,
    pub period: BudgetPeriod,
    pub token_cap: i64,
    /// Millionths of a dollar beside the tokens, when set; with `token_cap` 0, dollars only
    /// (API minor 18).
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: u8,
    pub hard_stop: bool,
    /// `2026-10-22`, a week's Monday, `2026-10` or `total`.
    pub period_key: String,
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    /// Priced dollars spent in the period, in millionths (API minor 18).
    #[schema(required = false)]
    pub usd_spent_micros: i64,
    /// Dollars added for the period by approved overruns, in millionths (API minor 18).
    #[schema(required = false)]
    pub raised_usd_micros: i64,
}

impl From<store::Standing> for BudgetStanding {
    fn from(s: store::Standing) -> Self {
        let b = s.budget;
        Self {
            budget_id: b.id.0,
            scope: match b.scope {
                CoreScope::Company(c) => BudgetScope::Company { company_id: c.0 },
                CoreScope::Department(d) => BudgetScope::Department { department_id: d.0 },
                CoreScope::Project(p) => BudgetScope::Project { project_id: p.0 },
                CoreScope::Agent(a) => BudgetScope::Agent { agent_id: a.0 },
                CoreScope::Sprint(s) => BudgetScope::Sprint { sprint_id: s.0 },
                CoreScope::Issue(i) => BudgetScope::Issue { issue_id: i.0 },
            },
            period: b.period.into(),
            token_cap: b.token_cap,
            usd_cap_micros: b.usd_cap_micros,
            warn_at_percent: b.warn_at_percent,
            hard_stop: b.hard_stop,
            period_key: s.period_key,
            spent: s.spent,
            raised: s.raised,
            usd_spent_micros: s.usd_spent,
            raised_usd_micros: s.raised_usd,
        }
    }
}

/// A harness and model's price, US dollars per million tokens; each set is a new version, and
/// earlier spend keeps the version that priced it.
#[derive(Debug, Serialize, ToSchema)]
pub struct Price {
    pub harness: Harness,
    pub model: String,
    pub version: i64,
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
    pub cache_usd_per_mtok: f64,
}

impl From<store::Price> for Price {
    fn from(p: store::Price) -> Self {
        let usd = |micros: i64| micros as f64 / 1e6;
        Self {
            harness: p.harness.into(),
            model: p.model,
            version: p.version,
            input_usd_per_mtok: usd(p.input_micros_per_mtok),
            output_usd_per_mtok: usd(p.output_micros_per_mtok),
            cache_usd_per_mtok: usd(p.cache_micros_per_mtok),
        }
    }
}

/// One version of a price, from when it took effect.
#[derive(Debug, Serialize, ToSchema)]
pub struct PriceVersion {
    #[serde(flatten)]
    pub price: Price,
    pub set_at: Timestamp,
}

/// A skill version of a company (`AgentSkill` in the monolith's contract).
#[derive(Debug, Serialize, ToSchema)]
pub struct CompanySkill {
    pub id: i64,
    pub name: String,
    pub version: i64,
    /// `company`, `department`, `role` or `project`.
    pub attached_to: String,
    /// The department or project id, or the role.
    pub attached_id: Option<i64>,
    pub attached_role: Option<String>,
    /// Its body's size; a run gets as many as fit `skills.budget_bytes`, most specific first.
    pub bytes: i64,
}

impl From<gov::Skill> for CompanySkill {
    fn from(s: gov::Skill) -> Self {
        let (attached_to, attached_id, attached_role) = match s.attach {
            SkillAttach::Company => ("company", None, None),
            SkillAttach::Department(d) => ("department", Some(d.0), None),
            SkillAttach::Role(r) => ("role", None, Some(r)),
            SkillAttach::Project(p) => ("project", Some(p.0), None),
        };
        Self {
            id: s.id.0,
            name: s.name,
            version: s.version,
            attached_to: attached_to.to_owned(),
            attached_id,
            attached_role,
            bytes: s.body.len() as i64,
        }
    }
}

/// A project knowledge entry (E8).
#[derive(Debug, Serialize, ToSchema)]
pub struct Knowledge {
    pub id: i64,
    pub project_id: i64,
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
    /// `retired`: kept for history, never given to a run.
    pub status: KnowledgeStatus,
    pub retired_reason: Option<String>,
    /// The entry this one replaced.
    pub supersedes: Option<i64>,
    /// The entry that replaced this one.
    pub superseded_by: Option<i64>,
    /// Why it was accepted or rejected.
    pub reason: Option<String>,
    /// The proposer's one-line reason for it.
    pub rationale: Option<String>,
    /// What accepting a proposal applies its body to: `spec` or `profile.<field>`.
    pub target: Option<String>,
    /// The agent that proposed it; absent for an entry the admin added.
    pub proposed_by_agent_id: Option<i64>,
    pub created_at: Timestamp,
    /// Its last audited change (`created_at` when none).
    pub updated_at: Timestamp,
    /// The body was cut to 16 KiB in a list.
    pub body_truncated: bool,
}

/// What an agent published, and where it came from.
#[derive(Debug, Serialize, ToSchema)]
pub struct Artifact {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub kind: ArtifactKind,
    pub mime: String,
    pub size: i64,
    /// The content's SHA-256, hex.
    pub sha256: String,
    /// Secrets redacted from its content before it was stored (text artifacts only).
    pub redactions: i64,
    /// Stored as it is, never scanned for secrets (not text: images, PDF, zip).
    pub unscanned: bool,
    pub issue_id: Option<i64>,
    pub requirement_id: Option<i64>,
    pub run_id: Option<i64>,
    pub agent_id: Option<i64>,
    /// `text`, `image`, or `none` (download it).
    pub preview: String,
    pub created_at: Timestamp,
}

impl From<artifacts::Artifact> for Artifact {
    fn from(a: artifacts::Artifact) -> Self {
        let preview = match preview_of(&a.mime) {
            Preview::Text => "text",
            Preview::Image => "image",
            Preview::None => "none",
        };
        Self {
            id: a.id.0,
            company_id: a.company_id.0,
            name: a.name,
            kind: a.kind.into(),
            mime: a.mime,
            size: a.size,
            sha256: a.sha256,
            redactions: a.redactions,
            unscanned: a.unscanned,
            issue_id: a.issue_id.map(|i| i.0),
            requirement_id: a.requirement_id.map(|r| r.0),
            run_id: a.run_id.map(|r| r.0),
            agent_id: a.agent_id.map(|g| g.0),
            preview: preview.to_owned(),
            created_at: ts(&a.created_at),
        }
    }
}
