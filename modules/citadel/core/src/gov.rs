//! Governance model: approvals, budgets, skills, project knowledge and device keys
//! (brainstorm §7–§8). Records only; the gates and enforcement come in E7, E8 and E10.
//!
//! Timestamps are ISO-8601 text, as stored. Device keys are never held here: the store
//! keeps only their SHA-256.

use std::str::FromStr;

use crate::org::{AgentId, CompanyId, DepartmentId, UnknownVariant, id, text_enum};
use crate::work::{IssueId, ProjectId, SprintId, UserId};

mod accounts;
mod knowledge;
pub use accounts::*;
pub use knowledge::*;

id!(
    ApprovalId,
    BudgetId,
    SkillId,
    KnowledgeEntryId,
    DeviceKeyId,
    PriceId,
    ArtifactId
);

// What an agent published (E15.12).
text_enum!(ArtifactKind {
    Report => "report",
    File => "file",
    Screenshot => "screenshot",
    Other => "other",
});

text_enum!(ApprovalKind {
    SprintCommit => "sprint_commit",
    PrMerge => "pr_merge",
    BudgetOverrun => "budget_overrun",
    HireAgent => "hire_agent",
    PermissionEscalation => "permission_escalation",
    PlanApproval => "plan_approval",
    // A branch push the forge token was refused for changing workflow files (#103): a human
    // pushes it with credentials that may; approving says so and lets its PR open.
    WorkflowPush => "workflow_push",
});

// `expired`: nobody decided it in time, or what it asked about is gone (its run ended).
text_enum!(ApprovalStatus {
    Pending => "pending",
    Approved => "approved",
    Rejected => "rejected",
    Expired => "expired",
});

// How a harness's use is paid for (E7.3): per token, or by a subscription with no per-token
// price (its runs are counted in tokens, never in made-up dollars).
text_enum!(Billing {
    Metered => "metered",
    Subscription => "subscription",
});

text_enum!(BudgetPeriod {
    Day => "day",
    Week => "week",
    Month => "month",
    Total => "total",
});

text_enum!(KnowledgeKind {
    Decision => "decision",
    Landmine => "landmine",
    State => "state",
    Retro => "retro",
});

// `retired`: accepted once, then retired by the admin; kept for history, never given to a run.
text_enum!(KnowledgeStatus {
    Proposed => "proposed",
    Accepted => "accepted",
    Rejected => "rejected",
    Retired => "retired",
});

/// An approval before it is stored; it starts `pending`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    pub company_id: CompanyId,
    pub kind: ApprovalKind,
    /// What it is about; each must belong to the company.
    pub issue_id: Option<IssueId>,
    pub sprint_id: Option<SprintId>,
    pub agent_id: Option<AgentId>,
    pub requested_by: AgentId,
    /// Kind-specific detail, a JSON document.
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: ApprovalId,
    pub company_id: CompanyId,
    pub kind: ApprovalKind,
    pub issue_id: Option<IssueId>,
    pub sprint_id: Option<SprintId>,
    pub agent_id: Option<AgentId>,
    pub requested_by: AgentId,
    pub status: ApprovalStatus,
    /// Set exactly when a human approved or rejected it.
    pub decided_by: Option<UserId>,
    /// The decider's reply, or why it expired.
    pub reply: Option<String>,
    pub payload: String,
    /// When it expires if still pending; `None` when it waits for as long as it takes.
    pub expires_at: Option<String>,
    /// When it was asked.
    pub created_at: String,
    /// When it left `pending` (approved, rejected or expired).
    pub decided_at: Option<String>,
}

/// What a budget caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetScope {
    Company(CompanyId),
    Department(DepartmentId),
    Project(ProjectId),
    Agent(AgentId),
    Sprint(SprintId),
    Issue(IssueId),
}

/// A budget before it is stored; one per (scope, period).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBudget {
    pub scope: BudgetScope,
    pub period: BudgetPeriod,
    pub token_cap: i64,
    /// Dollars (millionths) beside the tokens; with `token_cap` 0, dollars only.
    pub usd_cap_micros: Option<i64>,
    /// 1–100.
    pub warn_at_percent: u8,
    pub hard_stop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub id: BudgetId,
    pub scope: BudgetScope,
    pub period: BudgetPeriod,
    pub token_cap: i64,
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: u8,
    pub hard_stop: bool,
}

/// Where a skill is attached, within its company.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SkillAttach {
    Company,
    Department(DepartmentId),
    /// An agent role (free-text job title).
    Role(String),
    Project(ProjectId),
}

/// A skill before it is stored; (company, name, version) is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSkill {
    pub company_id: CompanyId,
    pub name: String,
    /// From 1.
    pub version: i64,
    /// Markdown.
    pub body: String,
    pub attach: SkillAttach,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub id: SkillId,
    pub company_id: CompanyId,
    pub name: String,
    pub version: i64,
    pub body: String,
    pub attach: SkillAttach,
}

/// The most a run is given of skill bodies, in bytes (E4.3): the default of the
/// `skills.budget_bytes` setting (E15.17).
pub const SKILL_BUDGET_BYTES: usize = 64 * 1024;

impl SkillAttach {
    /// Higher is more specific, and is kept first when a run's skills overflow the budget:
    /// project, then role, then department, then the whole company.
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Project(_) => 3,
            Self::Role(_) => 2,
            Self::Department(_) => 1,
            Self::Company => 0,
        }
    }
}

/// The skills a run is given, and those its budget left out: never dropped silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSkills {
    /// By precedence (highest first), then name.
    pub skills: Vec<Skill>,
    /// What did not fit, in the same order.
    pub dropped: Vec<Skill>,
}

impl RunSkills {
    /// The kept skills as one markdown document, for a harness's instructions file; `None`
    /// when there are none. Each is a section headed by its name and version; what the budget
    /// dropped is named at the end, so the agent knows it is missing.
    pub fn render(&self) -> Option<String> {
        if self.skills.is_empty() {
            return None;
        }
        let mut out = String::new();
        for s in &self.skills {
            out.push_str(&format!(
                "# Skill: {} (v{})\n\n{}\n\n",
                s.name,
                s.version,
                s.body.trim()
            ));
        }
        if !self.dropped.is_empty() {
            let names: Vec<String> = self.dropped.iter().map(|s| s.name.clone()).collect();
            out.push_str(&format!("Left out for size: {}.\n", names.join(", ")));
        }
        Some(out)
    }
}

/// Orders `skills` by precedence, then name, and keeps the longest prefix whose bodies fit
/// in `budget` bytes; the rest, the lowest precedence, are dropped and listed.
pub fn fit_skills(mut skills: Vec<Skill>, budget: usize) -> RunSkills {
    skills.sort_by(|a, b| {
        let by_precedence = b.attach.precedence().cmp(&a.attach.precedence());
        by_precedence.then_with(|| a.name.cmp(&b.name))
    });
    let mut used = 0;
    let fits = skills
        .iter()
        .take_while(|s| {
            used += s.body.len();
            used <= budget
        })
        .count();
    let dropped = skills.split_off(fits);
    RunSkills { skills, dropped }
}

/// A knowledge entry before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKnowledgeEntry {
    pub project_id: ProjectId,
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
    pub status: KnowledgeStatus,
    /// `None` when a human wrote it.
    pub proposed_by: Option<AgentId>,
    /// Set exactly when `status` is not `Proposed`.
    pub decided_by: Option<UserId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeEntry {
    pub id: KnowledgeEntryId,
    pub project_id: ProjectId,
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
    pub status: KnowledgeStatus,
    pub proposed_by: Option<AgentId>,
    /// The human who decided it, if a human did.
    pub decided_by: Option<UserId>,
    /// The project's team lead who decided it, if an agent did (E8.2).
    pub decided_by_agent: Option<AgentId>,
    /// Why it was accepted or rejected.
    pub reason: Option<String>,
    /// A `state` proposal of a new project spec (its body), applied when accepted (E8.2).
    pub targets_spec: bool,
    /// The project profile field a proposal changes (E15.13), its body the new value; applied
    /// only when a human accepts it.
    pub profile_field: Option<String>,
    /// The proposer's one-line reason for it, when it gave one.
    pub rationale: Option<String>,
    /// Why the admin retired it (`Retired`).
    pub retired_reason: Option<String>,
    /// The entry this one replaced (retired as this one was added).
    pub supersedes: Option<KnowledgeEntryId>,
}

/// A per-device API key (#18), without the key itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    pub id: DeviceKeyId,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_text() {
        for k in [
            ApprovalKind::SprintCommit,
            ApprovalKind::PrMerge,
            ApprovalKind::BudgetOverrun,
            ApprovalKind::HireAgent,
            ApprovalKind::PermissionEscalation,
        ] {
            assert_eq!(k.as_str().parse::<ApprovalKind>(), Ok(k));
        }
        assert_eq!("total".parse::<BudgetPeriod>(), Ok(BudgetPeriod::Total));
        assert_eq!(
            "landmine".parse::<KnowledgeKind>(),
            Ok(KnowledgeKind::Landmine)
        );
        assert_eq!(
            "accepted".parse::<KnowledgeStatus>(),
            Ok(KnowledgeStatus::Accepted)
        );
        assert!("merged".parse::<ApprovalStatus>().is_err());
    }

    fn skill(name: &str, attach: SkillAttach, bytes: usize) -> Skill {
        Skill {
            id: SkillId(0),
            company_id: CompanyId(1),
            name: name.to_owned(),
            version: 1,
            body: "x".repeat(bytes),
            attach,
        }
    }

    #[test]
    fn skills_keep_precedence_order_and_drop_the_lowest_on_overflow() {
        let all = vec![
            skill("b-company", SkillAttach::Company, 10),
            skill("a-company", SkillAttach::Company, 10),
            skill("role", SkillAttach::Role("QA".to_owned()), 10),
            skill("project", SkillAttach::Project(ProjectId(1)), 10),
            skill("dept", SkillAttach::Department(DepartmentId(1)), 10),
        ];
        let names = |v: &[Skill]| v.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
        let fitted = fit_skills(all.clone(), 50);
        assert_eq!(
            names(&fitted.skills),
            ["project", "role", "dept", "a-company", "b-company"]
        );
        assert!(fitted.dropped.is_empty());
        let tight = fit_skills(all, 35);
        assert_eq!(names(&tight.skills), ["project", "role", "dept"]);
        assert_eq!(names(&tight.dropped), ["a-company", "b-company"]);

        let shown = tight.render().unwrap();
        assert!(shown.starts_with("# Skill: project (v1)\n\nxxxxxxxxxx\n\n# Skill: role"));
        assert!(
            shown.ends_with("Left out for size: a-company, b-company.\n"),
            "{shown}"
        );
        assert_eq!(fit_skills(vec![], 10).render(), None);
    }
}
