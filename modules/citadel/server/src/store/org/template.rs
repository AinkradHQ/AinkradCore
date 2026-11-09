//! The Engineering template (E6.5, decisions #17, #22): the one shipped department. Applying
//! it gives a company an Engineering department, a CTO, and one scrum team (product owner,
//! team lead, two developers, QA, DevOps) with default harnesses, models and capacities, and a
//! short role skill for each (published with `publish_skill`, attached to the role).
//!
//! Every agent it adds is hired like any other (E6.4): pending until a human approves its
//! `hire_agent` approval. It is idempotent: a department, team, agent (by name) or seat already
//! there is kept, and a skill is published again only when its text changed. The whole apply is
//! one `BEGIN IMMEDIATE` transaction, each step audited: it lands complete or not at all.

use citadel_core::audit::AuditActor;
use citadel_core::gov::{ApprovalId, SkillAttach};
use citadel_core::org::{AgentStatus, Harness, OrgRole, TeamRole};

use super::*;
use crate::store::gov::{list_skills, publish_skill_in};

/// The department and team names the template uses.
pub const ENGINEERING: &str = "Engineering";
pub const ENGINEERING_TEAM: &str = "Core";

/// One agent of the template: its name (unique within the company, how a re-apply finds it),
/// job title, seat on the team (none for the CTO), harness, model and per-sprint capacity.
struct Seat {
    name: &'static str,
    role: &'static str,
    org_role: OrgRole,
    team_role: Option<TeamRole>,
    harness: Harness,
    model: &'static str,
    capacity: Option<u32>,
}

const fn seat(
    name: &'static str,
    role: &'static str,
    team_role: TeamRole,
    model: &'static str,
    capacity: Option<u32>,
) -> Seat {
    Seat {
        name,
        role,
        org_role: OrgRole::None,
        team_role: Some(team_role),
        harness: Harness::Claude,
        model,
        capacity,
    }
}

const SEATS: [Seat; 7] = [
    Seat {
        name: "CTO",
        role: "CTO",
        org_role: OrgRole::Cto,
        team_role: None,
        harness: Harness::Claude,
        model: "opus",
        capacity: None,
    },
    seat(
        "Product Owner",
        "Product Owner",
        TeamRole::ProductOwner,
        "sonnet",
        None,
    ),
    seat(
        "Team Lead",
        "Team Lead",
        TeamRole::TeamLead,
        "opus",
        Some(5),
    ),
    seat(
        "Developer 1",
        "Developer",
        TeamRole::Member,
        "sonnet",
        Some(8),
    ),
    seat(
        "Developer 2",
        "Developer",
        TeamRole::Member,
        "sonnet",
        Some(8),
    ),
    seat("QA", "QA", TeamRole::Member, "sonnet", Some(5)),
    seat("DevOps", "DevOps", TeamRole::Member, "sonnet", Some(5)),
];

/// (skill name, role it is attached to, body).
const SKILLS: [(&str, &str, &str); 6] = [
    (
        "cto",
        "CTO",
        include_str!("../../../templates/engineering/cto.md"),
    ),
    (
        "product-owner",
        "Product Owner",
        include_str!("../../../templates/engineering/product-owner.md"),
    ),
    (
        "team-lead",
        "Team Lead",
        include_str!("../../../templates/engineering/team-lead.md"),
    ),
    (
        "developer",
        "Developer",
        include_str!("../../../templates/engineering/developer.md"),
    ),
    (
        "qa",
        "QA",
        include_str!("../../../templates/engineering/qa.md"),
    ),
    (
        "devops",
        "DevOps",
        include_str!("../../../templates/engineering/devops.md"),
    ),
];

/// What applying the template left in place.
#[derive(Debug, Clone)]
pub struct Applied {
    pub department: Department,
    pub team: Team,
    /// The CTO first, then the team in seat order.
    pub agents: Vec<Agent>,
    /// The hire approvals this apply opened (none on a re-apply).
    pub hires: Vec<ApprovalId>,
    /// How many skills this apply published (none on a re-apply with the same text).
    pub skills_published: usize,
}

/// Applies the Engineering template to the company as `actor` at `now`; see the module docs.
pub async fn apply_engineering(
    pool: &SqlitePool,
    company: CompanyId,
    actor: AuditActor,
    now: &str,
) -> Result<Applied, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    get_company(&mut *tx, company)
        .await?
        .ok_or(OrgError::NotFound)?;
    let department = match list_departments(&mut *tx, company)
        .await?
        .into_iter()
        .find(|d| d.name == ENGINEERING)
    {
        Some(d) => d,
        None => add_department_in(&mut tx, company, ENGINEERING, actor).await?,
    };
    let team = match list_teams(&mut *tx, department.id)
        .await?
        .into_iter()
        .find(|t| t.name == ENGINEERING_TEAM)
    {
        Some(t) => t,
        None => add_team_in(&mut tx, department.id, ENGINEERING_TEAM, actor).await?,
    };
    let existing = list_agents(&mut *tx, company).await?;
    let seated = list_memberships(&mut *tx, team.id).await?;
    let (mut agents, mut hires) = (vec![], vec![]);
    for s in &SEATS {
        let found = existing.iter().find(|a| {
            a.name == s.name || (s.org_role == OrgRole::Cto && a.org_role == OrgRole::Cto)
        });
        let agent = match found {
            Some(a) => a.clone(),
            None => {
                let new = NewAgent {
                    company_id: company,
                    name: s.name.to_owned(),
                    role: s.role.to_owned(),
                    org_role: s.org_role,
                    reports_to: None,
                    harness: s.harness,
                    model: s.model.to_owned(),
                    runner_tags: vec![],
                    status: AgentStatus::PendingApproval,
                };
                let why = format!("Engineering template: {}", s.role);
                let (a, hire) = hire_agent_in(&mut tx, &new, None, &why, actor, now).await?;
                hires.push(hire.id);
                a
            }
        };
        if let Some(role) = s.team_role
            && !seated.iter().any(|m| m.agent_id == agent.id)
        {
            seat_member_in(&mut tx, team.id, agent.id, role, s.capacity, actor).await?;
        }
        agents.push(agent);
    }
    let published = list_skills(&mut *tx, company).await?;
    let mut skills_published = 0;
    for (name, role, body) in SKILLS {
        let latest = published.iter().rev().find(|k| k.name == name);
        if latest.is_none_or(|k| k.body != body) {
            let attach = SkillAttach::Role(role.to_owned());
            publish_skill_in(&mut tx, company, name, body, &attach, actor).await?;
            skills_published += 1;
        }
    }
    tx.commit().await?;
    Ok(Applied {
        department,
        team,
        agents,
        hires,
        skills_published,
    })
}
