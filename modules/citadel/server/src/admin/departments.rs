//! Org commands (E6): departments, teams and team seats, intake requests, cross-department
//! flags and the Engineering template, as the admin,
//! through the audited org and intake services. `add` prints the new id on stdout; `list` prints
//! one tab-separated row per item; `intake route` prints each routed project's id.

use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::org::{AgentId, CompanyId, DepartmentId, TeamId, TeamRole};
use citadel_core::work::{Actor, IssueId, ProjectId, ProjectMode};
use citadel_server::scheduler::{Clock, SystemClock};
use citadel_server::store::{self, org, work};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str = "  citadel-server department add <db> <company-id> <name>
  citadel-server department list <db> <company-id>
  citadel-server team add <db> <department-id> <name>
  citadel-server team list <db> <department-id>
  citadel-server member add <db> <team-id> <agent-id>
                 --role <product_owner|team_lead|member> [--capacity <points>]
  citadel-server member remove <db> <team-id> <agent-id>
  citadel-server intake add <db> <company-id> <title> [--body <text>]
  citadel-server intake route <db> <issue-id> <project:<project-id> | <department-id>:<KEY>:<name>> […]
  citadel-server issue cross-department <db> <issue-id> <on|off>
  citadel-server template apply <db> engineering <company-id>
An intake request waits on the company's active CEO, who routes it (MCP route_intake); with
no CEO it waits on the admin, who routes it with intake route (to an existing project, or a
new scrum project per department owned by its first team; either kicked off by the owning
team's product owner). Escalation
climbs an issue's team (lead, product owner, then the admin); a cross-department issue reaches
the CEO (or CTO) before the admin. template apply engineering adds the Engineering department,
a CTO and a team (product owner, team lead, two developers, QA, DevOps) with role skills; each
agent waits on its hire approval. Applying it again adds only what is missing.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs an org command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["department", "add", db, company, name] => {
            let company = CompanyId(id(company).ok()?);
            department(Path::new(db), company, name).await
        }
        ["department", "list", db, company] => {
            departments(Path::new(db), CompanyId(id(company).ok()?)).await
        }
        ["team", "add", db, department, name] => {
            let department = DepartmentId(id(department).ok()?);
            team(Path::new(db), department, name).await
        }
        ["team", "list", db, department] => {
            teams(Path::new(db), DepartmentId(id(department).ok()?)).await
        }
        ["member", "add", db, team, agent, rest @ ..] => {
            let f = flags(rest, &["--role", "--capacity"])?;
            let role: TeamRole = f.get("--role")?.parse().ok()?;
            let capacity = match f.get("--capacity") {
                Some(c) => Some(c.parse().ok()?),
                None => None,
            };
            let (team, agent) = (TeamId(id(team).ok()?), AgentId(id(agent).ok()?));
            seat(Path::new(db), team, agent, role, capacity).await
        }
        ["member", "remove", db, team, agent] => {
            let (team, agent) = (TeamId(id(team).ok()?), AgentId(id(agent).ok()?));
            unseat(Path::new(db), team, agent).await
        }
        ["intake", "add", db, company, title, rest @ ..] => {
            let f = flags(rest, &["--body"])?;
            let company = CompanyId(id(company).ok()?);
            intake(
                Path::new(db),
                company,
                title,
                f.get("--body").unwrap_or(&""),
            )
            .await
        }
        ["intake", "route", db, issue, routes @ ..] if !routes.is_empty() => {
            let mut parsed = vec![];
            for r in routes {
                if let Some(p) = r.strip_prefix("project:") {
                    parsed.push(work::Route::Existing(ProjectId(id(p).ok()?)));
                    continue;
                }
                let mut parts = r.splitn(3, ':');
                let (Some(d), Some(key), Some(name)) = (parts.next(), parts.next(), parts.next())
                else {
                    return None;
                };
                parsed.push(work::Route::New {
                    department: DepartmentId(id(d).ok()?),
                    team: None,
                    name: name.to_owned(),
                    key: key.to_owned(),
                    mode: ProjectMode::Scrum,
                });
            }
            route(Path::new(db), IssueId(id(issue).ok()?), &parsed).await
        }
        [
            "issue",
            "cross-department",
            db,
            issue,
            flag @ ("on" | "off"),
        ] => cross(Path::new(db), IssueId(id(issue).ok()?), *flag == "on").await,
        ["template", "apply", db, "engineering", company] => {
            engineering(Path::new(db), CompanyId(id(company).ok()?)).await
        }
        _ => return None,
    })
}

/// Prints the team's id; each agent, and the hires to approve, on stderr.
async fn engineering(db: &Path, company: CompanyId) -> Result_ {
    let pool = store::connect(db).await?;
    let a = org::apply_engineering(&pool, company, BY, &SystemClock.now()).await?;
    for agent in &a.agents {
        let (name, status) = (&agent.name, agent.status.as_str());
        eprintln!("agent {name} (id {}): {status}", agent.id.0);
    }
    let hires: Vec<String> = a.hires.iter().map(|h| h.0.to_string()).collect();
    eprintln!(
        "team {} (id {}) in {}; {} skill(s) published; approve the hires: {}",
        a.team.name,
        a.team.id.0,
        a.department.name,
        a.skills_published,
        hires.join(" ")
    );
    println!("{}", a.team.id.0);
    Ok(())
}

async fn cross(db: &Path, issue: IssueId, on: bool) -> Result_ {
    let pool = store::connect(db).await?;
    if !org::set_cross_department(&pool, issue, on, BY).await? {
        return Err(format!("no issue {}", issue.0).into());
    }
    eprintln!("issue {} cross-department: {on}", issue.0);
    println!("{}", issue.0);
    Ok(())
}

async fn intake(db: &Path, company: CompanyId, title: &str, body: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::submit_intake(&pool, company, title, body, BY).await?;
    eprintln!("intake request {} waits on {:?}", i.id.0, i.next_actor);
    println!("{}", i.id.0);
    Ok(())
}

async fn route(db: &Path, issue: IssueId, routes: &[work::Route]) -> Result_ {
    let pool = store::connect(db).await?;
    for r in work::route_intake(&pool, issue, Actor::Human(ADMIN), routes).await? {
        let (p, po) = (&r.project, r.product_owner.0);
        let new = if r.created { "new " } else { "" };
        eprintln!(
            "{new}project {} (id {}) kicked off by agent {po}",
            p.key, p.id.0
        );
        println!("{}", p.id.0);
    }
    Ok(())
}

async fn department(db: &Path, company: CompanyId, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let d = org::add_department(&pool, company, name, BY).await?;
    eprintln!("department {} (id {})", d.name, d.id.0);
    println!("{}", d.id.0);
    Ok(())
}

async fn departments(db: &Path, company: CompanyId) -> Result_ {
    let pool = store::connect(db).await?;
    for d in org::list_departments(&pool, company).await? {
        println!("{}\t{}", d.id.0, d.name);
    }
    Ok(())
}

async fn team(db: &Path, department: DepartmentId, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let t = org::add_team(&pool, department, name, BY).await?;
    eprintln!("team {} (id {})", t.name, t.id.0);
    println!("{}", t.id.0);
    Ok(())
}

/// One row per team: its id and name, then each seat as `agent:role`.
async fn teams(db: &Path, department: DepartmentId) -> Result_ {
    let pool = store::connect(db).await?;
    for t in org::list_teams(&pool, department).await? {
        let seats: Vec<String> = org::list_memberships(&pool, t.id)
            .await?
            .iter()
            .map(|m| format!("{}:{}", m.agent_id.0, m.team_role.as_str()))
            .collect();
        println!("{}\t{}\t{}", t.id.0, t.name, seats.join(","));
    }
    Ok(())
}

async fn seat(
    db: &Path,
    team: TeamId,
    agent: AgentId,
    role: TeamRole,
    capacity: Option<u32>,
) -> Result_ {
    let pool = store::connect(db).await?;
    org::seat_member(&pool, team, agent, role, capacity, BY).await?;
    eprintln!("agent {} on team {} as {}", agent.0, team.0, role.as_str());
    println!("{}", agent.0);
    Ok(())
}

async fn unseat(db: &Path, team: TeamId, agent: AgentId) -> Result_ {
    let pool = store::connect(db).await?;
    if !org::unseat_member(&pool, team, agent, BY).await? {
        return Err(format!("agent {} has no seat on team {}", agent.0, team.0).into());
    }
    eprintln!("agent {} off team {}", agent.0, team.0);
    println!("{}", agent.0);
    Ok(())
}
