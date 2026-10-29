//! Seeding commands (E4.4, E5.1): just enough to set up a company, an agent, a project, epics
//! and issues, and to order the backlog, from a shell; sprints and WIP limits in `pm`; departments,
//! teams and seats in `departments`. The real API is E10. Each prints the
//! new (or changed) row's id on stdout (and what it did on stderr), so a script can capture it.

use std::collections::HashMap;
use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{AgentId, AgentStatus, CompanyId, NewAgent, OrgRole};
use ainkrad_core::work::{
    IssueId, IssueKind, IssueState, IssueTransition, NewIssue, NewProject, NextActor, Position,
    ProjectId, ProjectMode, ProjectRepo, SprintApproval, UserId,
};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, org, work};
use ainkrad_proto::runner::{PermissionMode, Policy};

use crate::Result_;

mod accounts;
mod avatars;
mod departments;
mod forge;
mod knowledge;
mod linear;
mod money;
mod pm;
mod profile;
mod repos;
mod requirements;
mod routing;
mod settings;
mod timing;
pub use accounts::USAGE as ACCOUNT_USAGE;
pub use avatars::USAGE as AVATAR_USAGE;
pub use departments::USAGE as ORG_USAGE;
pub use forge::USAGE as FORGE_USAGE;
pub use knowledge::USAGE as KNOWLEDGE_USAGE;
pub use linear::USAGE as LINEAR_USAGE;
pub use money::USAGE as MONEY_USAGE;
pub use pm::USAGE as PM_USAGE;
pub use profile::USAGE as PROFILE_USAGE;
pub use repos::USAGE as REPO_USAGE;
pub use requirements::USAGE as REQUIREMENT_USAGE;
pub use routing::USAGE as ROUTING_USAGE;
pub use settings::USAGE as SETTING_USAGE;
pub use timing::USAGE as TIMING_USAGE;

/// The one admin user (#18): who seeds, and who an issue waits on until it is assigned.
const ADMIN: UserId = UserId(1);

pub const USAGE: &str = "  ainkrad-core-server company add <db> <name>
  ainkrad-core-server agent add <db> <company-id> <name> --harness <claude|codex|opencode|agy>
                 [--model <m>] [--role <r>] [--tags <a,b,…>] [--org-role <ceo|cto|none>]
                 [--active]
  ainkrad-core-server project add <db> <company-id> <KEY> <name> [--repo <url-or-path>]
                 [--branch <b>] [--permission <ask|accept_edits>] [--mode <kanban|scrum>]
                 [--approval <owner|product_owner>]
  ainkrad-core-server issue add <db> <project-id> <title> [--body <text>] [--assignee <agent-id>]
  ainkrad-core-server epic add <db> <project-id> <title>
  ainkrad-core-server issue move <db> <issue-id> <top|bottom|before|after> [<issue-id>]
agent add creates the agent pending_approval with a hire_agent approval; approval approve
activates it (E6.4). --active is only for bootstrapping a company's first CEO.";

/// `--name value` pairs, each name among `known`; `None` on anything else.
fn flags<'a>(rest: &[&'a str], known: &[&str]) -> Option<HashMap<&'a str, &'a str>> {
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        match pair {
            [name, value] if known.contains(name) => found.insert(*name, *value),
            _ => return None,
        };
    }
    Some(found)
}

fn id(text: &str) -> Result<i64, String> {
    text.parse().map_err(|_| format!("{text:?} is not an id"))
}

/// Runs a seeding command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["sprint" | "wip" | "approval", ..]
        | ["issue", "estimate", ..]
        | ["issue", "block" | "unblock-link", ..]
        | ["project", "spec", ..] => return pm::run(args).await,
        ["budget" | "price" | "billing" | "cost", ..] => return money::run(args).await,
        ["account", ..] | ["agent", "fallback", ..] => return accounts::run(args).await,
        ["agent", "appearance" | "avatar", ..] => return avatars::run(args).await,
        ["agent", "tier", ..] | ["project", "tier-rule", ..] => return routing::run(args).await,
        ["knowledge" | "skill", ..] => return knowledge::run(args).await,
        ["project", "profile" | "policy", ..] => return profile::run(args).await,
        ["repo", ..] | ["issue", "repos", ..] => return repos::run(args).await,
        ["forge", ..] => return forge::run(args).await,
        ["linear", ..] => return linear::run(args).await,
        ["setting", ..] => return settings::run(args).await,
        ["requirement", ..] => return requirements::run(args).await,
        ["runs", ..] => return timing::run(args).await,
        ["department" | "team" | "member" | "intake" | "template", ..]
        | ["issue", "cross-department", ..] => {
            return departments::run(args).await;
        }
        ["company", "add", db, name] => company(Path::new(db), name).await,
        ["agent", "add", db, company, name, rest @ ..] => {
            let active = rest.contains(&"--active");
            let rest: Vec<&str> = rest.iter().copied().filter(|a| *a != "--active").collect();
            let f = flags(
                &rest,
                &["--harness", "--model", "--role", "--tags", "--org-role"],
            )?;
            agent(Path::new(db), company, name, &f, active).await
        }
        ["project", "add", db, company, key, name, rest @ ..] => {
            let f = flags(
                rest,
                &["--repo", "--branch", "--permission", "--mode", "--approval"],
            )?;
            project(Path::new(db), company, key, name, &f).await
        }
        ["issue", "add", db, project, title, rest @ ..] => {
            let f = flags(rest, &["--body", "--assignee"])?;
            issue(Path::new(db), project, title, &f).await
        }
        ["epic", "add", db, project, title] => epic(Path::new(db), project, title).await,
        ["issue", "move", db, issue, to @ ..] => {
            let to = match to {
                ["top"] => Position::Top,
                ["bottom"] => Position::Bottom,
                ["before", anchor] => Position::Before(IssueId(id(anchor).ok()?)),
                ["after", anchor] => Position::After(IssueId(id(anchor).ok()?)),
                _ => return None,
            };
            move_issue(Path::new(db), issue, to).await
        }
        _ => return None,
    })
}

async fn company(db: &Path, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let c = org::create_company(&pool, name).await?;
    eprintln!("company {} (id {})", c.name, c.id.0);
    println!("{}", c.id.0);
    Ok(())
}

/// A new agent waits on its `hire_agent` approval (E6.4); `active` is only for bootstrapping the
/// company's first CEO.
async fn agent(
    db: &Path,
    company: &str,
    name: &str,
    f: &HashMap<&str, &str>,
    active: bool,
) -> Result_ {
    let harness = f.get("--harness").ok_or("--harness is required")?;
    let new = NewAgent {
        company_id: CompanyId(id(company)?),
        name: name.to_owned(),
        role: f.get("--role").unwrap_or(&"Developer").to_string(),
        org_role: f.get("--org-role").unwrap_or(&"none").parse::<OrgRole>()?,
        reports_to: None,
        harness: harness.parse().map_err(|e| format!("--harness: {e}"))?,
        model: f.get("--model").unwrap_or(&"").to_string(),
        runner_tags: f.get("--tags").map_or_else(Vec::new, |t| crate::tags(t)),
        status: AgentStatus::PendingApproval,
    };
    let pool = store::connect(db).await?;
    let by = AuditActor::User(ADMIN);
    let a = if active {
        let a = org::bootstrap_ceo(&pool, &new, by).await?;
        eprintln!(
            "agent {} (id {}) on {}, active",
            a.name,
            a.id.0,
            a.harness.as_str()
        );
        a
    } else {
        let why = "added by the admin";
        let (a, hire) = org::hire_agent(&pool, &new, None, why, by, &SystemClock.now()).await?;
        eprintln!(
            "agent {} (id {}) on {}, pending: approval approve <db> {}",
            a.name,
            a.id.0,
            a.harness.as_str(),
            hire.id.0
        );
        a
    };
    println!("{}", a.id.0);
    Ok(())
}

async fn project(
    db: &Path,
    company: &str,
    key: &str,
    name: &str,
    f: &HashMap<&str, &str>,
) -> Result_ {
    let mode: PermissionMode = f.get("--permission").unwrap_or(&"ask").parse()?;
    if mode == PermissionMode::Sandboxed {
        return Err("a sandboxed project needs a sandboxed runner; not seeded here".into());
    }
    let new = NewProject {
        company_id: CompanyId(id(company)?),
        team_id: None,
        name: name.to_owned(),
        key: key.to_owned(),
        mode: f
            .get("--mode")
            .unwrap_or(&"kanban")
            .parse::<ProjectMode>()?,
        sprint_approval: f
            .get("--approval")
            .unwrap_or(&"owner")
            .parse::<SprintApproval>()?,
    };
    let pool = store::connect(db).await?;
    let p = work::create_project(&pool, &new).await?;
    if let Some(url) = f.get("--repo") {
        let repo = ProjectRepo {
            project_id: p.id,
            url: url.to_string(),
            default_branch: f.get("--branch").unwrap_or(&"main").to_string(),
        };
        work::set_project_repo(&pool, &repo).await?;
    }
    let policy = Policy {
        mode,
        ..Policy::default()
    };
    work::set_project_policy(&pool, p.id, &policy, AuditActor::User(ADMIN)).await?;
    eprintln!("project {} {} (id {})", p.key, p.name, p.id.0);
    println!("{}", p.id.0);
    Ok(())
}

/// A task in `todo` waiting on the admin, then handed to the assignee through the engine
/// (`Reassign`), which wakes the agent: the runner picks it up from there.
async fn issue(db: &Path, project: &str, title: &str, f: &HashMap<&str, &str>) -> Result_ {
    let new = NewIssue {
        project_id: ProjectId(id(project)?),
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: title.to_owned(),
        body: f.get("--body").unwrap_or(&"").to_string(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(ADMIN)),
        points: None,
        sprint_id: None,
    };
    let pool = store::connect(db).await?;
    let mut i = work::create_issue(&pool, &new).await?;
    if let Some(agent) = f.get("--assignee") {
        let next = NextActor::Agent(AgentId(id(agent)?));
        let to = IssueTransition::Reassign { next };
        let by = AuditActor::User(ADMIN);
        i = work::transition_issue(&pool, i.id, &to, by).await?;
    }
    let key = work::issue_key(&pool, i.id).await?.unwrap_or_default();
    eprintln!("issue {key} (id {}), next actor {:?}", i.id.0, i.next_actor);
    println!("{}", i.id.0);
    Ok(())
}

async fn epic(db: &Path, project: &str, title: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let e = work::create_epic(&pool, ProjectId(id(project)?), title).await?;
    eprintln!("epic {} (id {})", e.title, e.id.0);
    println!("{}", e.id.0);
    Ok(())
}

/// Moves the issue in its project's order, as the admin; prints the issue's id.
async fn move_issue(db: &Path, issue: &str, to: Position) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::move_issue(&pool, IssueId(id(issue)?), to, AuditActor::User(ADMIN)).await?;
    eprintln!("issue {} moved {to:?} (rank {})", i.id.0, i.rank);
    println!("{}", i.id.0);
    Ok(())
}
