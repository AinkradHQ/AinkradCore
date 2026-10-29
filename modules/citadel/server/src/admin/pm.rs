//! Planning commands (E5): sprints, WIP limits, project specs and approval decisions from a
//! shell, as the admin, through the same
//! store calls (rules and audit) the agents' tools use. Each prints the sprint's or issue's id
//! on stdout, or the report as JSON.

use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::gov::{ApprovalId, ApprovalKind, ApprovalStatus};
use citadel_core::org::CompanyId;
use citadel_core::work::{
    BlockerLink, IssueId, IssueState, NewSprint, ProjectId, SprintId, SprintState,
};
use citadel_server::scheduler::{Clock, SystemClock};
use citadel_server::store::{self, gov, work};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str = "  citadel-server sprint plan <db> <project-id> <name> --start <YYYY-MM-DD>
                 --end <YYYY-MM-DD> [--goal <text>]
  citadel-server issue estimate <db> <issue-id> <points|none>
  citadel-server issue block <db> <issue-id> --by <blocker-issue-id>
  citadel-server issue unblock-link <db> <issue-id> --by <blocker-issue-id>
  citadel-server sprint add <db> <sprint-id> <issue-id>
  citadel-server sprint remove <db> <issue-id>
  citadel-server sprint close <db> <sprint-id> [--carry-to <sprint-id>]
  citadel-server sprint report <db> <sprint-id>
  citadel-server sprint delete <db> <sprint-id>
  citadel-server wip set <db> <project-id> <state> <limit|none>
  citadel-server project spec <db> <project-id> <text>
  citadel-server approval list <db> <company-id> [--pending]
  citadel-server approval approve <db> <approval-id> [--reply <text>] [--raise <tokens>]
  citadel-server approval reject <db> <approval-id> [--reply <text>]
  citadel-server approval deadline <db> <kind> <seconds|none>
`sprint add` and `sprint remove` work on a planned sprint and, for the admin only, on an active
one: a scope change, which moves the sprint's committed points by the issue's (an issue joining
an active sprint needs points) and is audited as sprint.scope_added / sprint.scope_removed; the
points committed at start stay in sprint.started. A closed sprint's scope is fixed. A sprint
planned under a name the project already uses gets the next number (\"Sprint 1\" -> \"Sprint 2\").
`sprint delete` removes a planned sprint with no issues and no commit waiting (sprint.deleted).
A sprint starts only through its commit (E5.4): the product owner commits it, and under the
owner policy it waits for `approval approve`. Every kind (sprint_commit, pr_merge,
budget_overrun, hire_agent, permission_escalation, plan_approval, workflow_push) is decided the
same way; the reply wakes the agent that asked.
A workflow_push opens when the forge refused a run's branch push for changing workflow files
(.github/workflows) without the workflow scope; the server cannot push it. Approving it means
a human pushes the branch, with credentials that have the workflow scope, from the issue's
worktree on the runner host (<work root>/worktrees/issue-<issue id>, or the repo's directory in
it): `git push origin <branch>:<branch>` (branch and sha are in the payload). Approve before or
after pushing: the PR opens by itself once the branch is on the forge; nobody is woken. Rejecting it sends the reply to the agent, which drops the
workflow change so its own push goes through. `approval deadline` sets how long new approvals of a kind wait before
they expire (none: until decided); it is the server-wide `approval.deadline.<kind>` setting,
which `setting set` can also set per company. A budget_overrun is approved with --raise: that many more
tokens for the budget's current period. `issue block` links the blocker (same company, no cycle)
and blocks the issue; when the blocker closes, the issue goes back to todo and its next actor is
woken. `issue unblock-link` removes the link, unblocking the issue if it was its last open one.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs a planning command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["sprint", "plan", db, project, name, rest @ ..] => {
            let f = flags(rest, &["--start", "--end", "--goal"])?;
            let new = NewSprint {
                project_id: ProjectId(id(project).ok()?),
                name: name.to_string(),
                goal: f.get("--goal").unwrap_or(&"").to_string(),
                state: SprintState::Planned,
                starts_on: Some(f.get("--start")?.to_string()),
                ends_on: Some(f.get("--end")?.to_string()),
            };
            plan(Path::new(db), &new).await
        }
        ["issue", "estimate", db, issue, points] => {
            let points = match *points {
                "none" => None,
                n => Some(n.parse().ok()?),
            };
            estimate(Path::new(db), IssueId(id(issue).ok()?), points).await
        }
        ["issue", "block", db, issue, "--by", blocker] => {
            let link = BlockerLink {
                blocker: IssueId(id(blocker).ok()?),
                blocked: IssueId(id(issue).ok()?),
            };
            block(Path::new(db), link).await
        }
        ["issue", "unblock-link", db, issue, "--by", blocker] => {
            let link = BlockerLink {
                blocker: IssueId(id(blocker).ok()?),
                blocked: IssueId(id(issue).ok()?),
            };
            unlink(Path::new(db), link).await
        }
        ["sprint", "add", db, sprint, issue] => {
            let (s, i) = (SprintId(id(sprint).ok()?), IssueId(id(issue).ok()?));
            add(Path::new(db), s, i).await
        }
        ["sprint", "remove", db, issue] => remove(Path::new(db), IssueId(id(issue).ok()?)).await,
        ["sprint", "close", db, sprint, rest @ ..] => {
            let f = flags(rest, &["--carry-to"])?;
            let to = match f.get("--carry-to") {
                Some(to) => Some(SprintId(id(to).ok()?)),
                None => None,
            };
            close(Path::new(db), SprintId(id(sprint).ok()?), to).await
        }
        ["sprint", "report", db, sprint] => report(Path::new(db), SprintId(id(sprint).ok()?)).await,
        ["sprint", "delete", db, sprint] => delete(Path::new(db), SprintId(id(sprint).ok()?)).await,
        ["wip", "set", db, project, state, limit] => {
            let state: IssueState = state.parse().ok()?;
            let limit = match *limit {
                "none" => None,
                n => Some(n.parse().ok()?),
            };
            wip(Path::new(db), ProjectId(id(project).ok()?), state, limit).await
        }
        ["project", "spec", db, project, text] => {
            spec(Path::new(db), ProjectId(id(project).ok()?), text).await
        }
        ["approval", "list", db, company, rest @ ..] => {
            let pending = match rest {
                [] => false,
                ["--pending"] => true,
                _ => return None,
            };
            approvals(Path::new(db), id(company).ok()?, pending).await
        }
        ["approval", "deadline", db, kind, secs] => {
            let secs = match *secs {
                "none" => None,
                n => Some(n.parse().ok().filter(|n| *n > 0)?),
            };
            deadline(Path::new(db), kind.parse().ok()?, secs).await
        }
        [
            "approval",
            verb @ ("approve" | "reject"),
            db,
            approval,
            rest @ ..,
        ] => {
            let f = flags(rest, &["--reply", "--raise"])?;
            let a = ApprovalId(id(approval).ok()?);
            let raise = match f.get("--raise") {
                Some(r) if *verb == "approve" => Some(r.parse().ok()?),
                Some(_) => return None,
                None => None,
            };
            let reply = f.get("--reply").copied();
            decide(Path::new(db), a, *verb == "approve", reply, raise).await
        }
        _ => return None,
    })
}

async fn plan(db: &Path, new: &NewSprint) -> Result_ {
    let pool = store::connect(db).await?;
    let s = work::plan_sprint(&pool, new, BY).await?;
    eprintln!("sprint {} (id {}) planned", s.name, s.id.0);
    println!("{}", s.id.0);
    Ok(())
}

async fn estimate(db: &Path, issue: IssueId, points: Option<u32>) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::estimate_issue(&pool, issue, points, BY).await?;
    eprintln!("issue {} estimated at {:?} points", i.id.0, i.points);
    println!("{}", i.id.0);
    Ok(())
}

/// Links the blocker and blocks the issue, as the admin.
async fn block(db: &Path, link: BlockerLink) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::link_blocker(&pool, link, true, BY).await?;
    eprintln!("issue {} blocked by {}", i.id.0, link.blocker.0);
    println!("{}", i.id.0);
    Ok(())
}

/// Removes the link, as the admin; the issue is unblocked if that was its last open blocker.
async fn unlink(db: &Path, link: BlockerLink) -> Result_ {
    let pool = store::connect(db).await?;
    if !work::remove_blocker(&pool, link, BY).await? {
        return Err(format!("issue {} does not block {}", link.blocker.0, link.blocked.0).into());
    }
    let i = work::get_issue(&pool, link.blocked)
        .await?
        .ok_or("no such issue")?;
    eprintln!(
        "issue {} no longer blocked by {} ({})",
        i.id.0,
        link.blocker.0,
        i.state.as_str()
    );
    println!("{}", i.id.0);
    Ok(())
}

async fn add(db: &Path, sprint: SprintId, issue: IssueId) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::add_to_sprint(&pool, sprint, issue, BY).await?;
    eprintln!("issue {} in sprint {}", i.id.0, sprint.0);
    println!("{}", i.id.0);
    Ok(())
}

async fn remove(db: &Path, issue: IssueId) -> Result_ {
    let pool = store::connect(db).await?;
    let i = work::remove_from_sprint(&pool, issue, BY).await?;
    eprintln!("issue {} back in the backlog", i.id.0);
    println!("{}", i.id.0);
    Ok(())
}

async fn spec(db: &Path, project: ProjectId, text: &str) -> Result_ {
    let pool = store::connect(db).await?;
    if !work::set_project_spec(&pool, project, text, BY).await? {
        return Err(format!("no project {}", project.0).into());
    }
    eprintln!("project {} spec set ({} bytes)", project.0, text.len());
    println!("{}", project.0);
    Ok(())
}

/// One line per approval of the company (only the pending with `pending`): id, kind, status,
/// subject, payload, reply, deadline.
async fn approvals(db: &Path, company: i64, pending: bool) -> Result_ {
    let pool = store::connect(db).await?;
    let all = gov::list_approvals(&pool, CompanyId(company)).await?;
    for a in all
        .into_iter()
        .filter(|a| !pending || a.status == ApprovalStatus::Pending)
    {
        let subject = match (a.sprint_id, a.issue_id, a.agent_id) {
            (Some(s), _, _) => format!("sprint {}", s.0),
            (None, Some(i), _) => format!("issue {}", i.0),
            (None, None, Some(g)) => format!("agent {}", g.0),
            (None, None, None) => "-".to_owned(),
        };
        println!(
            "{}\t{}\t{}\t{subject}\t{}\t{}\t{}",
            a.id.0,
            a.kind.as_str(),
            a.status.as_str(),
            a.payload,
            a.reply.unwrap_or_default(),
            a.expires_at.unwrap_or_else(|| "-".to_owned())
        );
    }
    Ok(())
}

async fn deadline(db: &Path, kind: ApprovalKind, secs: Option<u64>) -> Result_ {
    use citadel_core::settings::{Key, Scope};
    let pool = store::connect(db).await?;
    let (key, value) = (Key::approval_deadline(kind), secs.unwrap_or(0).to_string());
    let now = SystemClock.now();
    store::settings::set(&pool, key, Scope::Server, &value, BY, &now).await?;
    let shown = secs.map_or("none".to_owned(), |s| format!("{s}s"));
    eprintln!("new {} approvals expire after {shown}", kind.as_str());
    println!("{}", kind.as_str());
    Ok(())
}

async fn decide(
    db: &Path,
    a: ApprovalId,
    approve: bool,
    reply: Option<&str>,
    raise: Option<i64>,
) -> Result_ {
    let pool = store::connect(db).await?;
    let now = SystemClock.now();
    let decided = match raise {
        Some(raise) => gov::approve_budget_raise(&pool, a, raise, ADMIN, reply, &now).await?,
        None => gov::decide_approval(&pool, a, approve, ADMIN, reply, &now).await?,
    };
    eprintln!("approval {} {}", decided.id.0, decided.status.as_str());
    println!("{}", decided.id.0);
    Ok(())
}

async fn close(db: &Path, sprint: SprintId, carry_to: Option<SprintId>) -> Result_ {
    let pool = store::connect(db).await?;
    let s = work::close_sprint(&pool, sprint, carry_to, BY).await?;
    eprintln!("sprint {} (id {}) closed", s.name, s.id.0);
    println!("{}", s.id.0);
    Ok(())
}

async fn delete(db: &Path, sprint: SprintId) -> Result_ {
    let pool = store::connect(db).await?;
    let s = work::delete_empty_sprint(&pool, sprint, BY).await?;
    eprintln!("sprint {} (id {}) deleted", s.name, s.id.0);
    println!("{}", s.id.0);
    Ok(())
}

async fn report(db: &Path, sprint: SprintId) -> Result_ {
    let pool = store::connect(db).await?;
    let r = work::sprint_report(&pool, sprint, &SystemClock.now())
        .await?
        .ok_or_else(|| format!("no sprint {}", sprint.0))?;
    let mut v = work::report_json(&r);
    v["review"] = work::sprint_review(&pool, sprint).await?.into();
    v["cost"] = gov::cost_json(&gov::cost_report(&pool, gov::CostScope::Sprint(sprint)).await?);
    println!("{v}");
    Ok(())
}

async fn wip(db: &Path, project: ProjectId, state: IssueState, limit: Option<u32>) -> Result_ {
    let pool = store::connect(db).await?;
    work::set_wip_limit(&pool, project, state, limit, BY).await?;
    eprintln!(
        "project {} {} WIP limit {limit:?}",
        project.0,
        state.as_str()
    );
    println!("{}", project.0);
    Ok(())
}
