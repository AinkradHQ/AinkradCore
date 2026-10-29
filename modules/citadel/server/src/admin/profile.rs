//! Project profile commands (E15.13), as the admin: show a project's profile with what a run is
//! given of it, and change fields of it, through the same store call (rules and audit) the API
//! uses. The project's permission policy (E3.10) too: its mode and allowlist.

use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::work::ProjectId;
use citadel_server::profile::ProfilePatch;
use citadel_server::store::{self, work};
use ainkrad_proto::runner::{PermissionMode, Policy};

use super::{ADMIN, id};
use crate::Result_;

pub const USAGE: &str = "  citadel-server project profile show <db> <project-id>
  citadel-server project profile set <db> <project-id> <json>
profile show prints the profile as JSON (with plan approval and permission mode); stderr says how
much of it a run is given within the profile.budget_bytes setting and what is left out. profile
set changes only the fields in the JSON object, e.g. '{\"definition_of_done\": [\"tests pass\"],
\"merge_method\": \"merge\"}'; fields: stack, definition_of_done, protected_branches,
branch_pattern, merge_method, merged_by, environments, conventions, docs, models, network,
sprint_approval, permission_mode. Agents' proposed changes are knowledge proposals
(knowledge list marks them profile.<field>), applied by knowledge accept.
  citadel-server project policy show <db> <project-id>
  citadel-server project policy set <db> <project-id> --mode <ask|accept_edits|sandboxed>
                 [--allow <tool>|<tool>:<command prefix>]… [--sandboxed]
policy set replaces the project's permission policy (audited as project.policy_set): the mode,
the allowlist (each --allow, e.g. --allow Edit --allow 'Bash:npm run'; a prefix never matches a
command with shell operators, and a path outside the worktree always asks) and whether runs need
a sandboxed runner (--sandboxed; implied by --mode sandboxed). policy show prints it as JSON.";

/// Runs a profile command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["project", "profile", "show", db, project] => {
            show(Path::new(db), ProjectId(id(project).ok()?)).await
        }
        ["project", "profile", "set", db, project, patch] => {
            set(Path::new(db), ProjectId(id(project).ok()?), patch).await
        }
        ["project", "policy", "show", db, project] => {
            show_policy(Path::new(db), ProjectId(id(project).ok()?)).await
        }
        ["project", "policy", "set", db, project, rest @ ..] => {
            let policy = policy_flags(rest)?;
            set_policy(Path::new(db), ProjectId(id(project).ok()?), &policy).await
        }
        _ => return None,
    })
}

/// `--mode` (required), any number of `--allow`, and `--sandboxed`; `None` on anything else.
fn policy_flags(mut rest: &[&str]) -> Option<Policy> {
    let (mut mode, mut allow, mut sandboxed) = (None, vec![], false);
    loop {
        rest = match rest {
            [] => break,
            ["--mode", m, more @ ..] => {
                mode = Some(m.parse::<PermissionMode>().ok()?);
                more
            }
            ["--allow", entry, more @ ..] => {
                allow.push((*entry).to_owned());
                more
            }
            ["--sandboxed", more @ ..] => {
                sandboxed = true;
                more
            }
            _ => return None,
        };
    }
    let mode = mode?;
    Some(Policy {
        sandboxed: sandboxed || mode == PermissionMode::Sandboxed,
        mode,
        allow,
    })
}

async fn show_policy(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    let p = work::project_policy(&pool, project)
        .await?
        .ok_or_else(|| format!("no project {}", project.0))?;
    println!("{}", serde_json::to_string_pretty(&p)?);
    Ok(())
}

async fn set_policy(db: &Path, project: ProjectId, policy: &Policy) -> Result_ {
    let pool = store::connect(db).await?;
    let by = AuditActor::User(ADMIN);
    if !work::set_project_policy(&pool, project, policy, by).await? {
        return Err(format!("no project {}", project.0).into());
    }
    eprintln!(
        "project {} policy: {}, allow [{}]{}",
        project.0,
        policy.mode.as_str(),
        policy.allow.join(", "),
        if policy.sandboxed { ", sandboxed" } else { "" }
    );
    println!("{}", project.0);
    Ok(())
}

async fn show(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    let p = work::project_profile(&pool, project)
        .await?
        .ok_or_else(|| format!("no project {}", project.0))?;
    let mut out = serde_json::to_value(&p.profile)?;
    out["sprint_approval"] = p.sprint_approval.as_str().into();
    out["permission_mode"] = p.permission_mode.as_str().into();
    println!("{}", serde_json::to_string_pretty(&out)?);
    let (fitted, budget) = work::run_profile(&pool, project).await?;
    let used = fitted.text.as_ref().map_or(0, String::len);
    eprintln!(
        "a run is given {used} of {budget} bytes; left out: {:?}",
        fitted.dropped
    );
    Ok(())
}

async fn set(db: &Path, project: ProjectId, patch: &str) -> Result_ {
    let patch: ProfilePatch =
        serde_json::from_str(patch).map_err(|e| format!("the profile JSON: {e}"))?;
    let pool = store::connect(db).await?;
    work::update_profile(&pool, project, &patch, AuditActor::User(ADMIN))
        .await?
        .ok_or_else(|| format!("no project {}", project.0))?;
    eprintln!("project {} profile updated", project.0);
    println!("{}", project.0);
    Ok(())
}
