//! Per-task model routing (E15.5), as the admin, through the audited store calls: an agent's
//! model per tier and a project's routing rules. `set` prints the agent's or project's id;
//! `list` one entry per line.

use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{AgentId, ModelRoute, Tier};
use ainkrad_core::work::ProjectId;
use ainkrad_core_server::store::{self, exec, org};

use super::{ADMIN, id};
use crate::Result_;

pub const USAGE: &str =
    "  ainkrad-core-server agent tier set <db> <agent-id> [small=<harness>/<model>] [large=<harness>/<model>]
  ainkrad-core-server agent tier list <db> <agent-id>
  ainkrad-core-server project tier-rule set <db> <project-id> [label:<name>=<tier> | kind:<kind>=<tier> …]
  ainkrad-core-server project tier-rule list <db> <project-id>
A task's tier picks the model its run starts on (E15.5): small and large are set per agent,
standard is the agent's own harness and model; the agent's fallbacks follow either. A
project's rules name the tier of issues by label or kind (with none set: label:chore and
label:docs are small); with no rule matching, routing.small_max_points and
routing.large_min_points decide by points. tier set or tier-rule set with nothing clears.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs a routing command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["agent", "tier", "set", db, agent, entries @ ..] => {
            let mut tiers = vec![];
            for e in entries {
                let (tier, route) = e.split_once('=')?;
                let (harness, model) = route.split_once('/')?;
                let route = ModelRoute {
                    harness: harness.parse().ok()?,
                    model: model.to_owned(),
                };
                tiers.push((tier.parse::<Tier>().ok()?, route));
            }
            tier_set(Path::new(db), AgentId(id(agent).ok()?), &tiers).await
        }
        ["agent", "tier", "list", db, agent] => {
            tier_list(Path::new(db), AgentId(id(agent).ok()?)).await
        }
        ["project", "tier-rule", "set", db, project, entries @ ..] => {
            let mut rules = vec![];
            for e in entries {
                let (rule, tier) = e.rsplit_once('=')?;
                rules.push((rule.to_owned(), tier.parse::<Tier>().ok()?));
            }
            rule_set(Path::new(db), ProjectId(id(project).ok()?), &rules).await
        }
        ["project", "tier-rule", "list", db, project] => {
            rule_list(Path::new(db), ProjectId(id(project).ok()?)).await
        }
        _ => return None,
    })
}

async fn tier_set(db: &Path, agent: AgentId, tiers: &[(Tier, ModelRoute)]) -> Result_ {
    let pool = store::connect(db).await?;
    if !org::set_tiers(&pool, agent, tiers, BY).await? {
        return Err(format!("no agent {}", agent.0).into());
    }
    eprintln!("agent {}: {} tiers", agent.0, tiers.len());
    println!("{}", agent.0);
    Ok(())
}

/// `<tier>\t<harness>/<model>` per line.
async fn tier_list(db: &Path, agent: AgentId) -> Result_ {
    let pool = store::connect(db).await?;
    for (tier, r) in org::list_tiers(&pool, agent).await? {
        println!("{}\t{}/{}", tier.as_str(), r.harness.as_str(), r.model);
    }
    Ok(())
}

async fn rule_set(db: &Path, project: ProjectId, rules: &[(String, Tier)]) -> Result_ {
    let pool = store::connect(db).await?;
    if !exec::set_tier_rules(&pool, project, rules, BY).await? {
        return Err(format!("no project {}", project.0).into());
    }
    eprintln!("project {}: {} routing rules", project.0, rules.len());
    println!("{}", project.0);
    Ok(())
}

/// `<rule>\t<tier>` per line, then `(defaults)` when none are set.
async fn rule_list(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    let (rules, defaults) = exec::list_tier_rules(&pool, project).await?;
    for (rule, tier) in rules {
        println!("{rule}\t{}", tier.as_str());
    }
    if defaults {
        eprintln!("(defaults: the project has set no rules)");
    }
    Ok(())
}
