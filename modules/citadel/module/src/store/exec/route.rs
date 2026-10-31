//! Which (harness, model) a run starts on (E15.5, pain #1: small jobs burning big-model tokens).
//!
//! A project's routing rules match an issue by label (`label:chore`) or kind (`kind:subtask`) and
//! name its tier; a project with no rules of its own uses `DEFAULT_RULES`. With no rule matching,
//! its points decide: at most `routing.small_max_points` is small, at least
//! `routing.large_min_points` large, anything else (or unestimated) standard. A run starts on its
//! agent's model for that tier (`store::org::set_tiers`), then its own entry, then its fallbacks.
//!
//! A tier only ever picks among models the admin configured for that agent: it grants no budget
//! and no access. The run is admitted against the same budgets whatever its tier, and the token
//! caps do not move. The monolith's account routing in this chain is S9's.

use sqlx::{Error, SqliteConnection};

use super::*;
use crate::domain::org::{ModelRoute, Tier};
use crate::domain::work::ProjectId;
use crate::store::org::{DEFAULT_RULES, fallbacks_in, tier_route_in};

async fn rules_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
) -> Result<Vec<(String, Tier)>, Error> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT rule, tier FROM citadel_tier_rules WHERE project_id = ?")
            .bind(project.0)
            .fetch_all(&mut *conn)
            .await?;
    if rows.is_empty() {
        return Ok(DEFAULT_RULES
            .iter()
            .map(|(r, t)| ((*r).to_owned(), *t))
            .collect());
    }
    rows.into_iter()
        .map(|(rule, tier)| Ok((rule, tier.parse().map_err(|e| Error::Decode(Box::new(e)))?)))
        .collect()
}

/// The tier of a task on `issue` (standard with none). A matching rule wins over points; of
/// several matching rules, the largest tier, as a big task on a small model costs more than the
/// reverse.
pub async fn task_tier_in(
    conn: &mut SqliteConnection,
    issue: Option<IssueId>,
) -> Result<Tier, Error> {
    let Some(issue) = issue else {
        return Ok(Tier::Standard);
    };
    let Some((project, kind, points)): Option<(i64, String, Option<i64>)> =
        sqlx::query_as("SELECT project_id, kind, points FROM citadel_issues WHERE id = ?")
            .bind(issue.0)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Ok(Tier::Standard);
    };
    let labels: Vec<String> = sqlx::query_scalar(
        "SELECT lower(l.name) FROM citadel_issue_labels il \
         JOIN citadel_labels l ON l.id = il.label_id WHERE il.issue_id = ?",
    )
    .bind(issue.0)
    .fetch_all(&mut *conn)
    .await?;
    let rank = |t: &Tier| match t {
        Tier::Small => 0,
        Tier::Standard => 1,
        Tier::Large => 2,
    };
    let matched = rules_in(conn, ProjectId(project))
        .await?
        .iter()
        .filter(|(rule, _)| match rule.split_once(':') {
            Some(("label", name)) => labels.contains(&name.trim().to_lowercase()),
            Some(("kind", k)) => *k == kind,
            _ => false,
        })
        .map(|(_, tier)| *tier)
        .max_by_key(rank);
    if let Some(tier) = matched {
        return Ok(tier);
    }
    let Some(points) = points else {
        return Ok(Tier::Standard);
    };
    if points <= crate::settings::value_in(conn, "routing.small_max_points").await? {
        return Ok(Tier::Small);
    }
    if points >= crate::settings::value_in(conn, "routing.large_min_points").await? {
        return Ok(Tier::Large);
    }
    Ok(Tier::Standard)
}

/// The agent's whole chain for a task of `tier`: its model for the tier (when it has one), its
/// own (harness, model), then its fallbacks, each once.
pub async fn chain_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    tier: Tier,
) -> Result<Vec<ModelRoute>, Error> {
    let (harness, model): (String, String) =
        sqlx::query_as("SELECT harness, model FROM citadel_agents WHERE id = ?")
            .bind(agent.0)
            .fetch_one(&mut *conn)
            .await?;
    let own = ModelRoute {
        harness: harness.parse().map_err(|e| Error::Decode(Box::new(e)))?,
        model,
    };
    let mut chain = vec![];
    if tier != Tier::Standard {
        chain.extend(tier_route_in(conn, agent, tier).await?);
    }
    for r in [own].into_iter().chain(fallbacks_in(conn, agent).await?) {
        if !chain.contains(&r) {
            chain.push(r);
        }
    }
    Ok(chain)
}
