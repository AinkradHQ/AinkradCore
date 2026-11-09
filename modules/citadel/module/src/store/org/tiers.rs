//! An agent's model tiers (E15.5): the (harness, model) its small and large tasks start on.
//! Its own (harness, model) is its standard tier, so only `small` and `large` are stored. Set
//! as a whole, audited. A project's routing rules are here too (`set_tier_rules`): the monolith
//! keeps them in `exec/tier.rs`, but they need only their table, so they are ported now (S7:
//! reuse these, add `task_tier_in` next to them).

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::{Error, Row, SqliteConnection, SqlitePool};

use super::chart::append_org_event;
use super::text;
use crate::domain::org::{AgentId, CompanyId, ModelRoute, Tier};
use crate::domain::work::IssueKind;
use crate::store::audit::{self, Event};

/// Replaces the agent's tiers with `tiers` (empty clears them) and appends `agent.tiers_set`;
/// `false` when the agent is gone. `standard` (the agent's own entry), a repeated tier or an
/// empty model is `InvalidArgument`.
pub async fn set_tiers(
    pool: &SqlitePool,
    agent: AgentId,
    tiers: &[(Tier, ModelRoute)],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let Some(company): Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
            .bind(agent.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    for (i, (tier, r)) in tiers.iter().enumerate() {
        let repeated = tiers[..i].iter().any(|(t, _)| t == tier);
        if *tier == Tier::Standard || repeated || r.model.trim().is_empty() {
            let why = format!(
                "bad tier {}: standard is the agent's own model; small and large once each, \
                 with a model",
                tier.as_str()
            );
            return Err(Error::InvalidArgument(why));
        }
    }
    sqlx::query("DELETE FROM citadel_agent_tiers WHERE agent_id = ?")
        .bind(agent.0)
        .execute(&mut *tx)
        .await?;
    for (tier, r) in tiers {
        sqlx::query(
            "INSERT INTO citadel_agent_tiers (agent_id, tier, harness, model) VALUES (?, ?, ?, ?)",
        )
        .bind(agent.0)
        .bind(tier.as_str())
        .bind(r.harness.as_str())
        .bind(r.model.trim())
        .execute(&mut *tx)
        .await?;
    }
    let entries: serde_json::Map<String, serde_json::Value> = tiers
        .iter()
        .map(|(t, r)| {
            let entry = format!("{}/{}", r.harness.as_str(), r.model.trim());
            (t.as_str().to_owned(), entry.into())
        })
        .collect();
    let details = json!({ "tiers": entries });
    let entity = ("agent", agent.0);
    append_org_event(
        &mut tx,
        CompanyId(company),
        actor,
        "agent.tiers_set",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The agent's (harness, model) for `tier`; `None` for `standard` or a tier it has none for.
pub async fn tier_route_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    tier: Tier,
) -> Result<Option<ModelRoute>, Error> {
    let row = sqlx::query(
        "SELECT harness, model FROM citadel_agent_tiers WHERE agent_id = ? AND tier = ?",
    )
    .bind(agent.0)
    .bind(tier.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|row| {
        Ok(ModelRoute {
            harness: text(&row, "harness")?,
            model: row.try_get("model")?,
        })
    })
    .transpose()
}

/// The agent's stored tiers, small then large.
pub async fn list_tiers(
    pool: &SqlitePool,
    agent: AgentId,
) -> Result<Vec<(Tier, ModelRoute)>, Error> {
    let rows = sqlx::query(
        "SELECT tier, harness, model FROM citadel_agent_tiers WHERE agent_id = ? \
         ORDER BY tier = 'large', tier",
    )
    .bind(agent.0)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            let route = ModelRoute {
                harness: text(row, "harness")?,
                model: row.try_get("model")?,
            };
            Ok((text(row, "tier")?, route))
        })
        .collect()
}

/// The rules of a project that has none set: chores and docs are small.
pub const DEFAULT_RULES: &[(&str, Tier)] =
    &[("label:chore", Tier::Small), ("label:docs", Tier::Small)];

/// Whether `rule` is `label:<name>` or `kind:<issue kind>`.
fn rule_ok(rule: &str) -> bool {
    match rule.split_once(':') {
        Some(("label", name)) => !name.trim().is_empty(),
        Some(("kind", kind)) => kind.parse::<IssueKind>().is_ok(),
        _ => false,
    }
}

/// Replaces the project's routing rules with `rules` (empty: back to `DEFAULT_RULES`) and
/// appends `project.tier_rules_set`; `false` when the project is gone. A rule that is not
/// `label:<name>` or `kind:<kind>`, or one given twice, is `InvalidArgument`.
pub async fn set_tier_rules(
    pool: &SqlitePool,
    project: crate::domain::work::ProjectId,
    rules: &[(String, Tier)],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let Some(company): Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
            .bind(project.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    for (i, (rule, _)) in rules.iter().enumerate() {
        if !rule_ok(rule) || rules[..i].iter().any(|(r, _)| r == rule) {
            let why = format!("bad rule {rule:?}: label:<name> or kind:<kind>, once each");
            return Err(Error::InvalidArgument(why));
        }
    }
    sqlx::query("DELETE FROM citadel_tier_rules WHERE project_id = ?")
        .bind(project.0)
        .execute(&mut *tx)
        .await?;
    for (rule, tier) in rules {
        sqlx::query("INSERT INTO citadel_tier_rules (project_id, rule, tier) VALUES (?, ?, ?)")
            .bind(project.0)
            .bind(rule)
            .bind(tier.as_str())
            .execute(&mut *tx)
            .await?;
    }
    let set: serde_json::Map<String, serde_json::Value> = rules
        .iter()
        .map(|(r, t)| (r.clone(), t.as_str().into()))
        .collect();
    let event = Event::new(actor, "project.tier_rules_set")
        .entity("project", project.0)
        .company(company)
        .details(json!({ "rules": set }));
    audit::append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(true)
}

/// The project's routing rules, and whether they are `DEFAULT_RULES` (none set).
pub async fn list_tier_rules(
    pool: &SqlitePool,
    project: crate::domain::work::ProjectId,
) -> Result<(Vec<(String, Tier)>, bool), Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT rule, tier FROM citadel_tier_rules WHERE project_id = ? ORDER BY rule",
    )
    .bind(project.0)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        let defaults = DEFAULT_RULES.iter().map(|(r, t)| ((*r).to_owned(), *t));
        return Ok((defaults.collect(), true));
    }
    rows.into_iter()
        .map(|(rule, tier)| {
            let tier = tier.parse().map_err(|e| Error::Decode(Box::new(e)))?;
            Ok((rule, tier))
        })
        .collect::<Result<_, Error>>()
        .map(|rules| (rules, false))
}
