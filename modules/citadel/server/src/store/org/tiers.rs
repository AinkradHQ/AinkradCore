//! An agent's model tiers (E15.5): the (harness, model) its small and large tasks start on.
//! Its own (harness, model) is its standard tier, so only `small` and `large` are stored. Set
//! as a whole, audited.

use citadel_core::audit::AuditActor;
use citadel_core::org::{AgentId, ModelRoute, Tier};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row, SqliteConnection};

use super::service::append_org_event;
use super::text;

/// Replaces the agent's tiers with `tiers` (empty clears them) and appends `agent.tiers_set`;
/// `false` when the agent is gone. `standard` (the agent's own entry), a repeated tier or an
/// empty model is `InvalidArgument`.
pub async fn set_tiers(
    pool: &SqlitePool,
    agent: AgentId,
    tiers: &[(Tier, ModelRoute)],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(company): Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
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
    sqlx::query("DELETE FROM agent_tiers WHERE agent_id = ?")
        .bind(agent.0)
        .execute(&mut *tx)
        .await?;
    for (tier, r) in tiers {
        sqlx::query("INSERT INTO agent_tiers (agent_id, tier, harness, model) VALUES (?, ?, ?, ?)")
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
    let company = citadel_core::org::CompanyId(company);
    let details = json!({ "tiers": entries });
    let entity = ("agent", agent.0);
    append_org_event(&mut tx, company, actor, "agent.tiers_set", entity, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// The agent's (harness, model) for `tier`; `None` for `standard` or a tier it has none for.
pub(crate) async fn tier_route_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    tier: Tier,
) -> Result<Option<ModelRoute>, Error> {
    let row = sqlx::query("SELECT harness, model FROM agent_tiers WHERE agent_id = ? AND tier = ?")
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
        "SELECT tier, harness, model FROM agent_tiers WHERE agent_id = ? \
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
