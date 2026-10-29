//! An agent's model fallback chain (E15.3): the (harness, model) entries tried after its own,
//! in order. Set as a whole, audited.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{AgentId, ModelRoute};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::service::append_org_event;
use super::text;

/// Replaces the agent's fallback chain with `chain` (empty clears it) and appends
/// `agent.fallbacks_set`; `false` when the agent is gone. An empty model or an entry repeating
/// the agent's own (harness, model) or an earlier one is `InvalidArgument`.
pub async fn set_fallbacks(
    pool: &SqlitePool,
    agent: AgentId,
    chain: &[ModelRoute],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some((company, harness, model)): Option<(i64, String, String)> =
        sqlx::query_as("SELECT company_id, harness, model FROM agents WHERE id = ?")
            .bind(agent.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    let mut seen = vec![(harness, model)];
    for r in chain {
        let entry = (r.harness.as_str().to_owned(), r.model.trim().to_owned());
        if entry.1.is_empty() || seen.contains(&entry) {
            let why = format!("bad fallback {}/{:?}: empty or repeated", entry.0, entry.1);
            return Err(Error::InvalidArgument(why));
        }
        seen.push(entry);
    }
    sqlx::query("DELETE FROM agent_fallbacks WHERE agent_id = ?")
        .bind(agent.0)
        .execute(&mut *tx)
        .await?;
    for (position, (harness, model)) in seen.iter().skip(1).enumerate() {
        sqlx::query(
            "INSERT INTO agent_fallbacks (agent_id, position, harness, model) VALUES (?, ?, ?, ?)",
        )
        .bind(agent.0)
        .bind(position as i64 + 1)
        .bind(harness)
        .bind(model)
        .execute(&mut *tx)
        .await?;
    }
    let entries: Vec<String> = seen
        .iter()
        .skip(1)
        .map(|(h, m)| format!("{h}/{m}"))
        .collect();
    let company = ainkrad_core::org::CompanyId(company);
    let details = json!({"fallbacks": entries});
    append_org_event(
        &mut tx,
        company,
        actor,
        "agent.fallbacks_set",
        ("agent", agent.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The agent's effective fallbacks: its preset's entries in place of its own (a chain preset,
/// its own or its company's default when it has no fallbacks), else its own.
pub(crate) async fn fallbacks_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
) -> Result<Vec<ModelRoute>, Error> {
    match super::presets::effective_preset_in(conn, agent).await? {
        Some(preset) => super::presets::preset_routes_in(conn, preset).await,
        None => own_fallbacks_in(conn, agent).await,
    }
}

/// The fallbacks set on the agent itself (`agent_fallbacks`), whatever its preset.
pub(super) async fn own_fallbacks_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
) -> Result<Vec<ModelRoute>, Error> {
    let rows = sqlx::query(
        "SELECT harness, model FROM agent_fallbacks WHERE agent_id = ? ORDER BY position",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|row| {
            use sqlx::Row;
            Ok(ModelRoute {
                harness: text(row, "harness")?,
                model: row.try_get("model")?,
            })
        })
        .collect()
}

/// The agent's own fallback chain, in order (without its own entry; a preset is not in it).
pub async fn list_fallbacks(pool: &SqlitePool, agent: AgentId) -> Result<Vec<ModelRoute>, Error> {
    own_fallbacks_in(&mut *pool.acquire().await?, agent).await
}
