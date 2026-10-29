//! Chain presets (parity API B2): a company's named chains of (harness, model, account)
//! entries, and which one an agent uses. An agent's effective fallbacks (`fallbacks_in`) are,
//! in order: its preset's entries; else its own (`agent_fallbacks`); else, when it has none, the
//! company's default preset's. Every change is audited and an event on the stream
//! (`chain_preset.created`, `.updated`, `.deleted`, `agent.chain_set`).

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ops::{ChainEntry, ChainPreset, NewChainPreset};
use ainkrad_core::org::{AgentId, CompanyId, ModelRoute};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::service::append_org_event;
use super::text;

fn entry(row: &SqliteRow) -> Result<ChainEntry, Error> {
    Ok(ChainEntry {
        harness: text(row, "harness")?,
        model: row.try_get("model")?,
        account_id: row.try_get("account_id")?,
    })
}

async fn entries_in(conn: &mut SqliteConnection, preset: i64) -> Result<Vec<ChainEntry>, Error> {
    sqlx::query(
        "SELECT harness, model, account_id FROM chain_preset_entries \
         WHERE preset_id = ? ORDER BY position",
    )
    .bind(preset)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(entry)
    .collect()
}

async fn preset_in(conn: &mut SqliteConnection, id: i64) -> Result<Option<ChainPreset>, Error> {
    let row = sqlx::query(
        "SELECT id, company_id, name, color, description, is_default FROM chain_presets \
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(ChainPreset {
        id,
        company_id: row.try_get("company_id")?,
        name: row.try_get("name")?,
        color: row.try_get("color")?,
        description: row.try_get("description")?,
        is_default: row.try_get("is_default")?,
        entries: entries_in(conn, id).await?,
    }))
}

pub async fn get_preset(pool: &SqlitePool, id: i64) -> Result<Option<ChainPreset>, Error> {
    preset_in(&mut *pool.acquire().await?, id).await
}

/// The company's presets, by name.
pub async fn list_presets(
    pool: &SqlitePool,
    company: CompanyId,
) -> Result<Vec<ChainPreset>, Error> {
    let mut conn = pool.acquire().await?;
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM chain_presets WHERE company_id = ? ORDER BY name")
            .bind(company.0)
            .fetch_all(&mut *conn)
            .await?;
    let mut out = vec![];
    for id in ids {
        out.extend(preset_in(&mut conn, id).await?);
    }
    Ok(out)
}

fn invalid(why: impl Into<String>) -> Error {
    Error::InvalidArgument(why.into())
}

/// Every pinned account must be in the company's pool.
async fn check_pins(
    conn: &mut SqliteConnection,
    company: i64,
    entries: &[ChainEntry],
) -> Result<(), Error> {
    for a in entries.iter().filter_map(|e| e.account_id) {
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM account_companies WHERE account_id = ? AND company_id = ?)",
        )
        .bind(a)
        .bind(company)
        .fetch_one(&mut *conn)
        .await?;
        if !ok {
            return Err(invalid(format!("account {a} is not in the company's pool")));
        }
    }
    Ok(())
}

async fn write_entries(
    conn: &mut SqliteConnection,
    preset: i64,
    entries: &[ChainEntry],
) -> Result<(), Error> {
    sqlx::query("DELETE FROM chain_preset_entries WHERE preset_id = ?")
        .bind(preset)
        .execute(&mut *conn)
        .await?;
    for (i, e) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO chain_preset_entries (preset_id, position, harness, model, account_id) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(preset)
        .bind(i as i64 + 1)
        .bind(e.harness.as_str())
        .bind(e.model.trim())
        .bind(e.account_id)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

fn details(p: &NewChainPreset) -> serde_json::Value {
    let entries: Vec<String> = p
        .entries
        .iter()
        .map(|e| format!("{}/{}", e.harness.as_str(), e.model.trim()))
        .collect();
    json!({"name": p.name.trim(), "color": p.color, "is_default": p.is_default,
           "entries": entries})
}

/// Adds a preset to the company; a name it has is a UNIQUE constraint error. A default one
/// takes the default from the old one.
pub async fn create_preset(
    pool: &SqlitePool,
    company: CompanyId,
    p: &NewChainPreset,
    actor: AuditActor,
) -> Result<ChainPreset, Error> {
    if let Some(why) = p.invalid() {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    check_pins(&mut tx, company.0, &p.entries).await?;
    if p.is_default {
        sqlx::query("UPDATE chain_presets SET is_default = 0 WHERE company_id = ?")
            .bind(company.0)
            .execute(&mut *tx)
            .await?;
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO chain_presets (company_id, name, color, description, is_default) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(company.0)
    .bind(p.name.trim())
    .bind(&p.color)
    .bind(&p.description)
    .bind(p.is_default)
    .fetch_one(&mut *tx)
    .await?;
    write_entries(&mut tx, id, &p.entries).await?;
    let by = ("chain_preset", id);
    append_org_event(
        &mut tx,
        company,
        actor,
        "chain_preset.created",
        by,
        details(p),
    )
    .await?;
    let made = preset_in(&mut tx, id).await?.ok_or(Error::RowNotFound)?;
    tx.commit().await?;
    Ok(made)
}

/// Replaces the preset's fields and entries; `None` when it is gone.
pub async fn update_preset(
    pool: &SqlitePool,
    id: i64,
    p: &NewChainPreset,
    actor: AuditActor,
) -> Result<Option<ChainPreset>, Error> {
    if let Some(why) = p.invalid() {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let company: Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM chain_presets WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(company) = company else {
        return Ok(None);
    };
    check_pins(&mut tx, company, &p.entries).await?;
    if p.is_default {
        sqlx::query("UPDATE chain_presets SET is_default = 0 WHERE company_id = ? AND id <> ?")
            .bind(company)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE chain_presets SET name = ?, color = ?, description = ?, is_default = ? WHERE id = ?",
    )
    .bind(p.name.trim())
    .bind(&p.color)
    .bind(&p.description)
    .bind(p.is_default)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    write_entries(&mut tx, id, &p.entries).await?;
    let by = ("chain_preset", id);
    let event = append_org_event(
        &mut tx,
        CompanyId(company),
        actor,
        "chain_preset.updated",
        by,
        details(p),
    );
    event.await?;
    let made = preset_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(made)
}

/// Deletes the preset (agents using it go back to their own chain); `false` when it is gone.
pub async fn delete_preset(pool: &SqlitePool, id: i64, actor: AuditActor) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(p) = preset_in(&mut tx, id).await? else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM chain_presets WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let by = ("chain_preset", id);
    let d = json!({"name": p.name});
    append_org_event(
        &mut tx,
        CompanyId(p.company_id),
        actor,
        "chain_preset.deleted",
        by,
        d,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// What `set_agent_chain` sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentChain {
    /// Use this preset (`None`: none, back to the agent's own fallbacks).
    Preset(Option<i64>),
    /// Use these fallbacks of its own, and no preset.
    Entries(Vec<ModelRoute>),
}

/// Sets how `agent` gets its chain and appends `agent.chain_set`; `false` when the agent is
/// gone. A preset of another company is `InvalidArgument`.
pub async fn set_agent_chain(
    pool: &SqlitePool,
    agent: AgentId,
    chain: &AgentChain,
    actor: AuditActor,
) -> Result<bool, Error> {
    if let AgentChain::Entries(routes) = chain {
        // The agent's own fallbacks are audited by `set_fallbacks` too.
        if !super::set_fallbacks(pool, agent, routes, actor).await? {
            return Ok(false);
        }
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let company: Option<i64> = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let preset = match chain {
        AgentChain::Preset(Some(p)) => {
            let of: Option<i64> =
                sqlx::query_scalar("SELECT company_id FROM chain_presets WHERE id = ?")
                    .bind(p)
                    .fetch_optional(&mut *tx)
                    .await?;
            if of != Some(company) {
                return Err(invalid(format!("no preset {p} in the agent's company")));
            }
            Some(*p)
        }
        _ => None,
    };
    sqlx::query("UPDATE agents SET chain_preset_id = ? WHERE id = ?")
        .bind(preset)
        .bind(agent.0)
        .execute(&mut *tx)
        .await?;
    let d = json!({"preset_id": preset});
    let by = ("agent", agent.0);
    append_org_event(&mut tx, CompanyId(company), actor, "agent.chain_set", by, d).await?;
    tx.commit().await?;
    Ok(true)
}

/// The preset `agent` takes its chain from now, if any: its own, else the company's default
/// when it has no fallbacks of its own.
pub async fn effective_preset_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
) -> Result<Option<i64>, Error> {
    sqlx::query_scalar(
        "SELECT coalesce(a.chain_preset_id, CASE WHEN NOT EXISTS \
             (SELECT 1 FROM agent_fallbacks f WHERE f.agent_id = a.id) \
             THEN (SELECT p.id FROM chain_presets p WHERE p.company_id = a.company_id \
                   AND p.is_default = 1) END) FROM agents a WHERE a.id = ?",
    )
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await
    .map(Option::flatten)
}

/// The preset entries as the chain's routes (the account pins are `entries_in`'s).
pub(super) async fn preset_routes_in(
    conn: &mut SqliteConnection,
    preset: i64,
) -> Result<Vec<ModelRoute>, Error> {
    let all = entries_in(conn, preset).await?;
    Ok(all
        .into_iter()
        .map(|e| ModelRoute {
            harness: e.harness,
            model: e.model,
        })
        .collect())
}

/// The agent's effective chain with the pins: its preset's entries, or its own fallbacks.
pub async fn effective_chain(
    pool: &SqlitePool,
    agent: AgentId,
) -> Result<(Option<i64>, Vec<ChainEntry>), Error> {
    let mut conn = pool.acquire().await?;
    let set: Option<i64> = sqlx::query_scalar("SELECT chain_preset_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(&mut *conn)
        .await?
        .flatten();
    match effective_preset_in(&mut conn, agent).await? {
        Some(p) => Ok((set, entries_in(&mut conn, p).await?)),
        None => {
            let own = super::fallbacks::own_fallbacks_in(&mut conn, agent).await?;
            let own = own.into_iter().map(|r| ChainEntry {
                harness: r.harness,
                model: r.model,
                account_id: None,
            });
            Ok((set, own.collect()))
        }
    }
}

/// Test-only: the models of the agent's effective fallbacks.
#[cfg(test)]
pub async fn fallbacks_for_test(pool: &SqlitePool, agent: AgentId) -> Vec<String> {
    let routes = super::fallbacks_in(&mut pool.acquire().await.unwrap(), agent)
        .await
        .unwrap();
    routes.into_iter().map(|r| r.model).collect()
}
