//! Fallback chains (KAN-437 family, S5; design `2026-11-06-core-account-scheduler` §4.1, §4.2, §4.5;
//! `2026-11-02-ai-provider-accounts` "Decision update 2026-11-06"). A chain is an ORDERED list of
//! 1 to 4 entries, each a pool and a model, across providers and account types. The entry's
//! harness is its pool provider's own, read at [`load`] (a stored copy could go stale). Pools still
//! choose accounts (the allocator); a chain only says which pool is tried next.
//!
//! - **Validation on write** ([`create`], [`update`]): 1 to 4 entries; no pool twice; each pool
//!   exists and is the chain's user's; the pool's harness is `claude`, `codex` or `agy` (never
//!   `opencode`: it has no account binding); a named harness is the pool's own; a model is a valid
//!   id, and an API-key pool's model has a price (the gateway refuses an unpriced one anyway; this
//!   says why sooner); at most one subscription pool per chain (Ahmed, 2026-11-06, decision 1).
//!   A subscription is alone in its pool (`pools::add_member`), so that is one subscription account.
//! - **Deletion.** A chain a live session walks is not deleted (`conflict`). A pool a chain names is
//!   not deleted (`pools::delete`, `conflict` naming the chain). An account deleted from under a
//!   chain only empties its seat in the pool; the entry stays, and the allocator skips an empty pool.
//! - **A session's chain** ([`create_session`], [`assign_in`]): the session row gets `chain_id`,
//!   `agent` and a SNAPSHOT of the resolved entries in the same transaction that inserts it, so an
//!   edit never moves a running run and a chain row is never visible without its chain.
//! - Every write is audited `chain.*`, naming ids, names and models, never a value.
//!
//! The routes that call the writes need admin and a step-up (S7); nothing here checks a device.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::secrets::Error;
use super::{account_keys, costs, pools, prices, providers};

pub const MAX_CHAINS: i64 = 64;
pub const MAX_ENTRIES: usize = 4;
/// Per user, as are the bindings below.
const MAX_BINDINGS: i64 = 1024;

mod assign;
mod view;
pub use assign::*;
pub use view::*;

/// One step of a chain, resolved: the allocator's own `Entry` (`{pool, provider, harness, model}`),
/// so the snapshot a session stores in `core_agent_sessions.chain` is the JSON `pick_in` reads.
pub use super::alloc::Entry as ChainEntry;

/// An entry as a caller writes it. `harness`, when given, must be the pool's own.
#[derive(Debug, Clone, Copy)]
pub struct EntrySpec<'a> {
    pub pool: i64,
    pub model: Option<&'a str>,
    pub harness: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub is_default: bool,
    pub entries: Vec<ChainEntry>,
    pub created_at: String,
    pub updated_at: String,
}

/// One agent's binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub user_id: i64,
    pub agent: String,
    pub chain_id: i64,
}

/// What a new session asks of the chains (design §4.5): its user, and the chain or agent it names.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub user_id: i64,
    pub chain: Option<i64>,
    pub agent: Option<&'a str>,
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    chain: i64,
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "chain".to_owned(),
            id: chain,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

fn shown(entries: &[ChainEntry]) -> Value {
    entries
        .iter()
        .map(|e| json!({"pool": e.pool, "harness": e.harness, "model": e.model}))
        .collect()
}

/// The entries of `chain_id` in fallback order, each with its provider and harness. `not_found`
/// for a chain with no entries (every chain has one or more).
pub async fn load(conn: &mut SqliteConnection, chain_id: i64) -> Result<Vec<ChainEntry>, Error> {
    let rows: Vec<(i64, Option<String>, String)> = sqlx::query_as(
        "SELECT e.pool_id, e.model, p.provider FROM core_chain_entries e \
         JOIN core_pools p ON p.id = e.pool_id WHERE e.chain_id = ? ORDER BY e.position",
    )
    .bind(chain_id)
    .fetch_all(&mut *conn)
    .await?;
    if rows.is_empty() {
        return refused("not_found", "no such chain");
    }
    let mut out = Vec::with_capacity(rows.len());
    for (pool, model, provider) in rows {
        let harness = providers::get_in(conn, &provider).await?.harness;
        out.push(ChainEntry {
            pool,
            provider,
            harness,
            model,
        });
    }
    Ok(out)
}

/// Checks `specs` (see the module doc) and resolves them.
async fn check_entries(
    conn: &mut SqliteConnection,
    user: i64,
    specs: &[EntrySpec<'_>],
) -> Result<Vec<ChainEntry>, Error> {
    if !(1..=MAX_ENTRIES).contains(&specs.len()) {
        return refused("bad_request", "a chain has 1 to 4 entries");
    }
    let mut out: Vec<ChainEntry> = Vec::with_capacity(specs.len());
    let mut subscriptions = 0;
    for s in specs {
        if out.iter().any(|e| e.pool == s.pool) {
            return refused("bad_request", "a pool is in a chain once");
        }
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT provider, user_id FROM core_pools WHERE id = ?")
                .bind(s.pool)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((provider, owner)) = row else {
            return refused("not_found", format!("no pool {}", s.pool));
        };
        if owner != user {
            return refused("bad_request", "a chain names only its own user's pools");
        }
        let def = providers::get_in(conn, &provider).await?;
        if !costs::HARNESSES.contains(&def.harness.as_str()) || def.harness == "opencode" {
            return refused("bad_request", "a chain runs claude, codex or agy pools");
        }
        if s.harness.is_some_and(|h| h != def.harness) {
            return refused("bad_request", "an entry's harness is its pool's own");
        }
        let subscription = account_keys::is_subscription(&def);
        subscriptions += i32::from(subscription);
        if let Some(m) = s.model {
            if !prices::valid_model(m) {
                return refused("bad_request", "a model id is 1 to 80 of [A-Za-z0-9._:/-]");
            }
            if !subscription && prices::rates_in(conn, &provider, m).await?.is_none() {
                return refused("bad_request", "an API-key pool's model needs a price");
            }
        }
        out.push(ChainEntry {
            pool: s.pool,
            provider,
            harness: def.harness,
            model: s.model.map(str::to_owned),
        });
    }
    if subscriptions > 1 {
        return refused("bad_request", "a chain holds at most one subscription");
    }
    Ok(out)
}

async fn write_entries(
    conn: &mut SqliteConnection,
    chain: i64,
    user: i64,
    entries: &[ChainEntry],
) -> Result<(), Error> {
    sqlx::query("DELETE FROM core_chain_entries WHERE chain_id = ?")
        .bind(chain)
        .execute(&mut *conn)
        .await?;
    for (i, e) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO core_chain_entries (user_id, chain_id, position, pool_id, model) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user)
        .bind(chain)
        .bind(i as i64)
        .bind(e.pool)
        .bind(&e.model)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn find(conn: &mut SqliteConnection, id: i64) -> Result<Chain, Error> {
    let row: Option<(i64, String, i64, String, String)> = sqlx::query_as(
        "SELECT user_id, name, is_default, created_at, updated_at FROM core_chains WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((user_id, name, is_default, created_at, updated_at)) = row else {
        return refused("not_found", "no such chain");
    };
    Ok(Chain {
        id,
        user_id,
        name,
        is_default: is_default == 1,
        entries: load(conn, id).await?,
        created_at,
        updated_at,
    })
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Chain, Error> {
    find(&mut *pool.acquire().await?, id).await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<Chain>, Error> {
    let mut conn = pool.acquire().await?;
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM core_chains ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(find(&mut conn, id).await?);
    }
    Ok(out)
}

/// Stores a chain of `user_id`'s: `chain.created`.
pub async fn create(
    pool: &SqlitePool,
    user_id: i64,
    name: &str,
    specs: &[EntrySpec<'_>],
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Chain, Error> {
    if !pools::valid_name(name) {
        return refused("bad_request", "a chain name is [a-z][a-z0-9._-]{0,63}");
    }
    let mut tx = super::begin_write(pool).await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_chains WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_CHAINS {
        return refused("limit_reached", "too many chains");
    }
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_chains WHERE name = ?")
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return refused("conflict", "a chain of that name exists");
    }
    let entries = check_entries(&mut tx, user_id, specs).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_chains (user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(user_id)
    .bind(name)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    write_entries(&mut tx, id, user_id, &entries).await?;
    let details = json!({"name": name, "entries": shown(&entries), "by_device": by_device});
    audit(&mut tx, actor, "chain.created", id, details).await?;
    let c = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// Replaces the name and the WHOLE entry list: `chain.updated`. A run already walking the chain
/// keeps its snapshot.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    name: &str,
    specs: &[EntrySpec<'_>],
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Chain, Error> {
    if !pools::valid_name(name) {
        return refused("bad_request", "a chain name is [a-z][a-z0-9._-]{0,63}");
    }
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, id).await?;
    let taken: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_chains WHERE name = ? AND id != ?")
            .bind(name)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if taken > 0 {
        return refused("conflict", "a chain of that name exists");
    }
    let entries = check_entries(&mut tx, old.user_id, specs).await?;
    sqlx::query("UPDATE core_chains SET name = ?, updated_at = ? WHERE id = ?")
        .bind(name)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    write_entries(&mut tx, id, old.user_id, &entries).await?;
    let details = json!({"name": name, "was": old.name, "from": shown(&old.entries),
                         "to": shown(&entries), "by_device": by_device});
    audit(&mut tx, actor, "chain.updated", id, details).await?;
    let c = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// Deletes a chain with its entries and bindings: `chain.deleted`. A chain a live session walks
/// is refused (`conflict`).
pub async fn delete(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let c = find(&mut tx, id).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions \
         WHERE chain_id = ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if live > 0 {
        return refused("conflict", format!("{live} live session(s) walk the chain"));
    }
    let bound: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_chain_bindings WHERE chain_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM core_chains WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"name": c.name, "entries": c.entries.len(), "bindings_dropped": bound,
                         "by_device": by_device});
    audit(&mut tx, actor, "chain.deleted", id, details).await?;
    tx.commit().await?;
    Ok(())
}

/// Makes the chain its user's default; the previous default stops being one: `chain.default_set`.
pub async fn set_default(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Chain, Error> {
    let mut tx = super::begin_write(pool).await?;
    let c = find(&mut tx, id).await?;
    let previous: Option<i64> =
        sqlx::query_scalar("SELECT id FROM core_chains WHERE user_id = ? AND is_default = 1")
            .bind(c.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    sqlx::query("UPDATE core_chains SET is_default = 0, updated_at = ? WHERE user_id = ? AND is_default = 1")
        .bind(now)
        .bind(c.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE core_chains SET is_default = 1, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"previous": previous, "by_device": by_device});
    audit(&mut tx, actor, "chain.default_set", id, details).await?;
    let c = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(c)
}
