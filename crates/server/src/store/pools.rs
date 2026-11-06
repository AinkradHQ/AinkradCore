//! Account pools and bindings (KAN-431; design `2026-11-02-ai-provider-accounts` §4, §6, §11b
//! item 6). A pool groups accounts of ONE provider, ordered; balancing and failover happen inside
//! it and never cross providers. Each provider has at most one default pool (the database says so),
//! which serves an agent bound to none. A binding names an agent (an opaque id) and a pool.
//!
//! Membership, binding, the default and enabling or disabling an account all change who may spend
//! which key, so the routes that call these functions need a step-up (KAN-432); each change is
//! audited here, naming ids and never a value. Attaching an account secret to a session is not
//! done through a pool: it stays admin-only (KAN-433), and a pool picks, it does not grant.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::account_keys;
use super::secrets::Error;

const MAX_POOLS: i64 = 64;
const MAX_MEMBERS: i64 = 64;
const MAX_BINDINGS: i64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub id: i64,
    pub name: String,
    pub provider: String,
    pub is_default: bool,
    /// Account ids, in fallback order.
    pub members: Vec<i64>,
    pub created_at: String,
    pub updated_at: String,
}

fn refused<T>(code: &'static str, message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.to_owned(),
    })
}

/// `[a-z][a-z0-9._-]{0,63}`.
pub fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// An agent id: 1 to 64 of `[A-Za-z0-9._:-]`.
pub fn valid_agent(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    pool: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "pool".to_owned(),
            id: pool,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

async fn members_in(conn: &mut SqliteConnection, pool: i64) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account_id FROM core_pool_members WHERE pool_id = ? ORDER BY position, account_id",
    )
    .bind(pool)
    .fetch_all(&mut *conn)
    .await
}

fn head(r: &SqliteRow) -> Result<Pool, sqlx::Error> {
    Ok(Pool {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        provider: r.try_get("provider")?,
        is_default: r.try_get::<i64, _>("is_default")? == 1,
        members: Vec::new(),
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

const COLUMNS: &str = "id, name, provider, is_default, created_at, updated_at";

async fn find(conn: &mut SqliteConnection, id: i64) -> Result<Pool, Error> {
    let sql = format!("SELECT {COLUMNS} FROM core_pools WHERE id = ?");
    let Some(r) = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
    else {
        return refused("not_found", "no such pool");
    };
    let mut p = head(&r)?;
    p.members = members_in(conn, id).await?;
    Ok(p)
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Pool, Error> {
    let mut conn = pool.acquire().await?;
    find(&mut conn, id).await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<Pool>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let sql = format!("SELECT {COLUMNS} FROM core_pools ORDER BY id");
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *conn)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut p = head(r)?;
        p.members = members_in(&mut conn, p.id).await?;
        out.push(p);
    }
    Ok(out)
}

pub async fn create(
    pool: &SqlitePool,
    name: &str,
    provider: &str,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Pool, Error> {
    if !valid_name(name) {
        return refused("bad_request", "a pool name is [a-z][a-z0-9._-]{0,63}");
    }
    if !super::accounts::PROVIDERS.contains(&provider) {
        return refused(
            "bad_request",
            "provider is anthropic, openai, google or claude-sub",
        );
    }
    let mut tx = super::begin_write(pool).await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_pools")
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_POOLS {
        return refused("limit_reached", "too many pools");
    }
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_pools WHERE name = ?")
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return refused("conflict", "a pool of that name exists");
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_pools (name, provider, created_at, updated_at) VALUES (?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(name)
    .bind(provider)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    audit(
        &mut tx,
        actor,
        "pool.created",
        id,
        json!({"name": name, "provider": provider, "by_device": by_device}),
    )
    .await?;
    let p = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

/// Deletes a pool with its memberships and bindings (the agents fall back to the default). The
/// default pool is not deleted: name another default first. A pool a fallback chain names is
/// refused (`conflict`, naming the chain).
pub async fn delete(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let p = find(&mut tx, id).await?;
    if p.is_default {
        return refused(
            "conflict",
            "the default pool is not deleted; make another pool the default first",
        );
    }
    // A chain that names the pool keeps it (the table says RESTRICT; this says which chain).
    let chains: Vec<String> = sqlx::query_scalar(
        "SELECT c.name FROM core_chains c WHERE c.id IN \
         (SELECT chain_id FROM core_chain_entries WHERE pool_id = ?) ORDER BY c.name",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    if !chains.is_empty() {
        return refused(
            "conflict",
            &format!("the pool is in the fallback chain {}", chains.join(", ")),
        );
    }
    let bound: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_pool_bindings WHERE pool_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM core_pools WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Pool ids are reused (no AUTOINCREMENT): a budget left behind would be inherited by the next pool.
    super::budgets::remove_subject_in(&mut tx, "pool", &id.to_string(), by_device, actor).await?;
    audit(
        &mut tx,
        actor,
        "pool.deleted",
        id,
        json!({"name": p.name, "members": p.members.len(), "bindings_dropped": bound,
               "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Appends `account` to the pool. It must be of the pool's provider, and in no pool twice.
pub async fn add_member(
    pool: &SqlitePool,
    id: i64,
    account: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Pool, Error> {
    let mut tx = super::begin_write(pool).await?;
    let p = find(&mut tx, id).await?;
    let provider: Option<String> =
        sqlx::query_scalar("SELECT provider FROM core_accounts WHERE id = ?")
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?;
    match provider {
        None => return refused("not_found", "no such account"),
        Some(a) if a != p.provider => {
            return refused(
                "bad_request",
                "an account joins only a pool of its own provider",
            );
        }
        Some(_) => {}
    }
    if p.members.contains(&account) {
        return refused("conflict", "the account is already in the pool");
    }
    // A subscription is alone in its pool (Ahmed, 2026-11-05).
    account_keys::check_pool(&mut tx, &p.members, account).await?;
    if p.members.len() as i64 >= MAX_MEMBERS {
        return refused("limit_reached", "the pool is full");
    }
    // After the last seat, not the member count: an account deleted elsewhere leaves a gap.
    sqlx::query(
        "INSERT INTO core_pool_members (pool_id, account_id, position) \
         SELECT ?, ?, COALESCE(MAX(position) + 1, 0) FROM core_pool_members WHERE pool_id = ?",
    )
    .bind(id)
    .bind(account)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE core_pools SET updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "pool.member_added",
        id,
        json!({"account": account, "by_device": by_device}),
    )
    .await?;
    let p = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

/// Removes `account` from the pool; the others keep their order.
pub async fn remove_member(
    pool: &SqlitePool,
    id: i64,
    account: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Pool, Error> {
    let mut tx = super::begin_write(pool).await?;
    let p = find(&mut tx, id).await?;
    if !p.members.contains(&account) {
        return refused("not_found", "the account is not in the pool");
    }
    sqlx::query("DELETE FROM core_pool_members WHERE pool_id = ? AND account_id = ?")
        .bind(id)
        .bind(account)
        .execute(&mut *tx)
        .await?;
    // Close the gap so positions stay 0..n in order.
    for (i, a) in p.members.iter().filter(|a| **a != account).enumerate() {
        sqlx::query(
            "UPDATE core_pool_members SET position = ? WHERE pool_id = ? AND account_id = ?",
        )
        .bind(i as i64)
        .bind(id)
        .bind(a)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE core_pools SET updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "pool.member_removed",
        id,
        json!({"account": account, "by_device": by_device}),
    )
    .await?;
    let p = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

/// Makes the pool its provider's default; the previous default stops being one.
pub async fn set_default(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Pool, Error> {
    let mut tx = super::begin_write(pool).await?;
    let p = find(&mut tx, id).await?;
    let previous: Option<i64> =
        sqlx::query_scalar("SELECT id FROM core_pools WHERE provider = ? AND is_default = 1")
            .bind(&p.provider)
            .fetch_optional(&mut *tx)
            .await?;
    sqlx::query("UPDATE core_pools SET is_default = 0, updated_at = ? WHERE provider = ? AND is_default = 1")
        .bind(now)
        .bind(&p.provider)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE core_pools SET is_default = 1, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "pool.default_set",
        id,
        json!({"provider": p.provider, "previous": previous, "by_device": by_device}),
    )
    .await?;
    let p = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

/// Binds `agent` to the pool for the pool's provider, replacing its earlier binding there.
pub async fn bind(
    pool: &SqlitePool,
    agent: &str,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(), Error> {
    if !valid_agent(agent) {
        return refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]");
    }
    let mut tx = super::begin_write(pool).await?;
    let p = find(&mut tx, id).await?;
    account_keys::check_bind(&p.provider)?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_pool_bindings")
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_BINDINGS {
        return refused("limit_reached", "too many bindings");
    }
    sqlx::query(
        "INSERT INTO core_pool_bindings (agent, provider, pool_id, created_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT (agent, provider) DO UPDATE SET pool_id = excluded.pool_id, \
         created_at = excluded.created_at",
    )
    .bind(agent)
    .bind(&p.provider)
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        actor,
        "pool.bound",
        id,
        json!({"agent": agent, "provider": p.provider, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Drops `agent`'s binding for `provider`; it falls back to the default pool.
pub async fn unbind(
    pool: &SqlitePool,
    agent: &str,
    provider: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let id: Option<i64> = sqlx::query_scalar(
        "DELETE FROM core_pool_bindings WHERE agent = ? AND provider = ? RETURNING pool_id",
    )
    .bind(agent)
    .bind(provider)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(id) = id else {
        return refused("not_found", "that agent has no binding for that provider");
    };
    audit(
        &mut tx,
        actor,
        "pool.unbound",
        id,
        json!({"agent": agent, "provider": provider, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One agent's binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub agent: String,
    pub provider: String,
    pub pool_id: i64,
}

/// Every binding, by agent then provider.
pub async fn list_bindings(pool: &SqlitePool) -> Result<Vec<Binding>, sqlx::Error> {
    sqlx::query("SELECT agent, provider, pool_id FROM core_pool_bindings ORDER BY agent, provider")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| {
            Ok(Binding {
                agent: r.try_get("agent")?,
                provider: r.try_get("provider")?,
                pool_id: r.try_get("pool_id")?,
            })
        })
        .collect()
}
