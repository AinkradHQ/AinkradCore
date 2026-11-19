//! The AI order (E7-1, D-18): what a person sees of chains and pools. One ordered list of accounts,
//! each with an optional model; the first account that is ready serves a new session and the next
//! takes over when it fails. Underneath it is the machinery that already exists: every account in
//! the order sits in its own HIDDEN single-account pool, and the list is a chain's entries
//! (up to 16), so the allocator and failover are untouched.
//!
//! - **One default order** per user: the user's default chain ([`get`], [`set`] with no agent). When
//!   there is none, `set` makes a hidden one. An older default chain whose pools hold several accounts
//!   reads as a flat list (each pool's members in order) and is rewritten as single-account pools on
//!   the first `set`: no data migration.
//! - **A per-agent override** (the Advanced part) is a hidden chain bound to the agent
//!   ([`set`] with an agent, [`clear_agent`]); an agent without one walks the default order.
//! - **Trust.** An account must exist (accounts carry no per-user owner); the chain rules of [`super::check_entries`] apply (harness, model price). A write
//!   changes which key a run spends next, so its route needs a step-up. It is audited `chain.*`
//!   with ids and models, never a value. An account deleted from under the order leaves an empty
//!   hidden pool the allocator skips; [`get`] does not list it and the next `set` drops it.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::{
    ChainEntry, EntrySpec, audit, check_entries, find, load, refused, shown, write_entries,
};
use crate::store::pools;
use crate::store::secrets::Error;

/// One account of an order, as a caller writes it.
#[derive(Debug, Clone, Copy)]
pub struct Spec<'a> {
    pub account: i64,
    pub model: Option<&'a str>,
}

/// One account of an order, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub account: i64,
    pub provider: String,
    pub harness: String,
    pub model: Option<String>,
}

/// An agent's own order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub agent: String,
    pub items: Vec<Item>,
}

/// The default order and the per-agent overrides.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Order {
    pub items: Vec<Item>,
    pub overrides: Vec<Override>,
}

/// A chain's entries as accounts: each pool's members in order, with the entry's model. A pool
/// with no member (its account was deleted) contributes nothing.
async fn flatten(conn: &mut SqliteConnection, chain: i64) -> Result<Vec<Item>, Error> {
    let entries = match load(conn, chain).await {
        Ok(e) => e,
        Err(Error::Refused {
            code: "not_found", ..
        }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for e in entries {
        let members: Vec<i64> = sqlx::query_scalar(
            "SELECT account_id FROM core_pool_members WHERE pool_id = ? \
             ORDER BY position, account_id",
        )
        .bind(e.pool)
        .fetch_all(&mut *conn)
        .await?;
        for account in members {
            out.push(Item {
                account,
                provider: e.provider.clone(),
                harness: e.harness.clone(),
                model: e.model.clone(),
            });
        }
    }
    Ok(out)
}

async fn default_chain(conn: &mut SqliteConnection, user: i64) -> Result<Option<i64>, Error> {
    Ok(
        sqlx::query_scalar("SELECT id FROM core_chains WHERE user_id = ? AND is_default = 1")
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// The agent's bound chain, when it is `user`'s.
async fn agent_chain(
    conn: &mut SqliteConnection,
    user: i64,
    agent: &str,
) -> Result<Option<(i64, bool)>, Error> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT c.id, c.hidden FROM core_chain_bindings b JOIN core_chains c ON c.id = b.chain_id \
         WHERE b.user_id = ? AND b.agent = ? AND c.user_id = ?",
    )
    .bind(user)
    .bind(agent)
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id, hidden)| (id, hidden == 1)))
}

/// The user's order and overrides.
pub async fn get(pool: &SqlitePool, user: i64) -> Result<Order, Error> {
    let mut conn = pool.acquire().await?;
    let items = match default_chain(&mut conn, user).await? {
        Some(c) => flatten(&mut conn, c).await?,
        None => Vec::new(),
    };
    let bound: Vec<(String, i64)> = sqlx::query_as(
        "SELECT b.agent, b.chain_id FROM core_chain_bindings b \
         JOIN core_chains c ON c.id = b.chain_id \
         WHERE b.user_id = ? AND c.user_id = ? AND c.hidden = 1 ORDER BY b.agent",
    )
    .bind(user)
    .bind(user)
    .fetch_all(&mut *conn)
    .await?;
    let mut overrides = Vec::with_capacity(bound.len());
    for (agent, chain) in bound {
        overrides.push(Override {
            agent,
            items: flatten(&mut conn, chain).await?,
        });
    }
    Ok(Order { items, overrides })
}

/// A new row's id, so its name (`order-<id>`) cannot meet a live one's.
async fn next_id(conn: &mut SqliteConnection, table: &str) -> Result<i64, Error> {
    let sql = format!("SELECT COALESCE(MAX(id), 0) + 1 FROM {table}");
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&mut *conn)
        .await?)
}

/// The hidden pool that holds `account` alone; made when missing.
pub(crate) async fn pool_for(
    conn: &mut SqliteConnection,
    user: i64,
    account: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<i64, Error> {
    // Accounts are the server's (the account rows carry no per-user owner), so only existence is checked.
    let provider: Option<String> =
        sqlx::query_scalar("SELECT provider FROM core_accounts WHERE id = ?")
            .bind(account)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(provider) = provider else {
        return refused("not_found", format!("no account {account}"));
    };
    let held: Option<i64> = sqlx::query_scalar(
        "SELECT p.id FROM core_pools p JOIN core_pool_members m ON m.pool_id = p.id \
         WHERE p.hidden = 1 AND p.user_id = ? AND m.account_id = ?",
    )
    .bind(user)
    .bind(account)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = held {
        return Ok(id);
    }
    let id = next_id(conn, "core_pools").await?;
    sqlx::query(
        "INSERT INTO core_pools (id, user_id, name, provider, is_default, hidden, created_at, \
         updated_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("order-{id}"))
    .bind(&provider)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO core_pool_members (user_id, pool_id, account_id, position) VALUES (?, ?, ?, 0)",
    )
    .bind(user)
    .bind(id)
    .bind(account)
    .execute(&mut *conn)
    .await?;
    let event = ainkrad_core::audit::NewAuditEvent {
        actor,
        action: "pool.created".to_owned(),
        entity: Some(ainkrad_core::audit::AuditEntity {
            kind: "pool".to_owned(),
            id,
        }),
        details: json!({"name": format!("order-{id}"), "provider": provider, "account": account,
                        "hidden": true, "by_device": by_device})
        .to_string(),
    };
    crate::store::audit::append(conn, &event).await?;
    Ok(id)
}

/// A hidden chain of `user`'s, empty until [`write_entries`] fills it.
async fn new_chain(
    conn: &mut SqliteConnection,
    user: i64,
    prefix: &str,
    default: bool,
    now: &str,
) -> Result<i64, Error> {
    let id = next_id(conn, "core_chains").await?;
    sqlx::query(
        "INSERT INTO core_chains (id, user_id, name, is_default, hidden, created_at, updated_at) \
         VALUES (?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(id)
    .bind(user)
    .bind(format!("{prefix}-{id}"))
    .bind(i64::from(default))
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

/// Replaces the user's default order, or `agent`'s override, with `specs` (1 to 16 accounts, none
/// twice): `chain.created` or `chain.updated`. A run already walking the chain keeps its snapshot.
pub async fn set(
    pool: &SqlitePool,
    user: i64,
    agent: Option<&str>,
    specs: &[Spec<'_>],
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Vec<Item>, Error> {
    if agent.is_some_and(|a| !pools::valid_agent(a)) {
        return refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]");
    }
    if specs
        .iter()
        .enumerate()
        .any(|(i, s)| specs[..i].iter().any(|t| t.account == s.account))
    {
        return refused("bad_request", "an account is in the order once");
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let mut entry_specs = Vec::with_capacity(specs.len());
    for s in specs {
        let pool = pool_for(&mut tx, user, s.account, by_device, actor, now).await?;
        entry_specs.push(EntrySpec {
            pool,
            model: s.model,
            harness: None,
        });
    }
    let entries: Vec<ChainEntry> = check_entries(&mut tx, user, &entry_specs).await?;
    let (chain, was, created) = match agent {
        None => match default_chain(&mut tx, user).await? {
            Some(id) => (id, Some(find(&mut tx, id).await?.entries), false),
            None => (
                new_chain(&mut tx, user, "ai-order", true, now).await?,
                None,
                true,
            ),
        },
        Some(a) => match agent_chain(&mut tx, user, a).await? {
            Some((id, true)) => (id, Some(find(&mut tx, id).await?.entries), false),
            // Bound to a chain the person made (or to none): the override is its own hidden chain.
            _ => {
                let id = new_chain(&mut tx, user, "agent-order", false, now).await?;
                sqlx::query(
                    "INSERT INTO core_chain_bindings (user_id, agent, chain_id, created_at) \
                     VALUES (?, ?, ?, ?) ON CONFLICT (user_id, agent) DO UPDATE SET \
                     chain_id = excluded.chain_id, created_at = excluded.created_at",
                )
                .bind(user)
                .bind(a)
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                (id, None, true)
            }
        },
    };
    write_entries(&mut tx, chain, user, &entries).await?;
    if !created {
        sqlx::query("UPDATE core_chains SET updated_at = ? WHERE id = ?")
            .bind(now)
            .bind(chain)
            .execute(&mut *tx)
            .await?;
    }
    let mut details = json!({"to": shown(&entries), "agent": agent, "order": true,
                             "by_device": by_device});
    if let Some(was) = was {
        details["from"] = shown(&was);
    }
    let action = if created {
        "chain.created"
    } else {
        "chain.updated"
    };
    audit(&mut tx, actor, action, chain, details).await?;
    let items = flatten(&mut tx, chain).await?;
    tx.commit().await?;
    Ok(items)
}

/// Drops `agent`'s override: it walks the default order again (`chain.unbound`). A hidden chain no
/// live session walks is deleted with it. `not_found` when the agent has no override.
pub async fn clear_agent(
    pool: &SqlitePool,
    user: i64,
    agent: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some((chain, true)) = agent_chain(&mut tx, user, agent).await? else {
        return refused("not_found", "that agent has no override");
    };
    sqlx::query("DELETE FROM core_chain_bindings WHERE user_id = ? AND agent = ?")
        .bind(user)
        .bind(agent)
        .execute(&mut *tx)
        .await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions WHERE chain_id = ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(chain)
    .fetch_one(&mut *tx)
    .await?;
    if live == 0 {
        sqlx::query("DELETE FROM core_chains WHERE id = ?")
            .bind(chain)
            .execute(&mut *tx)
            .await?;
    }
    audit(
        &mut tx,
        actor,
        "chain.unbound",
        chain,
        json!({"agent": agent, "order": true, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
