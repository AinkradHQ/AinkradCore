//! Where a new account goes (N40, N29, N35 K2): into its provider's default pool (made when
//! missing), and that pool into the user's default chain (made when missing), so a connected
//! account serves agents at once. It runs inside the transaction that stores the account, so a
//! half-done setup cannot remain. A subscription account is alone in its pool (the Core's rule),
//! so it gets a pool of its own when the default one is taken.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::SqliteConnection;

use super::account_keys;
use super::accounts::Account;
use super::chains::{self, EntrySpec};
use super::secrets::Error;

/// The default monthly dollar limit of a new key account (N35 K2), in micro-dollars.
pub const DEFAULT_MONTHLY_USD_MICROS: i64 = 20_000_000;

/// What the caller chose; every field optional, the defaults need no questions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Placement {
    pub user: i64,
    /// An existing pool of the account's provider; default: the provider's default pool.
    pub pool: Option<i64>,
    /// An existing chain; default: the user's default chain.
    pub chain: Option<i64>,
    /// 0-based seat of the pool in the chain; default: last.
    pub position: Option<usize>,
    /// Monthly dollar limit; `None`: [`DEFAULT_MONTHLY_USD_MICROS`], `Some(0)`: no limit.
    pub monthly_usd_micros: Option<i64>,
}

fn refused<T>(code: &'static str, m: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: m.into(),
    })
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    kind: &str,
    action: &str,
    id: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// The default pool's name for a provider (a pool name is lowercase).
fn default_pool_name(provider: &str) -> &str {
    match provider {
        "claude-sub" => "claude-plan",
        p => p,
    }
}

/// Puts the just-stored `a` into a pool, the pool into a chain, and gives a key account its
/// default monthly limit. Returns the pool id and the chain id (if any chain took it).
pub async fn place(
    tx: &mut SqliteConnection,
    a: &Account,
    p: &Placement,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(i64, Option<i64>), Error> {
    let subscription = account_keys::subscription_provider(&a.provider);
    let pool = match p.pool {
        Some(id) => explicit_pool(tx, a, p.user, id).await?,
        None => default_pool(tx, a, p.user, subscription, by_device, actor, now).await?,
    };
    let members: Vec<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_pool_members WHERE pool_id = ?")
            .bind(pool)
            .fetch_all(&mut *tx)
            .await?;
    account_keys::check_pool(tx, &members, a.id).await?;
    if members.len() >= 64 {
        return refused("limit_reached", "the pool is full");
    }
    sqlx::query(
        "INSERT INTO core_pool_members (user_id, pool_id, account_id, position) \
         SELECT ?, ?, ?, COALESCE(MAX(position) + 1, 0) FROM core_pool_members WHERE pool_id = ?",
    )
    .bind(p.user)
    .bind(pool)
    .bind(a.id)
    .bind(pool)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE core_pools SET updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(pool)
        .execute(&mut *tx)
        .await?;
    audit(
        tx,
        actor,
        "pool",
        "pool.member_added",
        pool,
        json!({"account": a.id, "by_device": by_device}),
    )
    .await?;
    let chain = into_chain(tx, a, p, pool, by_device, actor, now).await?;
    let cap = p.monthly_usd_micros.unwrap_or(DEFAULT_MONTHLY_USD_MICROS);
    // A subscription spends plan quota, not dollars: a dollar limit would mean nothing.
    if !subscription && cap > 0 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO core_budgets (subject_kind, subject_id, period, token_cap, \
             usd_cap_micros, hard_stop, created_at, updated_at) \
             VALUES ('account', ?, 'month', 0, ?, 1, ?, ?) RETURNING id",
        )
        .bind(a.id.to_string())
        .bind(cap)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        super::budgets::audit_in(
            tx,
            actor,
            "budget.created",
            id,
            json!({"kind": "account", "subject": a.id.to_string(), "period": "month",
                   "usd_cap_micros": cap, "default": p.monthly_usd_micros.is_none(),
                   "by_device": by_device}),
        )
        .await?;
    }
    Ok((pool, chain))
}

async fn explicit_pool(
    tx: &mut SqliteConnection,
    a: &Account,
    user: i64,
    id: i64,
) -> Result<i64, Error> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT provider, user_id FROM core_pools WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match row {
        Some((provider, owner)) if owner == user => match provider == a.provider {
            true => Ok(id),
            false => refused(
                "bad_request",
                "an account joins only a pool of its own provider",
            ),
        },
        _ => refused("not_found", format!("no pool {id}")),
    }
}

/// The provider's default pool; made when missing. A subscription account whose default pool is
/// taken gets a new, non-default pool.
async fn default_pool(
    tx: &mut SqliteConnection,
    a: &Account,
    user: i64,
    subscription: bool,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<i64, Error> {
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT p.id FROM core_pools p WHERE p.provider = ? AND p.user_id = ? AND p.is_default = 1 \
         AND (? = 0 OR NOT EXISTS (SELECT 1 FROM core_pool_members m WHERE m.pool_id = p.id))",
    )
    .bind(&a.provider)
    .bind(user)
    .bind(subscription)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let has_default: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_pools WHERE provider = ? AND is_default = 1")
            .bind(&a.provider)
            .fetch_one(&mut *tx)
            .await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_pools")
        .fetch_one(&mut *tx)
        .await?;
    if n >= 64 {
        return refused("limit_reached", "too many pools");
    }
    let base = default_pool_name(&a.provider);
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_pools WHERE name = ?")
        .bind(base)
        .fetch_one(&mut *tx)
        .await?;
    let name = match taken {
        0 => base.to_owned(),
        _ => format!("{base}-{}", a.id),
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_pools (user_id, name, provider, is_default, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(user)
    .bind(&name)
    .bind(&a.provider)
    .bind(i64::from(has_default == 0))
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    audit(
        tx,
        actor,
        "pool",
        "pool.created",
        id,
        json!({"name": name, "provider": a.provider, "by_device": by_device, "default": has_default == 0}),
    )
    .await?;
    Ok(id)
}

/// Appends (or inserts at `position`) the pool to the chain, making the user's default chain
/// when none exists. A chain the caller did not name is left alone when it cannot take the pool
/// (full, or a harness a chain does not run): the account still works through its pool.
async fn into_chain(
    tx: &mut SqliteConnection,
    a: &Account,
    p: &Placement,
    pool: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Option<i64>, Error> {
    let named = p.chain.is_some();
    let chain: Option<(i64, bool)> = match p.chain {
        Some(id) => {
            let r: Option<i64> =
                sqlx::query_scalar("SELECT id FROM core_chains WHERE id = ? AND user_id = ?")
                    .bind(id)
                    .bind(p.user)
                    .fetch_optional(&mut *tx)
                    .await?;
            match r {
                Some(id) => Some((id, false)),
                None => return refused("not_found", format!("no chain {id}")),
            }
        }
        None => sqlx::query_scalar::<_, i64>(
            "SELECT id FROM core_chains WHERE user_id = ? AND is_default = 1",
        )
        .bind(p.user)
        .fetch_optional(&mut *tx)
        .await?
        .map(|id| (id, false)),
    };
    let (id, existing) = match chain {
        Some((id, _)) => (Some(id), chains::load(tx, id).await?),
        None => (None, Vec::new()),
    };
    if existing.iter().any(|e| e.pool == pool) {
        return Ok(id);
    }
    let mut specs: Vec<EntrySpec<'_>> = existing
        .iter()
        .map(|e| EntrySpec {
            pool: e.pool,
            model: e.model.as_deref(),
            harness: None,
        })
        .collect();
    let at = p.position.map_or(specs.len(), |i| i.min(specs.len()));
    specs.insert(
        at,
        EntrySpec {
            pool,
            model: None,
            harness: None,
        },
    );
    let entries = match chains::check_entries(tx, p.user, &specs).await {
        Ok(e) => e,
        Err(Error::Refused {
            code: "bad_request",
            ..
        }) if !named => return Ok(id),
        Err(e) => return Err(e),
    };
    let (chain_id, is_new) = match id {
        Some(id) => (id, false),
        None => {
            let taken: i64 =
                sqlx::query_scalar("SELECT count(*) FROM core_chains WHERE name = 'default'")
                    .fetch_one(&mut *tx)
                    .await?;
            let name = if taken == 0 {
                "default".to_owned()
            } else {
                format!("default-{}", a.id)
            };
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO core_chains (user_id, name, is_default, created_at, updated_at) \
                 VALUES (?, ?, 1, ?, ?) RETURNING id",
            )
            .bind(p.user)
            .bind(name)
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            (id, true)
        }
    };
    chains::write_entries(tx, chain_id, p.user, &entries).await?;
    if !is_new {
        sqlx::query("UPDATE core_chains SET updated_at = ? WHERE id = ?")
            .bind(now)
            .bind(chain_id)
            .execute(&mut *tx)
            .await?;
    }
    let action = if is_new {
        "chain.created"
    } else {
        "chain.updated"
    };
    audit(
        tx,
        actor,
        "chain",
        action,
        chain_id,
        json!({"pool": pool, "position": at, "account": a.id, "by_device": by_device}),
    )
    .await?;
    Ok(Some(chain_id))
}
