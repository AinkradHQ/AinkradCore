//! What an account gains from the auth gateway (KAN-435 G7; design §5.1, §5.2, §7.1): which
//! providers may hold a key, the most one session may spend through an account, and the record of
//! the last one-shot `gateway.test`. The account row and its audit are `accounts`'.

use ainkrad_core::audit::AuditActor;
use serde_json::json;

use super::accounts::{Account, audit, find};
use super::gateway::MIN_CEILING_TOKENS;
use super::providers::Definition;
use super::secrets::Error;

/// The most a session limit may be: a typo, not a limit, above it.
const MAX_LIMIT: i64 = 1_000_000_000_000;

fn refused<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.into(),
    })
}

/// Why accounts of `def` hold no key, if they do not: only the gateway serves an API key (design
/// §10 Q4), and a user definition needs the key shape that binds its keys to its host (§5.3).
pub fn holds_keys_problem(def: &Definition) -> Option<&'static str> {
    if !def.delivery.iter().any(|m| m == "gateway") {
        return Some(
            "the provider is not delivered through the gateway, so its accounts hold no key",
        );
    }
    (!def.builtin && def.key_prefix.is_none()).then_some(
        "the provider declares no key_prefix, so its keys cannot be bound to its host: set one first",
    )
}

/// Sets what one session may spend through account `id` (`None`: only the budgets limit it). It
/// raises what a session may spend, so its route needs a step-up. A limit under what one turn
/// needs would start sessions that every request refuses, so it is refused.
pub async fn set_session_limits(
    pool: &sqlx::SqlitePool,
    id: i64,
    tokens: Option<i64>,
    usd_micros: Option<i64>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    let floor = i64::try_from(MIN_CEILING_TOKENS).unwrap_or(i64::MAX);
    if tokens.is_some_and(|t| !(floor..=MAX_LIMIT).contains(&t)) {
        return refused(format!(
            "max_tokens is {floor} (one turn: up to 128000 written and 200000 read) to {MAX_LIMIT}"
        ));
    }
    if usd_micros.is_some_and(|u| !(1..=MAX_LIMIT).contains(&u)) {
        return refused(format!("max_usd_micros is 1 to {MAX_LIMIT}"));
    }
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, id).await?;
    sqlx::query(
        "UPDATE core_accounts SET session_max_tokens = ?, session_max_usd_micros = ?, \
         updated_at = ? WHERE id = ?",
    )
    .bind(tokens)
    .bind(usd_micros)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        actor,
        "account.session_limits_set",
        id,
        json!({"label": old.label,
               "from": {"max_tokens": old.session_max_tokens, "max_usd_micros": old.session_max_usd_micros},
               "to": {"max_tokens": tokens, "max_usd_micros": usd_micros}, "by_device": by_device}),
    )
    .await?;
    let a = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(a)
}

/// Records the outcome of a one-shot test of account `id`'s key: when, and the status class (never
/// provider text). Audited `account.tested`, naming the runner that made it.
#[allow(clippy::too_many_arguments)]
pub async fn record_test(
    pool: &sqlx::SqlitePool,
    id: i64,
    result: &str,
    latency_ms: u64,
    runner: &str,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, id).await?;
    sqlx::query("UPDATE core_accounts SET last_test_at = ?, last_test_result = ? WHERE id = ?")
        .bind(now)
        .bind(result)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "account.tested",
        id,
        json!({"label": old.label, "result": result, "latency_ms": latency_ms,
               "runner": runner, "by_device": by_device}),
    )
    .await?;
    let a = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(a)
}

/// Whether account `id` was tested less than `secs` seconds before `now` (a test that never
/// answered is not recorded, so it does not count).
pub async fn tested_within(
    pool: &sqlx::SqlitePool,
    id: i64,
    now: &str,
    secs: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT coalesce((julianday(?1) - julianday(last_test_at)) * 86400 < ?2, 0) \
         FROM core_accounts WHERE id = ?3",
    )
    .bind(now)
    .bind(secs)
    .bind(id)
    .fetch_optional(pool)
    .await
    .map(|n: Option<bool>| n.unwrap_or(false))
}
