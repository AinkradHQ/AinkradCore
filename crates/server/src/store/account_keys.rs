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

/// Whether `def` is a subscription sign-in (`claude-sub`): a built-in whose only login is the
/// browser plus an approval code. Its account is alone in its pool (Ahmed, 2026-11-05) and is
/// created by a login, never by a pasted value.
pub fn is_subscription(def: &Definition) -> bool {
    def.builtin
        && def.login_methods.iter().any(|m| m == "browser_code")
        && !def.login_methods.iter().any(|m| m == "paste")
}

/// Whether `provider` is a built-in subscription provider.
pub fn subscription_provider(provider: &str) -> bool {
    super::providers::built_in()
        .iter()
        .any(|d| d.id == provider && is_subscription(d))
}

/// Refuses `subscription_pool_alone` when adding `account` to a pool holding `members` would put a
/// subscription account beside another account (either way round).
pub(super) async fn check_pool(
    conn: &mut sqlx::SqliteConnection,
    members: &[i64],
    account: i64,
) -> Result<(), Error> {
    let mut mine = false;
    let mut theirs = false;
    for (id, own) in members.iter().map(|m| (*m, false)).chain([(account, true)]) {
        let provider: Option<String> =
            sqlx::query_scalar("SELECT provider FROM core_accounts WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
        let sub = provider.is_some_and(|p| subscription_provider(&p));
        (mine, theirs) = (mine || (own && sub), theirs || (!own && sub));
    }
    match (mine && !members.is_empty()) || theirs {
        true => Err(Error::Refused {
            code: "subscription_pool_alone",
            message: "a subscription account is alone in its pool".to_owned(),
        }),
        false => Ok(()),
    }
}

/// Whether `name` is the account model's own name for an API-key account the gateway serves
/// (`acct.<provider>.<id>`, not a subscription's: that token is a leased env variable, L5).
pub fn gateway_served(name: &str) -> bool {
    super::gateway::account_secret(name).is_some_and(|(p, _)| !subscription_provider(p))
}

/// Adds what a lease of account secret `name` says about the account to its audit `details`: the
/// account id, and `method=subscription` for a subscription's token. Never a value.
pub(super) fn tag_lease(details: &mut serde_json::Value, name: &str) {
    if let Some((provider, id)) = super::gateway::account_secret(name) {
        details["account"] = json!(id);
        if subscription_provider(provider) {
            details["method"] = json!("subscription");
        }
    }
}

/// Drops the unredeemed leases on `secret_name`: an account taken out of use (disabled, cooling,
/// limited) must not be redeemable from a lease minted before.
pub(super) async fn revoke_leases_in(
    conn: &mut sqlx::SqliteConnection,
    secret_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM core_secret_leases WHERE secret_id = (SELECT id FROM core_secrets WHERE name = ?)",
    )
    .bind(secret_name)
    .execute(conn)
    .await
    .map(drop)
}

/// Drops every unredeemed lease on `secret_name` (an account that is not active leases nothing).
pub async fn revoke_leases(pool: &sqlx::SqlitePool, secret_name: &str) -> Result<(), sqlx::Error> {
    revoke_leases_in(&mut *pool.acquire().await?, secret_name).await
}

/// A subscription pool is never bound to an agent: an agent names its subscription account itself
/// (a session's secret), and nothing picks or fails over between accounts (a subscription is never
/// pooled). If binding is ever opened, `resolve` must refuse a pool of other than exactly one
/// member and never fail over.
pub(super) fn check_bind(provider: &str) -> Result<(), Error> {
    match subscription_provider(provider) {
        true => Err(Error::Refused {
            code: "bad_request",
            message:
                "a subscription pool is never bound to an agent: a session names its subscription \
                account itself, and nothing fails over between accounts"
                    .to_owned(),
        }),
        false => Ok(()),
    }
}

/// Why accounts of `def` hold no key, if they do not: only the gateway serves an API key (design
/// §10 Q4), and a user definition needs the key shape that binds its keys to its host (§5.3).
pub fn holds_keys_problem(def: &Definition) -> Option<&'static str> {
    // A subscription's token is a leased env variable (§5), signed in through a login.
    if !def.delivery.iter().any(|m| m == "gateway") && !is_subscription(def) {
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

/// Drops lease `lease` if no runner has redeemed it: a test that was sent and never answered must
/// not leave a live lease against its runner's cap. A redeemed lease is already spent.
pub async fn revoke_unused_lease(pool: &sqlx::SqlitePool, lease: &str) -> Result<(), sqlx::Error> {
    let hash = ring::digest::digest(&ring::digest::SHA256, lease.as_bytes());
    sqlx::query("DELETE FROM core_secret_leases WHERE hash = ? AND used_at IS NULL")
        .bind(hash.as_ref())
        .execute(pool)
        .await
        .map(drop)
}
