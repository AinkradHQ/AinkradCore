//! AI provider accounts, owned by the Core (KAN-428; design `2026-11-02-ai-provider-accounts` §4,
//! §11b). One account is one API key of one provider.
//!
//! - **Write-only.** The key is stored in the secrets broker under `acct.<provider>.<id>`; the
//!   account row never holds it. Nothing here returns it: [`Account`] has the last four
//!   characters (`masked_tail`, cut once, at write time, outside the broker) and nothing more.
//!   The only readers of the value stay the broker's own: the lease path, `open_for_module` and
//!   `open_for_masking`.
//! - **One transaction.** The row, its broker secret and its audit row commit together
//!   (`secrets::{create,rotate,delete}_in`), so a failed store leaves neither half behind.
//! - **Scope.** Which runners may be leased the key is the broker secret's scope; the row does
//!   not copy it. A scope is an explicit list of active runner devices (the broker refuses
//!   anything else, so there is no wildcard).
//! - **Global.** No company column: Citadel and anything else consume accounts, they do not own them.
//! - **Cap.** `cap` is how many sessions may hold the account at once. A new API-key account
//!   starts at [`DEFAULT_CAP`] (4); 0 turns the cap off. KAN-437 enforces it.
//! - **Audited.** Every change appends an `account.*` row naming the account, never the value.
//!
//! The broker's gates still apply to every store and replacement: `secrets.mode` 0 refuses all
//! of it, and the narrow gate `secrets.provider_accounts` decides whether a real key shape may
//! be stored.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::secrets::{self, Error, NewValue};
use crate::ops::secretbox::SecretBox;

mod create;
pub use create::{create, create_by, create_placed};

/// The cap a new API-key account starts with.
pub const DEFAULT_CAP: i64 = 4;
/// The most a cap may be (0 is off).
pub const MAX_CAP: i64 = 64;
/// The built-in providers (pools are of these only). An account may also name a stored user
/// definition (`account_keys::holds_keys_problem`).
pub const PROVIDERS: [&str; 4] = ["anthropic", "openai", "google", "claude-sub"];
/// The states an account is in.
pub const STATES: [&str; 5] = ["active", "cooling", "limited", "unhealthy", "disabled"];

/// An account as it is read: everything but its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: i64,
    pub provider: String,
    pub label: String,
    /// The provider's base URL when the account was stored; later edits of the definition do not
    /// move it (KAN-429).
    pub base_url: String,
    /// The broker secret holding the key. Internal: an API type must not carry it to a client
    /// that has no use for it (11b: the `read` scope saw it before).
    pub secret_name: String,
    /// The key's last four characters, or nothing when the key is too short to show any.
    pub masked_tail: String,
    pub state: String,
    pub state_reason: Option<String>,
    pub state_until: Option<String>,
    pub cap: i64,
    /// The most one session may spend through this account (`None`: only the budgets limit it);
    /// the Core's ceiling honours it (KAN-435 G7).
    pub session_max_tokens: Option<i64>,
    pub session_max_usd_micros: Option<i64>,
    /// The last one-shot `gateway.test` of the key: when, and the status class it answered.
    pub last_test_at: Option<String>,
    pub last_test_result: Option<String>,
    /// The runner devices the key may be leased to (the broker secret's scope).
    pub runners: Vec<String>,
    /// The device that stored it.
    pub owner: String,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// An account to store. Deliberately no `Debug`: `value` is the key.
pub struct NewAccount<'a> {
    pub provider: &'a str,
    pub label: &'a str,
    pub value: &'a str,
    /// Runner device ids, explicit; empty: no runner may be leased it.
    pub runners: &'a [String],
    /// Default [`DEFAULT_CAP`].
    pub cap: Option<i64>,
}

const COLUMNS: &str = "a.id, a.provider, a.label, a.secret_name, a.masked_tail, a.base_url, a.state, \
    a.state_reason, a.state_until, a.cap, a.owner, a.last_used_at, a.created_at, a.updated_at, \
    a.session_max_tokens, a.session_max_usd_micros, a.last_test_at, a.last_test_result, \
    COALESCE(s.runners, '[]') AS runners";

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

fn row(r: SqliteRow) -> Result<Account, sqlx::Error> {
    let runners: String = r.try_get("runners")?;
    Ok(Account {
        id: r.try_get("id")?,
        provider: r.try_get("provider")?,
        label: r.try_get("label")?,
        secret_name: r.try_get("secret_name")?,
        masked_tail: r.try_get("masked_tail")?,
        base_url: r.try_get("base_url")?,
        state: r.try_get("state")?,
        state_reason: r.try_get("state_reason")?,
        state_until: r.try_get("state_until")?,
        cap: r.try_get("cap")?,
        session_max_tokens: r.try_get("session_max_tokens")?,
        session_max_usd_micros: r.try_get("session_max_usd_micros")?,
        last_test_at: r.try_get("last_test_at")?,
        last_test_result: r.try_get("last_test_result")?,
        runners: serde_json::from_str(&runners).unwrap_or_default(),
        owner: r.try_get("owner")?,
        last_used_at: r.try_get("last_used_at")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// `[a-z][a-z0-9._-]{0,63}`: the label an operator sees, never a path or a secret name.
pub fn valid_label(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn check_cap(cap: i64) -> Result<(), Error> {
    match (0..=MAX_CAP).contains(&cap) {
        true => Ok(()),
        false => refused("bad_request", format!("cap is 0 (off) to {MAX_CAP}")),
    }
}

/// The last four characters of `value`; nothing for a key under 16 characters (a short value
/// would be mostly tail).
fn tail_of(value: &str) -> String {
    let n = value.chars().count();
    match n >= 16 {
        true => value.chars().skip(n - 4).collect(),
        false => String::new(),
    }
}

pub(super) async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    id: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "account".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

pub(super) async fn find(conn: &mut SqliteConnection, id: i64) -> Result<Account, Error> {
    let sql = format!(
        "SELECT {COLUMNS} FROM core_accounts a LEFT JOIN core_secrets s ON s.name = a.secret_name \
         WHERE a.id = ?"
    );
    match sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
    {
        Some(r) => Ok(row(r)?),
        None => refused("not_found", "no such account"),
    }
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Account, Error> {
    let mut conn = pool.acquire().await?;
    find(&mut conn, id).await
}

/// Every account, oldest first.
pub async fn list(pool: &SqlitePool) -> Result<Vec<Account>, sqlx::Error> {
    let sql = format!(
        "SELECT {COLUMNS} FROM core_accounts a LEFT JOIN core_secrets s ON s.name = a.secret_name \
         ORDER BY a.id"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(row)
        .collect()
}

async fn secret_exists(conn: &mut SqliteConnection, name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) > 0 FROM core_secrets WHERE name = ?")
        .bind(name)
        .fetch_one(conn)
        .await
}

/// Replaces the key (and its runner scope, when given): a new broker version, the masked tail
/// cut again, every outstanding lease on the old one dropped.
#[allow(clippy::too_many_arguments)]
pub async fn replace_secret(
    pool: &SqlitePool,
    sealer: &SecretBox,
    id: i64,
    value: &str,
    runners: Option<&[String]>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    let value = value.trim();
    let mut tx = super::begin_write(pool).await?;
    let a = find(&mut tx, id).await?;
    if super::account_keys::subscription_provider(&a.provider) {
        return refused(
            "login_required",
            "a subscription token comes from a sign-in, not a pasted value",
        );
    }
    let new = NewValue {
        value,
        runners,
        delivery: Some("env"),
    };
    // A restored backup or an import can leave the row without its broker secret: the new key
    // then creates it, so the account is never stuck.
    match secret_exists(&mut tx, &a.secret_name).await? {
        true => secrets::rotate_in(&mut tx, sealer, &a.secret_name, &new, by_device, actor, now)
            .await
            .map(drop)?,
        false => secrets::create_in(&mut tx, sealer, &a.secret_name, &new, by_device, actor, now)
            .await
            .map(drop)?,
    }
    sqlx::query("UPDATE core_accounts SET masked_tail = ?, updated_at = ? WHERE id = ?")
        .bind(tail_of(value))
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "account.secret_replaced",
        id,
        json!({"provider": a.provider, "label": a.label, "by_device": by_device}),
    )
    .await?;
    let a = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(a)
}

/// Sets the state (`disabled` takes the account out of use; `active` brings it back). A reason
/// and an end are kept only for a state other than `active`.
#[allow(clippy::too_many_arguments)]
pub async fn set_state(
    pool: &SqlitePool,
    id: i64,
    state: &str,
    reason: Option<&str>,
    until: Option<&str>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    if !STATES.contains(&state) {
        return refused(
            "bad_request",
            "state is active, cooling, limited, unhealthy or disabled",
        );
    }
    // An admin's note stays in the audit row; the state's own reason reads `manual`, so no free
    // text can pass for one of the health module's codes (`store::health`).
    let (reason, until) = match state {
        "active" => (None, None),
        _ => (reason.map(str::trim).filter(|r| !r.is_empty()), until),
    };
    let stored = (state != "active").then_some("manual");
    if reason.is_some_and(|r| r.len() > 200) {
        return refused("bad_request", "a reason is at most 200 bytes");
    }
    let mut tx = super::begin_write(pool).await?;
    if let Some(ts) = until {
        let ok: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
            .bind(ts)
            .fetch_one(&mut *tx)
            .await?;
        if !ok {
            return refused("bad_request", "until is not a timestamp");
        }
    }
    let old = find(&mut tx, id).await?;
    sqlx::query(
        "UPDATE core_accounts SET state = ?, state_reason = ?, state_until = ?, updated_at = ? \
         WHERE id = ?",
    )
    .bind(state)
    .bind(stored)
    .bind(until)
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let mut details = json!({"label": old.label, "from": old.state, "to": state, "reason": reason,
               "until": until, "by_device": by_device});
    if state == "active" {
        // "It's fine" (or any return to active): the health counts start again, and the audit row
        // says what the account was suspected of.
        sqlx::query(
            "UPDATE core_accounts SET fail_streak = 0, auth_streak = 0, backoff_secs = 0, \
             fail_since = NULL, plan_limit = NULL WHERE id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        details["was"] = json!(old.state_reason);
    }
    audit(&mut tx, actor, "account.state_set", id, details).await?;
    if state != "active" && super::account_keys::subscription_provider(&old.provider) {
        super::account_keys::revoke_leases_in(&mut tx, &old.secret_name).await?;
    }
    let a = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(a)
}

/// Sets the concurrency cap (0 is off).
pub async fn set_cap(
    pool: &SqlitePool,
    id: i64,
    cap: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Account, Error> {
    check_cap(cap)?;
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, id).await?;
    sqlx::query("UPDATE core_accounts SET cap = ?, updated_at = ? WHERE id = ?")
        .bind(cap)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "account.cap_set",
        id,
        json!({"label": old.label, "from": old.cap, "to": cap, "by_device": by_device}),
    )
    .await?;
    let a = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(a)
}

/// Deletes the account and its key (with the key's leases).
pub async fn delete(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let a = find(&mut tx, id).await?;
    // The seats the cascade takes with the row, so the audit trail says which pools lost it.
    let pools: Vec<i64> = sqlx::query_scalar(
        "SELECT pool_id FROM core_pool_members WHERE account_id = ? ORDER BY pool_id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM core_accounts WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Its budgets go with it (an id is never reused, so this is cleanup, not safety).
    super::budgets::remove_subject_in(&mut tx, "account", &id.to_string(), by_device, actor)
        .await?;
    // Whatever is left of the key goes with it; a key already gone (stripped restore) is no reason to keep the account.
    if secret_exists(&mut tx, &a.secret_name).await? {
        secrets::delete_in(&mut tx, &a.secret_name, by_device, actor).await?;
    }
    audit(
        &mut tx,
        actor,
        "account.deleted",
        id,
        json!({"provider": a.provider, "label": a.label, "pools": pools, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_is_four_characters_and_only_of_a_long_key() {
        assert_eq!(tail_of("0123456789abcdef"), "cdef");
        assert_eq!(tail_of("0123456789abcde"), "");
        assert_eq!(tail_of("ééééééééééééééééé1"), "ééé1");
    }

    #[test]
    fn labels_are_boundary_validated() {
        assert!(valid_label("claude-main") && valid_label("k1.eu"));
        assert!(
            !valid_label("") && !valid_label("Main") && !valid_label("../x") && !valid_label("a b")
        );
        assert!(!valid_label(&"a".repeat(65)));
    }
}
