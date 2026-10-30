//! The provider account pool (S9, E15.1): subscription and metered accounts per harness,
//! mapped to at most ONE broker secret (`ainkrad_core_server::store::secrets`) with delivery type
//! and runner list, assigned to companies, with rolling usage limits and cooldown status.
//!
//! No credential values, file paths, or environment variable names are stored in Citadel tables:
//! `citadel_accounts` holds `secret_name`, and live `delivery`/`runners` come from the Core
//! secrets broker when the secret exists in `core_secrets`.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::{begin_write, secrets};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::{SqliteConnection, SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use crate::domain::gov::{AccountId, AccountStatus, Billing, PlanTier};
use crate::domain::org::{CompanyId, Harness};
use crate::store::audit::{Event, append};
use crate::store::org::{affected, text};

mod limits;
mod usage;
pub use limits::*;
pub use usage::*;

/// What a runner's harness reported about the account's quota on its last run (E15.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSignal {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "tier_text")]
    pub plan_tier: Option<PlanTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub at: String,
}

mod tier_text {
    use super::PlanTier;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Option<PlanTier>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(t.map_or("", PlanTier::as_str))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<PlanTier>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|t| t.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// An account before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub harness: Harness,
    pub label: String,
    pub billing: Billing,
    pub config_dir: Option<String>,
    pub secret_name: Option<String>,
    pub delivery: Option<String>,
    pub runners: Option<Vec<String>>,
    /// When true, `secret_name` must already exist in `core_secrets`.
    pub require_broker_secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub harness: Harness,
    pub label: String,
    pub secret_name: String,
    pub delivery: String,
    pub runners: Vec<String>,
    pub billing: Billing,
    pub config_dir: String,
    pub status: AccountStatus,
    pub status_reason: Option<String>,
    pub status_until: Option<String>,
    pub last_used_at: Option<String>,
    pub plan_tier: Option<PlanTier>,
    pub signal: Option<AccountSignal>,
    pub created_at: String,
    pub company_ids: Vec<CompanyId>,
}

macro_rules! account_columns {
    () => {
        "id, harness, label, secret_name, delivery, runners, billing, config_dir, status, \
         status_reason, status_until, last_used_at, plan_tier, signal, created_at"
    };
}

pub(crate) use account_columns;

pub fn valid_label(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn valid_dir(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('/')
        && !s
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.chars().any(char::is_whitespace))
}

fn valid_runner_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(crate) fn account_row(row: SqliteRow, company_ids: Vec<CompanyId>) -> Result<Account, Error> {
    let tier = row.try_get::<Option<String>, _>("plan_tier")?;
    let signal = row.try_get::<Option<String>, _>("signal")?;
    let runners_raw: String = row.try_get("runners")?;
    Ok(Account {
        id: AccountId(row.try_get("id")?),
        harness: text(&row, "harness")?,
        label: row.try_get("label")?,
        secret_name: row.try_get("secret_name")?,
        delivery: row.try_get("delivery")?,
        runners: serde_json::from_str(&runners_raw).unwrap_or_default(),
        billing: text(&row, "billing")?,
        config_dir: row.try_get("config_dir")?,
        status: text(&row, "status")?,
        status_reason: row.try_get("status_reason")?,
        status_until: row.try_get("status_until")?,
        last_used_at: row.try_get("last_used_at")?,
        plan_tier: tier
            .map(|t| t.parse())
            .transpose()
            .map_err(|e| Error::Decode(Box::new(e)))?,
        signal: signal.and_then(|s| serde_json::from_str(&s).ok()),
        created_at: row.try_get("created_at")?,
        company_ids,
    })
}

pub(crate) async fn companies_in(
    conn: &mut SqliteConnection,
    account: AccountId,
) -> Result<Vec<CompanyId>, Error> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT company_id FROM citadel_account_companies WHERE account_id = ? ORDER BY company_id",
    )
    .bind(account.0)
    .fetch_all(&mut *conn)
    .await?;
    Ok(ids.into_iter().map(CompanyId).collect())
}

/// Overlays `delivery` and `runners` from `core_secrets` if the broker holds `a.secret_name`.
async fn overlay_broker_in(conn: &mut SqliteConnection, mut a: Account) -> Result<Account, Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT delivery, runners FROM core_secrets WHERE name = ?")
            .bind(&a.secret_name)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some((delivery, runners)) = row {
        a.delivery = delivery;
        a.runners = serde_json::from_str(&runners).unwrap_or_default();
    }
    Ok(a)
}

pub(crate) async fn get_account_in(
    conn: &mut SqliteConnection,
    id: AccountId,
) -> Result<Option<Account>, Error> {
    let Some(row) = sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM citadel_accounts WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let companies = companies_in(conn, id).await?;
    let a = account_row(row, companies)?;
    overlay_broker_in(conn, a).await.map(Some)
}

pub async fn get_account(pool: &SqlitePool, id: AccountId) -> Result<Option<Account>, Error> {
    let mut conn = pool.acquire().await?;
    get_account_in(&mut conn, id).await
}

pub async fn get_account_by_label(
    pool: &SqlitePool,
    label: &str,
) -> Result<Option<Account>, Error> {
    let mut conn = pool.acquire().await?;
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM citadel_accounts WHERE label = ?")
        .bind(label)
        .fetch_optional(&mut *conn)
        .await?;
    match id {
        Some(id) => get_account_in(&mut conn, AccountId(id)).await,
        None => Ok(None),
    }
}

pub async fn list_accounts(pool: &SqlitePool) -> Result<Vec<Account>, Error> {
    let mut conn = pool.acquire().await?;
    let rows = sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM citadel_accounts ORDER BY id"
    ))
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id = AccountId(row.try_get("id")?);
        let companies = companies_in(&mut conn, id).await?;
        out.push(overlay_broker_in(&mut conn, account_row(row, companies)?).await?);
    }
    Ok(out)
}

pub async fn create_account(
    pool: &SqlitePool,
    a: &NewAccount,
    actor: AuditActor,
) -> Result<Account, Error> {
    if !valid_label(&a.label) {
        return Err(Error::InvalidArgument(format!(
            "bad account label {:?}",
            a.label
        )));
    }
    let dir = a
        .config_dir
        .clone()
        .unwrap_or_else(|| format!("accounts/{}", a.label));
    if !valid_dir(&dir) {
        return Err(Error::InvalidArgument(format!("bad config_dir {dir:?}")));
    }
    let secret_name = a.secret_name.clone().unwrap_or_else(|| a.label.clone());
    if !secrets::valid_name(&secret_name) {
        return Err(Error::InvalidArgument(format!(
            "bad secret_name {secret_name:?}; must match [a-z][a-z0-9_.-]{{0,63}}"
        )));
    }
    let mut tx = begin_write(pool).await?;
    let broker_row: Option<(String, String)> =
        sqlx::query_as("SELECT delivery, runners FROM core_secrets WHERE name = ?")
            .bind(&secret_name)
            .fetch_optional(&mut *tx)
            .await?;
    if a.require_broker_secret && broker_row.is_none() {
        return Err(Error::InvalidArgument(format!(
            "the broker secret {secret_name:?} does not exist"
        )));
    }
    let delivery = match (&a.delivery, &broker_row) {
        (Some(d), _) => d.clone(),
        (None, Some((d, _))) => d.clone(),
        (None, None) => "env".to_owned(),
    };
    if !secrets::DELIVERY.contains(&delivery.as_str()) {
        return Err(Error::InvalidArgument(
            "delivery must be env, file or askpass".to_owned(),
        ));
    }
    let runners: Vec<String> = match (&a.runners, &broker_row) {
        (Some(r), _) => r.clone(),
        (None, Some((_, r))) => serde_json::from_str(r).unwrap_or_default(),
        (None, None) => Vec::new(),
    };
    if runners.iter().any(|r| !valid_runner_id(r)) {
        return Err(Error::InvalidArgument(
            "each runner in runners must be a valid runner id".to_owned(),
        ));
    }
    let row = sqlx::query(concat!(
        "INSERT INTO citadel_accounts (harness, label, secret_name, delivery, runners, billing, config_dir) \
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ",
        account_columns!()
    ))
    .bind(a.harness.as_str())
    .bind(&a.label)
    .bind(&secret_name)
    .bind(&delivery)
    .bind(json!(&runners).to_string())
    .bind(a.billing.as_str())
    .bind(&dir)
    .fetch_one(&mut *tx)
    .await?;
    let created = overlay_broker_in(&mut tx, account_row(row, vec![])?).await?;
    let details = json!({
        "harness": created.harness.as_str(),
        "label": created.label,
        "secret_name": created.secret_name,
        "delivery": created.delivery,
        "runners": created.runners,
        "billing": created.billing.as_str(),
        "config_dir": created.config_dir,
    });
    append_account_event(&mut tx, created.id, None, actor, "account.added", details).await?;
    tx.commit().await?;
    Ok(created)
}

pub async fn assign_account(
    pool: &SqlitePool,
    account: AccountId,
    company: CompanyId,
    assigned: bool,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let changed = match assigned {
        true => {
            sqlx::query(
                "INSERT OR IGNORE INTO citadel_account_companies (account_id, company_id) VALUES (?, ?)",
            )
            .bind(account.0)
            .bind(company.0)
            .execute(&mut *tx)
            .await
            .map(affected)?
        }
        false => {
            sqlx::query(
                "DELETE FROM citadel_account_companies WHERE account_id = ? AND company_id = ?",
            )
            .bind(account.0)
            .bind(company.0)
            .execute(&mut *tx)
            .await
            .map(affected)?
        }
    };
    if changed {
        let action = if assigned {
            "account.assigned"
        } else {
            "account.unassigned"
        };
        let details = json!({"company": company.0});
        append_account_event(&mut tx, account, Some(company), actor, action, details).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn set_account_status(
    pool: &SqlitePool,
    account: AccountId,
    status: AccountStatus,
    reason: Option<&str>,
    until: Option<&str>,
    actor: AuditActor,
) -> Result<Option<Account>, Error> {
    if let Some(ts) = until {
        let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
            .bind(ts)
            .fetch_one(pool)
            .await?;
        if !valid {
            return Err(Error::InvalidArgument(format!("bad timestamp {ts:?}")));
        }
    }
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let until = match status {
        AccountStatus::Active => None,
        _ => until,
    };
    let reason = match status {
        AccountStatus::Active => None,
        _ => reason,
    };
    let mut tx = begin_write(pool).await?;
    let changed = sqlx::query(
        "UPDATE citadel_accounts SET status = ?, status_reason = ?, status_until = ?, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(reason)
    .bind(until)
    .bind(account.0)
    .execute(&mut *tx)
    .await
    .map(affected)?;
    if !changed {
        return Ok(None);
    }
    let action = match status {
        AccountStatus::Active => "account.enabled",
        _ => "account.disabled",
    };
    let details = json!({"status": status.as_str(), "reason": reason, "until": until});
    append_account_event(&mut tx, account, None, actor, action, details).await?;
    let updated = get_account_in(&mut tx, account).await?;
    tx.commit().await?;
    Ok(updated)
}

pub async fn set_account_plan(
    pool: &SqlitePool,
    account: AccountId,
    tier: Option<PlanTier>,
    actor: AuditActor,
) -> Result<Option<Account>, Error> {
    let mut tx = begin_write(pool).await?;
    let changed = sqlx::query(
        "UPDATE citadel_accounts SET plan_tier = ?, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(tier.map(|t| t.as_str()))
    .bind(account.0)
    .execute(&mut *tx)
    .await
    .map(affected)?;
    if !changed {
        return Ok(None);
    }
    let details = json!({"plan_tier": tier.map(|t| t.as_str())});
    append_account_event(&mut tx, account, None, actor, "account.plan_set", details).await?;
    let updated = get_account_in(&mut tx, account).await?;
    tx.commit().await?;
    Ok(updated)
}

pub async fn delete_account(
    pool: &SqlitePool,
    account: AccountId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let Some((label, harness)): Option<(String, String)> =
        sqlx::query_as("SELECT label, harness FROM citadel_accounts WHERE id = ?")
            .bind(account.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    let companies: Vec<i64> = sqlx::query_scalar(
        "SELECT company_id FROM citadel_account_companies WHERE account_id = ? ORDER BY company_id",
    )
    .bind(account.0)
    .fetch_all(&mut *tx)
    .await?;
    let costs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM citadel_cost_events WHERE account_id = ?")
            .bind(account.0)
            .fetch_one(&mut *tx)
            .await?;
    if costs > 0 {
        let why = format!(
            "account {label:?} has {costs} history entries in the ledger; disable it instead"
        );
        return Err(Error::InvalidArgument(why));
    }
    sqlx::query("DELETE FROM citadel_accounts WHERE id = ?")
        .bind(account.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"label": label, "harness": harness, "companies": companies});
    let first_company = companies.first().copied().map(CompanyId);
    append_account_event(
        &mut tx,
        account,
        first_company,
        actor,
        "account.deleted",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn append_account_event(
    conn: &mut SqliteConnection,
    account: AccountId,
    company: Option<CompanyId>,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let company = match company {
        Some(c) => Some(c.0),
        None => {
            sqlx::query_scalar(
                "SELECT company_id FROM citadel_account_companies WHERE account_id = ? \
                 ORDER BY company_id LIMIT 1",
            )
            .bind(account.0)
            .fetch_optional(&mut *conn)
            .await?
        }
    };
    let mut ev = Event::new(actor, action)
        .entity("account", account.0)
        .details(details);
    if let Some(c) = company {
        ev = ev.company(c);
    }
    append(conn, ev).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_dirs_are_boundary_validated() {
        assert!(
            valid_label("claude-primary")
                && !valid_label("../credential")
                && !valid_label("Bad Label")
        );
        assert!(
            valid_dir("accounts/claude-primary")
                && !valid_dir("/etc/passwd")
                && !valid_dir("accounts/../secret")
        );
    }

    #[tokio::test]
    async fn account_schema_has_no_credential_value_column() {
        let db = crate::testing::db().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('citadel_accounts')")
                .fetch_all(&db.pool)
                .await
                .unwrap();
        assert!(columns.contains(&"secret_name".to_owned()));
        assert!(!columns.iter().any(|c| c.contains("value")
            || c.contains("token")
            || c.contains("credential_ref")
            || c.contains("credential_env")));
    }
}
