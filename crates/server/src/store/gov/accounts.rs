//! The provider account pool (E15.1, decision #41): accounts owned by the admin, assigned to
//! companies, one picked per run. Every write is audited in its own transaction. No secret is
//! ever stored: an account holds where its token lives on a runner host (`credential_ref`)
//! and which harness variable it goes in, both checked here.
//!
//! Pool rule: a harness with no account in the pool runs on the runner's own login, as before
//! accounts; once it has one, its runs need an `active` account assigned to their company, and
//! wait for one otherwise.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::gov::{Account, AccountId, AccountStatus, Billing, NewAccount, account_label_ok};
use ainkrad_core::org::{CompanyId, Harness};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::runner::relative_path_ok;
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::harness_billing;
use crate::store::audit;
use crate::store::org::text;
use crate::store::settings::value_in;

mod drops;
mod limits;
mod remove;
mod usage;
pub use drops::*;
pub use limits::*;
pub use remove::*;
pub use usage::*;

macro_rules! account_columns {
    () => {
        "a.id, a.harness, a.label, a.credential_ref, a.credential_env, a.config_dir, \
         a.billing, a.status, a.status_reason, a.status_until, a.last_used_at, a.plan_tier, \
         (SELECT group_concat(company_id) FROM (SELECT company_id FROM account_companies \
             WHERE account_id = a.id ORDER BY company_id)) AS companies"
    };
}

fn account(row: SqliteRow) -> Result<Account, Error> {
    let companies: Option<String> = row.try_get("companies")?;
    Ok(Account {
        id: AccountId(row.try_get("id")?),
        harness: text(&row, "harness")?,
        label: row.try_get("label")?,
        credential_ref: row.try_get("credential_ref")?,
        credential_env: row.try_get("credential_env")?,
        config_dir: row.try_get("config_dir")?,
        billing: text(&row, "billing")?,
        status: text(&row, "status")?,
        status_reason: row.try_get("status_reason")?,
        status_until: row.try_get("status_until")?,
        last_used_at: row.try_get("last_used_at")?,
        plan_tier: row.try_get("plan_tier")?,
        companies: companies
            .unwrap_or_default()
            .split(',')
            .filter_map(|c| c.parse().ok())
            .collect(),
    })
}

pub(crate) async fn append_account_event(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    account: AccountId,
    company: Option<CompanyId>,
    action: &str,
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "account".to_owned(),
            id: account.0,
        }),
        company_id: company,
        run_id: None,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

fn invalid(why: impl Into<String>) -> Error {
    Error::InvalidArgument(why.into())
}

/// Why `a` cannot be stored, if it cannot.
fn problem(a: &NewAccount) -> Option<String> {
    if !account_label_ok(&a.label) {
        return Some(format!("bad label {:?}: use [a-z0-9._-]", a.label));
    }
    if !relative_path_ok(&a.config_dir) {
        return Some(format!(
            "bad config dir {:?}: a relative path of plain names",
            a.config_dir
        ));
    }
    match (&a.credential_ref, &a.credential_env) {
        (None, None) => None,
        (Some(file), Some(var)) => {
            if !relative_path_ok(file) {
                return Some(format!(
                    "bad credential reference {file:?}: a file name under the runner's \
                     credentials dir"
                ));
            }
            let known = ainkrad_harness::auth_env(a.harness.as_str());
            (!known.contains(&var.as_str())).then(|| {
                format!(
                    "{} takes its token in one of {known:?}, not {var:?}",
                    a.harness.as_str()
                )
            })
        }
        _ => Some("a credential reference and its variable go together".to_owned()),
    }
}

/// A new account with the defaults filled in: config dir `accounts/<label>`, the harness's
/// first auth variable for a credential, and the harness's billing (E7.3), which is where an
/// account's billing starts from.
pub async fn new_account(
    pool: &SqlitePool,
    harness: Harness,
    label: &str,
    credential_ref: Option<String>,
    credential_env: Option<String>,
    config_dir: Option<String>,
    billing: Option<Billing>,
) -> Result<NewAccount, Error> {
    let credential_env = match (&credential_ref, credential_env) {
        (Some(_), None) => ainkrad_harness::auth_env(harness.as_str())
            .first()
            .map(|v| (*v).to_owned()),
        (_, env) => env,
    };
    let billing = match billing {
        Some(b) => b,
        None => harness_billing(pool, harness).await?,
    };
    Ok(NewAccount {
        harness,
        label: label.to_owned(),
        credential_ref,
        credential_env,
        config_dir: config_dir.unwrap_or_else(|| format!("accounts/{label}")),
        billing,
    })
}

/// Adds an account to the pool, `active` and assigned to no company, and appends
/// `account.created`. A bad label, path or variable is `InvalidArgument`; a taken label a
/// constraint error.
pub async fn create_account(
    pool: &SqlitePool,
    a: &NewAccount,
    actor: AuditActor,
) -> Result<Account, Error> {
    if let Some(why) = problem(a) {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (harness, label, credential_ref, credential_env, config_dir, \
         billing) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(a.harness.as_str())
    .bind(&a.label)
    .bind(&a.credential_ref)
    .bind(&a.credential_env)
    .bind(&a.config_dir)
    .bind(a.billing.as_str())
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"harness": a.harness.as_str(), "label": a.label,
                         "config_dir": a.config_dir, "credential_ref": a.credential_ref,
                         "credential_env": a.credential_env, "billing": a.billing.as_str()});
    append_account_event(
        &mut tx,
        actor,
        AccountId(id),
        None,
        "account.created",
        details,
    )
    .await?;
    let created = get_account_in(&mut tx, AccountId(id)).await?;
    tx.commit().await?;
    created.ok_or(Error::RowNotFound)
}

async fn get_account_in(
    conn: &mut SqliteConnection,
    id: AccountId,
) -> Result<Option<Account>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM accounts a WHERE a.id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(account)
    .transpose()
}

pub async fn get_account(pool: &SqlitePool, id: AccountId) -> Result<Option<Account>, Error> {
    get_account_in(&mut *pool.acquire().await?, id).await
}

pub async fn account_by_label(pool: &SqlitePool, label: &str) -> Result<Option<Account>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM accounts a WHERE a.label = ?"
    ))
    .bind(label)
    .fetch_optional(pool)
    .await?
    .map(account)
    .transpose()
}

/// The whole pool, by id.
pub async fn list_accounts(pool: &SqlitePool) -> Result<Vec<Account>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM accounts a ORDER BY a.id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(account)
    .collect()
}

/// Lets `company`'s runs use the account (`assign`), or stops them (`!assign`); appends
/// `account.assigned` / `account.unassigned`. `false` when nothing changed or either is gone.
/// A run already working as the account keeps it to its end.
pub async fn assign_account(
    pool: &SqlitePool,
    id: AccountId,
    company: CompanyId,
    assign: bool,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let sql = if assign {
        "INSERT INTO account_companies (account_id, company_id) \
         SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM accounts WHERE id = ?1) \
         AND EXISTS (SELECT 1 FROM companies WHERE id = ?2) ON CONFLICT DO NOTHING"
    } else {
        "DELETE FROM account_companies WHERE account_id = ?1 AND company_id = ?2"
    };
    let changed = sqlx::query(sql)
        .bind(id.0)
        .bind(company.0)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if changed {
        let action = if assign {
            "account.assigned"
        } else {
            "account.unassigned"
        };
        let details = json!({"company": company.0});
        append_account_event(&mut tx, actor, id, Some(company), action, details).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Sets the account's status by hand (`disabled`, or back to `active`), with `reason` for
/// any status but `active`; appends `account.status`. `false` when it is gone.
pub async fn set_account_status(
    pool: &SqlitePool,
    id: AccountId,
    status: AccountStatus,
    reason: Option<&str>,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let changed = status_in(&mut tx, id, status, reason, actor).await?;
    tx.commit().await?;
    Ok(changed)
}

pub(crate) async fn status_in(
    conn: &mut SqliteConnection,
    id: AccountId,
    status: AccountStatus,
    reason: Option<&str>,
    actor: AuditActor,
) -> Result<bool, Error> {
    let reason = match status {
        AccountStatus::Active => None,
        _ => Some(reason.unwrap_or("set by the admin")),
    };
    let changed = sqlx::query(
        "UPDATE accounts SET status = ?, status_reason = ?, status_until = NULL WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(reason)
    .bind(id.0)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;
    if changed {
        let details = json!({"status": status.as_str(), "reason": reason});
        append_account_event(conn, actor, id, None, "account.status", details).await?;
    }
    Ok(changed)
}

/// Sets the account's plan tier (`None` clears it), audited as `account.plan_set` when it
/// changes. `false` when it is gone.
pub async fn set_account_plan(
    pool: &SqlitePool,
    id: AccountId,
    tier: Option<&str>,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let changed =
        sqlx::query("UPDATE accounts SET plan_tier = ? WHERE id = ? AND plan_tier IS NOT ?")
            .bind(tier)
            .bind(id.0)
            .bind(tier)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
    if changed {
        let details = json!({"plan_tier": tier});
        append_account_event(&mut tx, actor, id, None, "account.plan_set", details).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Which account a run of `company` on `harness` works as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// The pool has no account for the harness: the runner's own login.
    NoPool,
    /// The pool has some, but none active and assigned to the company: the run waits.
    Unavailable,
    Account(AccountId),
}

/// The account a new run of `company` on `harness` gets at `now`: an active one assigned to
/// the company (after `refresh_in` brought back those whose limits passed), by the company's
/// `account.pick_strategy`: 0, the least used in its current windows first (E15.2: its fullest
/// limit's share), then the least recently used (never used before all), then by id; 1, the
/// least recently used (round robin); 2, the first by id (fill first).
pub(crate) async fn pick_account_in(
    conn: &mut SqliteConnection,
    company: CompanyId,
    harness: Harness,
    now: &str,
) -> Result<Pick, Error> {
    refresh_in(conn, now).await?;
    let strategy = value_in(conn, Key::AccountPickStrategy, Scope::Company(company)).await?;
    let candidates: Vec<i64> = sqlx::query_scalar(
        "SELECT a.id FROM accounts a JOIN account_companies ac ON ac.account_id = a.id \
         WHERE ac.company_id = ? AND a.harness = ? AND a.status = 'active' \
         ORDER BY iif(?3 = 2, a.id, 0), a.last_used_at IS NOT NULL, a.last_used_at, a.id",
    )
    .bind(company.0)
    .bind(harness.as_str())
    .bind(strategy)
    .fetch_all(&mut *conn)
    .await?;
    let mut best: Option<(f64, i64)> = None;
    for id in candidates {
        // Round robin and fill first take the order as it is.
        let used = match strategy {
            0 => utilisation_in(conn, AccountId(id), now).await?,
            _ => 0.0,
        };
        if best.is_none_or(|(least, _)| used < least) {
            best = Some((used, id));
        }
    }
    if let Some((_, id)) = best {
        return Ok(Pick::Account(AccountId(id)));
    }
    let pooled: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE harness = ?)")
            .bind(harness.as_str())
            .fetch_one(&mut *conn)
            .await?;
    Ok(if pooled {
        Pick::Unavailable
    } else {
        Pick::NoPool
    })
}

/// Puts `run` on `account`, marks the account used at `now` and counts the prompt against
/// its limits (the caller audits the run's dispatch with it). The schema refuses an account
/// of another company or harness.
pub(crate) async fn use_account_in(
    conn: &mut SqliteConnection,
    run: i64,
    account: AccountId,
    now: &str,
) -> Result<(), Error> {
    sqlx::query("UPDATE runs SET account_id = ? WHERE id = ?")
        .bind(account.0)
        .bind(run)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE accounts SET last_used_at = ? WHERE id = ?")
        .bind(now)
        .bind(account.0)
        .execute(&mut *conn)
        .await?;
    record_message_in(conn, account, run, now).await
}

/// The account `run` works as, if any.
pub async fn run_account(
    pool: &SqlitePool,
    run: ainkrad_core::exec::RunId,
) -> Result<Option<Account>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM accounts a JOIN runs r ON r.account_id = a.id WHERE r.id = ?"
    ))
    .bind(run.0)
    .fetch_optional(pool)
    .await?
    .map(account)
    .transpose()
}
