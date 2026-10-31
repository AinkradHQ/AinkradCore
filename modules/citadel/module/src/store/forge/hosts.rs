//! The hosts a forge or Linear API may be on besides the public ones (S6): an operator adds a
//! self-hosted forge's host name here, with a step-up. The poller's call policy reads them on
//! every pass (`forge::Runtime::pass`).

use std::net::IpAddr;

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::{Error, SqlitePool};

use crate::store::audit::{Event, append};

/// Why `host` is not a name an API may live on: a bare host name, lowercase, with a dot, never an
/// IP address (the call policy refuses those) or a local name.
pub fn host_problem(host: &str) -> Option<String> {
    let name_ok = (3..=253).contains(&host.len())
        && host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && host
            .split('.')
            .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
    if !name_ok {
        return Some(format!("{host:?} is not a lowercase host name"));
    }
    let numeric = host
        .split('.')
        .all(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if numeric || host.parse::<IpAddr>().is_ok() {
        return Some("an IP address is not a host name".to_owned());
    }
    if host.ends_with(".local") || host.ends_with(".internal") || host.ends_with(".localhost") {
        return Some("a local name cannot be a forge host".to_owned());
    }
    None
}

pub async fn list_hosts(pool: &SqlitePool) -> Result<Vec<String>, Error> {
    sqlx::query_scalar("SELECT host FROM citadel_forge_hosts ORDER BY host")
        .fetch_all(pool)
        .await
}

/// Allows `host` (audited `forge.host_added`); `false` when it already was.
pub async fn add_host(pool: &SqlitePool, host: &str, actor: AuditActor) -> Result<bool, Error> {
    if let Some(why) = host_problem(host) {
        return Err(Error::InvalidArgument(why));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let added = sqlx::query("INSERT OR IGNORE INTO citadel_forge_hosts (host) VALUES (?)")
        .bind(host)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    if added {
        let ev = Event::new(actor, "forge.host_added").details(json!({"host": host}));
        append(&mut tx, ev).await?;
    }
    tx.commit().await?;
    Ok(added)
}

/// Stops allowing `host` (audited `forge.host_removed`); `false` when it was not there.
pub async fn remove_host(pool: &SqlitePool, host: &str, actor: AuditActor) -> Result<bool, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let gone = sqlx::query("DELETE FROM citadel_forge_hosts WHERE host = ?")
        .bind(host)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    if gone {
        let ev = Event::new(actor, "forge.host_removed").details(json!({"host": host}));
        append(&mut tx, ev).await?;
    }
    tx.commit().await?;
    Ok(gone)
}

/// The company that owns `project`.
pub async fn company_of_project(
    pool: &SqlitePool,
    project: crate::domain::work::ProjectId,
) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(project.0)
        .fetch_one(pool)
        .await
}

/// Whether `secret` is a provider account's credential (`citadel_accounts`): never a forge's.
pub async fn is_account_secret(pool: &SqlitePool, secret: &str) -> Result<bool, Error> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_accounts WHERE secret_name = ?")
        .bind(secret)
        .fetch_one(pool)
        .await?;
    Ok(n > 0)
}

/// Binds `secret` to `host` and `company` the first time it is used; afterwards any other host
/// or company is refused (`Ok(Err(why))`): one credential, one place it may be sent.
pub async fn bind_secret(
    pool: &SqlitePool,
    secret: &str,
    host: &str,
    company: i64,
) -> Result<Result<(), String>, Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO citadel_forge_secret_hosts (secret, host, company_id) \
         VALUES (?, ?, ?)",
    )
    .bind(secret)
    .bind(host)
    .bind(company)
    .execute(pool)
    .await?;
    let (bound_host, bound_company): (String, i64) =
        sqlx::query_as("SELECT host, company_id FROM citadel_forge_secret_hosts WHERE secret = ?")
            .bind(secret)
            .fetch_one(pool)
            .await?;
    Ok(if (bound_host.as_str(), bound_company) == (host, company) {
        Ok(())
    } else {
        Err(format!(
            "the credential {secret} is bound to another host or company; use a new secret for this link"
        ))
    })
}
