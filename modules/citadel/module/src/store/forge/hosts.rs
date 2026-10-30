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
