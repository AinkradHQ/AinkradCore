//! The verdict on a credential: tests, and what they do to an auth suspicion (see `health`).

use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::health::{MAX_CONFIRM_TRIES, load, recover_in, sys_audit};
use super::{Connection, Who, audit, find, refused};
use crate::connections::adapter::{Identity, Registry, TestError};
use crate::ops::secretbox::SecretBox;
use crate::store::secrets::Error;

/// Clears an auth suspicion or confirmed auth failure (a replaced credential, an admin's
/// re-enable): `active` again, pending ended. Other states are left alone.
pub(super) async fn clear_auth_in(
    conn: &mut SqliteConnection,
    id: i64,
    now: &str,
    source: &str,
) -> Result<(), sqlx::Error> {
    let from: Option<(String, String)> = sqlx::query_as(
        "SELECT name, status FROM core_connections WHERE id = ? AND (auth_pending = 1 \
         OR state_reason IN ('auth_suspected', 'auth_failed'))",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((name, was)) = from else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE core_connections SET auth_pending = 0, auth_tries = 0, updated_at = ?2, \
         status = iif(state_reason IN ('auth_suspected', 'auth_failed'), 'active', status), \
         state_reason = iif(state_reason IN ('auth_suspected', 'auth_failed'), NULL, state_reason), \
         state_until = iif(state_reason IN ('auth_suspected', 'auth_failed'), NULL, state_until) \
         WHERE id = ?1",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    let details = json!({"name": name, "from": was, "to": "active", "reason": "auth_cleared",
        "source": source});
    sys_audit(conn, "connection.state_set", id, details).await
}

/// What a credential test came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    /// It works, and belongs to this identity.
    Passed(Identity),
    /// The service refused it: a confirmed auth failure.
    Rejected,
    /// No verdict.
    Inconclusive,
}

/// Records a test of credential `version`: `last_tested_at`, the identity when it passed, and the
/// verdict on a pending or any other auth failure (see the module docs). Audited
/// `connection.tested` with the result class only. Refused (`conflict`) when the credential is no
/// longer that version: a verdict on an old credential must not settle the new one. Only
/// [`run_test`] calls it outside tests, so a verdict always comes from an adapter.
pub(super) async fn record_test(
    pool: &SqlitePool,
    id: i64,
    version: i64,
    outcome: TestOutcome,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let old = find(&mut tx, who.workspace, id).await?;
    if super::secret::version_in(&mut tx, id).await? != version {
        return refused(
            "conflict",
            "the credential changed while it was tested; the result was dropped",
        );
    }
    recover_in(&mut tx, id, who.now).await?;
    sqlx::query("UPDATE core_connections SET last_tested_at = ?, updated_at = ? WHERE id = ?")
        .bind(who.now)
        .bind(who.now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let mut details = json!({"by_device": who.by_device});
    match &outcome {
        TestOutcome::Passed(identity) => {
            let subject: String = identity.subject.chars().take(200).collect();
            details["result"] = json!("passed");
            details["identity_changed"] =
                json!(old.identity.as_deref().is_some_and(|i| i != subject));
            sqlx::query("UPDATE core_connections SET identity = ? WHERE id = ?")
                .bind(&subject)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            clear_auth_in(&mut tx, id, who.now, "test").await?;
        }
        TestOutcome::Rejected => {
            details["result"] = json!("rejected");
            if old.status != "disabled" {
                sqlx::query(
                    "UPDATE core_connections SET status = 'disabled', state_reason = 'auth_failed', \
                     state_until = NULL, auth_pending = 0, auth_tries = 0 WHERE id = ?",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
                let d = json!({"name": old.name, "from": old.status, "to": "disabled",
                    "reason": "auth_failed", "source": "test"});
                sys_audit(&mut tx, "connection.state_set", id, d).await?;
            }
        }
        TestOutcome::Inconclusive => {
            details["result"] = json!("inconclusive");
            let h = load(&mut tx, id).await?;
            if let Some(h) = h.filter(|h| h.auth_pending) {
                let tries = h.auth_tries + 1;
                sqlx::query("UPDATE core_connections SET auth_tries = ? WHERE id = ?")
                    .bind(tries)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                if tries >= MAX_CONFIRM_TRIES {
                    clear_auth_in(&mut tx, id, who.now, "test").await?;
                    let d = json!({"name": h.name, "state": "inconclusive", "tries": tries});
                    sys_audit(&mut tx, "connection.auth_inconclusive", id, d).await?;
                }
            }
        }
    }
    audit(&mut tx, who.actor, "connection.tested", id, details).await?;
    let c = find(&mut tx, who.workspace, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// Tests connection `id` with its kind's adapter and records the outcome. The credential is
/// opened and the adapter called with no transaction held.
pub async fn run_test(
    pool: &SqlitePool,
    sealer: &SecretBox,
    reg: &Registry,
    id: i64,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let c = super::get(pool, who.workspace, id).await?;
    let Some(adapter) = reg.get(&c.kind) else {
        return refused("unknown_kind", "no adapter for this kind");
    };
    let (material, version) = super::secret::open(pool, sealer, who.workspace, id).await?;
    let outcome = match adapter.test(&material).await {
        Ok(identity) => TestOutcome::Passed(identity),
        Err(TestError::Rejected) => TestOutcome::Rejected,
        Err(TestError::Inconclusive) => TestOutcome::Inconclusive,
    };
    record_test(pool, id, version, outcome, who).await
}

/// Whether the connection may be used now: `Ok`, or the refusal's code and message. Call after
/// [`recover`].
pub fn usable(c: &Connection) -> Result<(), (&'static str, String)> {
    if c.disabled {
        return Err(("disabled", "the connection is switched off".to_owned()));
    }
    match (c.status.as_str(), c.state_reason.as_deref()) {
        ("active", _) => Ok(()),
        ("disabled", Some("exported")) => Err((
            "no_credential",
            "exported without its credential: store a new one".to_owned(),
        )),
        ("disabled", _) => Err((
            "auth_failed",
            "the service refused its credential; replace it and test again".to_owned(),
        )),
        (_, Some("auth_suspected")) => Err((
            "auth_pending",
            "the service may have refused its credential; a test decides".to_owned(),
        )),
        (state, reason) => Err((
            "unhealthy",
            format!(
                "the connection is {state} ({}{})",
                reason.unwrap_or("no reason"),
                c.state_until
                    .as_deref()
                    .map(|u| format!(", until {u}"))
                    .unwrap_or_default()
            ),
        )),
    }
}
