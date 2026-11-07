//! Creating, editing and deleting a connection; each is one transaction with its audit row.

use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::{Connection, MAX_PER_USER, Who, audit, find, refused, secret, valid_name, valid_text};
use crate::connections::adapter::Registry;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::store::secrets::Error;

pub struct NewConnection<'a> {
    pub kind: &'a str,
    pub name: &'a str,
    pub label: &'a str,
    pub auth_method: &'a str,
}

/// Stores a connection and its sealed credential together. The kind must be registered and offer
/// `auth_method`; `name` is unique per kind. Its identity is empty until a test reads it.
pub async fn create(
    pool: &SqlitePool,
    sealer: &SecretBox,
    reg: &Registry,
    new: &NewConnection<'_>,
    material: &Material,
    who: Who<'_>,
) -> Result<Connection, Error> {
    create_with(pool, sealer, reg, new, material, None, who).await
}

/// [`create`] for a GitHub App connection: the installation its token is minted for is stored in
/// the same transaction, so a connection never exists without it.
pub async fn create_with(
    pool: &SqlitePool,
    sealer: &SecretBox,
    reg: &Registry,
    new: &NewConnection<'_>,
    material: &Material,
    installation: Option<(i64, &str)>,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let Some(adapter) = reg.get(new.kind) else {
        return refused("bad_request", "no such kind");
    };
    if adapter.descriptor().auth_method(new.auth_method).is_none() {
        return refused("bad_request", "the kind does not offer that auth method");
    }
    if !valid_name(new.name) {
        return refused("bad_request", "a name is [a-z][a-z0-9._-]{0,63}");
    }
    if !valid_text(new.label, 80) {
        return refused(
            "bad_request",
            "a label is 1 to 80 characters, no control characters",
        );
    }
    let nonce = secret::new_nonce()?;
    let mut tx = crate::store::begin_write(pool).await?;
    secret::gate(&mut tx, material, Some(adapter.descriptor())).await?;
    let owner: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = ?")
        .bind(who.workspace)
        .fetch_one(&mut *tx)
        .await?;
    if owner == 0 {
        return refused("bad_request", "no such user");
    }
    if let Some((installation, account)) = installation {
        super::apps::claim_in(&mut tx, installation, account, who.workspace, who.now).await?;
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connections WHERE user_id = ?")
        .bind(who.workspace)
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_PER_USER {
        return refused("limit_reached", "too many connections");
    }
    let taken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_connections WHERE user_id = ? AND kind = ? AND name = ?",
    )
    .bind(who.workspace)
    .bind(new.kind)
    .bind(new.name)
    .fetch_one(&mut *tx)
    .await?;
    if taken > 0 {
        return refused("conflict", "a connection of that name exists for this kind");
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_connections (user_id, kind, name, label, auth_method, created_by, \
         created_at, updated_at, nonce, installation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(who.workspace)
    .bind(new.kind)
    .bind(new.name)
    .bind(new.label)
    .bind(new.auth_method)
    .bind(who.by_device)
    .bind(who.now)
    .bind(who.now)
    .bind(&nonce)
    .bind(installation.map(|i| i.0))
    .fetch_one(&mut *tx)
    .await?;
    let seal = secret::Seal {
        id,
        user_id: who.workspace,
        nonce: &nonce,
        version: 1,
    };
    secret::store_in(&mut tx, sealer, &seal, material, who.now).await?;
    audit(
        &mut tx,
        who.actor,
        "connection.created",
        id,
        json!({"kind": new.kind, "name": new.name, "label": new.label,
               "auth_method": new.auth_method, "by_device": who.by_device}),
    )
    .await?;
    let c = find(&mut tx, who.workspace, id).await?;
    tx.commit().await?;
    Ok(c)
}

const LABEL_RULE: &str = "a label is 1 to 80 characters, no control characters";
const NAME_RULE: &str = "a name is [a-z][a-z0-9._-]{0,63}";

async fn label_in(
    tx: &mut SqliteConnection,
    id: i64,
    label: &str,
    who: Who<'_>,
) -> Result<(), Error> {
    if !valid_text(label, 80) {
        return refused("bad_request", LABEL_RULE);
    }
    let old = find(tx, who.workspace, id).await?;
    sqlx::query("UPDATE core_connections SET label = ?, updated_at = ? WHERE id = ?")
        .bind(label)
        .bind(who.now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"from": old.label, "to": label, "by_device": who.by_device});
    audit(tx, who.actor, "connection.updated", id, details).await
}

async fn rename_in(
    tx: &mut SqliteConnection,
    id: i64,
    name: &str,
    who: Who<'_>,
) -> Result<(), Error> {
    if !valid_name(name) {
        return refused("bad_request", NAME_RULE);
    }
    let old = find(tx, who.workspace, id).await?;
    let taken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_connections WHERE user_id = ? AND kind = ? AND name = ? \
         AND id != ?",
    )
    .bind(old.user_id)
    .bind(&old.kind)
    .bind(name)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if taken > 0 {
        return refused("conflict", "a connection of that name exists for this kind");
    }
    sqlx::query("UPDATE core_connections SET name = ?, updated_at = ? WHERE id = ?")
        .bind(name)
        .bind(who.now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"from": old.name, "to": name, "by_device": who.by_device});
    audit(tx, who.actor, "connection.renamed", id, details).await
}

async fn disabled_in(
    tx: &mut SqliteConnection,
    id: i64,
    disabled: bool,
    who: Who<'_>,
) -> Result<(), Error> {
    let old = find(tx, who.workspace, id).await?;
    if old.disabled != disabled {
        sqlx::query("UPDATE core_connections SET disabled = ?, updated_at = ? WHERE id = ?")
            .bind(disabled)
            .bind(who.now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let action = if disabled {
            "connection.disabled"
        } else {
            "connection.enabled"
        };
        audit(
            tx,
            who.actor,
            action,
            id,
            json!({"by_device": who.by_device}),
        )
        .await?;
    }
    if !disabled {
        super::verdict::clear_auth_in(tx, id, who.now, "admin").await?;
    }
    Ok(())
}

/// Changes the label people see.
pub async fn update_label(
    pool: &SqlitePool,
    id: i64,
    label: &str,
    who: Who<'_>,
) -> Result<Connection, Error> {
    edit(
        pool,
        id,
        &Edit {
            label: Some(label),
            ..Edit::default()
        },
        who,
    )
    .await
}

/// Renames a connection (bindings and grants name its id, so they follow). Unique per kind.
pub async fn rename(
    pool: &SqlitePool,
    id: i64,
    name: &str,
    who: Who<'_>,
) -> Result<Connection, Error> {
    edit(
        pool,
        id,
        &Edit {
            name: Some(name),
            ..Edit::default()
        },
        who,
    )
    .await
}

/// The admin's switch. Turning it off also clears a health `disabled` (a confirmed auth failure):
/// an admin who re-enables has decided to try it again, and the next test or use re-confirms.
pub async fn set_disabled(
    pool: &SqlitePool,
    id: i64,
    disabled: bool,
    who: Who<'_>,
) -> Result<Connection, Error> {
    edit(
        pool,
        id,
        &Edit {
            disabled: Some(disabled),
            ..Edit::default()
        },
        who,
    )
    .await
}

/// What to change about a connection; each field optional.
#[derive(Default)]
pub struct Edit<'a> {
    pub name: Option<&'a str>,
    pub label: Option<&'a str>,
    pub disabled: Option<bool>,
}

/// Applies every field of `e` in ONE transaction: all of it or none (a name that is taken
/// leaves the label and the switch as they were). Each change keeps its own audit row.
pub async fn edit(
    pool: &SqlitePool,
    id: i64,
    e: &Edit<'_>,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    find(&mut tx, who.workspace, id).await?;
    if let Some(l) = e.label {
        label_in(&mut tx, id, l, who).await?;
    }
    if let Some(d) = e.disabled {
        disabled_in(&mut tx, id, d, who).await?;
    }
    // The name last: the change most likely to be refused.
    if let Some(n) = e.name {
        rename_in(&mut tx, id, n, who).await?;
    }
    let c = find(&mut tx, who.workspace, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// Deletes a connection with its grants, credential (wiped) and unused-scope bindings. Refused
/// (`conflict`) while it is its kind's default (the workspace binding): clear or move the default
/// first.
pub async fn delete(pool: &SqlitePool, id: i64, who: Who<'_>) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let c = find(&mut tx, who.workspace, id).await?;
    let default: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_connection_bindings WHERE connection_id = ? \
         AND scope_kind = 'workspace'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if default > 0 {
        return refused(
            "conflict",
            "the connection is its kind's default; name another default or clear it first",
        );
    }
    // Any other binding (unused scopes) goes with it.
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connection_bindings WHERE connection_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let grants = sqlx::query("DELETE FROM core_connection_grants WHERE connection_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    secret::secure(&mut tx).await?;
    secret::wipe_in(&mut tx, id).await?;
    sqlx::query("DELETE FROM core_connections WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    secret::secure_off(&mut tx).await?;
    let details = json!({"kind": c.kind, "name": c.name, "grants_dropped": grants,
                         "bindings_dropped": sessions, "by_device": who.by_device});
    audit(&mut tx, who.actor, "connection.deleted", id, details).await?;
    tx.commit().await?;
    Ok(())
}
