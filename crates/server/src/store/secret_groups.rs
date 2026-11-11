//! Secret groups (N24, decision G2: one level, no group in a group): a name, a description and a
//! runner list that every member without runners of its own inherits (`secrets::effective`).
//! Never a value; the audit rows are `secret_group.*`.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::secrets::{Error, valid_name};

/// A group and the names of its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub runners: Vec<String>,
    pub members: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn refused<T>(code: &'static str, message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.to_owned(),
    })
}

/// The id of group `name`; a missing one is a bad request (the secret named it).
pub async fn id_of(conn: &mut SqliteConnection, name: &str) -> Result<i64, Error> {
    let id = sqlx::query_scalar("SELECT id FROM core_secret_groups WHERE name = ?")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    match id {
        Some(id) => Ok(id),
        None => refused("bad_request", "no such secret group"),
    }
}

const SELECT: &str = "SELECT g.id, g.name, g.description, g.runners, g.created_at, g.updated_at, \
    (SELECT json_group_array(name) FROM core_secrets WHERE group_id = g.id) AS members \
    FROM core_secret_groups g";

fn group(row: sqlx::sqlite::SqliteRow) -> Result<Group, sqlx::Error> {
    let list = |k: &str| -> Result<Vec<String>, sqlx::Error> {
        let text: String = row.try_get(k)?;
        Ok(serde_json::from_str(&text).unwrap_or_default())
    };
    let mut members = list("members")?;
    members.sort();
    Ok(Group {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        runners: list("runners")?,
        members,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Every group, by name.
pub async fn list(pool: &SqlitePool) -> Result<Vec<Group>, sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY g.name")))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(group)
        .collect()
}

pub async fn find(conn: &mut SqliteConnection, name: &str) -> Result<Group, Error> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE g.name = ?")))
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    match row {
        Some(row) => Ok(group(row)?),
        None => refused("not_found", "no such secret group"),
    }
}

fn check(description: &str) -> Result<(), Error> {
    match description.chars().count() <= 200 && !description.contains(['\n', '\r']) {
        true => Ok(()),
        false => refused(
            "bad_request",
            "a description is one line of at most 200 characters",
        ),
    }
}

async fn audit(
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
            kind: "secret_group".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// Makes group `name`. `runners` are checked as a secret's are.
pub async fn create(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    runners: &[String],
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Group, Error> {
    if !valid_name(name) {
        return refused("bad_request", "a name is [a-z][a-z0-9_.-]{0,63}");
    }
    check(description)?;
    let mut tx = super::begin_write(pool).await?;
    super::secrets::check_runners(&mut tx, runners).await?;
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_groups WHERE name = ?")
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return refused("conflict", "a group of that name exists");
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_secret_groups (name, description, runners, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(description)
    .bind(json!(runners).to_string())
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"name": name, "runners": runners, "by_device": by_device});
    audit(&mut tx, actor, "secret_group.created", id, details).await?;
    let g = find(&mut tx, name).await?;
    tx.commit().await?;
    Ok(g)
}

/// Changes a group's description and/or runners (`None` keeps it).
pub async fn update(
    pool: &SqlitePool,
    name: &str,
    description: Option<&str>,
    runners: Option<&[String]>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Group, Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, name).await?;
    let description = description.unwrap_or(&old.description);
    check(description)?;
    let runners = runners.unwrap_or(&old.runners);
    super::secrets::check_runners(&mut tx, runners).await?;
    sqlx::query(
        "UPDATE core_secret_groups SET description = ?, runners = ?, updated_at = ? WHERE id = ?",
    )
    .bind(description)
    .bind(json!(runners).to_string())
    .bind(now)
    .bind(old.id)
    .execute(&mut *tx)
    .await?;
    let details = json!({"name": name, "runners": runners, "by_device": by_device});
    audit(&mut tx, actor, "secret_group.updated", old.id, details).await?;
    let g = find(&mut tx, name).await?;
    tx.commit().await?;
    Ok(g)
}

/// Deletes an empty group; one with members is a conflict (they would lose the runners they
/// inherit).
pub async fn delete(
    pool: &SqlitePool,
    name: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, name).await?;
    if !old.members.is_empty() {
        return refused(
            "conflict",
            "the group still has secrets; move or delete them first",
        );
    }
    sqlx::query("DELETE FROM core_secret_groups WHERE id = ?")
        .bind(old.id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        actor,
        "secret_group.deleted",
        old.id,
        json!({"name": name, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
