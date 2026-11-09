//! Who may use a connection (design §4): a grant names a user, a role or an agent, the
//! capabilities it may use and the resources it may reach. Capabilities default to the kind's
//! read-only ones; a write capability is only ever there because the grant names it (and the
//! audit row lists the writes). A resource limit is `key -> values` over the kind's limit keys;
//! no limit means any resource.

use std::collections::BTreeMap;

use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::{MAX_GRANTS, Who, audit, find, refused};
use crate::connections::adapter::{Descriptor, Registry};
use crate::store::secrets::Error;

/// The roles a grant may name: the workspace's admins and its members.
pub const ROLES: [&str; 2] = ["admin", "member"];
/// Values per limit key, and bytes of one value.
const MAX_VALUES: usize = 64;
const MAX_VALUE_LEN: usize = 100;

pub type Limits = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: i64,
    pub connection_id: i64,
    pub grantee_kind: String,
    pub grantee: String,
    pub capabilities: Vec<String>,
    pub limits: Limits,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct NewGrant<'a> {
    /// `user` (a user id), `role` (see [`ROLES`]) or `agent` (an agent id).
    pub grantee_kind: &'a str,
    pub grantee: &'a str,
    /// `None`: the kind's read-only capabilities. `Some`: exactly these (write ones included).
    pub capabilities: Option<&'a [String]>,
    pub limits: &'a Limits,
}

macro_rules! columns {
    () => {
        "id, connection_id, grantee_kind, grantee, capabilities, limits, created_by, created_at, \
         updated_at"
    };
}

fn grant(r: &SqliteRow) -> Result<Grant, sqlx::Error> {
    let decode = |col: &str, e: serde_json::Error| sqlx::Error::ColumnDecode {
        index: col.to_owned(),
        source: Box::new(e),
    };
    let caps: String = r.try_get("capabilities")?;
    let limits: String = r.try_get("limits")?;
    Ok(Grant {
        id: r.try_get("id")?,
        connection_id: r.try_get("connection_id")?,
        grantee_kind: r.try_get("grantee_kind")?,
        grantee: r.try_get("grantee")?,
        capabilities: serde_json::from_str(&caps).map_err(|e| decode("capabilities", e))?,
        limits: serde_json::from_str(&limits).map_err(|e| decode("limits", e))?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// A limit value is a name (`owner/repo`, a project key) or `prefix/*` for everything under a prefix.
fn value_ok(v: &str) -> bool {
    let body = v.strip_suffix("/*").unwrap_or(v);
    (1..=MAX_VALUE_LEN).contains(&v.len())
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        && super::clean_path(body)
}

/// Whether `value` is within the limit list `allowed`.
pub fn value_matches(allowed: &[String], value: &str) -> bool {
    allowed.iter().any(|a| match a.strip_suffix("/*") {
        Some(prefix) => value
            .strip_prefix(prefix)
            .and_then(|r| r.strip_prefix('/'))
            .is_some_and(super::clean_path),
        None => a == value,
    })
}

fn check_limits(d: &Descriptor, limits: &Limits) -> Result<(), Error> {
    for (key, values) in limits {
        if d.limit_key(key).is_none() {
            return refused(
                "bad_request",
                format!("{} has no limit key {key:?}", d.kind),
            );
        }
        if values.is_empty() || values.len() > MAX_VALUES || !values.iter().all(|v| value_ok(v)) {
            return refused(
                "bad_request",
                format!("limit {key:?} is 1 to {MAX_VALUES} names, as `owner/repo` or `owner/*`"),
            );
        }
    }
    Ok(())
}

/// A user grantee is a member of the connection's workspace: today a workspace is its owner
/// user, so only that user (more members come with user membership, #18).
async fn check_grantee(
    conn: &mut SqliteConnection,
    workspace: i64,
    kind: &str,
    grantee: &str,
) -> Result<(), Error> {
    match kind {
        "user" => {
            let n: i64 = match grantee.parse::<i64>() {
                Ok(id) if id == workspace => {
                    sqlx::query_scalar("SELECT count(*) FROM users WHERE id = ?")
                        .bind(id)
                        .fetch_one(&mut *conn)
                        .await?
                }
                _ => 0,
            };
            match n {
                1 => Ok(()),
                _ => refused(
                    "bad_request",
                    "a user grantee is a member of the connection's workspace",
                ),
            }
        }
        "role" if ROLES.contains(&grantee) => Ok(()),
        "role" => refused("bad_request", "a role is admin or member"),
        "agent" if crate::store::pools::valid_agent(grantee) => Ok(()),
        "agent" => refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]"),
        _ => refused("bad_request", "a grantee is a user, a role or an agent"),
    }
}

pub(super) async fn list_in(
    conn: &mut SqliteConnection,
    connection_id: i64,
) -> Result<Vec<Grant>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_connection_grants WHERE connection_id = ? ORDER BY id"
    ))
    .bind(connection_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(grant)
    .collect()
}

/// Workspace `ws`'s grants on `connection_id` (none for another workspace's connection).
pub async fn list(
    pool: &SqlitePool,
    ws: i64,
    connection_id: i64,
) -> Result<Vec<Grant>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let mut all = list_in(&mut conn, connection_id).await?;
    let own: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connections WHERE id = ? AND user_id = ?")
            .bind(connection_id)
            .bind(ws)
            .fetch_one(&mut *conn)
            .await?;
    if own == 0 {
        all.clear();
    }
    Ok(all)
}

/// Grants (or changes the grant of) a user, role or agent on a connection: one grant per
/// grantee, replaced in place. Audited `connection.granted`, naming any write capabilities.
pub async fn set(
    pool: &SqlitePool,
    reg: &Registry,
    connection_id: i64,
    new: &NewGrant<'_>,
    who: Who<'_>,
) -> Result<Grant, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let c = find(&mut tx, who.workspace, connection_id).await?;
    let Some(adapter) = reg.get(&c.kind) else {
        return refused("unknown_kind", "no adapter for this kind");
    };
    let d = adapter.descriptor();
    check_grantee(&mut tx, c.user_id, new.grantee_kind, new.grantee).await?;
    let caps = match new.capabilities {
        None => d.read_only(),
        Some([]) => {
            return refused(
                "bad_request",
                "a grant needs a capability; revoke it instead",
            );
        }
        Some(list) => {
            let mut caps: Vec<String> = Vec::new();
            for name in list {
                if d.capability(name).is_none() {
                    return refused(
                        "bad_request",
                        format!("{} has no capability {name:?}", d.kind),
                    );
                }
                if !caps.contains(name) {
                    caps.push(name.clone());
                }
            }
            caps
        }
    };
    check_limits(d, new.limits)?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_connection_grants WHERE connection_id = ? \
         AND grantee_kind = ? AND grantee = ?",
    )
    .bind(connection_id)
    .bind(new.grantee_kind)
    .bind(new.grantee)
    .fetch_one(&mut *tx)
    .await?;
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connection_grants WHERE connection_id = ?")
            .bind(connection_id)
            .fetch_one(&mut *tx)
            .await?;
    if exists == 0 && n >= MAX_GRANTS {
        return refused("limit_reached", "too many grants on this connection");
    }
    let r = sqlx::query(concat!(
        "INSERT INTO core_connection_grants (user_id, connection_id, grantee_kind, grantee, \
         capabilities, limits, created_by, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (connection_id, grantee_kind, grantee) DO UPDATE SET \
         capabilities = excluded.capabilities, limits = excluded.limits, \
         updated_at = excluded.updated_at RETURNING ",
        columns!()
    ))
    .bind(c.user_id)
    .bind(connection_id)
    .bind(new.grantee_kind)
    .bind(new.grantee)
    .bind(json!(caps).to_string())
    .bind(json!(new.limits).to_string())
    .bind(who.by_device)
    .bind(who.now)
    .bind(who.now)
    .fetch_one(&mut *tx)
    .await?;
    let g = grant(&r)?;
    let writes: Vec<&String> = caps
        .iter()
        .filter(|n| d.capability(n).is_some_and(|c| c.write))
        .collect();
    audit(
        &mut tx,
        who.actor,
        "connection.granted",
        connection_id,
        json!({"grantee_kind": new.grantee_kind, "grantee": new.grantee, "capabilities": caps,
               "writes": writes, "limits": new.limits, "replaced": exists > 0,
               "by_device": who.by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(g)
}

/// Takes a grantee's grant away; whether there was one. Audited `connection.grant_revoked`.
pub async fn revoke(
    pool: &SqlitePool,
    connection_id: i64,
    (grantee_kind, grantee): (&str, &str),
    who: Who<'_>,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    find(&mut tx, who.workspace, connection_id).await?;
    let n = sqlx::query(
        "DELETE FROM core_connection_grants WHERE connection_id = ? AND grantee_kind = ? \
         AND grantee = ?",
    )
    .bind(connection_id)
    .bind(grantee_kind)
    .bind(grantee)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n > 0 {
        audit(
            &mut tx,
            who.actor,
            "connection.grant_revoked",
            connection_id,
            json!({"grantee_kind": grantee_kind, "grantee": grantee, "by_device": who.by_device}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(n > 0)
}
