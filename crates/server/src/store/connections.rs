//! Connections, owned by the Core (C1; design `2026-11-06-core-connections-design` §1-§5). A
//! connection is one account on one kind (`github`, `jira`): many per kind, shared in the
//! workspace, used by those it is granted to.
//!
//! - **Write-only credential.** The access and refresh tokens are sealed in
//!   `core_connection_secrets` (master key, label `core.connection:<id>:<nonce>:v<n>`, rotated with the
//!   broker's secrets by `reseal_all`). [`Connection`] has no field for them; the only reader is
//!   [`secret::open`], for the broker and an adapter's test. No row, event, audit row or error
//!   built here names a token, and `Material` prints nothing.
//! - **The gate.** Sealing obeys the broker's gates: `secrets.mode` 0 refuses it, and below
//!   mode 2 a token the redactor recognises as a real credential shape is refused.
//! - **Control.** The store does not know roles of devices: C5's routes decide who may manage
//!   (admin, with step-up). Here a grant says who may USE (a user, a role, an agent), with which
//!   capabilities (read-only unless it names write ones) and which resources. Managing a
//!   connection is not using it: an admin needs a grant too.
//! - **Routing** (decision 7): a session never names a connection. A use goes to the connection
//!   of the kind whose grant limits cover the resource; if several cover it, the kind's default
//!   (the workspace binding) wins; none, or several without a default, refuses with the reason
//!   (`ambiguous` lists them). The project, agent and session binding scopes are unused capacity.
//! - **Delete** is refused (`conflict`) while the connection is its kind's default (the workspace
//!   binding). Its grants, secret (overwritten, freed pages zero-filled in the file by
//!   `secure_delete`; the WAL keeps an older copy until a checkpoint) and unused-scope bindings go
//!   with it.
//! - **Workspaces.** Every function takes the acting workspace (`Who::workspace`, or an argument)
//!   and finds a connection only there: another workspace's id is `not_found`.
//! - **Health** is S3's states, cooldowns and lazy recovery; an upstream auth failure is pending
//!   until a test confirms it, and only a test that the service rejects disables ([`verdict`]).
//! - **Audit.** Every write appends a `connection.*` row naming ids, kinds and results, never a
//!   payload. The names are registered ([`AUDIT_ACTIONS`]) but, until C4, not in the contract.
//! - **Limits.** Per user (the workspace owner): [`MAX_PER_USER`] connections,
//!   [`MAX_BINDINGS`] bindings; per connection [`MAX_GRANTS`] grants.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::secrets::Error;

pub mod bindings;
pub mod grants;
pub mod health;
pub mod resolve;
pub mod secret;
pub mod verdict;
mod write;
pub use write::{NewConnection, create, delete, rename, set_disabled, update_label};

#[cfg(test)]
mod tests;

pub const MAX_PER_USER: i64 = 32;
pub const MAX_GRANTS: i64 = 32;
pub const MAX_BINDINGS: i64 = 128;

/// The audit actions this module writes. Registered with the platform's by `kinds::register_platform`
/// but kept out of the contract list (`PLATFORM_AUDIT_ACTIONS`) while nothing writes them in
/// production. C4, the first story that does (it writes `connection.used`), must move them into
/// `PLATFORM_AUDIT_ACTIONS`, drop the second `register` call and bump API_MINOR.
pub const AUDIT_ACTIONS: &[&str] = &[
    "connection.auth_failed",
    "connection.auth_inconclusive",
    "connection.bound",
    "connection.created",
    "connection.deleted",
    "connection.disabled",
    "connection.enabled",
    "connection.grant_revoked",
    "connection.granted",
    "connection.renamed",
    "connection.secret_replaced",
    "connection.state_set",
    "connection.tested",
    "connection.unbound",
    "connection.updated",
    "connection.used",
];

/// Who did it and when; the audit row's actor, the device named in its details, the clock, and
/// the workspace (the owner user) the call acts in.
#[derive(Clone, Copy)]
pub struct Who<'a> {
    pub workspace: i64,
    pub by_device: &'a str,
    pub actor: AuditActor,
    pub now: &'a str,
}

/// A connection as it is read: everything but its credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: i64,
    pub user_id: i64,
    pub kind: String,
    pub name: String,
    pub label: String,
    /// The account or site the credential belongs to, as the last test read it.
    pub identity: Option<String>,
    pub auth_method: String,
    /// Health: `active`, `cooling`, `limited`, `unhealthy` or `disabled` (a confirmed auth failure).
    pub status: String,
    pub state_reason: Option<String>,
    pub state_until: Option<String>,
    pub last_tested_at: Option<String>,
    /// The access token's expiry, when known.
    pub expires_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    /// The admin's own off switch.
    pub disabled: bool,
}

macro_rules! select {
    () => {
        "SELECT c.id, c.user_id, c.kind, c.name, c.label, c.identity, c.auth_method, c.status, \
         c.state_reason, c.state_until, c.last_tested_at, c.created_by, c.created_at, \
         c.updated_at, c.disabled, s.expires_at AS expires_at FROM core_connections c \
         LEFT JOIN core_connection_secrets s ON s.connection_id = c.id"
    };
}

fn row(r: &SqliteRow) -> Result<Connection, sqlx::Error> {
    Ok(Connection {
        id: r.try_get("id")?,
        user_id: r.try_get("user_id")?,
        kind: r.try_get("kind")?,
        name: r.try_get("name")?,
        label: r.try_get("label")?,
        identity: r.try_get("identity")?,
        auth_method: r.try_get("auth_method")?,
        status: r.try_get("status")?,
        state_reason: r.try_get("state_reason")?,
        state_until: r.try_get("state_until")?,
        last_tested_at: r.try_get("last_tested_at")?,
        expires_at: r.try_get("expires_at")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
        disabled: r.try_get::<i64, _>("disabled")? == 1,
    })
}

pub(crate) fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// `[a-z][a-z0-9._-]{0,63}`, unique per kind.
pub fn valid_name(s: &str) -> bool {
    super::pools::valid_name(s)
}

/// A label or identity is text a person reads: no control characters.
pub fn valid_text(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.chars().count()) && !s.chars().any(char::is_control)
}

/// A path of non-empty segments, none of them `.` or `..`.
pub fn clean_path(s: &str) -> bool {
    s.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// A project, repo or session id: 1 to 128 of `[A-Za-z0-9._:/-]`, as a clean path.
pub fn valid_ref(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        && clean_path(s)
}

pub(crate) async fn audit(
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
            kind: "connection".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// The connection `id` of workspace `ws`; another workspace's is `not_found`.
pub(crate) async fn find(
    conn: &mut SqliteConnection,
    ws: i64,
    id: i64,
) -> Result<Connection, Error> {
    match sqlx::query(concat!(select!(), " WHERE c.id = ? AND c.user_id = ?"))
        .bind(id)
        .bind(ws)
        .fetch_optional(&mut *conn)
        .await?
    {
        Some(r) => Ok(row(&r)?),
        None => refused("not_found", "no such connection"),
    }
}

pub async fn get(pool: &SqlitePool, ws: i64, id: i64) -> Result<Connection, Error> {
    let mut conn = pool.acquire().await?;
    find(&mut conn, ws, id).await
}

/// `user_id`'s connections (of `kind` when given), oldest first.
pub async fn list(
    pool: &SqlitePool,
    user_id: i64,
    kind: Option<&str>,
) -> Result<Vec<Connection>, sqlx::Error> {
    sqlx::query(concat!(
        select!(),
        " WHERE c.user_id = ?1 AND (?2 IS NULL OR c.kind = ?2) ORDER BY c.id"
    ))
    .bind(user_id)
    .bind(kind)
    .fetch_all(pool)
    .await?
    .iter()
    .map(row)
    .collect()
}
