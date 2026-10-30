//! The registry of event kinds and audit actions (E1-04.2, E1-10.2). An event of a kind, or an
//! audit row of an action, that is not registered is refused by the database (the triggers of
//! migration `0002`), whichever path writes it.
//!
//! The platform's names are the lists below, registered by `store::connect`; a module's are its
//! `Module::event_kinds` and `Module::audit_actions`, registered by `migrate_modules`. A name is
//! dotted lowercase (`[a-z][a-z0-9_]*` segments joined by `.`); an audit action has at least two
//! segments; a module's names start with its id and a dot (`ops.line`), and a module may not take
//! a first segment the platform uses. The contract lists the registered names (`api/v1/spec`).
//!
//! Each event kind is visible to one scope (E1-04.3, [`VISIBLE`]): a device's event stream
//! carries only the kinds its scopes allow (`store::events::view`). The platform's `audit` is
//! `admin`, as the audit log is; a module's kinds take `Module::event_scope` (its own route
//! scope unless it says otherwise).

use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

/// The owner of the platform's names.
pub const PLATFORM: &str = "core";

/// The platform's event kinds: `audit`, one per audit row, written by the `events_from_audit`
/// trigger; and the runner hub's presence (`hub`): `runner.connected`, `runner.disconnected`,
/// `runner.degraded` (silent past two heartbeats); `notify.delivery`, one per push the
/// notifications service tried (E2-12); and a terminal's life (E2-01), who and when, never its
/// content: `terminal.opened`, `.attached`, `.detached`, `.exited`, `.closed`.
pub const PLATFORM_EVENT_KINDS: &[&str] = &[
    "audit",
    "notify.delivery",
    "runner.connected",
    "runner.degraded",
    "runner.disconnected",
    "terminal.attached",
    "terminal.closed",
    "terminal.detached",
    "terminal.exited",
    "terminal.opened",
];

/// The scopes an event kind may be visible to (a runner reads no event stream).
pub const VISIBLE: [&str; 5] = ["read", "approve", "terminal", "agent", "admin"];

/// The scope each platform event kind is visible to: `audit` is the audit log, `admin` as
/// `GET /api/v1/audit` is; runner presence (`runner.*`) is `read`, as `GET /api/v1/runners`
/// is; a terminal's (`terminal.*`) is `terminal`. A `runner` device sees none: it reads no
/// event stream at all.
pub fn platform_scope(kind: &str) -> &'static str {
    if kind.starts_with("runner.") {
        "read"
    } else if kind.starts_with("terminal.") {
        "terminal"
    } else {
        "admin"
    }
}

/// The platform's audit actions.
pub const PLATFORM_AUDIT_ACTIONS: &[&str] = &[
    "api.refused",
    "auth.lockout",
    "auth.lockout_cleared",
    "auth.step_up",
    "device.renamed",
    "device.scopes_changed",
    "device.enrolled",
    "device.last_admin_refused",
    "device.revoked",
    "job.failed",
    "job.missed",
    "job.ran",
    "notify.token_pruned",
    "pairing.approved",
    "pairing.burned",
    "pairing.claimed",
    "pairing.created",
    "pairing.expired",
    "pairing.refused",
    "pairing.rejected",
    "passkey.locked",
    "recover.started",
    "runner.command",
    "runner.refused",
    "secret.created",
    "secret.deleted",
    "secret.leased",
    "secret.redeemed",
    "secret.rotated",
    "setting.reset",
    "setting.set",
];

/// Whether `name` is dotted lowercase with at least `segments` segments.
fn well_formed(name: &str, segments: usize) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= segments
        && parts.iter().all(|p| {
            p.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// Why `owner` may not register `name` (an event kind unless `action`), if it may not.
pub fn refusal(owner: &str, name: &str, action: bool) -> Option<String> {
    if !well_formed(name, if action { 2 } else { 1 }) {
        return Some(format!("{name:?} is not dotted lowercase"));
    }
    if owner == PLATFORM {
        return None;
    }
    let first = name.split('.').next().unwrap_or_default();
    if first != owner || !name.contains('.') {
        return Some(format!("{name:?} does not start with `{owner}.`"));
    }
    let platform = PLATFORM_EVENT_KINDS.iter().chain(PLATFORM_AUDIT_ACTIONS);
    if platform
        .map(|n| n.split('.').next())
        .any(|p| p == Some(first))
    {
        return Some(format!("`{first}` is a platform namespace"));
    }
    None
}

/// Registers `owner`'s event kinds, each with the scope it is visible to, and audit actions.
/// Idempotent (a kind's scope is updated to the one given); refuses a malformed name
/// (`refusal`), a scope outside [`VISIBLE`], or a name another owner registered first
/// (`InvalidArgument`).
pub async fn register(
    conn: &mut SqliteConnection,
    owner: &str,
    event_kinds: &[(&str, &str)],
    audit_actions: &[&str],
) -> Result<(), sqlx::Error> {
    for (kind, scope) in event_kinds {
        if !VISIBLE.contains(scope) {
            return Err(sqlx::Error::InvalidArgument(format!(
                "{kind:?} is visible to {scope:?}, not a scope events are read with"
            )));
        }
        if let Some(why) = refusal(owner, kind, false) {
            return Err(sqlx::Error::InvalidArgument(why));
        }
        let held: String = sqlx::query_scalar(
            "INSERT INTO event_kinds (kind, owner, scope) VALUES (?1, ?2, ?3) \
             ON CONFLICT DO UPDATE SET scope = iif(owner = ?2, ?3, scope) RETURNING owner",
        )
        .bind(kind)
        .bind(owner)
        .bind(scope)
        .fetch_one(&mut *conn)
        .await?;
        if held != owner {
            return Err(sqlx::Error::InvalidArgument(format!(
                "{kind:?} is registered by {held}"
            )));
        }
    }
    let tables = [(audit_actions, "audit_actions", "action", true)];
    for (names, table, column, action) in tables {
        for name in names {
            if let Some(why) = refusal(owner, name, action) {
                return Err(sqlx::Error::InvalidArgument(why));
            }
            let held: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {table} ({column}, owner) VALUES (?1, ?2) \
                 ON CONFLICT DO UPDATE SET owner = owner RETURNING owner"
            )))
            .bind(name)
            .bind(owner)
            .fetch_one(&mut *conn)
            .await?;
            if held != owner {
                return Err(sqlx::Error::InvalidArgument(format!(
                    "{name:?} is registered by {held}"
                )));
            }
        }
    }
    Ok(())
}

/// Registers the platform's names, in one write.
pub async fn register_platform(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let kinds: Vec<(&str, &str)> = PLATFORM_EVENT_KINDS
        .iter()
        .map(|k| (*k, platform_scope(k)))
        .collect();
    register(&mut tx, PLATFORM, &kinds, PLATFORM_AUDIT_ACTIONS).await?;
    tx.commit().await
}

/// For tests: registers each name for the module its first segment names; event kinds are
/// visible to `read`.
#[cfg(test)]
pub(crate) async fn allow(pool: &SqlitePool, event_kinds: &[&str], audit_actions: &[&str]) {
    let mut tx = super::begin_write(pool).await.unwrap();
    let owner = |name: &str| name.split('.').next().unwrap().to_owned();
    for k in event_kinds {
        register(&mut tx, &owner(k), &[(*k, "read")], &[])
            .await
            .unwrap();
    }
    for a in audit_actions {
        register(&mut tx, &owner(a), &[], &[*a]).await.unwrap();
    }
    tx.commit().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rule() {
        assert_eq!(refusal(PLATFORM, "audit", false), None);
        assert!(
            refusal(PLATFORM, "audit", true).is_some(),
            "an action is dotted"
        );
        assert_eq!(refusal("ops", "ops.line", false), None);
        assert_eq!(refusal("ops", "ops.run.done", true), None);
        for (owner, name) in [
            ("ops", "ops"),
            ("ops", "other.line"),
            ("ops", "Ops.line"),
            ("ops", "ops..line"),
            ("ops", "ops.line."),
            ("ops", "ops.1line"),
            ("ops", "ops.li-ne"),
            ("setting", "setting.x"),
            ("device", "device.x"),
        ] {
            assert!(refusal(owner, name, false).is_some(), "{owner} {name}");
        }
    }
}
