//! Which connection a use gets, and whether it may have it (design §4, §5). [`resolve`] is the
//! one decision; the broker (C4) and Core features call it, then [`record_use`] with how the
//! upstream call went.
//!
//! **Order.** An explicit `pick` (a connection id) is used as given. Otherwise the bindings of
//! the kind, most specific first: session, agent, project or repo, workspace default. The first
//! binding found DECIDES: if its connection is refused the use is refused naming that level, and
//! a less specific binding is never tried (it could be another account). No binding: `no_binding`;
//! nothing is picked on its own, even with one connection of the kind.
//!
//! **Checks**, in this order, each a distinct refusal code: `unknown_kind`, `capability_unknown`,
//! `not_allowlisted` (the session's capability allowlist), `no_binding`, `not_found` (another
//! workspace's connection, or one gone), `disabled`, `auth_failed`, `auth_pending`, `unhealthy`,
//! `not_granted` (no grant of the user, the role or the agent), `capability_missing`,
//! `resource_required`, `resource_denied`. Grants are judged one at a time: the use passes if ONE
//! grant of the caller covers the capability and the resource. Managing a connection is not
//! using it: an admin needs a grant too.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::grants::{Grant, value_matches};
use super::{Connection, audit, get, health, refused, valid_ref, verdict};
use crate::connections::adapter::Registry;
use crate::store::secrets::Error;

/// Who asks, for what.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The workspace owner whose connections these are.
    pub workspace: i64,
    /// The caller; an agent acts for its user, so the user's grants apply to it.
    pub user: i64,
    /// `admin` or `member` (C5 derives it from the device's scopes).
    pub role: &'a str,
    pub agent: Option<&'a str>,
    pub project: Option<&'a str>,
    pub session: Option<&'a str>,
    /// A connection chosen by id instead of by bindings.
    pub pick: Option<i64>,
    /// The capability the operation needs (`Descriptor::capability_of`).
    pub capability: &'a str,
    /// The resource it touches: a limit key and a concrete value (`repos`, `owner/repo`).
    pub resource: Option<(&'a str, &'a str)>,
    /// The session's allowlist of capabilities; `None`: no further limit.
    pub allowlist: Option<&'a [String]>,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub connection: Connection,
    /// `explicit`, or the scope of the binding that chose it.
    pub via: &'static str,
    pub grant: i64,
}

/// Why one grant does not cover the use, weakest first.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Miss {
    Capability,
    ResourceRequired,
    ResourceDenied,
}

fn covers(g: &Grant, cx: &Context<'_>) -> Result<(), Miss> {
    if !g.capabilities.iter().any(|c| c == cx.capability) {
        return Err(Miss::Capability);
    }
    if g.limits.is_empty() {
        return Ok(());
    }
    let Some((key, value)) = cx.resource else {
        return Err(Miss::ResourceRequired);
    };
    match g.limits.get(key) {
        Some(allowed) if value_matches(allowed, value) => Ok(()),
        _ => Err(Miss::ResourceDenied),
    }
}

fn mine(g: &Grant, cx: &Context<'_>) -> bool {
    match g.grantee_kind.as_str() {
        "user" => g.grantee == cx.user.to_string(),
        "role" => g.grantee == cx.role,
        "agent" => cx.agent == Some(g.grantee.as_str()),
        _ => false,
    }
}

async fn binding(
    pool: &SqlitePool,
    kind: &str,
    cx: &Context<'_>,
) -> Result<(i64, &'static str), Error> {
    let levels = [
        ("session", cx.session),
        ("agent", cx.agent),
        ("project", cx.project),
        ("workspace", Some("")),
    ];
    for (scope, r) in levels {
        let Some(r) = r else { continue };
        let id: Option<i64> = sqlx::query_scalar(
            "SELECT connection_id FROM core_connection_bindings WHERE user_id = ? AND kind = ? \
             AND scope_kind = ? AND scope_ref = ?",
        )
        .bind(cx.workspace)
        .bind(kind)
        .bind(scope)
        .bind(r)
        .fetch_optional(pool)
        .await?;
        if let Some(id) = id {
            return Ok((id, scope));
        }
    }
    refused(
        "no_binding",
        format!("no {kind} connection is bound for this use"),
    )
}

/// The connection `cx` may use for `kind`, or the reason it may not.
pub async fn resolve(
    pool: &SqlitePool,
    reg: &Registry,
    kind: &str,
    cx: &Context<'_>,
    now: &str,
) -> Result<Resolved, Error> {
    let Some(adapter) = reg.get(kind) else {
        return refused("unknown_kind", "no such kind");
    };
    if adapter.descriptor().capability(cx.capability).is_none() {
        return refused(
            "capability_unknown",
            format!("{kind} has no such capability"),
        );
    }
    if cx
        .allowlist
        .is_some_and(|l| !l.iter().any(|c| c == cx.capability))
    {
        return refused(
            "not_allowlisted",
            "the session's allowlist does not cover it",
        );
    }
    if cx
        .resource
        .is_some_and(|(k, v)| !valid_ref(v) || adapter.descriptor().limit_key(k).is_none())
    {
        return refused(
            "bad_request",
            "the resource is a limit key and a plain name",
        );
    }
    let (id, via) = match cx.pick {
        Some(id) => (id, "explicit"),
        None => binding(pool, kind, cx).await?,
    };
    // Ownership first: another workspace's connection is refused before anything is written for it.
    let c = get(pool, id).await?;
    if c.user_id != cx.workspace || c.kind != kind {
        return refused("not_found", "no such connection");
    }
    health::recover(pool, id, now).await?;
    let c = get(pool, id).await?;
    let at = |why: String| format!("{why} (chosen by {via})");
    if let Err((code, why)) = verdict::usable(&c) {
        return refused(code, at(why));
    }
    let grants = super::grants::list(pool, id).await?;
    let mut worst = None;
    let mut ok = None;
    for g in grants.iter().filter(|g| mine(g, cx)) {
        match covers(g, cx) {
            Ok(()) => {
                ok = Some(g.id);
                break;
            }
            Err(miss) => worst = worst.max(Some(miss)),
        }
    }
    match (ok, worst) {
        (Some(grant), _) => Ok(Resolved {
            connection: c,
            via,
            grant,
        }),
        (None, None) => refused(
            "not_granted",
            at("no grant lets this caller use it".to_owned()),
        ),
        (None, Some(Miss::Capability)) => refused(
            "capability_missing",
            at("the grant does not include it".to_owned()),
        ),
        (None, Some(Miss::ResourceRequired)) => refused(
            "resource_required",
            at("the grant is limited to resources".to_owned()),
        ),
        (None, Some(Miss::ResourceDenied)) => refused(
            "resource_denied",
            at("the resource is outside the grant".to_owned()),
        ),
    }
}

/// The results a use record may carry.
pub const RESULTS: [&str; 3] = ["ok", "refused", "error"];

/// One use of a connection, audited `connection.used`: kind, connection, the operation and how it
/// ended. `action` is an operation name (`github.get_issue`) and `code` the refusal code or an
/// upstream status class; both are checked to be plain identifiers, so no payload can ride in.
/// `connection` is `None` for a use refused before one was chosen.
pub async fn record_use(
    pool: &SqlitePool,
    connection: Option<i64>,
    kind: &str,
    (action, result, code): (&str, &str, Option<&str>),
    cx: &Context<'_>,
) -> Result<(), Error> {
    let ident = |s: &str| {
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.".contains(&b))
    };
    if !ident(kind)
        || !ident(action)
        || !RESULTS.contains(&result)
        || code.is_some_and(|c| !ident(c))
    {
        return refused(
            "bad_request",
            "a use record is plain identifiers and a known result",
        );
    }
    let details = json!({"kind": kind, "action": action, "capability": cx.capability,
        "result": result, "code": code, "user": cx.user, "agent": cx.agent,
        "session": cx.session});
    let mut tx = crate::store::begin_write(pool).await?;
    match connection {
        Some(id) => audit(&mut tx, AuditActor::System, "connection.used", id, details).await?,
        None => {
            let event = ainkrad_core::audit::NewAuditEvent {
                actor: AuditActor::System,
                action: "connection.used".to_owned(),
                entity: None,
                details: details.to_string(),
            };
            crate::store::audit::append(&mut tx, &event).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
