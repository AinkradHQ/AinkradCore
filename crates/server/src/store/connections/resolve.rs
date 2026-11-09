//! Which connection a use gets, and whether it may have it (design §4, §5, decision 7).
//! [`resolve`] is the one decision; the broker (C4) and Core features call it, then
//! [`record_use`] with how the upstream call went.
//!
//! **A session never names a connection.** It may use every connection granted to it, several per
//! kind at once. The candidates for a use are the kind's connections of the caller's workspace
//! that (1) the caller is GRANTED (a user or role grant, and, in an agent's session, also that
//! agent's grant: the intersection) with the capability, (2) whose grant limits cover the
//! resource (a GitHub repo, a Jira project), and (3) are enabled and healthy. One candidate is
//! used. Several: the kind's default (the workspace binding) if it is among them, else the use is
//! refused as `ambiguous` (it names the candidates): nothing is picked by chance. None: the
//! refusal says why, most informative first: `unhealthy` / `disabled` / `auth_failed` /
//! `auth_pending` / `no_credential` (a connection that covers it cannot be used now),
//! `resource_denied`, `resource_required`, `capability_missing`, `not_granted` (it exists but
//! none is granted), `no_connection` (the workspace has none of the kind). A connection the caller
//! is not granted is never a candidate and never described.
//!
//! **Checks before any of that**, each its own code: `not_a_member`, `unknown_kind`, `capability_unknown`,
//! `allowlist_required` (an agent's session needs an allowlist), `not_allowlisted`, `bad_request`
//! (a resource is a known limit key and a clean path). An agent grant alone grants nothing; an
//! agent grant only narrows. Managing a connection is not using it: an admin needs a grant too.
//! The project, agent and session bindings are unused capacity; only the workspace binding is read.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::grants::{Grant, Limits, value_matches};
use super::{Connection, audit, health, refused, valid_ref, verdict};
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
    /// Recorded with the use; it never selects a connection.
    pub session: Option<&'a str>,
    /// The capability the operation needs (`Descriptor::capability_of`).
    pub capability: &'a str,
    /// The operation itself, when known: one the descriptor marks `self_limited` may omit the
    /// resource under a limited grant (the adapter enforces the limits it is handed).
    pub operation: Option<&'a str>,
    /// The resource it touches: a limit key and a concrete value (`repos`, `owner/repo`).
    pub resource: Option<(&'a str, &'a str)>,
    /// The session's allowlist of capabilities; `None`: no further limit.
    pub allowlist: Option<&'a [String]>,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub connection: Connection,
    /// `only` (the one candidate) or `default` (the kind's default won among several).
    pub via: &'static str,
    pub grant: i64,
    /// The EFFECTIVE resource limits: every covering user or role grant combined (an unlimited
    /// one wins, else the union per key), intersected per key with the agent grant's in an
    /// agent's session (an agent grant narrows an unlimited one). Empty: unlimited. A candidate
    /// whose limits would leave a key empty is dropped, so a returned list is never empty. C4
    /// hands exactly these to the adapter.
    pub limits: Limits,
}

/// Why one grant does not cover the use, weakest first.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Miss {
    Capability,
    ResourceRequired,
    ResourceDenied,
}

fn covers(g: &Grant, cx: &Context<'_>, self_limited: bool) -> Result<(), Miss> {
    if !g.capabilities.iter().any(|c| c == cx.capability) {
        return Err(Miss::Capability);
    }
    if g.limits.is_empty() {
        return Ok(());
    }
    let Some((key, value)) = cx.resource else {
        return match self_limited {
            true => Ok(()),
            false => Err(Miss::ResourceRequired),
        };
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
        _ => false,
    }
}

/// The connection `cx` may use for `kind`, or the reason it may not.
pub async fn resolve(
    pool: &SqlitePool,
    reg: &Registry,
    kind: &str,
    cx: &Context<'_>,
    now: &str,
) -> Result<Resolved, Error> {
    // A caller is a member of the workspace it asks in (today: its owner user; #18 adds more).
    if cx.user != cx.workspace {
        return refused(
            "not_a_member",
            "the caller is not a member of this workspace",
        );
    }
    let Some(adapter) = reg.get(kind) else {
        return refused("unknown_kind", "no such kind");
    };
    if adapter.descriptor().capability(cx.capability).is_none() {
        return refused(
            "capability_unknown",
            format!("{kind} has no such capability"),
        );
    }
    let d = adapter.descriptor();
    if cx
        .operation
        .is_some_and(|op| d.capability_of(op).is_none_or(|c| c.name != cx.capability))
    {
        return refused(
            "bad_request",
            "the operation does not belong to the capability",
        );
    }
    let sl = cx.operation.is_some_and(|op| d.is_self_limited(op));
    // A session with an agent must say what it may call.
    if cx.agent.is_some() && cx.allowlist.is_none() {
        return refused(
            "allowlist_required",
            "an agent's session needs an allowlist",
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
    let ids: Vec<i64> = super::list(pool, cx.workspace, Some(kind))
        .await?
        .iter()
        .map(|c| c.id)
        .collect();
    for id in &ids {
        health::recover(pool, *id, now).await?;
    }
    let all = super::list(pool, cx.workspace, Some(kind)).await?;
    let mut conn = pool.acquire().await?;
    // The weakest reason first; the strongest one seen is the refusal.
    let mut worst: Option<Why> = None;
    let mut usable: Vec<(Connection, i64, Limits)> = Vec::new();
    for c in all {
        let grants = super::grants::list_in(&mut conn, c.id).await?;
        let base: Vec<&Grant> = grants.iter().filter(|g| mine(g, cx)).collect();
        // Every covering user or role grant counts, not the first: an unlimited one wins, else
        // their limits are united. An agent's grant then only narrows that.
        let judged = covering(&base, cx, sl).and_then(|gs| {
            let first = gs[0].id;
            let user_side = combined(&gs);
            let eff = match cx.agent {
                Some(a) => {
                    let own: Vec<&Grant> = grants
                        .iter()
                        .filter(|g| g.grantee_kind == "agent" && g.grantee == a)
                        .collect();
                    narrow(&user_side, &combined(&covering(&own, cx, sl)?))
                }
                None => user_side,
            };
            // A key that allows nothing makes this connection no candidate: routing looks at the
            // limits the use really gets.
            match eff.values().any(Vec::is_empty) {
                true => Err(Some(Miss::ResourceDenied)),
                false => Ok((first, eff)),
            }
        });
        match (judged, verdict::usable(&c)) {
            (Ok((grant, limits)), Ok(())) => usable.push((c, grant, limits)),
            (Ok(_), Err((code, msg))) => worst = worst.max(Some(Why::Health(code, msg))),
            (Err(miss), _) => worst = worst.max(Some(Why::Grant(miss))),
        }
    }
    drop(conn);
    match usable.len() {
        0 => Err(match worst {
            Some(w) => w.refusal(),
            None => Error::Refused {
                code: "no_connection",
                message: format!("the workspace has no {kind} connection"),
            },
        }),
        1 => {
            let (connection, grant, limits) = usable.remove(0);
            Ok(Resolved {
                connection,
                via: "only",
                grant,
                limits,
            })
        }
        _ => {
            let default: Option<i64> = sqlx::query_scalar(
                "SELECT connection_id FROM core_connection_bindings WHERE user_id = ? \
                 AND kind = ? AND scope_kind = 'workspace' AND scope_ref = ''",
            )
            .bind(cx.workspace)
            .bind(kind)
            .fetch_optional(pool)
            .await?;
            match usable.iter().position(|(c, ..)| Some(c.id) == default) {
                Some(i) => {
                    let (connection, grant, limits) = usable.swap_remove(i);
                    Ok(Resolved {
                        connection,
                        via: "default",
                        grant,
                        limits,
                    })
                }
                None => {
                    let names: Vec<&str> = usable.iter().map(|(c, ..)| c.name.as_str()).collect();
                    refused(
                        "ambiguous",
                        format!(
                            "several {kind} connections cover it ({}) and none is the default",
                            names.join(", ")
                        ),
                    )
                }
            }
        }
    }
}

/// Why no connection was used, weakest first (the strongest seen is reported).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Why {
    Grant(Option<Miss>),
    Health(&'static str, String),
}

impl Why {
    fn refusal(self) -> Error {
        match self {
            Why::Health(code, message) => Error::Refused { code, message },
            Why::Grant(miss) => denial(miss),
        }
    }
}

/// Every grant of `list` that covers the use, or the strongest miss (`None`: no grant).
fn covering<'g>(
    list: &[&'g Grant],
    cx: &Context<'_>,
    self_limited: bool,
) -> Result<Vec<&'g Grant>, Option<Miss>> {
    let (mut ok, mut worst) = (Vec::new(), None);
    for g in list {
        match covers(g, cx, self_limited) {
            Ok(()) => ok.push(*g),
            Err(miss) => worst = worst.max(Some(miss)),
        }
    }
    match ok.is_empty() {
        true => Err(worst),
        false => Ok(ok),
    }
}

/// What several grants allow together: a key stays limited only if every grant limits it (a
/// grant that does not is unlimited there), and then to the union of their values.
fn combined(gs: &[&Grant]) -> Limits {
    let mut out = Limits::new();
    for key in gs.iter().flat_map(|g| g.limits.keys()) {
        if out.contains_key(key) || !gs.iter().all(|g| g.limits.contains_key(key)) {
            continue;
        }
        let mut v: Vec<String> = gs.iter().flat_map(|g| g.limits[key].clone()).collect();
        v.sort();
        v.dedup();
        out.insert(key.clone(), v);
    }
    out
}

/// `base` intersected per key with the agent's: a value stays if the other side covers it
/// (exactly, or under its `prefix/*`). A key only one side limits is kept as it is.
fn narrow(base: &Limits, agent: &Limits) -> Limits {
    let mut out = Limits::new();
    for key in base.keys().chain(agent.keys()) {
        let values = match (base.get(key), agent.get(key)) {
            (Some(b), Some(x)) => {
                let mut v: Vec<String> = b
                    .iter()
                    .filter(|v| value_matches(x, v))
                    .chain(x.iter().filter(|v| value_matches(b, v)))
                    .cloned()
                    .collect();
                v.sort();
                v.dedup();
                v
            }
            (Some(v), None) | (None, Some(v)) => v.clone(),
            (None, None) => continue,
        };
        out.insert(key.clone(), values);
    }
    out
}

fn denial(miss: Option<Miss>) -> Error {
    let (code, message) = match miss {
        None => (
            "not_granted",
            "no connection of the kind is granted to this caller",
        ),
        Some(Miss::Capability) => ("capability_missing", "the grant does not include it"),
        Some(Miss::ResourceRequired) => ("resource_required", "the grant is limited to resources"),
        Some(Miss::ResourceDenied) => ("resource_denied", "the resource is outside every grant"),
    };
    Error::Refused {
        code,
        message: message.to_owned(),
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
    reg: &Registry,
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
    let known = reg.get(kind).is_some_and(|a| {
        let d = a.descriptor();
        // The operation must belong to the capability the use names.
        d.capability_of(action)
            .is_some_and(|c| c.name == cx.capability)
    });
    let plain = cx.agent.is_none_or(crate::store::pools::valid_agent)
        && cx.session.is_none_or(valid_ref)
        && code.is_none_or(ident);
    if !known || !plain || !RESULTS.contains(&result) {
        return refused(
            "bad_request",
            "a use record is a known operation and capability, plain identifiers and a known result",
        );
    }
    if let Some(id) = connection
        && super::get(pool, cx.workspace, id).await?.kind != kind
    {
        return refused("not_found", "no such connection");
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
