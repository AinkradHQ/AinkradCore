//! What a session may do with connections (C4; design §4, §5, decision 7): the Core's own record of
//! which user and agent a session acts for and which capabilities it may call. The broker reads
//! it from here and from nowhere else: a tool call carries a tool name and arguments, never a
//! user, an agent or an allowlist. A session with no row here has no connection tools.
//!
//! `tc_seq` is the cursor over the runner's numbered tool calls. [`advance`] moves it BEFORE a
//! call runs, so a call the runner resends after a lost answer is not run twice.

use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;

use super::grants::{self, Grant};
use super::valid_ref;
use crate::store::secrets::Error;
use ainkrad_core::audit::AuditActor;
use serde_json::json;

/// A session as the broker sees it. Read from the Core's session row; never from a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub session: String,
    /// The runner the session is placed on: only it may call for the session.
    pub runner: String,
    pub live: bool,
    /// The workspace owner the session acts for.
    pub user: i64,
    /// `None` when the session has no `core_session_connections` row (no tools).
    pub grant: Option<Granted>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub agent: Option<String>,
    pub allowlist: Vec<String>,
    pub tc_seq: u64,
}

/// The access of session `id`, or `None` when there is no such session.
pub async fn load(pool: &SqlitePool, id: &str) -> Result<Option<Access>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT s.user_id, s.runner, s.state, a.session AS has, a.agent, a.allowlist, a.tc_seq \
         FROM core_agent_sessions s LEFT JOIN core_session_connections a ON a.session = s.id \
         WHERE s.id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let state: String = r.try_get("state")?;
    let has: Option<String> = r.try_get("has")?;
    let grant = match has {
        None => None,
        Some(_) => {
            let list: String = r.try_get("allowlist")?;
            let allowlist: Vec<String> = serde_json::from_str::<Value>(&list)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            Some(Granted {
                agent: r.try_get("agent")?,
                allowlist,
                tc_seq: u64::try_from(r.try_get::<i64, _>("tc_seq")?).unwrap_or(0),
            })
        }
    };
    Ok(Some(Access {
        session: id.to_owned(),
        runner: r.try_get("runner")?,
        live: !matches!(state.as_str(), "ended" | "lost"),
        user: r.try_get("user_id")?,
        grant,
    }))
}

/// Gives session `session` connection tools: the agent whose grants narrow the user's, and the
/// capabilities it may call (at most 16 plain names). Called by the Core when the session is made,
/// never from a request of the runner. Kept in the row alone (the audit log names registered
/// actions only; every use of it is audited as `connection.used`).
pub async fn set(
    pool: &SqlitePool,
    session: &str,
    agent: Option<&str>,
    allowlist: &[String],
) -> Result<(), Error> {
    let plain = |c: &String| {
        (1..=40).contains(&c.len())
            && c.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    if !valid_ref(session)
        || agent.is_some_and(|a| !crate::store::pools::valid_agent(a))
        || allowlist.len() > 16
        || !allowlist.iter().all(plain)
    {
        return super::refused(
            "bad_request",
            "a session's access is an agent id and at most 16 capability names",
        );
    }
    let list = serde_json::to_string(allowlist).expect("strings serialize");
    sqlx::query(
        "INSERT INTO core_session_connections (session, user_id, agent, allowlist) \
         SELECT id, user_id, ?2, ?3 FROM core_agent_sessions WHERE id = ?1 \
         ON CONFLICT (session) DO UPDATE SET agent = excluded.agent, allowlist = excluded.allowlist",
    )
    .bind(session)
    .bind(agent)
    .bind(list)
    .execute(pool)
    .await?;
    Ok(())
}

/// Moves the call cursor of `session` to `to` if that is a step forward; whether it did. A call at
/// or below the cursor was already taken.
pub async fn advance(pool: &SqlitePool, session: &str, to: u64) -> Result<bool, sqlx::Error> {
    let to = i64::try_from(to).unwrap_or(i64::MAX);
    let done = sqlx::query(
        "UPDATE core_session_connections SET tc_seq = ? WHERE session = ? AND tc_seq < ?",
    )
    .bind(to)
    .bind(session)
    .bind(to)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The capabilities session `acc` could use at all on a connection of `kind` (any resource): the
/// user's grants (user or role `member`), intersected on the same connection with the agent's
/// grants in an agent's session, and with the session's allowlist. A disabled or auth-failed
/// connection grants nothing. This is the dry run behind the tool list; `resolve` is still the
/// decision of each call.
pub async fn usable_caps(
    pool: &SqlitePool,
    acc: &Access,
    kind: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let Some(g) = &acc.grant else {
        return Ok(Vec::new());
    };
    let mut conn = pool.acquire().await?;
    let mut out: Vec<String> = Vec::new();
    for c in super::list(pool, acc.user, Some(kind)).await? {
        if c.disabled || c.status == "disabled" {
            continue;
        }
        let all: Vec<Grant> = grants::list_in(&mut conn, c.id).await?;
        let mine = |gr: &Grant| match gr.grantee_kind.as_str() {
            "user" => gr.grantee == acc.user.to_string(),
            "role" => gr.grantee == "member",
            _ => false,
        };
        let caps = |pred: &dyn Fn(&Grant) -> bool| -> Vec<&String> {
            all.iter()
                .filter(|gr| pred(gr))
                .flat_map(|gr| gr.capabilities.iter())
                .collect()
        };
        let user_side = caps(&mine);
        let agent_side = g
            .agent
            .as_deref()
            .map(|a| caps(&|gr: &Grant| gr.grantee_kind == "agent" && gr.grantee == a));
        for cap in user_side {
            let by_agent = agent_side.as_ref().is_none_or(|own| own.contains(&cap));
            if by_agent && g.allowlist.contains(cap) && !out.contains(cap) {
                out.push(cap.clone());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Whether `agent` holds a grant on connection `id` of workspace `ws` right now.
pub async fn agent_granted(
    pool: &SqlitePool,
    ws: i64,
    id: i64,
    agent: &str,
) -> Result<bool, sqlx::Error> {
    Ok(grants::list(pool, ws, id)
        .await?
        .iter()
        .any(|g| g.grantee_kind == "agent" && g.grantee == agent))
}

/// Writes the audit row of a call refused before any connection or kind was known (an unknown tool
/// name): no operation can be named, so none is. Plain codes only.
pub async fn audit_unknown(
    pool: &SqlitePool,
    user: i64,
    session: Option<&str>,
    code: &str,
) -> Result<(), Error> {
    let details = json!({"result": "refused", "code": code, "user": user, "session": session});
    let mut tx = crate::store::begin_write(pool).await?;
    let event = ainkrad_core::audit::NewAuditEvent {
        actor: AuditActor::System,
        action: "connection.used".to_owned(),
        entity: None,
        details: details.to_string(),
    };
    crate::store::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(())
}
