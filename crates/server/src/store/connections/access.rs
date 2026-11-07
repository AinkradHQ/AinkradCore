//! What a session may do with connections (C4; design §4, §5, decision 7): the Core's own record of
//! which user and agent a session acts for and which capabilities it may call. The broker reads
//! it from here and from nowhere else: a tool call carries a tool name and arguments, never a
//! user, an agent or an allowlist.
//!
//! Every session has access, with no row to write: its user is the session row's `user_id`, its
//! agent the session row's `agent`, its allowlist none (every operation that user is granted). An
//! optional `core_session_connections` row narrows it with an allowlist ([`set`]). An agent's
//! session with no allowlist keeps C1's rule: `resolve` refuses it (`allowlist_required`), so it
//! has no tools until an allowlist is set (C5's API).
//!
//! `tc_seq` is the cursor over the runner's numbered tool calls. [`advance`] moves it BEFORE a
//! call runs (creating the row on the first call), so a call the runner resends after a lost
//! answer is not run twice.

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
    pub grant: Granted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    /// The session row's agent.
    pub agent: Option<String>,
    /// `None`: no further limit (see the module docs for an agent's session).
    pub allowlist: Option<Vec<String>>,
    pub tc_seq: u64,
}

/// The access of session `id`, or `None` when there is no such session.
pub async fn load(pool: &SqlitePool, id: &str) -> Result<Option<Access>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT s.user_id, s.runner, s.state, s.agent, a.allowlist, a.tc_seq \
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
    // A stored list that does not read is an empty one (nothing allowed), never "no limit".
    let allowlist = r
        .try_get::<Option<String>, _>("allowlist")?
        .map(|list| serde_json::from_str::<Vec<String>>(&list).unwrap_or_default());
    let tc_seq: Option<i64> = r.try_get("tc_seq")?;
    Ok(Some(Access {
        session: id.to_owned(),
        runner: r.try_get("runner")?,
        live: !matches!(state.as_str(), "ended" | "lost"),
        user: r.try_get("user_id")?,
        grant: Granted {
            agent: r.try_get("agent")?,
            allowlist,
            tc_seq: u64::try_from(tc_seq.unwrap_or(0)).unwrap_or(0),
        },
    }))
}

/// Narrows session `session` to the capabilities in `allowlist` (at most 16 plain names). Called by
/// the Core, never from a request of the runner. Kept in the row alone (the audit log names
/// registered actions only; every use of it is audited as `connection.used`).
pub async fn set(pool: &SqlitePool, session: &str, allowlist: &[String]) -> Result<(), Error> {
    let plain = |c: &String| {
        (1..=40).contains(&c.len())
            && c.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    if !valid_ref(session) || allowlist.len() > 16 || !allowlist.iter().all(plain) {
        return super::refused(
            "bad_request",
            "a session's allowlist is at most 16 capability names",
        );
    }
    let list = serde_json::to_string(allowlist).expect("strings serialize");
    sqlx::query(
        "INSERT INTO core_session_connections (session, user_id, allowlist) \
         SELECT id, user_id, ?2 FROM core_agent_sessions WHERE id = ?1 \
         ON CONFLICT (session) DO UPDATE SET allowlist = excluded.allowlist",
    )
    .bind(session)
    .bind(list)
    .execute(pool)
    .await?;
    Ok(())
}

/// What a call's number says against the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The next number: take the call (the cursor moved).
    Take,
    /// At or below the cursor: a resend, already taken.
    Stale,
    /// Past the next number: a call was lost. The cursor moved to it so later calls line up, and
    /// this one is answered `out_of_order`, not run.
    Gap,
}

/// Moves the call cursor of `session` to `seq` unless it is already there or past it, and says
/// which of the three it was. The first call of a session creates its row.
pub async fn advance(pool: &SqlitePool, session: &str, seq: u64) -> Result<Step, sqlx::Error> {
    let to = i64::try_from(seq).unwrap_or(i64::MAX);
    let mut tx = crate::store::begin_write(pool).await?;
    let cur: Option<i64> =
        sqlx::query_scalar("SELECT tc_seq FROM core_session_connections WHERE session = ?")
            .bind(session)
            .fetch_optional(&mut *tx)
            .await?;
    let cur = cur.unwrap_or(0);
    if to <= cur {
        return Ok(Step::Stale);
    }
    let moved = sqlx::query(
        "INSERT INTO core_session_connections (session, user_id, tc_seq) \
         SELECT id, user_id, ?2 FROM core_agent_sessions WHERE id = ?1 \
         ON CONFLICT (session) DO UPDATE SET tc_seq = excluded.tc_seq",
    )
    .bind(session)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(match (moved.rows_affected(), to == cur + 1) {
        (0, _) => Step::Stale,
        (_, true) => Step::Take,
        _ => Step::Gap,
    })
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
    let g = &acc.grant;
    // An agent's session with no allowlist is refused by `resolve`: it sees no tools.
    if g.agent.is_some() && g.allowlist.is_none() {
        return Ok(Vec::new());
    }
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
            let allowed = g.allowlist.as_ref().is_none_or(|l| l.contains(cap));
            if by_agent && allowed && !out.contains(cap) {
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

/// The one aggregated audit row of a flood: `count` calls of `session` were refused for rate since
/// the last row, none of them with a row of its own. Plain codes and numbers only.
pub async fn audit_flood(
    pool: &SqlitePool,
    acc: Option<&Access>,
    session: &str,
    count: usize,
) -> Result<(), Error> {
    let session = valid_ref(session).then_some(session);
    let details = json!({"result": "refused", "code": "rate_limited", "count": count,
        "user": acc.map_or(0, |a| a.user), "session": session});
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
