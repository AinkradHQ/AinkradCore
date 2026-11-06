//! Bindings, which chain a new session gets, and a session's chain (see the parent module).

use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use ainkrad_core::audit::AuditActor;

use super::{Binding, ChainEntry, MAX_BINDINGS, Request, audit, find, load, refused};
use crate::store::agents::{NewSession, Session, SessionSecret};
use crate::store::pools;
use crate::store::secrets::{ACCOUNT_PREFIX, Error};

/// Binds `agent` to the chain, replacing its earlier binding: `chain.bound`.
pub async fn bind(
    pool: &SqlitePool,
    agent: &str,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(), Error> {
    if !pools::valid_agent(agent) {
        return refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]");
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let c = find(&mut tx, id).await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_chain_bindings WHERE user_id = ?")
        .bind(c.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if n >= MAX_BINDINGS {
        return refused("limit_reached", "too many bindings");
    }
    sqlx::query(
        "INSERT INTO core_chain_bindings (user_id, agent, chain_id, created_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT (user_id, agent) DO UPDATE SET chain_id = excluded.chain_id, \
         created_at = excluded.created_at",
    )
    .bind(c.user_id)
    .bind(agent)
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        actor,
        "chain.bound",
        id,
        json!({"agent": agent, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Drops `agent`'s binding (its sessions fall back to the default chain): `chain.unbound`.
pub async fn unbind(
    pool: &SqlitePool,
    user_id: i64,
    agent: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let id: Option<i64> = sqlx::query_scalar(
        "DELETE FROM core_chain_bindings WHERE user_id = ? AND agent = ? RETURNING chain_id",
    )
    .bind(user_id)
    .bind(agent)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(id) = id else {
        return refused("not_found", "that agent has no chain binding");
    };
    audit(
        &mut tx,
        actor,
        "chain.unbound",
        id,
        json!({"agent": agent, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Every binding, by agent.
pub async fn list_bindings(pool: &SqlitePool) -> Result<Vec<Binding>, sqlx::Error> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT user_id, agent, chain_id FROM core_chain_bindings ORDER BY agent, user_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(user_id, agent, chain_id)| Binding {
            user_id,
            agent,
            chain_id,
        })
        .collect())
}

/// Which chain a new session of `user` gets (design §4.5): the one it names (`not_found` if it is
/// missing or another user's), else, when it names an `agent`, the one that agent is bound to, else
/// the user's default; a request naming neither gets none (the harness then uses the runner's own
/// login, as before).
pub async fn resolve_for(
    conn: &mut SqliteConnection,
    user: i64,
    chain: Option<i64>,
    agent: Option<&str>,
) -> Result<Option<i64>, Error> {
    if let Some(id) = chain {
        let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM core_chains WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
        return match owner {
            Some(o) if o == user => Ok(Some(id)),
            _ => refused("not_found", "no such chain"),
        };
    }
    if let Some(agent) = agent {
        let bound: Option<i64> = sqlx::query_scalar(
            "SELECT b.chain_id FROM core_chain_bindings b JOIN core_chains c ON c.id = b.chain_id \
             WHERE b.agent = ? AND b.user_id = ? AND c.user_id = ?",
        )
        .bind(agent)
        .bind(user)
        .bind(user)
        .fetch_optional(&mut *conn)
        .await?;
        if bound.is_some() {
            return Ok(bound);
        }
        // The default serves an agent bound to none (design §4.5 item 2), never a request that names
        // neither a chain nor an agent (item 3: that one has no account, as before).
        return Ok(sqlx::query_scalar(
            "SELECT id FROM core_chains WHERE user_id = ? AND is_default = 1",
        )
        .bind(user)
        .fetch_optional(&mut *conn)
        .await?);
    }
    Ok(None)
}

/// Gives the `starting` session `session` the chain `chain_id`: its `chain_id`, `agent` and a
/// snapshot of the resolved entries. Refused: no such session or chain, another user's chain, a
/// session that already runs, already has a chain, is a module's, or names an `acct.*` secret (a
/// pinned account never fails over).
pub async fn assign_in(
    conn: &mut SqliteConnection,
    session: &str,
    chain_id: i64,
    agent: Option<&str>,
) -> Result<Vec<ChainEntry>, Error> {
    if agent.is_some_and(|a| !pools::valid_agent(a)) {
        return refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]");
    }
    let row = sqlx::query(
        "SELECT user_id, state, chain_id, owner_module, secrets FROM core_agent_sessions \
         WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return refused("not_found", "no such session");
    };
    let user: i64 = row.try_get("user_id")?;
    let state: String = row.try_get("state")?;
    let had: Option<i64> = row.try_get("chain_id")?;
    let owner: Option<String> = row.try_get("owner_module")?;
    let secrets: String = row.try_get("secrets")?;
    if state != "starting" || had.is_some() {
        return refused("conflict", "only a new session without a chain takes one");
    }
    if owner.is_some() {
        return refused("bad_request", "a module's session takes no chain");
    }
    // Unreadable secrets fail closed: a session whose secrets cannot be read takes no chain.
    let Ok(named) = serde_json::from_str::<Vec<SessionSecret>>(&secrets) else {
        return refused("bad_request", "the session's secrets are unreadable");
    };
    if named.iter().any(|s| s.name.starts_with(ACCOUNT_PREFIX)) {
        return refused(
            "bad_request",
            "a session with a chain names no account secret",
        );
    }
    let c = find(conn, chain_id).await?;
    if c.user_id != user {
        return refused("not_found", "no such chain");
    }
    let snapshot = serde_json::to_string(&c.entries).expect("entries serialize");
    sqlx::query("UPDATE core_agent_sessions SET chain_id = ?, chain = ?, agent = ? WHERE id = ?")
        .bind(chain_id)
        .bind(snapshot)
        .bind(agent)
        .bind(session)
        .execute(&mut *conn)
        .await?;
    Ok(c.entries)
}

/// The snapshot a session walks, if it has a chain.
pub async fn session_chain(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<Option<Vec<ChainEntry>>, Error> {
    let raw: Option<Option<String>> =
        sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(raw.flatten().and_then(|s| serde_json::from_str(&s).ok()))
}

/// `agents::create_owned_ref` with the chains of design §4.5: [`resolve_for`] says which chain, and
/// the row is inserted and given its chain in ONE transaction, so a chain session is never seen
/// (and never launched on the runner's own login) before its chain is on it. With a chain, the row's
/// harness and model are placeholders: the first entry's, until the allocator picks; the caller
/// passes `harness: ""` and no model (a named one is `bad_request`). With none, the session is exactly
/// `create_owned_ref`'s (its harness required), with the agent recorded.
pub async fn create_session(
    pool: &SqlitePool,
    new: &NewSession<'_>,
    owner: Option<&str>,
    owner_ref: Option<&str>,
    req: Request<'_>,
    actor: AuditActor,
    now: &str,
) -> Result<Session, Error> {
    if req.agent.is_some_and(|a| !pools::valid_agent(a)) {
        return refused("bad_request", "an agent id is 1 to 64 of [A-Za-z0-9._:-]");
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let chain = resolve_for(&mut tx, req.user_id, req.chain, req.agent).await?;
    // The entry the allocator picks sets the harness and the model, so a request with a chain names
    // neither (`harness: ""`, no model; design §4.5), and one without a chain names its harness.
    if chain.is_some() && (!new.harness.is_empty() || new.model.is_some()) {
        return refused(
            "bad_request",
            "a session with a chain names no harness or model",
        );
    }
    if chain.is_none() && new.harness.is_empty() {
        return refused("bad_request", "a session with no chain names its harness");
    }
    let first = match chain {
        Some(id) => load(&mut tx, id).await?.into_iter().next(),
        None => None,
    };
    let id = match &first {
        Some(e) => {
            let placed = NewSession {
                harness: &e.harness,
                model: e.model.as_deref(),
                ..*new
            };
            crate::store::agents::create_in(&mut tx, &placed, owner, owner_ref, actor, now).await?
        }
        None => crate::store::agents::create_in(&mut tx, new, owner, owner_ref, actor, now).await?,
    };
    match chain {
        Some(c) => drop(assign_in(&mut tx, &id, c, req.agent).await?),
        None => {
            sqlx::query("UPDATE core_agent_sessions SET agent = ? WHERE id = ?")
                .bind(req.agent)
                .bind(&id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(crate::store::agents::get(pool, &id)
        .await?
        .expect("just stored"))
}
