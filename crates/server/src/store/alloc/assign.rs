//! The allocator's writes to the session row: the assignment, the wait, and the step back a
//! re-pick takes. Every one runs in the caller's write transaction.

use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::{Ask, Entry, Picked};
use crate::store::agents::SessionSecret;
use crate::store::events;
use crate::store::gateway::account_secret;
use crate::store::secrets::ACCOUNT_PREFIX;

/// How many accounts a launch may refuse after the pick before the session ends (design §5).
pub const MAX_REPICKS: usize = 2;

/// What the allocator needs to know of a session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub user: i64,
    /// The chain snapshot; `None` for a session that names its account itself (the allocator is
    /// never involved in it). A snapshot that does not read is an empty chain: nothing to give.
    pub chain: Option<Vec<Entry>>,
    pub account: Option<i64>,
    pub pos: Option<usize>,
    /// The accounts a launch has refused already.
    pub tried: Vec<i64>,
}

pub async fn view_in(conn: &mut SqliteConnection, id: &str) -> Result<Option<View>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT user_id, chain, account_id, chain_pos, tried_accounts FROM core_agent_sessions \
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(View {
        user: r.try_get("user_id")?,
        chain: r
            .try_get::<Option<String>, _>("chain")?
            .map(|j| serde_json::from_str(&j).unwrap_or_default()),
        account: r.try_get("account_id")?,
        pos: r
            .try_get::<Option<i64>, _>("chain_pos")?
            .and_then(|p| usize::try_from(p).ok()),
        tried: serde_json::from_str(&r.try_get::<String, _>("tried_accounts")?).unwrap_or_default(),
    }))
}

pub async fn view(pool: &SqlitePool, id: &str) -> Result<Option<View>, sqlx::Error> {
    view_in(&mut *pool.acquire().await?, id).await
}

/// Whether a session that draws from a chain may not launch as `secrets` (the row the caller
/// holds) has it: no account yet, or an account its copy of the row does not name (the pick
/// finished after it was read). Either way the harness would start on the runner's own login.
pub async fn unassigned(
    pool: &SqlitePool,
    id: &str,
    secrets: &[SessionSecret],
) -> Result<bool, sqlx::Error> {
    let row: Option<(bool, Option<i64>)> = sqlx::query_as(
        "SELECT chain IS NOT NULL, account_id FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((true, held)) => !held.is_some_and(|a| {
            secrets
                .iter()
                .any(|s| account_secret(&s.name).is_some_and(|(_, n)| n == a))
        }),
        _ => false,
    })
}

async fn secrets_of(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<SessionSecret>, sqlx::Error> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT secrets FROM core_agent_sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    Ok(json
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default())
}

/// The assignment the session already has, as a pick (a retry gets it back, and no second hold).
pub(super) async fn existing_in(
    conn: &mut SqliteConnection,
    ask: &Ask<'_>,
) -> Result<Option<Picked>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT account_id, chain_pos, harness, model, gateway_account_id FROM core_agent_sessions \
         WHERE id = ? AND account_id IS NOT NULL AND chain_pos IS NOT NULL",
    )
    .bind(ask.session)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let account: i64 = r.try_get("account_id")?;
    let pos = usize::try_from(r.try_get::<i64, _>("chain_pos")?).unwrap_or(0);
    let Some(secret) = secrets_of(conn, ask.session)
        .await?
        .into_iter()
        .find(|s| account_secret(&s.name).is_some_and(|(_, id)| id == account))
    else {
        return Ok(None);
    };
    let entry = ask.chain.get(pos);
    Ok(Some(Picked {
        account,
        pool: entry.map_or(0, |e| e.pool),
        pos,
        provider: entry.map_or_else(String::new, |e| e.provider.clone()),
        harness: r.try_get("harness")?,
        model: r.try_get("model")?,
        secret,
        gateway: r.try_get::<Option<i64>, _>("gateway_account_id")?.is_some(),
    }))
}

/// Writes the pick to the session's row, if it has one (a successor row, S6, is inserted with the
/// same values): the account, its secret in place of any account secret the row held, the harness
/// and model of the entry, the chain position, and `gateway_account_id` for an API key (the grant
/// refuses a session whose gateway account is not the one its secret names).
pub(super) async fn assign_in(
    conn: &mut SqliteConnection,
    session: &str,
    p: &Picked,
) -> Result<(), sqlx::Error> {
    let mut secrets = secrets_of(conn, session).await?;
    secrets.retain(|s| !s.name.starts_with(ACCOUNT_PREFIX));
    secrets.push(p.secret.clone());
    sqlx::query(
        "UPDATE core_agent_sessions SET account_id = ?, gateway_account_id = ?, secrets = ?, \
         harness = ?, model = ?, chain_pos = ?, waiting = NULL \
         WHERE id = ? AND state NOT IN ('ended', 'lost')",
    )
    .bind(p.account)
    .bind(p.gateway.then_some(p.account))
    .bind(serde_json::to_string(&secrets).expect("names serialize"))
    .bind(&p.harness)
    .bind(&p.model)
    .bind(i64::try_from(p.pos).unwrap_or(i64::MAX))
    .bind(session)
    .execute(conn)
    .await
    .map(drop)
}

/// The session stays `starting` and says until when and why: in its row, and once in an
/// `agent.state` event per change (the supervisor asks again every few seconds).
pub(super) async fn waiting_in(
    conn: &mut SqliteConnection,
    session: &str,
    until: &str,
    why: &str,
) -> Result<(), sqlx::Error> {
    let waiting = json!({"until": until, "why": why});
    let changed = sqlx::query(
        "UPDATE core_agent_sessions SET waiting = ?1 WHERE id = ?2 AND state = 'starting' \
         AND account_id IS NULL AND waiting IS NOT ?1",
    )
    .bind(waiting.to_string())
    .bind(session)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if changed > 0 {
        let payload = json!({"session": session, "state": "starting", "reason": "waiting",
            "waiting": waiting});
        events::append(conn, "agent.state", &payload).await?;
    }
    Ok(())
}

/// A launch refused the session's account after the pick: the hold goes back, the account is
/// remembered as tried and the assignment is cleared, for a pick that leaves it out. `None` when
/// the session has no account, or has used its [`MAX_REPICKS`].
pub async fn retreat_in(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<Option<Vec<i64>>, sqlx::Error> {
    let Some(v) = view_in(conn, session).await? else {
        return Ok(None);
    };
    // One session, one account, for its whole life: only a row that never reached its runner may
    // leave the account the pick gave it (a session that ran, or is woken, ends instead).
    let fresh: bool = sqlx::query_scalar(
        "SELECT count(*) > 0 FROM core_agent_sessions WHERE id = ? AND state = 'starting' \
         AND resumes = 0 AND last_seq = 0 AND harness_session IS NULL",
    )
    .bind(session)
    .fetch_one(&mut *conn)
    .await?;
    let Some(account) = v.account.filter(|_| fresh && v.tried.len() < MAX_REPICKS) else {
        return Ok(None);
    };
    let mut tried = v.tried;
    tried.push(account);
    let mut secrets = secrets_of(conn, session).await?;
    secrets.retain(|s| !s.name.starts_with(ACCOUNT_PREFIX));
    crate::store::budgets::guard::release_in(conn, session).await?;
    sqlx::query(
        "UPDATE core_agent_sessions SET account_id = NULL, gateway_account_id = NULL, \
         secrets = ?, tried_accounts = ?, waiting = NULL WHERE id = ?",
    )
    .bind(serde_json::to_string(&secrets).expect("names serialize"))
    .bind(json!(tried).to_string())
    .bind(session)
    .execute(conn)
    .await?;
    Ok(Some(tried))
}
