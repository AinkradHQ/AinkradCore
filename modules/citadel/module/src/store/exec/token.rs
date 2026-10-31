//! A run's token for its agent's callbacks (the MCP server, S8). Issued for a live run, for at
//! most `run.token_ttl_secs`; revoked when the run ends (`transition_in`) or a new one is issued;
//! checked by [`authorize_run_token`] on every call. The raw token is 32 bytes from the OS RNG,
//! hex behind a `cit_run_` prefix so secret scanners can spot it, returned once and never stored:
//! only its SHA-256 is. Lookup is by that hash through the primary key, so no comparison runs over
//! secret bytes. A token names one run, and everything it may reach is read from that run.

use ainkrad_core_server::auth::crypto;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row, SqliteConnection};

use super::*;
use crate::domain::org::CompanyId;
use crate::store::audit::{self, Event};

/// Why a token was refused. Coarse to the bearer; precise for the log.
#[derive(Debug)]
pub enum AuthError {
    Unknown,
    Expired,
    Revoked,
    RunNotLive,
    Db(Error),
}

impl From<Error> for AuthError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown run token",
            Self::Expired => "run token expired",
            Self::Revoked => "run token revoked",
            Self::RunNotLive => "run is not running",
            Self::Db(_) => "internal error",
        })
    }
}

/// What a valid token grants: one run, and the agent, issue and company of that run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunScope {
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub company_id: CompanyId,
}

/// A raw token. Not `Debug`, so nothing prints it by accident.
pub struct RunToken(String);

impl RunToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

pub fn key_hash(raw: &str) -> String {
    hex(&crypto::sha256(raw.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Issues a fresh token for a live run and revokes the one it had: at most one token per run is
/// ever valid. `RunNotLive` when the run is missing or not claimed or running.
pub async fn issue_run_token(
    pool: &SqlitePool,
    id: RunId,
    now: &str,
) -> Result<RunToken, AuthError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let Some(run) = run_in(&mut tx, id)
        .await?
        .filter(|r| !r.state.is_terminal() && r.state != RunState::Queued)
    else {
        return Err(AuthError::RunNotLive);
    };
    revoke_in(&mut tx, id, now).await?;
    let raw = format!("cit_run_{}", hex(&crypto::random::<32>()));
    let ttl = crate::settings::value_in(&mut tx, "run.token_ttl_secs").await?;
    let (expires_at, company): (String, i64) = sqlx::query_as(
        "INSERT INTO citadel_run_tokens (token_hash, run_id, issued_at, expires_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', ?3, ?4)) \
         RETURNING expires_at, (SELECT company_id FROM citadel_agents WHERE id = ?5)",
    )
    .bind(key_hash(&raw))
    .bind(id.0)
    .bind(now)
    .bind(format!("+{ttl} seconds"))
    .bind(run.agent_id.0)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(
        &mut tx,
        Event::new(SYSTEM, "run.token_issued")
            .entity("run", id.0)
            .company(company)
            .run(id.0)
            .details(json!({"expires_at": expires_at})),
    )
    .await?;
    tx.commit().await?;
    Ok(RunToken(raw))
}

/// Revokes the run's unrevoked token, if any, as of `now`.
pub(crate) async fn revoke_in(
    conn: &mut SqliteConnection,
    run: RunId,
    now: &str,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE citadel_run_tokens SET revoked_at = ? WHERE run_id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(run.0)
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// The scope `raw` grants at `now`, read from the stored run. Refused when no token has its hash
/// (`Unknown`), it was revoked, it is past its expiry, or its run is no longer live.
pub async fn authorize_run_token(
    pool: &SqlitePool,
    raw: &str,
    now: &str,
) -> Result<RunScope, AuthError> {
    let Some(row) = sqlx::query(
        "SELECT t.revoked_at IS NOT NULL AS revoked, julianday(t.expires_at) <= julianday(?) AS expired, \
         r.id, r.state, r.agent_id, r.issue_id, a.company_id, a.status AS agent_status, \
         r.cancel_requested_at IS NOT NULL AS stopping \
         FROM citadel_run_tokens t JOIN citadel_runs r ON r.id = t.run_id \
         JOIN citadel_agents a ON a.id = r.agent_id WHERE t.token_hash = ?",
    )
    .bind(now)
    .bind(key_hash(raw))
    .fetch_optional(pool)
    .await?
    else {
        return Err(AuthError::Unknown);
    };
    if row.try_get("revoked")? {
        return Err(AuthError::Revoked);
    }
    if row.try_get("expired")? {
        return Err(AuthError::Expired);
    }
    let state: RunState = text(&row, "state")?;
    // An agent that is paused or terminated, or a run being stopped, keeps no write power even if
    // the runner never answers the stop.
    let agent_status: String = row.try_get("agent_status")?;
    if state.is_terminal()
        || state == RunState::Queued
        || agent_status != "active"
        || row.try_get::<bool, _>("stopping")?
    {
        return Err(AuthError::RunNotLive);
    }
    Ok(RunScope {
        run_id: RunId(row.try_get("id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        company_id: CompanyId(row.try_get("company_id")?),
    })
}
