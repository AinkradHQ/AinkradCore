//! Per-run tokens (E4.1): issued when a run starts, in the start's transaction; revoked when
//! it ends, in `transition_in`'s shared terminal path; checked by `authorize_run_token`.
//!
//! Issued at start, not at claim: the harness that uses the token is launched at start,
//! and a claimed run that never starts (cancelled, lost) never held one. The raw token is
//! 32 bytes from the OS RNG (`getrandom`), hex-encoded behind a `cit_run_` prefix so secret
//! scanners can spot it. Only its SHA-256 (`key_hash`) is stored. Lookup is by that hash
//! through a unique index, so no comparison runs over secret bytes and a constant-time
//! compare buys nothing: the raw token never meets a stored value.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::auth::{RUN_TOKEN_TTL_SECS, RunScope, RunToken};
use ainkrad_core::exec::{RunEvent, RunState};
use ainkrad_core::org::CompanyId;
use sqlx::SqliteConnection;

use super::*;
use crate::store::{audit, random_key};

/// Why a token was refused. Deliberately coarse to the bearer; precise for the server log.
#[derive(Debug)]
pub enum AuthError {
    /// No token has this hash.
    Unknown,
    /// Past its hard expiry.
    Expired,
    /// Rotated out, or its run ended.
    Revoked,
    /// Its run is not `running` (or, for issuing, not found).
    RunNotLive,
    Db(Error),
}

impl From<Error> for AuthError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown run token"),
            Self::Expired => f.write_str("run token expired"),
            Self::Revoked => f.write_str("run token revoked"),
            Self::RunNotLive => f.write_str("run is not running"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AuthError {}

/// Starts a claimed run (`RunEvent::Start`, as `transition_run`) and issues its token, in one
/// transaction. The token is returned once and never again.
pub async fn start_run(
    pool: &SqlitePool,
    id: RunId,
    actor: AuditActor,
    session: Option<String>,
    now: &str,
) -> Result<(Run, RunToken), TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let current = run_in(&mut tx, id)
        .await?
        .ok_or(TransitionError::NotFound)?;
    let start = RunEvent::Start { session };
    let (started, _) = transition_in(&mut tx, &current, actor, &start, now).await?;
    if started.state != RunState::Running {
        return Err(TransitionError::Conflict);
    }
    let token = issue_in(&mut tx, &started, actor, now).await?;
    tx.commit().await?;
    Ok((started, token))
}

/// Issues a fresh token for a running run and revokes the one it had: at most one token per
/// run is ever valid. `RunNotLive` when the run is missing or not running.
pub async fn rotate_run_token(
    pool: &SqlitePool,
    id: RunId,
    actor: AuditActor,
    now: &str,
) -> Result<RunToken, AuthError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let run = run_in(&mut tx, id).await?;
    let Some(run) = run.filter(|r| r.state == RunState::Running) else {
        return Err(AuthError::RunNotLive);
    };
    let token = issue_in(&mut tx, &run, actor, now).await?;
    tx.commit().await?;
    Ok(token)
}

/// Revokes the run's unrevoked token, if any, as of `now`.
pub(super) async fn revoke_in(
    conn: &mut SqliteConnection,
    run: RunId,
    now: &str,
) -> Result<(), Error> {
    sqlx::query("UPDATE run_tokens SET revoked_at = ? WHERE run_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(run.0)
        .execute(&mut *conn)
        .await
        .map(drop)
}

/// Revokes the run's token and stores the hash of a new one expiring `RUN_TOKEN_TTL_SECS`
/// after `now`; audits `run.token_issued` (never the token).
async fn issue_in(
    conn: &mut SqliteConnection,
    run: &Run,
    actor: AuditActor,
    now: &str,
) -> Result<RunToken, Error> {
    revoke_in(conn, run.id, now).await?;
    let token = RunToken::new(random_key("cit_run_")?);
    let (expires_at, company_id): (String, i64) = sqlx::query_as(
        "INSERT INTO run_tokens (token_hash, run_id, expires_at) \
         VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)) \
         RETURNING expires_at, (SELECT company_id FROM agents WHERE id = ?)",
    )
    .bind(key_hash(token.expose()))
    .bind(run.id.0)
    .bind(now)
    .bind(format!("+{RUN_TOKEN_TTL_SECS} seconds"))
    .bind(run.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    audit::append(
        &mut *conn,
        &NewAuditEvent {
            actor,
            action: "run.token_issued".to_owned(),
            entity: Some(AuditEntity {
                kind: "run".to_owned(),
                id: run.id.0,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id: Some(run.id),
            details: format!("{{\"expires_at\":\"{expires_at}\"}}"),
        },
    )
    .await?;
    Ok(token)
}

/// The scope `raw` grants at `now`: its run, and that run's agent, issue and company, all
/// read from the stored run. Refused when no token has its hash (`Unknown`), it was revoked
/// (`Revoked`), it is past its expiry (`Expired`), or its run is not running (`RunNotLive`).
pub async fn authorize_run_token(
    pool: &SqlitePool,
    raw: &str,
    now: &str,
) -> Result<RunScope, AuthError> {
    let mut conn = pool.acquire().await?;
    check_time(&mut conn, now).await?;
    let Some(row) = sqlx::query(
        "SELECT t.revoked_at IS NOT NULL AS revoked, \
         julianday(t.expires_at) <= julianday(?) AS expired, \
         r.id, r.state, r.agent_id, r.issue_id, a.company_id \
         FROM run_tokens t JOIN runs r ON r.id = t.run_id JOIN agents a ON a.id = r.agent_id \
         WHERE t.token_hash = ?",
    )
    .bind(now)
    .bind(key_hash(raw))
    .fetch_optional(&mut *conn)
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
    if text::<RunState>(&row, "state")? != RunState::Running {
        return Err(AuthError::RunNotLive);
    }
    Ok(RunScope {
        run_id: RunId(row.try_get("id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        company_id: CompanyId(row.try_get("company_id")?),
    })
}
