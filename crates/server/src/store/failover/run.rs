//! A run is its attempts: the helpers that read and settle them.

use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

/// The attempt of `id`'s run that is newest (the one nothing replaced), `id` itself when it is the
/// run's last. A chain of at most [`super::MAX_HOPS`] hops, bounded anyway.
pub async fn newest_in(conn: &mut SqliteConnection, id: &str) -> Result<String, sqlx::Error> {
    let mut at = id.to_owned();
    for _ in 0..32 {
        let next: Option<String> =
            sqlx::query_scalar("SELECT id FROM core_agent_sessions WHERE failover_of = ?")
                .bind(&at)
                .fetch_optional(&mut *conn)
                .await?;
        match next {
            Some(n) => at = n,
            None => break,
        }
    }
    Ok(at)
}

pub async fn newest(pool: &SqlitePool, id: &str) -> Result<String, sqlx::Error> {
    newest_in(&mut *pool.acquire().await?, id).await
}

/// Whether a replacement of `id` exists.
pub async fn has_successor_in(conn: &mut SqliteConnection, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) > 0 FROM core_agent_sessions WHERE failover_of = ?")
        .bind(id)
        .fetch_one(conn)
        .await
}

/// Whether `id` replaces an attempt (it is a failover's).
pub async fn has_predecessor_in(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT failover_of IS NOT NULL FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_optional(conn)
        .await
        .map(|b: Option<bool>| b.unwrap_or(false))
}

/// The accounts the run of `session` has used (every attempt's, the session's own too) and the
/// pools its budget stops took out of the chain: what its pick must leave out (I3).
pub async fn context_in(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<(Vec<i64>, Vec<i64>), sqlx::Error> {
    let run: Option<String> =
        sqlx::query_scalar("SELECT coalesce(run_id, id) FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(&mut *conn)
            .await?;
    // `run_id = ? OR id = ?` uses the run index (a `coalesce` over the column would scan).
    let used: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT account_id FROM core_agent_sessions \
         WHERE account_id IS NOT NULL AND id != ?1 AND (run_id = ?2 OR id = ?2)",
    )
    .bind(session)
    .bind(run)
    .fetch_all(&mut *conn)
    .await?;
    let skip: Option<String> =
        sqlx::query_scalar("SELECT skip_pools FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(conn)
            .await?;
    let skip = skip
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    Ok((used, skip))
}

/// What [`cancel_run`] settled.
pub struct Cancelled {
    /// The run's newest attempt: the one to stop.
    pub newest: String,
    /// The attempts whose failover this call settled (and [`restore_run`] opens again).
    pub settled: Vec<String>,
}

/// A person cancels or kills the run `id` belongs to: no attempt of it moves any more, and the
/// attempt to stop is the run's newest (the one the person may not know of yet). One write, so a
/// move that commits first has its successor found here, and a move that follows finds its
/// attempt settled and starts nothing.
pub async fn cancel_run(pool: &SqlitePool, id: &str) -> Result<Cancelled, sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let run: Option<String> =
        sqlx::query_scalar("SELECT coalesce(run_id, id) FROM core_agent_sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let settled: Vec<String> = sqlx::query_scalar(
        "UPDATE core_agent_sessions SET failover_done = 1 WHERE failover_done = 0 \
         AND (run_id = ?1 OR id = ?1) RETURNING id",
    )
    .bind(run)
    .fetch_all(&mut *tx)
    .await?;
    let newest = newest_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Cancelled { newest, settled })
}

/// Opens again exactly the attempts a [`cancel_run`] settled, when the stop it was for never reached
/// the runner: the run is no more cancelled than it was.
pub async fn restore_run(pool: &SqlitePool, settled: &[String]) -> Result<(), sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    for id in settled {
        sqlx::query("UPDATE core_agent_sessions SET failover_done = 0 WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

/// Settles an attempt whose run goes no further (the decision was to end).
pub async fn settle(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_agent_sessions SET failover_done = 1 WHERE id = ? AND failover_done = 0 \
         AND state IN ('ended', 'lost')",
    )
    .bind(id)
    .execute(pool)
    .await
    .map(drop)
}

/// Settles an attempt and says why the run ended in its outcome (`failover`), for a run that
/// cannot move on (the runner never came back).
pub async fn settle_with(pool: &SqlitePool, id: &str, why: &str) -> Result<(), sqlx::Error> {
    let note = json!({"result": "ended", "why": why}).to_string();
    sqlx::query(
        "UPDATE core_agent_sessions SET failover_done = 1, \
         outcome = json_set(coalesce(outcome, '{}'), '$.failover', json(?)) \
         WHERE id = ? AND failover_done = 0 AND state IN ('ended', 'lost')",
    )
    .bind(note)
    .bind(id)
    .execute(pool)
    .await
    .map(drop)
}

/// The decision to move, written before the stop that carries it out is sent (see
/// `failover_class`); whether this call wrote it (a person's cancel or another writer may have
/// settled the attempt first).
pub async fn set_class(pool: &SqlitePool, id: &str, class: &str) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE core_agent_sessions SET failover_class = ? WHERE id = ? AND failover_class IS NULL \
         AND failover_done = 0 AND chain IS NOT NULL AND owner_module IS NULL \
         AND state NOT IN ('ended', 'lost')",
    )
    .bind(class)
    .bind(id)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() > 0)
}

/// [`unfinished`], only those that ended after `since` (an ISO time): a Core that comes back long
/// after an attempt ended does not start a run the person saw end.
pub async fn unfinished_since(pool: &SqlitePool, since: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM core_agent_sessions WHERE state IN ('ended', 'lost') AND failover_done = 0 \
         AND chain IS NOT NULL AND owner_module IS NULL AND julianday(updated_at) > julianday(?) \
         ORDER BY n",
    )
    .bind(since)
    .fetch_all(pool)
    .await
}

/// The attempts that are over and whose failover was never settled: what a restart finishes.
pub async fn unfinished(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM core_agent_sessions WHERE state IN ('ended', 'lost') AND failover_done = 0 \
         AND chain IS NOT NULL AND owner_module IS NULL ORDER BY n",
    )
    .fetch_all(pool)
    .await
}
