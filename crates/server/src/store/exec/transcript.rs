//! Run transcripts (E3.9): sequenced chunks, accepted only from the runner holding the run's
//! unexpired lease, stored once per `(run, seq)` and read back in `seq` order. Callers
//! redact before they append: the store writes what it is given.

use serde_json::Value;

use super::*;

/// One stored transcript chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct TranscriptChunk {
    pub seq: i64,
    pub at: String,
    pub kind: String,
    pub payload: Value,
}

/// Why a chunk was refused.
#[derive(Debug)]
pub enum ChunkError {
    /// This runner does not hold the run's lease, or it has expired.
    NotHolder,
    /// `seq` is not a positive 63-bit number.
    BadSeq,
    Db(Error),
}

impl From<Error> for ChunkError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHolder => f.write_str("runner does not hold the run's lease"),
            Self::BadSeq => f.write_str("seq must count from 1"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ChunkError {}

/// Stores chunk `seq` of `run` from `runner` at `now`; its kind is the payload's `type`.
/// The first `usage` or `usage_so_far` chunk sets the run's `context_tokens`; a
/// `session_started` one its `session_id`. The first chunk, and the first answer, stamp the
/// run's stages (E15.6, `stages`).
/// `false` when that `seq` is already stored (a resend), which is left as it was.
pub async fn append_run_event(
    pool: &SqlitePool,
    run: RunId,
    runner: RunnerId,
    seq: u64,
    payload: &Value,
    now: &str,
) -> Result<bool, ChunkError> {
    let seq = i64::try_from(seq)
        .ok()
        .filter(|s| *s > 0)
        .ok_or(ChunkError::BadSeq)?;
    let kind = payload["type"].as_str().filter(|k| !k.is_empty());
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let holds: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM leases WHERE run_id = ? AND runner_id = ? \
         AND julianday(expires_at) > julianday(?))",
    )
    .bind(run.0)
    .bind(runner.0)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if !holds {
        return Err(ChunkError::NotHolder);
    }
    let stored = sqlx::query(
        "INSERT INTO run_events (run_id, seq, at, kind, payload) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (run_id, seq) DO NOTHING",
    )
    .bind(run.0)
    .bind(seq)
    .bind(now)
    .bind(kind.unwrap_or("chunk"))
    .bind(Json(payload))
    .execute(&mut *tx)
    .await
    .map(affected)?;
    // The first usage the harness reports is its first model call's: the run's context (E15.5).
    // Kept once; a later chunk never moves it, and an empty report (a failed start) is no size.
    let n = |k: &str| payload[k].as_i64().unwrap_or(0).max(0);
    let context = n("input") + n("cache_read") + n("cache_write");
    // Harnesses that name their own session say so here; the latest is the run's current one
    // (a fallback starts another), which a later run may resume (`resume_session`).
    if let (true, Some("session_started"), Some(id)) = (stored, kind, payload["id"].as_str()) {
        sqlx::query("UPDATE runs SET session_id = ? WHERE id = ?")
            .bind(id)
            .bind(run.0)
            .execute(&mut *tx)
            .await?;
    }
    if stored {
        mark_stages_in(&mut tx, run, kind.unwrap_or("chunk")).await?;
    }
    // The runner gave the admin's message to the harness (1.19).
    if let (true, Some("user_message"), Some(id)) = (stored, kind, payload["id"].as_i64()) {
        delivered_in(&mut tx, run, id, now).await?;
    }
    if stored && context > 0 && matches!(kind, Some("usage" | "usage_so_far")) {
        sqlx::query("UPDATE runs SET context_tokens = ? WHERE id = ? AND context_tokens IS NULL")
            .bind(context)
            .bind(run.0)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(stored)
}

/// The run's transcript, in `seq` order.
pub async fn list_run_events(pool: &SqlitePool, run: RunId) -> Result<Vec<TranscriptChunk>, Error> {
    sqlx::query("SELECT seq, at, kind, payload FROM run_events WHERE run_id = ? ORDER BY seq")
        .bind(run.0)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| {
            Ok(TranscriptChunk {
                seq: row.try_get("seq")?,
                at: row.try_get("at")?,
                kind: row.try_get("kind")?,
                payload: row.try_get::<Json<Value>, _>("payload")?.0,
            })
        })
        .collect()
}

/// Prunes the transcripts of runs that ended longer ago than their company's
/// `transcript.retention_secs` (0 keeps them): their chunks are deleted, the run stays with
/// `transcript_pruned_at`, and each company's pass is audited once as `run.transcripts_pruned`
/// with the runs it pruned. The runs pruned at `now`.
pub async fn prune_transcripts(pool: &SqlitePool, now: &str) -> Result<Vec<RunId>, Error> {
    use ainkrad_core::audit::{AuditActor, NewAuditEvent};
    use ainkrad_core::settings::{Key, Scope};
    let companies: Vec<i64> = sqlx::query_scalar("SELECT id FROM companies ORDER BY id")
        .fetch_all(pool)
        .await?;
    let mut pruned = vec![];
    for company in companies {
        let at = Scope::Company(ainkrad_core::org::CompanyId(company));
        let keep = crate::store::settings::value(pool, Key::TranscriptRetentionSecs, at).await?;
        if keep == 0 {
            continue;
        }
        let mut tx = crate::store::begin_write(pool).await?;
        let runs: Vec<i64> = sqlx::query_scalar(
            "UPDATE runs SET transcript_pruned_at = ?1 WHERE transcript_pruned_at IS NULL \
             AND ended_at IS NOT NULL AND julianday(ended_at) < julianday(?1) - ?2 / 86400.0 \
             AND agent_id IN (SELECT id FROM agents WHERE company_id = ?3) RETURNING id",
        )
        .bind(now)
        .bind(keep)
        .bind(company)
        .fetch_all(&mut *tx)
        .await?;
        if runs.is_empty() {
            continue;
        }
        sqlx::query("DELETE FROM run_events WHERE run_id IN (SELECT value FROM json_each(?))")
            .bind(Json(&runs))
            .execute(&mut *tx)
            .await?;
        let event = NewAuditEvent {
            actor: AuditActor::System,
            action: "run.transcripts_pruned".to_owned(),
            entity: None,
            company_id: Some(ainkrad_core::org::CompanyId(company)),
            run_id: None,
            details: serde_json::json!({"runs": runs, "retention_secs": keep}).to_string(),
        };
        crate::store::audit::append(&mut *tx, &event).await?;
        tx.commit().await?;
        pruned.extend(runs.into_iter().map(RunId));
    }
    Ok(pruned)
}
