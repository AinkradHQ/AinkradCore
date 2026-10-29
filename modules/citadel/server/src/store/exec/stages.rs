//! Latency (E15.6, pain #2: even small tasks take too long). Two halves:
//!
//! - **Push dispatch**: every new wake and every ended run bumps a process-wide signal
//!   (`wake_signal`), so a runner connection waiting for work dispatches at once instead of on
//!   its next poll. Wakes written by another process (the admin CLI) or coming due later are
//!   still found by the connection's fallback poll (`dispatch.fallback_poll_ms`).
//! - **Stage timings**: a run's start as wake → claim → workspace → harness → first token →
//!   end. `woken_at` is stamped at dispatch, `claimed_at` / `started_at` (the workspace is
//!   ready) / `ended_at` by its transitions, `harness_started_at` by its first transcript chunk
//!   and `first_token_at` by its first answer (`FIRST_TOKEN`). Like the transitions' stamps they
//!   are the database's clock, so a run's stages are always in order. A first token later than
//!   `latency.first_token_budget_secs` after the wake appends `run.first_token_slow`.

use std::sync::LazyLock;

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::org::CompanyId;
use citadel_core::settings::Key;
use citadel_core::work::ProjectId;
use serde_json::json;
use sqlx::SqliteConnection;
use tokio::sync::watch;

use super::*;
use crate::store::audit;
use crate::store::settings::{scope_of_run_in, value_in};

static WAKES: LazyLock<watch::Sender<u64>> = LazyLock::new(|| watch::channel(0).0);

/// A receiver that changes whenever a wake may have become dispatchable in this process.
pub fn wake_signal() -> watch::Receiver<u64> {
    WAKES.subscribe()
}

/// Tells every waiting runner connection to look for work. A spurious signal costs one empty
/// dispatch; the transaction that wrote the wake may still be open, and the dispatcher's
/// `BEGIN IMMEDIATE` waits for it.
pub(crate) fn signal_wakes() {
    WAKES.send_modify(|n| *n = n.wrapping_add(1));
}

/// Transcript kinds that are the model answering.
pub const FIRST_TOKEN: &[&str] = &[
    "assistant_text",
    "tool_use",
    "usage_so_far",
    "usage",
    "approval_requested",
];

/// Stamps the stages a newly stored chunk of `kind` marks on `run`: its harness's start (any
/// first chunk) and its first token; warns once when the first token missed its budget.
pub(super) async fn mark_stages_in(
    conn: &mut SqliteConnection,
    run: RunId,
    kind: &str,
) -> Result<(), Error> {
    let answer = FIRST_TOKEN.contains(&kind);
    let marked: Option<(bool, Option<f64>)> = sqlx::query_as(
        "UPDATE runs SET harness_started_at = coalesce(harness_started_at, \
             strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), \
         first_token_at = iif(?2 AND first_token_at IS NULL, \
             strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), first_token_at) \
         WHERE id = ?1 AND (harness_started_at IS NULL OR (?2 AND first_token_at IS NULL)) \
         RETURNING first_token_at IS NOT NULL AND ?2, \
             (julianday(first_token_at) - julianday(woken_at)) * 86400",
    )
    .bind(run.0)
    .bind(answer)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((true, Some(secs))) = marked else {
        return Ok(());
    };
    let at = scope_of_run_in(conn, run).await?;
    let budget = value_in(conn, Key::FirstTokenBudgetSecs, at).await?;
    if secs <= budget as f64 {
        return Ok(());
    }
    let company: i64 = sqlx::query_scalar(
        "SELECT a.company_id FROM runs r JOIN agents a ON a.id = r.agent_id WHERE r.id = ?",
    )
    .bind(run.0)
    .fetch_one(&mut *conn)
    .await?;
    let secs = (secs * 1000.0).round() / 1000.0;
    tracing::warn!(
        run = run.0,
        secs,
        budget,
        "a run's first token missed its budget"
    );
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: "run.first_token_slow".to_owned(),
        entity: Some(AuditEntity {
            kind: "run".to_owned(),
            id: run.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(run),
        details: json!({"secs": secs, "budget_secs": budget}).to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

/// The stages, in order: wake → claim, claim → workspace ready, workspace → harness up,
/// harness → first token, the whole wake → first token, and first token → end.
pub const STAGES: &[&str] = &[
    "wake_to_claim",
    "claim_to_workspace",
    "workspace_to_harness",
    "harness_to_first_token",
    "wake_to_first_token",
    "first_token_to_end",
];

/// One stage over a project's runs: how many runs reached it, and the median and 95th
/// percentile of its seconds (nearest rank); `None` with no run.
#[derive(Debug, Clone, PartialEq)]
pub struct StageStat {
    pub stage: &'static str,
    pub runs: usize,
    pub p50_secs: Option<f64>,
    pub p95_secs: Option<f64>,
}

/// The `p`th percentile (0–100) of `sorted` by nearest rank.
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted.get(rank.max(1) - 1).copied()
}

/// Every stage over `project`'s runs queued at or after `since` (all, with none). A `since`
/// that is no timestamp is `InvalidArgument`.
pub async fn stage_timing(
    pool: &SqlitePool,
    project: ProjectId,
    since: Option<&str>,
) -> Result<Vec<StageStat>, Error> {
    if let Some(since) = since {
        check_time(&mut *pool.acquire().await?, since).await?;
    }
    // In `STAGES` order.
    let rows = sqlx::query(
        "SELECT (julianday(claimed_at) - julianday(woken_at)) * 86400, \
             (julianday(started_at) - julianday(claimed_at)) * 86400, \
             (julianday(harness_started_at) - julianday(started_at)) * 86400, \
             (julianday(first_token_at) - julianday(harness_started_at)) * 86400, \
             (julianday(first_token_at) - julianday(woken_at)) * 86400, \
             (julianday(ended_at) - julianday(first_token_at)) * 86400 \
         FROM runs r JOIN issues i ON i.id = r.issue_id WHERE i.project_id = ?1 \
         AND (?2 IS NULL OR julianday(r.queued_at) >= julianday(?2))",
    )
    .bind(project.0)
    .bind(since)
    .fetch_all(pool)
    .await?;
    let mut stats = vec![];
    for (i, stage) in STAGES.iter().enumerate() {
        let mut secs = vec![];
        for row in &rows {
            secs.extend(row.try_get::<Option<f64>, _>(i)?);
        }
        secs.sort_by(f64::total_cmp);
        let ms = |s: Option<f64>| s.map(|s| (s * 1000.0).round() / 1000.0);
        stats.push(StageStat {
            stage,
            runs: secs.len(),
            p50_secs: ms(percentile(&secs, 50.0)),
            p95_secs: ms(percentile(&secs, 95.0)),
        });
    }
    Ok(stats)
}
