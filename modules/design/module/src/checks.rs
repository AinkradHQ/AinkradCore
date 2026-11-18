//! Font and Icon Composer checks (V6-01, T8): an upload of either is stored `pending` and inert. The
//! Core never parses it; this job sends it to a runner's sandboxed `ainkrad-design` helper
//! (`design.check`) and records the verdict: `ok` (served from then on) or `refused`. A helper that
//! crashes or hits a memory, CPU or process limit on the file is a refusal too. Running out of wall
//! clock (`design_limit`: load can cause it), no capable runner, a busy one, a sandbox that did not
//! start (`spawn_failed`) or a lost answer leaves the asset `pending` for the next run.
//! Audit and events carry the sha256 only. The runner is the trust root for the verdict: every runner
//! is paired by the Core's one owner (a hostile runner's "ok" still only reaches sandboxed helpers).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::v2::{
    Body, Command, DESIGN_MAX_INPUT, DesignCheck, ErrorCode, OP_DESIGN_CHECK, Reply, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const EVERY_SECS: u64 = 30;
/// Assets checked per run; the next run takes the rest.
const PER_RUN: i64 = 4;
/// Wall-clock stops (`design_limit`) on one asset before it is refused: a file that never finishes.
pub(crate) const MAX_LIMITS: i64 = 3;
const WAIT: Duration = Duration::from_secs(120);

/// The app the job runs on (a job handler is given none); set by `Module::attach`.
pub(crate) static APP: OnceLock<App> = OnceLock::new();

/// The online runner that offers `design.check` with the most free slots.
fn place(app: &App) -> Option<String> {
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && r.drivers
                    .iter()
                    .any(|d| d.commands.iter().any(|c| c == OP_DESIGN_CHECK))
        })
        .collect();
    all.sort_by(|a, b| {
        let free = |r: &ainkrad_core_server::hub::RunnerState| r.capacity.saturating_sub(r.load);
        free(&b.1).cmp(&free(&a.1)).then(a.0.cmp(&b.0))
    });
    all.into_iter().next().map(|(id, _)| id)
}

/// A dispatch's outcome as a verdict: `Some(ok)` to record, `None` to try again later.
pub(crate) fn verdict(o: &Result<Body, StreamError>) -> Option<bool> {
    match o {
        Ok(Body::Result(Reply::DesignCheck(c))) => Some(c.ok),
        // The file crashed the helper, ran it out of a limit, or is too big to send: refused.
        // A wall-clock stop (`DesignLimit`) is not among them: it stays pending.
        // Three of them on one asset refuse it (`tried`).
        Err(e) if matches!(e.code, ErrorCode::DesignFailed | ErrorCode::TooLarge) => Some(false),
        _ => None,
    }
}

async fn decide(app: &App, sha: &str, ok: bool) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(&app.pool).await?;
    let changed = sqlx::query(
        "UPDATE design_assets SET check_state = ? WHERE sha256 = ? AND check_state = 'pending'",
    )
    .bind(if ok { "ok" } else { "refused" })
    .bind(sha)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        crate::assets::record(&mut tx, "asset", "checked", sha, None).await?;
    }
    tx.commit().await
}

/// Whether a dispatch's outcome is a wall-clock stop, which counts against the asset.
pub(crate) fn timed_out(o: &Result<Body, StreamError>) -> bool {
    matches!(o, Err(e) if e.code == ErrorCode::DesignLimit)
}

/// Records an attempt that decided nothing: the time, and a wall-clock stop counted. The third
/// wall-clock stop refuses the asset; whether it did.
async fn tried(app: &App, sha: &str, limited: bool) -> Result<bool, sqlx::Error> {
    let attempts: i64 = sqlx::query_scalar(
        "UPDATE design_assets SET check_tried_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
         check_attempts = check_attempts + ? WHERE sha256 = ? RETURNING check_attempts",
    )
    .bind(i64::from(limited))
    .bind(sha)
    .fetch_one(&app.pool)
    .await?;
    if limited && attempts >= MAX_LIMITS {
        decide(app, sha, false).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Checks up to `PER_RUN` pending assets; how many were decided.
pub async fn check_pending(app: &App) -> Result<usize, String> {
    let db = |e: sqlx::Error| e.to_string();
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT sha256, kind, size FROM design_assets \
         WHERE check_state = 'pending' AND kind IN ('font', 'icon_composer') \
         ORDER BY COALESCE(check_tried_at, ''), created_at, sha256 LIMIT ?",
    )
    .bind(PER_RUN)
    .fetch_all(&app.pool)
    .await
    .map_err(db)?;
    let mut decided = 0;
    for (sha, kind, size) in rows {
        // base64 and the job's JSON around it must fit the runner's message cap.
        if usize::try_from(size).map_or(true, |s| s / 3 * 4 + 4096 > DESIGN_MAX_INPUT) {
            decide(app, &sha, false).await.map_err(db)?;
            decided += 1;
            continue;
        }
        let Some(runner) = place(app) else { break };
        let data: Vec<u8> = sqlx::query_scalar("SELECT data FROM design_assets WHERE sha256 = ?")
            .bind(&sha)
            .fetch_one(&app.pool)
            .await
            .map_err(db)?;
        let cmd = Command::DesignCheck(DesignCheck {
            kind,
            data: STANDARD.encode(&data),
        });
        let Ok(sent) = app.hub.dispatch_design(&runner, cmd) else {
            break;
        };
        let outcome = tokio::time::timeout(WAIT, sent.outcome())
            .await
            .unwrap_or_else(|_| Err(StreamError::new(ErrorCode::Lost, "no answer in time")));
        match verdict(&outcome) {
            Some(ok) => {
                decide(app, &sha, ok).await.map_err(db)?;
                decided += 1;
            }
            None => {
                if tried(app, &sha, timed_out(&outcome)).await.map_err(db)? {
                    decided += 1;
                } else {
                    tracing::info!(
                        code = ?outcome.as_ref().err().map(|e| e.code),
                        "a design asset check did not finish; it stays pending"
                    );
                }
            }
        }
    }
    Ok(decided)
}

struct CheckJob;

impl JobHandler for CheckJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = APP.get() else { return Ok(()) };
            if check_pending(app).await? == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

pub(crate) fn job() -> Job {
    Job::new(
        "design_asset_checks",
        Schedule::Every(EVERY_SECS),
        Arc::new(CheckJob),
    )
}

#[cfg(test)]
mod tests_review2;
