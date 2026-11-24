//! Automatic room Overviews: a room with current records and no overview gets one queued, and a
//! written one is queued again when the room learned enough since (`REFRESH_RECORDS` new records,
//! or any new record once the overview is `REFRESH_AGE_SECS` old). Same path as the manual button
//! (`overview::enqueue`), so the room's model policy, the account check and the one-room-at-a-time
//! queue apply unchanged: a local-only room is never queued, and a room with an overview already
//! open is never queued twice.
//!
//! No loop: a room is looked at once per `SCAN_EVERY_SECS`; a refresh waits `MIN_GAP_SECS` after the
//! last write (debounce) and a room's own open distil; a failed write waits `FAILED_WAIT_SECS`.
//! Distils come first: nothing is queued while distils hold all but one of their running slots.

use std::sync::atomic::Ordering;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use axum::http::StatusCode;

use crate::{Brain, distil, overview};

const SCAN_EVERY_SECS: i64 = 60;
pub(crate) const REFRESH_RECORDS: i64 = 25;
pub(crate) const REFRESH_AGE_SECS: i64 = 86_400;
pub(crate) const MIN_GAP_SECS: i64 = 3_600;
pub(crate) const FAILED_WAIT_SECS: i64 = 6 * 3_600;

/// Whether a room with `new` records since its overview (`age` seconds old, `None` = never written)
/// is due one.
pub(crate) fn due(current: i64, new: i64, age: Option<i64>) -> bool {
    match age {
        None => current > 0,
        Some(a) => {
            a >= MIN_GAP_SECS && (new >= REFRESH_RECORDS || (new > 0 && a >= REFRESH_AGE_SECS))
        }
    }
}

/// One sweep at unix time `now`; queues at most one room and returns how many it queued.
pub(crate) async fn sweep(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    if now - b.inner.overview_scan.load(Ordering::SeqCst) < SCAN_EVERY_SECS {
        return Ok(0);
    }
    b.inner.overview_scan.store(now, Ordering::SeqCst);
    let Some(by) = crate::auto_distil::requester(app).await? else {
        return Ok(0);
    };
    // Distils first: leave them their slots, and wait for a queue that is already open.
    let (open, running): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM brain_overview_queue WHERE state IN ('queued','running')), \
                (SELECT count(*) FROM brain_distils WHERE state = 'running')",
    )
    .fetch_one(&app.pool)
    .await?;
    if open > 0 || running >= distil::MAX_RUNNING - 1 {
        return Ok(0);
    }
    let rooms: Vec<String> =
        sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
            .fetch_all(&app.pool)
            .await?;
    for room in rooms {
        if !room_due(app, b, &room, now).await? {
            continue;
        }
        match overview::enqueue(app, b, &room, &by).await {
            Ok(true) => return Ok(1),
            Ok(false) => {}
            Err(e) if e.status == StatusCode::CONFLICT => {}
            Err(e) => return Err(e),
        }
    }
    Ok(0)
}

async fn room_due(app: &App, b: &Brain, room: &str, now: i64) -> Result<bool, ApiError> {
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_distils WHERE room = ? AND state IN ('queued','needs_local_model','waiting','running')",
    )
    .bind(room)
    .fetch_one(&app.pool)
    .await?;
    if open > 0 {
        return Ok(false);
    }
    let Ok(pool) = distil::canon(app, b, room).await else {
        return Ok(false);
    };
    let r = look(&pool, now).await;
    pool.close().await;
    Ok(r?)
}

async fn look(pool: &sqlx::SqlitePool, now: i64) -> Result<bool, sqlx::Error> {
    let ov: Option<(String, Option<String>, String, bool)> = sqlx::query_as(
        "SELECT state, written_at, updated_at, overview IS NOT NULL FROM room_overview WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    async fn secs(pool: &sqlx::SqlitePool, t: &str) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar("SELECT CAST(strftime('%s', ?) AS INTEGER)")
            .bind(t)
            .fetch_one(pool)
            .await
    }
    if let Some((state, _, updated, _)) = &ov {
        if state == "writing" {
            return Ok(false);
        }
        if state == "failed"
            && secs(pool, updated)
                .await?
                .is_none_or(|u| now - u < FAILED_WAIT_SECS)
        {
            return Ok(false);
        }
    }
    let written = ov
        .as_ref()
        .and_then(|(_, w, _, has)| w.as_deref().filter(|_| *has));
    let current: i64 = sqlx::query_scalar("SELECT count(*) FROM records WHERE status = 'accepted' AND valid_to IS NULL AND archived_at IS NULL")
        .fetch_one(pool)
        .await?;
    let Some(w) = written else {
        return Ok(due(current, 0, None));
    };
    let new: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM records WHERE status = 'accepted' AND valid_to IS NULL AND archived_at IS NULL AND datetime(created_at) > datetime(?)",
    )
    .bind(w)
    .fetch_one(pool)
    .await?;
    Ok(due(current, new, secs(pool, w).await?.map(|t| now - t)))
}

impl Brain {
    /// The automatic Overview sweep as of unix time `now` (the `brain_overview` job runs it).
    pub async fn overview_sweep_at(&self, now: i64) -> Result<u32, ApiError> {
        match self.inner.app.get() {
            Some(app) => sweep(app, self, now).await,
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds() {
        assert!(!due(0, 0, None), "no records, no overview");
        assert!(due(3, 0, None), "first overview");
        assert!(due(100, 25, Some(MIN_GAP_SECS)), "25 new");
        assert!(!due(100, 24, Some(MIN_GAP_SECS)), "24 new, young");
        assert!(due(100, 1, Some(REFRESH_AGE_SECS)), "one new, a day old");
        assert!(!due(100, 0, Some(REFRESH_AGE_SECS * 9)), "nothing new");
        assert!(!due(100, 99, Some(MIN_GAP_SECS - 1)), "debounce");
    }
}
