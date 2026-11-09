//! Runner disk (E15.9, pain #8): each runner's last disk report, from `Hello` and `Disk`. A
//! report that turns `full` (over the cap, nothing left to evict) appends `runner.disk_full`
//! once, which the admin is pushed; the stuck report lists every online runner still full.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{StuckIssue, disk_stuck};
use ainkrad_proto::runner::DiskReport;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;

/// Stores `report` as `runner`'s at `now`; `true` when it turned the runner full, which is
/// audited as `runner.disk_full`. `false` when there is no such runner, or it was full before.
pub async fn record_disk(
    pool: &SqlitePool,
    runner: RunnerId,
    report: &DiskReport,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let was: Option<Option<bool>> =
        sqlx::query_scalar("SELECT json_extract(disk, '$.full') FROM runners WHERE id = ?")
            .bind(runner.0)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(was) = was else {
        return Ok(false);
    };
    sqlx::query("UPDATE runners SET disk = ?, disk_at = ? WHERE id = ?")
        .bind(Json(report))
        .bind(now)
        .bind(runner.0)
        .execute(&mut *tx)
        .await?;
    let filled = report.full && was != Some(true);
    if filled {
        let event = NewAuditEvent {
            actor: AuditActor::Runner(runner),
            action: "runner.disk_full".to_owned(),
            entity: Some(AuditEntity {
                kind: "runner".to_owned(),
                id: runner.0,
            }),
            company_id: None,
            run_id: None,
            details: json!({"used_bytes": report.used_bytes, "cap_bytes": report.cap_bytes,
                "at": now})
            .to_string(),
        };
        audit::append(&mut *tx, &event).await?;
    }
    tx.commit().await?;
    Ok(filled)
}

/// The runner's last disk report and when it came; `None` before its first.
pub async fn runner_disk(
    pool: &SqlitePool,
    runner: RunnerId,
) -> Result<Option<(DiskReport, String)>, Error> {
    let row: Option<(Option<Json<DiskReport>>, Option<String>)> =
        sqlx::query_as("SELECT disk, disk_at FROM runners WHERE id = ?")
            .bind(runner.0)
            .fetch_optional(pool)
            .await?;
    Ok(match row {
        Some((Some(Json(report)), Some(at))) => Some((report, at)),
        _ => None,
    })
}

/// Every online runner whose last report is full, for the stuck report.
pub(super) async fn full_disks_in(conn: &mut SqliteConnection) -> Result<Vec<StuckIssue>, Error> {
    let rows: Vec<(i64, String, Json<DiskReport>)> = sqlx::query_as(
        "SELECT id, name, disk FROM runners WHERE status = 'online' \
         AND json_extract(disk, '$.full') ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, Json(d))| disk_stuck(RunnerId(id), &name, d.used_bytes, d.cap_bytes))
        .collect())
}
