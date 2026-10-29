//! A runner's disk over the API (E15.9): its last report against its settings, idle worktrees
//! with their countdown; a report turning full is audited once and listed as stuck.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::StuckKind;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::ProjectMode;
use ainkrad_proto::runner::{DiskReport, WorktreeDisk};

use super::*;
use crate::store::exec::{record_disk, stuck_report};
use crate::store::settings;

fn report(used: u64, full: bool) -> DiskReport {
    DiskReport {
        used_bytes: used,
        cap_bytes: 50_000_000_000,
        caches_bytes: 19_000_000_000,
        mirrors_bytes: 1_000_000_000,
        worktrees: vec![
            WorktreeDisk {
                issue: 61,
                bytes: 4_000_000_000,
                active: false,
                idle_secs: 3600,
            },
            WorktreeDisk {
                issue: 63,
                bytes: 8_000_000_000,
                active: true,
                idle_secs: 0,
            },
        ],
        removed: vec![],
        full,
    }
}

#[tokio::test]
async fn a_runners_disk_is_its_last_report_against_its_settings() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/runners/{}/disk", a.runner.0);
    assert_eq!(fx.get(&uri).await.0, StatusCode::NOT_FOUND, "no report yet");
    assert_eq!(
        fx.get("/api/v1/runners/99/disk").await.0,
        StatusCode::NOT_FOUND
    );

    let by = AuditActor::System;
    let at = Scope::Runner(a.runner);
    settings::set(pool, Key::WorkspaceIdleSecs, at, "43200", by, NOW)
        .await
        .unwrap();
    assert!(
        !record_disk(pool, a.runner, &report(32_000_000_000, false), NOW)
            .await
            .unwrap()
    );
    let disk = fx.ok(&uri).await;
    assert_eq!(disk["used_bytes"], 32_000_000_000u64);
    assert_eq!(disk["cap_bytes"], 50_000_000_000u64);
    assert_eq!(disk["evict_percent"], 90);
    assert_eq!(disk["caches_bytes"], 19_000_000_000u64);
    assert_eq!(disk["active_bytes"], 8_000_000_000u64);
    assert_eq!(disk["idle_bytes"], 4_000_000_000u64);
    assert_eq!(disk["idle_limit_secs"], 43_200, "the runner's own idle age");
    assert_eq!(disk["measured_at"], NOW);
    assert_eq!(disk["worktrees"][0]["issue_id"], 61);
    assert_eq!(disk["worktrees"][0]["removed_in_secs"], 43_200 - 3600);
    assert!(disk["worktrees"][1]["removed_in_secs"].is_null(), "active");
    assert_eq!(disk["full"], false);
}

#[tokio::test]
async fn a_full_disk_is_audited_once_and_stuck_while_it_lasts() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    sqlx::query("UPDATE runners SET status = 'online' WHERE id = ?")
        .bind(a.runner.0)
        .execute(pool)
        .await
        .unwrap();
    let full = report(51_000_000_000, true);
    assert!(record_disk(pool, a.runner, &full, NOW).await.unwrap());
    assert!(
        !record_disk(pool, a.runner, &full, NOW).await.unwrap(),
        "once"
    );
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'runner.disk_full'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(audited, 1);
    let stuck = stuck_report(pool, NOW).await.unwrap();
    let disk: Vec<_> = stuck
        .iter()
        .filter(|s| s.kind == StuckKind::RunnerDiskFull)
        .collect();
    assert_eq!(disk.len(), 1, "{stuck:?}");
    assert!(
        disk[0].reason.contains("51.0 GB of its 50.0 GB"),
        "{}",
        disk[0].reason
    );

    // Freed: no longer stuck, and the next fill is told again.
    record_disk(pool, a.runner, &report(20_000_000_000, false), NOW)
        .await
        .unwrap();
    let stuck = stuck_report(pool, NOW).await.unwrap();
    assert!(!stuck.iter().any(|s| s.kind == StuckKind::RunnerDiskFull));
    assert!(record_disk(pool, a.runner, &full, NOW).await.unwrap());
}
