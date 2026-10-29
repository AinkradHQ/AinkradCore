//! Disk over the wire (E15.9): `Welcome` carries the runner's disk and warm settings (its own
//! over the server's), and the report of the clean-up pass that follows is stored.

use std::sync::{Arc, Mutex};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::store::exec::runner_disk;
use ainkrad_proto::runner::{DiskReport, Outcome, RunToken, RunnerLimits};
use ainkrad_runner::{Executor, Job, Report};
use tokio::sync::mpsc;

use super::support::*;
use crate::harness::runner;

/// Keeps the limits it is given and reports a disk at its cap.
struct Disky(Arc<Mutex<Option<RunnerLimits>>>);

impl Executor for Disky {
    async fn start(&self, _: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _: &Job, _: RunToken, _: mpsc::Sender<Report>) -> Outcome {
        Outcome::Succeeded
    }

    fn set_limits(&self, limits: RunnerLimits) {
        *self.0.lock().unwrap() = Some(limits);
    }

    async fn housekeep(&self) -> Option<DiskReport> {
        let cap = self.0.lock().unwrap().map_or(0, |l| l.disk_cap_bytes);
        Some(DiskReport {
            used_bytes: cap + 1,
            cap_bytes: cap,
            full: true,
            ..DiskReport::default()
        })
    }
}

#[tokio::test]
async fn welcome_carries_the_runners_limits_and_its_report_is_stored() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let r = runner(pool, "box", &[]).await;
    setting(pool, "workspace.idle_secs", 7_200).await;
    ainkrad_core_server::store::settings::set(
        pool,
        Key::DiskCapBytes,
        Scope::Runner(r),
        "80000000000",
        AuditActor::System,
        "2026-10-22T10:00:00.000Z",
    )
    .await
    .unwrap();
    let seen = Arc::new(Mutex::new(None));
    stack.runner("box", &[], Disky(seen.clone()));
    until(
        pool,
        "the disk report",
        "SELECT count(*) FROM runners WHERE disk IS NOT NULL",
    )
    .await;
    assert_eq!(
        *seen.lock().unwrap(),
        Some(RunnerLimits {
            disk_cap_bytes: 80_000_000_000,
            disk_evict_percent: 90,
            workspace_idle_secs: 7_200,
            warm_idle_secs: 900,
        }),
        "the runner's cap over the server's, the server's idle age"
    );
    let (report, _) = runner_disk(pool, r).await.unwrap().unwrap();
    assert_eq!(report.cap_bytes, 80_000_000_000);
    assert!(report.full);
    until(
        pool,
        "the full disk audited",
        "SELECT count(*) FROM audit_events WHERE action = 'runner.disk_full'",
    )
    .await;
}
