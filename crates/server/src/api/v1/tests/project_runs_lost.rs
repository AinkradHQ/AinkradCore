//! L4 (PR 318 review): a runner the Core has not met since it started loses its runs once the
//! Core has been up longer than the grace.

use super::project_runs::{Fake, project, run, start};
use super::*;
use crate::runs::{self, RUNNER_LOST_AFTER};

#[tokio::test]
async fn a_runner_never_met_since_boot_is_lost_after_the_grace() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let id = start(&fx, &link, p).await.unwrap();
    *link.seen.lock().unwrap() = None;
    *link.uptime.lock().unwrap() = RUNNER_LOST_AFTER - 1;
    runs::sweep(&fx.app, &link).await;
    assert_eq!(
        run(&fx, &id).await.state,
        "running",
        "inside the grace it may still reconnect"
    );
    *link.uptime.lock().unwrap() = RUNNER_LOST_AFTER + 1;
    runs::sweep(&fx.app, &link).await;
    let r = run(&fx, &id).await;
    assert_eq!(
        (r.state.as_str(), r.stop_reason.as_deref()),
        ("stopped", Some("runner_lost"))
    );
}
