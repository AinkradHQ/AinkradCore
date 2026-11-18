//! M1 (PR 318 review): a healthy start is not killed. The runner already lists the run `running`
//! while `run.start` has not answered, and a reconcile runs in that window.

use ainkrad_proto::v2::{RunCheckout, RunInfo, RunList, RunPhase, RunStart};

use super::project_runs::{Fake, project, run, w};
use super::*;
use crate::hub::Elevated;
use crate::runs::{self, Fut, Link, LinkError, Presence};

/// A `Link` whose `run.start` runs a reconcile before it answers, as the sweep may.
struct Racing {
    inner: Fake,
    app: App,
}

impl Link for Racing {
    fn runners(&self) -> Vec<String> {
        self.inner.runners()
    }
    fn presence(&self, r: &str) -> Option<Presence> {
        self.inner.presence(r)
    }
    fn uptime_secs(&self) -> i64 {
        self.inner.uptime_secs()
    }
    fn start<'a>(
        &'a self,
        runner: &'a str,
        req: RunStart,
        proof: Elevated,
    ) -> Fut<'a, Result<RunInfo, LinkError>> {
        Box::pin(async move {
            let info = self.inner.start(runner, req, proof).await?;
            // The runner now holds the run, `running`; `status` says so before the answer is back.
            runs::reconcile(&self.app, self, runner).await;
            Ok(info)
        })
    }
    fn stop<'a>(&'a self, r: &'a str, run: &'a str) -> Fut<'a, Result<RunInfo, LinkError>> {
        self.inner.stop(r, run)
    }
    fn status<'a>(&'a self, r: &'a str) -> Fut<'a, Result<RunList, LinkError>> {
        self.inner.status(r)
    }
    fn checkouts<'a>(
        &'a self,
        r: &'a str,
        run: &'a str,
        repos: &'a [String],
    ) -> Fut<'a, Result<Vec<RunCheckout>, String>> {
        self.inner.checkouts(r, run, repos)
    }
}

#[tokio::test]
async fn a_reconcile_during_a_start_does_not_get_the_healthy_run_stopped() {
    let fx = fx().await;
    let p = project(&fx, "shop").await;
    let link = Racing {
        inner: Fake::new(),
        app: fx.app.clone(),
    };
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    let id = pending.run.id.clone();
    runs::drive_start(&fx.app, &link, pending, Elevated::for_tests()).await;
    assert_eq!(run(&fx, &id).await.state, "running");
    assert!(
        link.inner.stops().is_empty(),
        "a healthy start is never stopped"
    );
    assert_eq!(link.inner.held.lock().unwrap().as_slice(), [id]);
}

#[tokio::test]
async fn a_start_nobody_is_driving_is_still_promoted_by_a_reconcile() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "docs").await);
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    let id = pending.run.id.clone();
    *link.listed.lock().unwrap() = Some(vec![RunInfo {
        run: id.clone(),
        project: 1,
        phase: RunPhase::Running,
        failed_service: None,
        reason: None,
        services: vec![],
    }]);
    runs::reconcile(&fx.app, &link, "r1").await;
    assert_eq!(
        run(&fx, &id).await.state,
        "running",
        "the Core restarted mid-start"
    );
}
