//! The runner hardcodes no limit (E15.17): `Assign` carries the run's token cap from the
//! project's `run.token_cap`, and its `limits` from the settings of its project (how long an
//! escalation waits, its stall limit) and of this runner (resumes of a dropped session).

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::store::settings;
use ainkrad_proto::runner::{Outcome, RunLimits, RunToken};
use ainkrad_runner::{Executor, Job, Report};
use tokio::sync::mpsc;

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

/// Hands each job to the test and succeeds.
struct Seen(mpsc::UnboundedSender<Job>);

impl Executor for Seen {
    async fn start(&self, _: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, job: &Job, _: RunToken, _: mpsc::Sender<Report>) -> Outcome {
        let _ = self.0.send(job.clone());
        Outcome::Succeeded
    }
}

#[tokio::test]
async fn assign_carries_the_projects_cap_and_the_runners_limits() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let r = runner(pool, "box", &[]).await;
    let set = |key: Key, at: Scope, v: i64| async move {
        let now = "2026-10-22T10:00:00.000Z";
        settings::set(pool, key, at, &v.to_string(), AuditActor::System, now)
            .await
            .unwrap();
    };
    set(Key::RunTokenCap, Scope::Company(c), 50_000).await;
    set(Key::RunTokenCap, Scope::Project(p), 5_000).await;
    set(Key::DeadlinePermissionEscalation, Scope::Company(c), 300).await;
    set(Key::MaxResumes, Scope::Server, 1).await;
    set(Key::MaxResumes, Scope::Runner(r), 4).await;
    set(Key::ResumeBackoffMs, Scope::Runner(r), 100).await;
    set(Key::ResumeBackoffMaxMs, Scope::Server, 1_000).await;
    set(Key::WarmMax, Scope::Runner(r), 0).await;
    set(Key::StallAfterSecs, Scope::Company(c), 1_200).await;
    set(Key::StallAfterSecs, Scope::Project(p), 300).await;
    assign(pool, issue(pool, p).await, dev).await;
    let (tx, mut jobs) = mpsc::unbounded_channel();
    stack.runner("box", &[], Seen(tx));
    let job = jobs.recv().await.unwrap();
    assert_eq!(
        job.token_cap,
        Some(5_000),
        "the project's cap beats the company's"
    );
    assert_eq!(
        job.limits,
        Some(RunLimits {
            approval_timeout_secs: 300,
            max_resumes: 4,
            resume_backoff_ms: 100,
            resume_backoff_max_ms: 1_000,
            warm_max: 0,
            stall_after_secs: 300,
            tool_output_bytes: 2048,
            fallback_on_model_unavailable: true,
            fallback_on_rate_limited: true,
            fallback_on_quota: true,
            fallback_on_unhealthy: true,
        }),
        "the project's stall limit beats the company's (E15.7)"
    );
}
