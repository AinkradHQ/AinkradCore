//! The progress watchdog over the wire (E15.7): `Progress` stamps the run apart from its lease
//! heartbeat, and a run the runner ends `Stalled` fails as `stalled`, with its issue escalated
//! up the chain rather than retried.

use citadel_core::work::NextActor;
use citadel_server::store::work::get_issue;
use ainkrad_proto::runner::{Outcome, RepoDiff, RunToken};
use ainkrad_runner::{Executor, Job, Report};
use tokio::sync::mpsc;

use super::support::*;
use crate::harness::{agent, assign, company, count, issue, runner};

/// Reports progress with a 2-file diff (+38 −6 in `core`, 1.18), then stalls.
struct Stalls;

impl Executor for Stalls {
    async fn start(&self, _: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let _ = reports
            .send(Report::Progress {
                diff_files: Some(2),
                repos: vec![RepoDiff {
                    repo: "core".to_owned(),
                    files: 2,
                    insertions: 38,
                    deletions: 6,
                }],
            })
            .await;
        Outcome::Stalled
    }
}

#[tokio::test]
async fn a_stalled_run_fails_as_stalled_and_its_issue_escalates() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    runner(pool, "box", &[]).await;
    let i = issue(pool, p).await;
    assign(pool, i, dev).await;
    stack.runner("box", &[], Stalls);
    let stalled = "SELECT count(*) FROM runs WHERE state = 'failed' AND terminal_reason = 'stalled' \
                   AND last_progress_at IS NOT NULL AND diff_files = 2 \
                   AND json_extract(diff_repos, '$[0].insertions') = 38";
    until(pool, "the run to stall", stalled).await;
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(
        issue.next_actor,
        Some(NextActor::Human(citadel_core::work::UserId(1))),
        "no team: up to the admin"
    );
    let retries = "SELECT count(*) FROM wake_requests WHERE source = 'retry'";
    assert_eq!(count(pool, retries).await, 0, "never retried");
}
