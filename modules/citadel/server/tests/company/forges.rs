//! E9.1 and E9.2's acceptance against a fake GitHub and a fake GitLab: an agent works an issue
//! and asks for its PR; the runner pushes the issue branch as the run ends; the poller opens
//! the PR (a merge request on GitLab) from it, and its checks come back to the issue (row,
//! comments, a wake on failure).

use citadel_core::work::ProjectMode;
use citadel_server::store::forge::{PrPhase, issue_pr};
use citadel_server::store::work::list_comments;
use ainkrad_providers::fake::{Hub, Shared};
use ainkrad_providers::{Kind, fake};
use serde_json::json;

use super::stage::{Stage, git};

const UNPUSHED_GR: &str = "the branch citadel/GR-1 is not on the forge (not pushed yet); it opens \
                           once a run on this issue pushes the branch";

/// A fake forge of `kind` wanting `forge_token`: its API URL and state.
pub(super) async fn forge(kind: Kind) -> (String, Shared<Hub>) {
    match kind {
        Kind::GitHub => fake::github("forge_token").await,
        Kind::GitLab => fake::gitlab("forge_token").await,
    }
}

/// Sets PR 1's checks on the fake to `pending`, `failure` or `success`, the way `kind` says
/// it: GitHub check runs, a GitLab head pipeline.
pub(super) fn set_checks(kind: Kind, hub: &Shared<Hub>, verdict: &str) {
    let sha = hub.lock().unwrap().prs[&1].head_sha.clone();
    set_checks_on(kind, hub, &sha, verdict);
}

/// `set_checks` on commit `sha`, before or after a PR has it.
pub(super) fn set_checks_on(kind: Kind, hub: &Shared<Hub>, sha: &str, verdict: &str) {
    let mut hub = hub.lock().unwrap();
    match kind {
        Kind::GitHub => {
            let (status, conclusion) = match verdict {
                "pending" => ("in_progress", None),
                v => ("completed", Some(v.to_owned())),
            };
            let run = ("build".to_owned(), status.to_owned(), conclusion);
            hub.check_runs.insert(sha.to_owned(), vec![run]);
        }
        Kind::GitLab => {
            let status = match verdict {
                "pending" => "running",
                "failure" => "failed",
                other => other,
            };
            hub.pipelines.insert(sha.to_owned(), status.to_owned());
        }
    }
}

#[tokio::test]
async fn an_issue_gets_a_pr_and_its_checks_come_back_on_github() {
    pr_and_checks(Kind::GitHub, "GH").await;
}

#[tokio::test]
async fn an_issue_gets_a_merge_request_and_its_pipeline_comes_back_on_gitlab() {
    pr_and_checks(Kind::GitLab, "GL").await;
}

async fn pr_and_checks(kind: Kind, key: &str) {
    let mut stage = Stage::new(kind.as_str()).await;
    let o = stage.org().await;
    let project = stage.project(&o, key, ProjectMode::Kanban).await;
    let (api, hub) = forge(kind).await;
    let origin = stage.on_forge(project, kind, &api, "forge_token").await;
    hub.lock().unwrap().git = Some(origin.clone());

    let issue = stage.issue(project, "Add the export", None).await;
    let title = format!("{key}-1: Add the export");
    let n = stage
        .play(
            issue,
            &[
                ("transition", json!({"transition": "start"})),
                ("open_pr", json!({"title": title, "body": "Adds export."})),
                ("get_issue", json!({})),
            ],
        )
        .await;
    let commit = "echo export > export.txt && git add -A && git commit -qm 'Add the export'";
    stage.script(issue, n, commit).await;
    stage.assign(issue, o.dev).await;
    assert_eq!(stage.ended(issue, 1).await, "succeeded");
    let replies = stage.replies(issue, 1).await;
    let branch = format!("citadel/{key}-1");
    assert_eq!(replies[1]["state"], "requested", "{replies:?}");
    assert_eq!(replies[1]["head"], branch.as_str());
    assert_eq!(replies[2]["pr"]["state"], "requested");

    // The runner pushed the branch; the poller opens the PR from it.
    let pushed = git(&origin, &["rev-parse", &format!("refs/heads/{branch}")]);
    let events: Vec<String> = sqlx::query_scalar("SELECT payload FROM run_events")
        .fetch_all(&stage.pool)
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| e.contains("branch_pushed")),
        "{events:?}"
    );
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    assert_eq!(pr.head_sha.as_deref(), Some(pushed.as_str()));
    {
        let hub = hub.lock().unwrap();
        let opened = &hub.prs[&1];
        assert_eq!((&opened.head, opened.base.as_str()), (&branch, "main"));
        assert_eq!(opened.title, title);
    }

    // Checks: pending is quiet, a failure is commented and wakes the developer, success too.
    set_checks(kind, &hub, "pending");
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.checks, "pending");
    set_checks(kind, &hub, "failure");
    stage.poll().await;
    stage.poll().await;
    assert_eq!(
        stage.ended(issue, 2).await,
        "succeeded",
        "the failure woke the developer"
    );
    set_checks(kind, &hub, "success");
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.checks, "success");
    let said: Vec<String> = list_comments(&stage.pool, issue)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.body)
        .filter(|b| b.starts_with("PR #1"))
        .collect();
    let short = &pushed[..12];
    let (url, failing) = match kind {
        Kind::GitHub => ("https://github.test/acme/app/pull/1", "build"),
        Kind::GitLab => (
            "https://gitlab.test/acme/app/-/merge_requests/1",
            "pipeline",
        ),
    };
    assert_eq!(
        said,
        [
            format!("PR #1 opened: {url}"),
            format!("PR #1: checks failed on {short}: {failing}."),
            format!("PR #1: checks passed on {short}."),
        ],
        "each change once, repeats quiet"
    );
    let audited: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE 'pr.%' ORDER BY seq")
            .fetch_all(&stage.pool)
            .await
            .unwrap();
    assert_eq!(
        audited,
        [
            "pr.requested",
            "pr.opened",
            "pr.checks",
            "pr.checks",
            "pr.checks"
        ]
    );
}

/// Without the branch pushed the forge refuses the PR: the issue hears once that the branch is
/// not pushed; a missing token file is reported the same way and never leaks a token.
#[tokio::test]
async fn a_refused_pr_is_reported_once_and_retried() {
    let mut stage = Stage::new("github-refused").await;
    let o = stage.org().await;
    let project = stage
        .project(&o, "GR", citadel_core::work::ProjectMode::Kanban)
        .await;
    let (api, hub) = fake::github("ghp_fake_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "ghp_fake_token")
        .await;
    hub.lock().unwrap().git = Some(origin);
    let issue = stage.issue(project, "Nothing committed", None).await;
    for _ in 0..2 {
        stage
            .play(issue, &[("open_pr", json!({"title": "GR-1"}))])
            .await;
    }
    stage.assign(issue, o.dev).await;
    stage.ended(issue, 1).await;
    stage.poll().await;
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Requested);
    assert_eq!(pr.last_error.as_deref(), Some(UNPUSHED_GR));
    let refusals = list_comments(&stage.pool, issue)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.body.contains("not pushed yet"))
        .count();
    assert_eq!(refusals, 1);
    // The refusal woke the developer, who asks again; a PR is not opened while its issue has
    // a live run.
    stage.ended(issue, 2).await;

    std::fs::remove_file(stage.dir.join("forge-token")).unwrap();
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert!(pr.last_error.unwrap().contains("reading the token file"));
    let texts: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&stage.pool)
        .await
        .unwrap();
    assert!(
        !texts.iter().any(|t| t.contains("ghp_fake_token")),
        "a token reached the audit"
    );
}

/// A PR asked for by a run that pushed nothing (it died first, or committed nothing) waits for
/// a later run on its issue to end instead of being retried every poll: one refused attempt per
/// ended run, one comment, and the PR opens once a run pushes the branch.
#[tokio::test]
async fn a_pr_of_an_unpushed_branch_waits_for_a_run_that_pushes_it() {
    let mut stage = Stage::new("github-unpushed").await;
    let o = stage.org().await;
    let project = stage.project(&o, "GU", ProjectMode::Kanban).await;
    let (api, hub) = fake::github("forge_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin);
    let issue = stage.issue(project, "Unpushed", None).await;
    stage
        .play(issue, &[("open_pr", json!({"title": "GU-1"}))])
        .await;
    // The refusal wakes the developer, whose run commits nothing either (it acts, so it is not
    // nudged again: any non-read call counts, refused or not).
    let start = [("transition", json!({"transition": "start"}))];
    stage.play(issue, &start).await;
    stage.assign(issue, o.dev).await;
    stage.ended(issue, 1).await;
    let posts = |hub: &Shared<Hub>| {
        let hub = hub.lock().unwrap();
        hub.requests
            .iter()
            .filter(|r| *r == "POST /repos/acme/app/pulls")
            .count()
    };
    stage.poll().await;
    stage.ended(issue, 2).await;
    for _ in 0..3 {
        stage.poll().await;
    }
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Requested);
    assert!(pr.last_error.unwrap().contains("not pushed yet"));
    assert_eq!(posts(&hub), 2, "one attempt per ended run, not per poll");
    let said = list_comments(&stage.pool, issue)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.body.contains("not pushed yet"))
        .count();
    assert_eq!(said, 1, "said once");
    assert_eq!(stage.runs_on(issue).await, 2, "the repeat woke nobody");

    // A later run commits; its push gets the PR opened.
    let n = stage.play(issue, &start).await;
    let commit = "echo x > x.txt && git add -A && git commit -qm Work";
    stage.script(issue, n, commit).await;
    stage.wake(issue, o.dev).await;
    stage.ended(issue, n as i64).await;
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    assert_eq!(pr.last_error, None);
    assert_eq!(posts(&hub), 3);
}

/// A token that may not read check runs (403, a fine-grained PAT without Checks) falls back to
/// Actions runs, then to commit statuses: the PR is followed, its checks are what could be
/// read, the issue is told once, and no error sticks to the PR.
#[tokio::test]
async fn unreadable_check_runs_fall_back_and_are_said_once() {
    let mut stage = Stage::new("github-no-checks").await;
    let o = stage.org().await;
    let project = stage.project(&o, "GC", ProjectMode::Kanban).await;
    let (api, hub) = fake::github("forge_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin);
    let issue = stage.issue(project, "Checks", None).await;
    let n = stage
        .play(issue, &[("open_pr", json!({"title": "GC-1"}))])
        .await;
    let commit = "echo x > x.txt && git add -A && git commit -qm Work";
    stage.script(issue, n, commit).await;
    stage.assign(issue, o.dev).await;
    stage.ended(issue, 1).await;
    hub.lock().unwrap().forbidden = vec!["check-runs", "runs"];
    stage.poll().await;
    let sha = hub.lock().unwrap().prs[&1].head_sha.clone();
    hub.lock()
        .unwrap()
        .statuses
        .insert(sha, vec![("ci/legacy".to_owned(), "success".to_owned())]);
    stage.poll().await;
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.checks.as_str()), (PrPhase::Open, "success"));
    assert_eq!(pr.last_error, None);
    assert_eq!(
        pr.checks_note.as_deref(),
        Some(ainkrad_providers::github::STATUSES_ONLY)
    );
    let noted = list_comments(&stage.pool, issue)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.body.contains("can't be read with this token"))
        .count();
    assert_eq!(noted, 1, "said once, not every poll");
}
