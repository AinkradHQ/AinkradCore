//! The GitHub client against the fake GitHub: what it sends and how it reads the answers.

use super::*;
use crate::fake;

fn new_pr() -> NewPr {
    NewPr {
        head: "citadel/CIT-1".to_owned(),
        base: "main".to_owned(),
        title: "CIT-1: Build it".to_owned(),
        body: "Closes CIT-1.".to_owned(),
    }
}

#[tokio::test]
async fn opens_reads_checks_merges_with_a_merge_commit_and_comments() {
    let (api, hub) = fake::github("ghp_token").await;
    let gh = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_token"));

    let pr = gh.open_pr(&new_pr()).await.unwrap();
    assert_eq!(pr.number, 1);
    assert_eq!(pr.state, PrState::Open);
    assert_eq!(pr.url, "https://github.test/acme/app/pull/1");
    let opened = hub.lock().unwrap().prs[&1].clone();
    assert_eq!(
        (opened.head.as_str(), opened.base.as_str()),
        ("citadel/CIT-1", "main")
    );
    assert_eq!(opened.title, "CIT-1: Build it");

    assert_eq!(gh.pr_status(1).await.unwrap().checks, Checks::None);
    hub.lock()
        .unwrap()
        .checks(1, &[("build", "in_progress", None)]);
    assert_eq!(gh.pr_status(1).await.unwrap().checks, Checks::Pending);
    hub.lock().unwrap().checks(
        1,
        &[
            ("build", "completed", Some("success")),
            ("lint", "completed", Some("skipped")),
        ],
    );
    assert_eq!(gh.pr_status(1).await.unwrap().checks, Checks::Success);
    // A failing commit status fails the lot, by name.
    let sha = pr.head_sha.clone();
    hub.lock().unwrap().statuses.insert(
        sha.clone(),
        vec![("ci/legacy".to_owned(), "failure".to_owned())],
    );
    let failing = gh.pr_status(1).await.unwrap();
    assert_eq!(failing.checks, Checks::Failure);
    assert_eq!(failing.failed, ["ci/legacy"]);
    hub.lock().unwrap().statuses.clear();

    gh.comment(1, "QA passed.").await.unwrap();
    let stale = gh.merge(1, "old-sha", "Merge x: y").await.unwrap_err();
    assert!(matches!(stale, Error::Http { status: 409, .. }), "{stale}");
    gh.merge(1, &sha, "Merge citadel/CIT-1: Build it")
        .await
        .unwrap();
    let merged = gh.pr_status(1).await.unwrap();
    assert_eq!(merged.pr.state, PrState::Merged);
    let hub = hub.lock().unwrap();
    assert_eq!(
        hub.merges,
        [(1, "merge".to_owned())],
        "a merge commit, never squash"
    );
    assert_eq!(
        hub.merge_titles,
        [(1, "Merge citadel/CIT-1: Build it".to_owned())],
        "the merge commit's title goes with the merge"
    );
    assert_eq!(hub.comments, [(1, "QA passed.".to_owned())]);
    assert_eq!(hub.requests[0], "POST /repos/acme/app/pulls");
}

#[tokio::test]
async fn deletes_a_branch_once_and_a_branch_already_gone_is_fine() {
    let (api, hub) = fake::github("ghp_token").await;
    let gh = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_token"));

    gh.delete_branch("citadel/CIT-1").await.unwrap();
    gh.delete_branch("citadel/CIT-1").await.unwrap();
    assert_eq!(hub.lock().unwrap().deleted, ["citadel/CIT-1"]);
    assert_eq!(
        hub.lock().unwrap().requests,
        [
            "DELETE /repos/acme/app/git/refs/heads/citadel/CIT-1",
            "DELETE /repos/acme/app/git/refs/heads/citadel/CIT-1",
        ]
    );
}

#[tokio::test]
async fn errors_carry_the_apis_message_and_never_the_token() {
    let (api, hub) = fake::github("ghp_right").await;
    let wrong = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_wrong_s3cret"));
    let e = wrong.open_pr(&new_pr()).await.unwrap_err();
    assert_eq!(
        e,
        Error::Http {
            status: 401,
            message: "Bad credentials".to_owned()
        }
    );
    assert!(!format!("{e} {e:?}").contains("s3cret"));

    let gh = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_right"));
    gh.open_pr(&new_pr()).await.unwrap();
    hub.lock().unwrap().unmergeable.push(1);
    let sha = hub.lock().unwrap().prs[&1].head_sha.clone();
    let e = gh.merge(1, &sha, "Merge x: y").await.unwrap_err();
    assert_eq!(e.to_string(), "HTTP 405: Pull Request is not mergeable");
    let gone = GitHub::new(
        client(),
        "http://127.0.0.1:9",
        "acme/app",
        Secret::new("ghp_right"),
    );
    assert!(matches!(gone.pr_status(1).await, Err(Error::Transport(_))));
}

#[tokio::test]
async fn unreadable_check_runs_fall_back_to_actions_runs_then_to_statuses() {
    let (api, hub) = fake::github("ghp_token").await;
    let gh = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_token"));
    let sha = gh.open_pr(&new_pr()).await.unwrap().head_sha;
    hub.lock()
        .unwrap()
        .checks(1, &[("build", "completed", Some("success"))]);
    hub.lock().unwrap().workflow_runs.insert(
        sha.clone(),
        vec![(
            "ci".to_owned(),
            "completed".to_owned(),
            Some("failure".to_owned()),
        )],
    );
    hub.lock().unwrap().statuses.insert(
        sha.clone(),
        vec![("ci/legacy".to_owned(), "pending".to_owned())],
    );
    let full = gh.pr_status(1).await.unwrap();
    assert_eq!((full.checks, full.note), (Checks::Pending, None));

    // No Checks scope: the head's Actions runs stand in for its check runs.
    hub.lock().unwrap().forbidden.push("check-runs");
    let actions = gh.pr_status(1).await.unwrap();
    assert_eq!(actions.checks, Checks::Failure);
    assert_eq!(actions.failed, ["ci"]);
    assert_eq!(actions.note.as_deref(), Some(ACTIONS_ONLY));

    // No Actions scope either: the commit statuses alone.
    hub.lock().unwrap().forbidden.push("runs");
    let statuses = gh.pr_status(1).await.unwrap();
    assert_eq!(statuses.checks, Checks::Pending);
    assert_eq!(statuses.note.as_deref(), Some(STATUSES_ONLY));
}

#[tokio::test]
async fn a_pr_of_a_branch_never_pushed_is_a_missing_branch() {
    let (api, hub) = fake::github("ghp_token").await;
    let origin = std::env::temp_dir().join(format!("citadel-gh-origin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&origin);
    let git = |args: &[&str]| {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(&origin)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    };
    std::fs::create_dir_all(&origin).unwrap();
    git(&["init", "-q", "--bare"]);
    hub.lock().unwrap().git = Some(origin.clone());
    let gh = GitHub::new(client(), &api, "acme/app", Secret::new("ghp_token"));
    let e = gh.open_pr(&new_pr()).await.unwrap_err();
    assert_eq!(e, Error::MissingBranch("citadel/CIT-1".to_owned()));
    assert_eq!(
        hub.lock().unwrap().requests.last().map(String::as_str),
        Some("GET /repos/acme/app/branches/citadel/CIT-1")
    );
    let _ = std::fs::remove_dir_all(&origin);
}
