//! The GitLab client against the fake GitLab.

use super::*;
use crate::fake;

#[tokio::test]
async fn opens_reads_pipelines_merges_without_squash_and_comments() {
    let (api, hub) = fake::gitlab("glpat-token").await;
    let gl = GitLab::new(client(), &api, "acme/app", Secret::new("glpat-token"));
    let new = NewPr {
        head: "citadel/CIT-1".to_owned(),
        base: "main".to_owned(),
        title: "CIT-1: Build it".to_owned(),
        body: "Closes CIT-1.".to_owned(),
    };
    let mr = gl.open_pr(&new).await.unwrap();
    assert_eq!((mr.number, mr.state), (1, PrState::Open));
    assert_eq!(mr.url, "https://gitlab.test/acme/app/-/merge_requests/1");
    assert_eq!(
        hub.lock().unwrap().requests[0],
        "POST /projects/acme%2Fapp/merge_requests",
        "the project path is URL-encoded"
    );

    assert_eq!(gl.pr_status(1).await.unwrap().checks, Checks::None);
    let sha = mr.head_sha.clone();
    hub.lock()
        .unwrap()
        .pipelines
        .insert(sha.clone(), "running".to_owned());
    assert_eq!(gl.pr_status(1).await.unwrap().checks, Checks::Pending);
    hub.lock()
        .unwrap()
        .pipelines
        .insert(sha.clone(), "failed".to_owned());
    let failed = gl.pr_status(1).await.unwrap();
    assert_eq!(
        (failed.checks, failed.failed),
        (Checks::Failure, vec!["pipeline".to_owned()])
    );
    hub.lock()
        .unwrap()
        .pipelines
        .insert(sha.clone(), "success".to_owned());
    hub.lock().unwrap().statuses.insert(
        sha.clone(),
        vec![("danger".to_owned(), "success".to_owned())],
    );
    assert_eq!(gl.pr_status(1).await.unwrap().checks, Checks::Success);

    gl.comment(1, "QA passed.").await.unwrap();
    let stale = gl.merge(1, "old", "Merge x: y").await.unwrap_err();
    assert!(matches!(stale, Error::Http { status: 409, .. }), "{stale}");
    gl.merge(1, &sha, "Merge citadel/CIT-1: Build it")
        .await
        .unwrap();
    assert_eq!(gl.pr_status(1).await.unwrap().pr.state, PrState::Merged);
    let hub = hub.lock().unwrap();
    assert_eq!(hub.merges, [(1, "merge".to_owned())], "never squashed");
    assert_eq!(
        hub.merge_titles,
        [(1, "Merge citadel/CIT-1: Build it".to_owned())]
    );
    assert_eq!(hub.comments, [(1, "QA passed.".to_owned())]);
}

#[tokio::test]
async fn deletes_a_branch_with_its_slash_encoded_and_a_branch_already_gone_is_fine() {
    let (api, hub) = fake::gitlab("glpat-token").await;
    let gl = GitLab::new(client(), &api, "acme/app", Secret::new("glpat-token"));

    gl.delete_branch("feat/ain-53").await.unwrap();
    gl.delete_branch("feat/ain-53").await.unwrap();
    assert_eq!(hub.lock().unwrap().deleted, ["feat/ain-53"]);
    assert_eq!(
        hub.lock().unwrap().requests,
        [
            "DELETE /projects/acme%2Fapp/repository/branches/feat%2Fain-53",
            "DELETE /projects/acme%2Fapp/repository/branches/feat%2Fain-53",
        ]
    );
}

#[tokio::test]
async fn a_wrong_token_is_refused_and_never_echoed() {
    let (api, _) = fake::gitlab("glpat-right").await;
    let gl = GitLab::new(client(), &api, "acme/app", Secret::new("glpat-wr0ng"));
    let e = gl.pr_status(1).await.unwrap_err();
    assert_eq!(e.to_string(), "HTTP 401: 401 Unauthorized");
    assert!(!format!("{e:?}").contains("wr0ng"));
}
