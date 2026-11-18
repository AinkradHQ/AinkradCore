//! Run checkouts (P5-05): a run that builds from a repo leases the project's repos to its runner
//! before `run.start` and tells the runner to clone them from the Core's copies; the leases end
//! with the run (stop or fail), and an archived project's copy cannot be fetched at all.

use ainkrad_proto::v2::RunPhase;
use serde_json::json;

use super::project_runs::{Fake, run, start, w};
use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};
use crate::store::projects;
use crate::store::run_specs;

/// A project whose one service builds from its repo `web` (a local fixture remote), a runner
/// device, and a fake link that places runs on it.
async fn shop() -> (Fx, Fake, TestDevice, i64, i64, std::path::PathBuf) {
    let mut fx = fx().await;
    let dir = tmp("run-checkouts");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, _) = remote(&dir);
    let vm = super::secrets::runner(&fx, "vm").await;
    let now = fx.app.clock.now();
    let p = projects::create(&fx.app.pool, "shop", "Shop", "", "manual", w(&now))
        .await
        .unwrap();
    let repo: i64 = sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, 'web', ?, 'main', 1) RETURNING id",
    )
    .bind(p.id)
    .bind(path.to_str().unwrap())
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let spec = json!({"services": {"web": {"build": {"repo": "web"}}}});
    run_specs::save(&fx.app.pool, p.id, &spec, "manual", w(&now))
        .await
        .unwrap();
    let mut link = Fake::new();
    link.runners = vec![vm.id.clone()];
    (fx, link, vm, p.id, repo, dir)
}

async fn can_fetch(fx: &Fx, vm: &TestDevice, repo: i64) -> StatusCode {
    let uri = format!("/api/v1/mirrors/{repo}/info/refs?service=git-upload-pack");
    send(&fx.app, req(Method::GET, &uri, Some(vm), None))
        .await
        .0
}

#[tokio::test]
async fn a_spec_built_from_its_repo_starts_with_the_repo_leased_and_named_for_cloning() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "running");
    let sent = link.started.lock().unwrap().clone();
    let c = &sent[0].checkouts[0];
    let from = c.from_core.as_ref().expect("a clone from the Core's copy");
    assert_eq!((c.repo.as_str(), c.dir.as_str()), ("web", ""));
    assert_eq!((from.mirror, from.base.as_str()), (repo, "main"));
    // The runner can read the copy now, and no other device can.
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::OK);
    let other = super::secrets::runner(&fx, "other").await;
    assert_eq!(can_fetch(&fx, &other, repo).await, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_lease_is_revoked_on_stop_and_on_a_failed_start() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    start(&fx, &link, p).await.unwrap();
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::OK);
    let now = fx.app.clock.now();
    crate::runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    // A start the runner fails leaves no lease behind either.
    *link.start.lock().unwrap() = Ok(RunPhase::Failed);
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "failed");
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_archived_project_cannot_fetch_even_with_a_lease_and_cannot_start() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    start(&fx, &link, p).await.unwrap();
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::OK);
    let r = send(
        &fx.app,
        req(
            Method::POST,
            &format!("/api/v1/projects/{p}/archive"),
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    let now = fx.app.clock.now();
    let again = crate::runs::begin_start(&fx.app, &link, p, w(&now)).await;
    assert!(again.is_err());
    let _ = std::fs::remove_dir_all(dir);
}
