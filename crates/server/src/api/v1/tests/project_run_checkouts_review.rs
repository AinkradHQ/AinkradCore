//! PR 321 review: a run holds its repo leases only while cloning, a session's lease on the same
//! runner survives it (and a run's survives a session ending), a late finish of an old run revokes
//! nothing, and a spec that uses repos is placed on a runner that can clone.

use ainkrad_proto::v2::RunPhase;
use serde_json::json;

use super::project_run_checkouts::{can_fetch, shop};
use super::project_runs::{run, start, w};
use super::*;
use crate::runs;
use crate::store::agents::{self as store, NewSession};

/// A live project session of `project` on `runner` (its workspace names `repo`).
async fn session(fx: &Fx, runner: &str, project: i64, repo: i64) -> crate::store::agents::Session {
    let policy = json!({"mode": "ask"});
    let ws = json!({"repo": "https://github.com/acme/web.git", "base": "main",
                    "branch": "b", "mirror": repo});
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: Some(&ws),
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let s = store::create(&fx.app.pool, &new, sys, "2026-01-01T00:00:00Z")
        .await
        .unwrap();
    store::set_project(&fx.app.pool, &s.id, project)
        .await
        .unwrap();
    store::get(&fx.app.pool, &s.id).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_runs_own_lease_ends_when_run_start_returns() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "running");
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_live_session_on_the_runner_keeps_its_lease_through_a_run() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    let s = session(&fx, &vm.id, p, repo).await;
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(
        can_fetch(&fx, &vm, repo).await,
        StatusCode::OK,
        "after start"
    );
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    assert_eq!(run(&fx, &id).await.state, "stopped");
    assert_eq!(
        can_fetch(&fx, &vm, repo).await,
        StatusCode::OK,
        "after stop"
    );
    // The session ends last: its lease goes.
    let outcome = json!({"kind": "succeeded"});
    store::end(
        &fx.app.pool,
        &s.id,
        "ended",
        &outcome,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    crate::mirrors::release_session(&fx.app, &s).await;
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_session_ending_keeps_the_lease_while_a_run_of_the_project_is_live() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    let s = session(&fx, &vm.id, p, repo).await;
    // A run that is still starting (its runner is cloning).
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    let outcome = json!({"kind": "succeeded"});
    store::end(
        &fx.app.pool,
        &s.id,
        "ended",
        &outcome,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    crate::mirrors::release_session(&fx.app, &s).await;
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::OK);
    drop(pending);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_late_finish_of_an_old_run_does_not_revoke_a_newer_runs_lease() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    let old = start(&fx, &link, p).await.unwrap();
    let old = run(&fx, &old).await;
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    // A newer run is live and holds its lease (it is cloning).
    let now = fx.app.clock.now();
    let _newer = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    // The old run's finish arrives again, late: it ended nothing, so it revokes nothing.
    let end = crate::store::runs::End {
        state: "stopped",
        reason: Some("runner_lost"),
        error: None,
    };
    let done = runs::finish(&fx.app, &old, end, w(&now)).await.unwrap();
    assert!(!done);
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::OK);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_failed_start_still_leaves_no_lease() {
    let (fx, link, vm, p, repo, dir) = shop().await;
    *link.start.lock().unwrap() = Ok(RunPhase::Failed);
    let id = start(&fx, &link, p).await.unwrap();
    assert_eq!(run(&fx, &id).await.state, "failed");
    assert_eq!(can_fetch(&fx, &vm, repo).await, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_spec_that_uses_repos_is_placed_on_a_runner_that_can_clone() {
    let (fx, mut link, vm, p, _, dir) = shop().await;
    // The first runner is listed (and loaded) like `vm` but cannot clone.
    let other = super::secrets::runner(&fx, "a-first").await;
    link.runners = vec![other.id.clone(), vm.id.clone()];
    link.cannot_clone.lock().unwrap().push(other.id.clone());
    let now = fx.app.clock.now();
    let pending = runs::begin_start(&fx.app, &link, p, w(&now)).await.unwrap();
    assert_eq!(pending.run.runner, vm.id);
    let _ = std::fs::remove_dir_all(dir);
}
