//! Sessions of a project (P3-02): the Core builds the workspace from the project's repos, a client
//! cannot name a repo copy itself, and the copies are leased to the session's runner at launch
//! and only for the session's own project.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};
use crate::store::agents::{self as store, NewSession};

async fn admin(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

async fn project(fx: &Fx, slug: &str) -> i64 {
    let r = admin(
        fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": slug, "name": slug}),
    )
    .await;
    r.1["id"].as_i64().unwrap()
}

/// A repo row with `remote` as its remote (the API takes only https; a fixture is put in directly).
async fn add(fx: &Fx, project: i64, name: &str, remote: &str, primary: bool) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, ?, ?, 'main', ?) RETURNING id",
    )
    .bind(project)
    .bind(name)
    .bind(remote)
    .bind(primary)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

async fn create(fx: &Fx, body: Value) -> (StatusCode, Value) {
    admin(fx, Method::POST, "/api/v1/agent-sessions", body).await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["code"].as_str().unwrap_or(""))
}

#[tokio::test]
async fn the_core_builds_the_workspace_and_a_client_cannot_name_a_mirror() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let id = project(&fx, "shop").await;
    let new = |extra: Value| {
        let mut b = json!({"runner": vm.id, "harness": "claude"});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        b
    };
    // Refused before any session exists.
    let none = create(&fx, new(json!({"project_id": 999}))).await;
    assert_eq!(none.0, StatusCode::NOT_FOUND, "{}", none.1);
    assert_eq!(
        code(&create(&fx, new(json!({"project_id": id}))).await),
        (StatusCode::CONFLICT, "project_has_no_repos")
    );
    let ws = json!({"repo": "https://github.com/acme/web.git", "base": "main", "branch": "b"});
    assert_eq!(
        create(&fx, new(json!({"project_id": id, "workspace": ws})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut mirrored = ws.clone();
    mirrored["mirror"] = json!(1);
    assert_eq!(
        create(&fx, new(json!({"workspace": mirrored}))).await.0,
        StatusCode::BAD_REQUEST,
        "only the Core names a mirror"
    );
    let mut nested = ws.clone();
    nested["also"] = json!([mirrored]);
    assert_eq!(
        create(&fx, new(json!({"workspace": nested}))).await.0,
        StatusCode::BAD_REQUEST
    );
    let archived = project(&fx, "old").await;
    add(
        &fx,
        archived,
        "web",
        "https://github.com/acme/web.git",
        true,
    )
    .await;
    let r = admin(
        &fx,
        Method::POST,
        &format!("/api/v1/projects/{archived}/archive"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        code(&create(&fx, new(json!({"project_id": archived}))).await),
        (StatusCode::CONFLICT, "project_archived")
    );

    // One repo is the folder itself; several are `<folder>/<name>`, the primary first.
    let web = add(&fx, id, "web", "https://github.com/acme/web.git", true).await;
    let w = super::super::agents::project::workspace_for(&fx.app, id)
        .await
        .unwrap();
    assert_eq!(
        (w["mirror"].as_i64(), w["name"].as_str()),
        (Some(web), Some("web"))
    );
    assert!(w["also"].is_null());
    let api = add(&fx, id, "api", "https://github.com/acme/api.git", false).await;
    let w = super::super::agents::project::workspace_for(&fx.app, id)
        .await
        .unwrap();
    assert_eq!(w["name"], "web");
    assert_eq!(w["also"][0]["name"], "api");
    assert_eq!(w["also"][0]["mirror"].as_i64(), Some(api));
    assert_eq!(
        w["branch"], w["also"][0]["branch"],
        "one branch for the session"
    );
    assert_eq!(w["base"], "main");
    let parsed: ainkrad_proto::runner::Workspace = serde_json::from_value(w).unwrap();
    assert!(parsed.problem().is_none());
}

#[tokio::test]
async fn a_session_leases_only_its_own_active_projects_copies_to_its_runner() {
    let mut fx = fx().await;
    let dir = tmp("p3-02");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, head) = remote(&dir);
    let path = path.to_str().unwrap().to_owned();
    let (mine, theirs) = (project(&fx, "mine").await, project(&fx, "theirs").await);
    let repo = add(&fx, mine, "web", &path, true).await;
    let other = add(&fx, theirs, "web", &path, true).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let stranger = super::secrets::runner(&fx, "stranger").await;
    let m = fx.app.mirrors.clone().unwrap();
    let may = |dev: &str, repo: i64| {
        let (app, m, dev) = (fx.app.clone(), m.clone(), dev.to_owned());
        async move {
            crate::mirrors::servable(&app, &m, &dev, repo)
                .await
                .unwrap()
                .is_some()
        }
    };
    assert!(!may(&vm.id, repo).await, "no lease before a launch");

    // Another project's repo is refused, and nothing is leased for the call that names it.
    let r = crate::mirrors::for_session(&fx.app, &vm.id, mine, &[repo, other]).await;
    assert!(r.is_err(), "{r:?}");
    assert!(!may(&vm.id, repo).await && !may(&vm.id, other).await);

    // The launch fetches the copy and leases it to this runner, and to no other.
    crate::mirrors::for_session(&fx.app, &vm.id, mine, &[repo])
        .await
        .unwrap();
    let state = crate::store::projects::mirror(&fx.app.pool, repo)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        state.head.as_deref(),
        Some(head.as_str()),
        "fetched at launch"
    );
    assert!(may(&vm.id, repo).await);
    assert!(!may(&stranger.id, repo).await);
    assert!(!may(&vm.id, other).await, "the lease is for one repo");

    // An archived project's session cannot start, and its open lease serves nothing.
    let r = admin(
        &fx,
        Method::POST,
        &format!("/api/v1/projects/{mine}/archive"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert!(!may(&vm.id, repo).await);
    assert!(
        crate::mirrors::for_session(&fx.app, &vm.id, mine, &[repo])
            .await
            .is_err()
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_session_takes_a_project_once_and_only_before_it_starts() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let (a, b) = (project(&fx, "aa").await, project(&fx, "bb").await);
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let s = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    assert!(store::set_project(&fx.app.pool, &s.id, a).await.unwrap());
    assert!(
        !store::set_project(&fx.app.pool, &s.id, b).await.unwrap(),
        "once"
    );
    let got = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert_eq!(got.project_id, Some(a));
    let s2 = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    store::set_state(&fx.app.pool, &s2.id, "running", "t", false, NOW)
        .await
        .unwrap();
    assert!(
        !store::set_project(&fx.app.pool, &s2.id, a).await.unwrap(),
        "not once started"
    );
}

#[tokio::test]
async fn a_launch_leases_nothing_for_a_workspace_that_names_copies_it_has_no_project_for() {
    let mut fx = fx().await;
    let dir = tmp("p3-02-launch");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, _) = remote(&dir);
    let path = path.to_str().unwrap().to_owned();
    let (mine, theirs) = (project(&fx, "mine").await, project(&fx, "theirs").await);
    let (repo, other) = (
        add(&fx, mine, "web", &path, true).await,
        add(&fx, theirs, "web", &path, true).await,
    );
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({"mode": "ask"});
    let session = |repo: i64| {
        let ws = json!({"repo": "https://github.com/acme/web.git", "base": "main",
                        "branch": "b", "mirror": repo});
        let (fx, vm, policy) = (&fx, &vm, &policy);
        async move {
            let new = NewSession {
                runner: &vm.id,
                harness: "claude",
                model: None,
                prompt: None,
                workspace: Some(&ws),
                policy,
                secrets: &[],
                created_by: &fx.dev.id,
            };
            let sys = ainkrad_core::audit::AuditActor::System;
            store::create(&fx.app.pool, &new, sys, NOW).await.unwrap()
        }
    };
    let m = fx.app.mirrors.clone().unwrap();
    let may = |repo: i64| {
        let (app, m, dev) = (fx.app.clone(), m.clone(), vm.id.clone());
        async move {
            crate::mirrors::servable(&app, &m, &dev, repo)
                .await
                .unwrap()
                .is_some()
        }
    };
    // A workspace written without a project (a module's, say) opens nothing.
    let s = session(repo).await;
    assert!(crate::agents::project_mirrors(&fx.app, &s).await.is_err());
    assert!(!may(repo).await);
    // With a project, only its own repos.
    let s = session(other).await;
    store::set_project(&fx.app.pool, &s.id, mine).await.unwrap();
    let s = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert!(crate::agents::project_mirrors(&fx.app, &s).await.is_err());
    assert!(!may(other).await);
    let s = session(repo).await;
    store::set_project(&fx.app.pool, &s.id, mine).await.unwrap();
    let s = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    crate::agents::project_mirrors(&fx.app, &s).await.unwrap();
    assert!(may(repo).await);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_session_of_a_project_needs_an_admin_device() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let id = project(&fx, "shop").await;
    add(&fx, id, "web", "https://github.com/acme/web.git", true).await;
    // An `agent` device may start sessions, but not ones that fetch a project's repos with the
    // project's connection (fetching them is `admin`): refused before anything is built.
    let agent = fx.enroll("agent-only", &["agent"]).await;
    let body = json!({"runner": vm.id, "harness": "claude", "project_id": id});
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/agent-sessions",
            Some(&agent),
            Some(body),
        ),
    )
    .await;
    assert_eq!(
        code(&r),
        (StatusCode::FORBIDDEN, "forbidden_scope"),
        "{}",
        r.1
    );
}

#[test]
fn a_lease_outlasts_the_relays_clone_limit() {
    const { assert!(crate::mirrors::LEASE_SECS > 30 * 60) };
}

#[tokio::test]
async fn a_full_lease_table_fails_the_grant_with_a_reason() {
    let dir = tmp("p3-02-full");
    let m = Mirrors::new(dir.join("mirrors"));
    for i in 0..4096 {
        m.grant(&format!("d{i}"), 1, "k", 100).unwrap();
    }
    assert!(m.grant("one-more", 1, "k", 100).is_err());
    // A device that already holds one renews it; expired leases make room.
    m.grant("d0", 1, "k", 100).unwrap();
    m.grant("one-more", 1, "k", 100 + crate::mirrors::LEASE_SECS + 1)
        .unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn ending_a_session_revokes_its_leases_unless_a_sibling_still_runs() {
    let mut fx = fx().await;
    let dir = tmp("p3-02-release");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, _) = remote(&dir);
    let path = path.to_str().unwrap().to_owned();
    let mine = project(&fx, "mine").await;
    let repo = add(&fx, mine, "web", &path, true).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({"mode": "ask"});
    let ws = json!({"repo": "https://github.com/acme/web.git", "base": "main",
                    "branch": "b", "mirror": repo});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: Some(&ws),
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let mut made = Vec::new();
    for _ in 0..2 {
        let s = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
        store::set_project(&fx.app.pool, &s.id, mine).await.unwrap();
        made.push(store::get(&fx.app.pool, &s.id).await.unwrap().unwrap());
    }
    let m = fx.app.mirrors.clone().unwrap();
    let may = || {
        let (app, m, dev) = (fx.app.clone(), m.clone(), vm.id.clone());
        async move {
            crate::mirrors::servable(&app, &m, &dev, repo)
                .await
                .unwrap()
                .is_some()
        }
    };
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    assert!(may().await);
    let outcome = json!({"kind": "succeeded"});
    // The first ends while the second still lives on the same runner: the lease stays.
    store::end(&fx.app.pool, &made[0].id, "ended", &outcome, NOW)
        .await
        .unwrap();
    crate::mirrors::release_session(&fx.app, &made[0]).await;
    assert!(may().await, "a sibling session still needs the copy");
    // The last one ends: the lease goes.
    store::end(&fx.app.pool, &made[1].id, "ended", &outcome, NOW)
        .await
        .unwrap();
    crate::mirrors::release_session(&fx.app, &made[1]).await;
    assert!(!may().await);
    let _ = std::fs::remove_dir_all(dir);
}
