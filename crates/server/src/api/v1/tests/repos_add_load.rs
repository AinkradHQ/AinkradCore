//! `POST /projects/{id}/repos` while many mirrors are being fetched must answer at once.
//! A timing probe (`cargo test -- --ignored repos_add_load --nocapture`), not part of the suite.

use std::time::Instant;

use serde_json::json;

use super::connections_fx::cx;
use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "timing probe"]
async fn repos_add_load() {
    // With the broker on and a default GitHub connection, so a fetch looks for its token as in life.
    let mut cx = cx().await;
    let conn = cx.github("octo").await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-defaults/github",
        json!({"connection": conn}),
    )
    .await;
    let fx = &mut cx.fx;
    let dir = tmp("load");
    // A git whose fetch takes 4 s, as a slow network does, and then gets one real local repo.
    let (path, _) = remote(&dir);
    let slow = dir.join("slow-git");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in *\" fetch \"*)\n  sleep 4\n  for a in \"$@\"; do\n    case \"$a\" in https://github.com/*) a={};; esac\n    set -- \"$@\" \"$a\"; shift\n  done;;\nesac\nexec git \"$@\"\n",
        path.display()
    );
    std::fs::write(&slow, script).unwrap();
    std::fs::set_permissions(&slow, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors")).with_git(slow)));
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/projects",
            Some(&fx.dev),
            Some(json!({"slug": "big", "name": "Big"})),
        ),
    )
    .await;
    let id = r.1["id"].as_i64().unwrap();
    let mut repos = Vec::new();
    for i in 0..20 {
        let url = format!("https://github.com/acme/r{i}.git");
        let repo: i64 = sqlx::query_scalar(
            "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, \
             is_primary) VALUES (?, ?, ?, 'main', ?) RETURNING id",
        )
        .bind(id)
        .bind(format!("r{i}"))
        .bind(url)
        .bind(i == 0)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
        repos.push(repo);
    }
    for r in &repos {
        crate::mirrors::start(&fx.app, *r).await;
    }
    // Eight readers at once (the app polls the project list), the fetches running.
    let t = Instant::now();
    let get = format!("/api/v1/projects/{id}");
    let reads = (0..8).map(|_| async {
        let t = Instant::now();
        let (s, _) = send(&fx.app, req(Method::GET, &get, Some(&fx.dev), None)).await;
        (s, t.elapsed())
    });
    let mut slowest = std::time::Duration::ZERO;
    for (s, took) in futures_util::future::join_all(reads).await {
        assert_eq!(s, StatusCode::OK);
        slowest = slowest.max(took);
    }
    println!(
        "8 concurrent reads: slowest {slowest:?}, all done in {:?}",
        t.elapsed()
    );
    // While the fetches run: how many connections are out, and how long a read and an add take.
    for round in 0..25 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let pool = &fx.app.pool;
        let out = pool.size() as usize - pool.num_idle();
        let t = Instant::now();
        let get = format!("/api/v1/projects/{id}");
        let (s, _) = send(&fx.app, req(Method::GET, &get, Some(&fx.dev), None)).await;
        println!(
            "round {round}: {out} of {} connections out; get project {:?} ({s})",
            pool.size(),
            t.elapsed()
        );
    }
    let t = Instant::now();
    let uri = format!("/api/v1/projects/{id}/repos");
    let body = json!({"name": "late", "default_branch": "main",
                      "remote_url": "https://github.com/acme/late.git"});
    let (s, v) = send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), Some(body))).await;
    println!(
        "add_repo with 20 fetches in flight: {:?} ({s})",
        t.elapsed()
    );
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// The app polls the project list: several readers at once, each wanting a mirror row per repo,
/// must not wait on each other for pool connections (a reader that held one while asking for a
/// second starved the 4-connection pool until the 30 s acquire timeout).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_project_reads_do_not_starve_the_pool() {
    let fx = fx().await;
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/projects",
            Some(&fx.dev),
            Some(json!({"slug": "big", "name": "Big"})),
        ),
    )
    .await;
    let id = r.1["id"].as_i64().unwrap();
    for i in 0..6 {
        sqlx::query(
            "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, \
             is_primary) VALUES (?, ?, ?, 'main', ?)",
        )
        .bind(id)
        .bind(format!("r{i}"))
        .bind(format!("https://github.com/acme/r{i}.git"))
        .bind(i == 0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    }
    let get = format!("/api/v1/projects/{id}");
    let reads = (0..12).map(|_| send(&fx.app, req(Method::GET, &get, Some(&fx.dev), None)));
    let all = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        futures_util::future::join_all(reads),
    )
    .await
    .expect("the reads waited on each other for pool connections");
    assert!(all.iter().all(|(s, _)| *s == StatusCode::OK));
}
