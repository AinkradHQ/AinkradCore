//! Drafting a run spec from a project repo's files (P4-03): read from the Core's copy, saved as a
//! new version with the converter as origin, `admin` scope, never run.

use serde_json::{Value, json};

use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};

fn git(dir: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
}

/// An app with a project `shop` whose repo `web` has a `package.json` (not fetched yet).
async fn shop() -> (Fx, i64, i64) {
    let mut fx = fx().await;
    let dir = tmp("draft");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, _) = remote(&dir);
    std::fs::write(
        path.join("package.json"),
        r#"{"scripts":{"start":"node app.js --port 3100"}}"#,
    )
    .unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-q", "-m", "app"]);
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/projects",
            Some(&fx.dev),
            Some(json!({"slug": "shop", "name": "Shop"})),
        ),
    )
    .await;
    let id = r.1["id"].as_i64().unwrap();
    let repo: i64 = sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, 'web', ?, 'main', 1) RETURNING id",
    )
    .bind(id)
    .bind(path.to_str().unwrap())
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    (fx, id, repo)
}

async fn post(fx: &Fx, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    send(&fx.app, req(Method::POST, uri, Some(&fx.dev), body)).await
}

#[tokio::test]
async fn a_package_json_in_the_core_copy_is_drafted_and_saved_with_its_origin() {
    let (fx, id, repo) = shop().await;
    let uri = format!("/api/v1/projects/{id}/run/spec/draft");

    // Nothing is read before a fetch has made the copy.
    let r = post(&fx, &uri, None).await;
    assert_eq!(r.0, StatusCode::CONFLICT, "{}", r.1);
    let f = post(
        &fx,
        &format!("/api/v1/projects/{id}/repos/{repo}/fetch"),
        None,
    )
    .await;
    assert_eq!(f.0, StatusCode::OK, "{}", f.1);

    let r = post(&fx, &uri, None).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(r.1["file"], "package.json");
    assert_eq!(r.1["repo"], "web");
    assert_eq!(r.1["version"]["version"], 1);
    assert_eq!(r.1["version"]["origin"], "package_json");
    assert_eq!(
        r.1["version"]["spec"]["services"]["app"]["ports"][0]["port"],
        3100
    );

    // It is the project's latest spec, as the app's Run page reads it.
    let g = send(
        &fx.app,
        req(
            Method::GET,
            &format!("/api/v1/projects/{id}/spec"),
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(g.1["origin"], "package_json", "{}", g.1);

    // A Makefile that is not there, and paths that leave the repo or are not drafts, are refused.
    let r = post(
        &fx,
        &uri,
        Some(json!({"file": "Makefile", "image": "debian:stable-slim"})),
    )
    .await;
    assert_eq!(r.1["code"], "could_not_draft", "{}", r.1);
    for file in ["../package.json", "/etc/passwd", "a.txt", "sub//run.sh"] {
        let r = post(&fx, &uri, Some(json!({"file": file}))).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{file}: {}", r.1);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_project_run_specs")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}
