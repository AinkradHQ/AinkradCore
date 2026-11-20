//! The project's main copy (`<ws>/p/<id>/main`): cloned from the Core's copy on first need, once.

use serde_json::json;

use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};
use crate::workspace::paths::Workspace;

#[tokio::test]
async fn main_is_cloned_on_first_need_and_a_project_without_a_repo_is_named() {
    let mut fx = fx().await;
    let dir = tmp("main");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, head) = remote(&dir);
    let ws = Workspace::new(dir.join("ws"));
    std::fs::create_dir_all(ws.root()).unwrap();
    let mk = |slug: &'static str| {
        req(
            Method::POST,
            "/api/v1/projects",
            Some(&fx.dev),
            Some(json!({"slug": slug, "name": slug})),
        )
    };
    let id = send(&fx.app, mk("shop")).await.1["id"].as_i64().unwrap();
    let bare = send(&fx.app, mk("bare")).await.1["id"].as_i64().unwrap();
    let err = crate::mirrors::main_copy_for_test(&fx.app, &ws, bare)
        .await
        .unwrap_err();
    assert!(err.contains("has no repo"), "{err}");
    assert!(!ws.project_main(bare).exists());
    sqlx::query(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, 'web', ?, 'main', 1)",
    )
    .bind(id)
    .bind(path.to_str().unwrap())
    .execute(&fx.app.pool)
    .await
    .unwrap();
    // Two at once: the per-project lock makes one clone, the other finds it.
    let (a, b) = tokio::join!(
        crate::mirrors::main_copy_for_test(&fx.app, &ws, id),
        crate::mirrors::main_copy_for_test(&fx.app, &ws, id)
    );
    let main = a.unwrap();
    assert_eq!(main, b.unwrap());
    assert_eq!(main, ws.project_main(id));
    assert_eq!(std::fs::read_to_string(main.join("a.txt")).unwrap(), "one");
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(args)
            .current_dir(&main)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    };
    assert_eq!(git(&["rev-parse", "HEAD"]), head);
    assert_eq!(
        git(&["remote", "get-url", "origin"]),
        path.to_str().unwrap()
    );
    assert!(!main.with_extension("cloning").exists());
    // Already there: kept as it is (local work survives).
    std::fs::write(main.join("wip.txt"), "mine").unwrap();
    crate::mirrors::main_copy_for_test(&fx.app, &ws, id)
        .await
        .unwrap();
    assert!(main.join("wip.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
