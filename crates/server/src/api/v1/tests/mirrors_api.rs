//! The Core's repo copies (P3-01): "Fetch now", and serving them to runners: only the upload
//! side, only to a `runner` device, two clones at once, never a push.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use serde_json::{Value, json};

use super::*;
use crate::mirrors::Mirrors;
use crate::mirrors::tests::{remote, tmp};
use crate::ops::secretbox::SecretBox;
use crate::store::connections::grants::{self, Limits as Wall, NewGrant};
use crate::store::connections::{NewConnection, Who, create};

/// An app with a mirrors dir, a project `shop` and a repo whose remote is a local fixture.
async fn shop() -> (Fx, i64, i64, String, std::path::PathBuf) {
    let mut fx = fx().await;
    let dir = tmp("api");
    fx.app.mirrors = Some(Arc::new(Mirrors::new(dir.join("mirrors"))));
    let (path, head) = remote(&dir);
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
    // The API only takes https and ssh remotes; a fixture is put in directly.
    let repo: i64 = sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, 'web', ?, 'main', 1) RETURNING id",
    )
    .bind(id)
    .bind(path.to_str().unwrap())
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    (fx, id, repo, head, dir)
}

async fn fetch(fx: &Fx, dev: &TestDevice, id: i64, repo: i64) -> (StatusCode, Value) {
    let uri = format!("/api/v1/projects/{id}/repos/{repo}/fetch");
    send(&fx.app, req(Method::POST, &uri, Some(dev), None)).await
}

/// A signed git request; the answer's status, content type and bytes.
async fn raw(
    fx: &Fx,
    dev: Option<&TestDevice>,
    m: Method,
    uri: &str,
    body: &[u8],
) -> (StatusCode, String, Vec<u8>) {
    let mut b = Request::builder()
        .method(m.clone())
        .uri(uri)
        .header(header::HOST, HOST);
    if let Some(dev) = dev {
        for (n, v) in dev.headers(m.as_str(), uri, body) {
            b = b.header(n, v);
        }
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    let (status, ct) = (
        res.status(),
        res.headers()
            .get(header::CONTENT_TYPE)
            .map_or(String::new(), |v| v.to_str().unwrap().to_owned()),
    );
    (
        status,
        ct,
        to_bytes(res.into_body(), 1 << 24).await.unwrap().to_vec(),
    )
}

fn want(sha: &str) -> Vec<u8> {
    format!("0032want {sha}\n00000009done\n").into_bytes()
}

#[tokio::test]
async fn fetch_now_records_the_head_and_a_dead_remote_keeps_the_older_one() {
    let (fx, id, repo, head, dir) = shop().await;
    let r = fetch(&fx, &fx.dev, id, repo).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(r.1["repos"][0]["mirror"]["head"], head.as_str());
    assert!(r.1["repos"][0]["mirror"]["error"].is_null());
    std::fs::rename(dir.join("remote"), dir.join("gone")).unwrap();
    let r = fetch(&fx, &fx.dev, id, repo).await;
    assert_eq!(
        r.0,
        StatusCode::OK,
        "a failed fetch is a state, not an error"
    );
    let m = &r.1["repos"][0]["mirror"];
    assert_eq!(m["head"], head.as_str(), "older head kept");
    assert!(m["error"].as_str().is_some_and(|e| !e.is_empty()));
    // Who may, and what it is not.
    let phone = fx.enroll("phone", &["read"]).await;
    assert_eq!(fetch(&fx, &phone, id, repo).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        fetch(&fx, &fx.dev, id, repo + 99).await.0,
        StatusCode::NOT_FOUND
    );
    let mut off = fx.app.clone();
    off.mirrors = None;
    let r = send(
        &off,
        req(
            Method::POST,
            &format!("/api/v1/projects/{id}/repos/{repo}/fetch"),
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("mirrors_unavailable"))
    );
    let _ = send(
        &fx.app,
        req(
            Method::POST,
            &format!("/api/v1/projects/{id}/archive"),
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(fetch(&fx, &fx.dev, id, repo).await.0, StatusCode::CONFLICT);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_runner_clones_two_at_once_and_cannot_push_or_read_without_its_scope() {
    let (fx, id, repo, head, dir) = shop().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let vm2 = super::secrets::runner(&fx, "vm2").await;
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    crate::mirrors::grant_now(&fx.app, &vm2.id, repo).await;
    let refs = format!("/api/v1/mirrors/{repo}/info/refs?service=git-upload-pack");
    let pack = format!("/api/v1/mirrors/{repo}/git-upload-pack");
    // Nothing fetched yet.
    let r = raw(&fx, Some(&vm), Method::GET, &refs, b"").await;
    assert_eq!(r.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fetch(&fx, &fx.dev, id, repo).await.0, StatusCode::OK);

    let r = raw(&fx, Some(&vm), Method::GET, &refs, b"").await;
    assert_eq!(r.0, StatusCode::OK);
    assert_eq!(r.1, "application/x-git-upload-pack-advertisement");
    assert!(r.2.starts_with(b"001e# service=git-upload-pack\n0000"));
    assert!(String::from_utf8_lossy(&r.2).contains(&head));

    // Two runners clone at once, while a fetch runs too.
    let body = want(&head);
    let (a, b, c) = tokio::join!(
        raw(&fx, Some(&vm), Method::POST, &pack, &body),
        raw(&fx, Some(&vm2), Method::POST, &pack, &body),
        fetch(&fx, &fx.dev, id, repo),
    );
    for r in [a, b] {
        assert_eq!(r.0, StatusCode::OK);
        assert_eq!(r.1, "application/x-git-upload-pack-result");
        assert!(r.2.windows(4).any(|w| w == b"PACK"), "a pack");
    }
    assert_eq!(c.0, StatusCode::OK);

    // A push is refused to a runner, in both of git's steps, and nothing is written.
    let push_refs = format!("/api/v1/mirrors/{repo}/info/refs?service=git-receive-pack");
    let push = format!("/api/v1/mirrors/{repo}/git-receive-pack");
    let before = std::fs::read_dir(dir.join("mirrors").join(format!("{repo}.git")))
        .unwrap()
        .count();
    for r in [
        raw(&fx, Some(&vm), Method::GET, &push_refs, b"").await,
        raw(&fx, Some(&vm), Method::POST, &push, b"0000").await,
    ] {
        assert_eq!(r.0, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&r.2).contains("read_only"));
    }
    assert_eq!(
        std::fs::read_dir(dir.join("mirrors").join(format!("{repo}.git")))
            .unwrap()
            .count(),
        before
    );

    // Only the `runner` scope reads; unsigned is the plain 401; a bad service or repo is refused.
    let phone = fx.enroll("phone", &["read", "admin"]).await;
    for (m, uri) in [
        (Method::GET, &refs),
        (Method::POST, &pack),
        (Method::POST, &push),
    ] {
        assert_eq!(
            raw(&fx, Some(&phone), m.clone(), uri, b"").await.0,
            StatusCode::FORBIDDEN,
            "{uri}"
        );
        assert_eq!(
            raw(&fx, None, m, uri, b"").await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
    let bad = format!("/api/v1/mirrors/{repo}/info/refs?service=other");
    assert_eq!(
        raw(&fx, Some(&vm), Method::GET, &bad, b"").await.0,
        StatusCode::BAD_REQUEST
    );
    let none = "/api/v1/mirrors/999/info/refs?service=git-upload-pack";
    assert_eq!(
        raw(&fx, Some(&vm), Method::GET, none, b"").await.0,
        StatusCode::NOT_FOUND
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_token_comes_only_from_a_granted_github_connection_that_covers_the_repo() {
    let (fx, ..) = shop().await;
    let p = &fx.app.pool;
    let sealer = SecretBox::new(&[7; 32]);
    crate::store::settings::set(
        p,
        Key::SecretsMode,
        Scope::Server,
        "1",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    let reg = fx.app.connections.registry();
    let who = Who {
        workspace: 1,
        by_device: &fx.dev.id,
        actor: AuditActor::System,
        now: NOW,
    };
    let url = "https://github.com/acme/web.git";
    let token = |u: &'static str| crate::mirrors::token_for(p, reg, &sealer, 1, u, NOW);
    assert!(token(url).await.is_none(), "no connection: anonymous");
    let new = NewConnection {
        kind: "github",
        name: "gh",
        label: "GitHub",
        auth_method: "token",
    };
    let m = crate::connections::material::Material::new("gh1probe-7f3a9d41e0b2c8a6", None, None)
        .unwrap();
    let c = create(p, &sealer, reg, &new, &m, who).await.unwrap();
    assert!(
        token(url).await.is_none(),
        "a connection nobody is granted is not used"
    );
    let caps = vec!["read_repo".to_owned()];
    let limits: Wall = [("repos".to_owned(), vec!["acme/web".to_owned()])]
        .into_iter()
        .collect();
    let grant = NewGrant {
        grantee_kind: "role",
        grantee: "admin",
        capabilities: Some(&caps),
        limits: &limits,
    };
    grants::set(p, reg, c.id, &grant, who).await.unwrap();
    assert_eq!(
        token(url).await.as_deref().map(String::as_str),
        Some("gh1probe-7f3a9d41e0b2c8a6")
    );
    assert!(
        token("https://github.com/acme/other.git").await.is_none(),
        "outside the grant's repos"
    );
    assert!(
        token("https://gitlab.com/acme/web.git").await.is_none(),
        "another host"
    );
}

fn run(cmd: &mut std::process::Command) {
    assert!(cmd.status().unwrap().success());
}

#[tokio::test]
async fn a_removed_repo_is_gone_and_a_recycled_id_never_serves_the_old_objects() {
    let (fx, id, repo, old, dir) = shop().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    let refs = format!("/api/v1/mirrors/{repo}/info/refs?service=git-upload-pack");
    let pack = format!("/api/v1/mirrors/{repo}/git-upload-pack");
    let copy = dir.join("mirrors").join(format!("{repo}.git"));
    assert_eq!(fetch(&fx, &fx.dev, id, repo).await.0, StatusCode::OK);
    assert_eq!(
        raw(&fx, Some(&vm), Method::GET, &refs, b"").await.0,
        StatusCode::OK
    );
    // Kept aside, to put back as if the removal had not cleaned up.
    let aside = dir.join("aside.git");
    run(std::process::Command::new("cp")
        .arg("-R")
        .arg(&copy)
        .arg(&aside));

    let uri = format!("/api/v1/projects/{id}/repos/{repo}");
    let r = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert!(!copy.exists(), "the copy goes with the repo");
    for r in [
        raw(&fx, Some(&vm), Method::GET, &refs, b"").await,
        raw(&fx, Some(&vm), Method::POST, &pack, &want(&old)).await,
    ] {
        assert_eq!(r.0, StatusCode::NOT_FOUND);
    }

    // The id comes back for another repo whose remote cannot be reached, and the old copy is
    // still on disk: it is not served, and the failed fetch does not bring it back.
    run(std::process::Command::new("cp")
        .arg("-R")
        .arg(&aside)
        .arg(&copy));
    let gone = dir.join("nowhere");
    sqlx::query(
        "INSERT INTO core_project_repos (id, project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, ?, 'web', ?, 'main', 1)",
    )
    .bind(repo)
    .bind(id)
    .bind(gone.to_str().unwrap())
    .execute(&fx.app.pool)
    .await
    .unwrap();
    // The old lease named the old remote: it opens nothing of the recycled id.
    assert_eq!(
        raw(&fx, Some(&vm), Method::GET, &refs, b"").await.0,
        StatusCode::NOT_FOUND
    );
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    for r in [
        raw(&fx, Some(&vm), Method::GET, &refs, b"").await,
        raw(&fx, Some(&vm), Method::POST, &pack, &want(&old)).await,
    ] {
        assert_eq!(
            r.0,
            StatusCode::SERVICE_UNAVAILABLE,
            "never the old objects"
        );
    }
    let r = fetch(&fx, &fx.dev, id, repo).await;
    assert_eq!(r.0, StatusCode::OK);
    assert!(r.1["repos"][0]["mirror"]["error"].is_string());
    assert!(
        r.1["repos"][0]["mirror"]["head"].is_null(),
        "no head from the old repo"
    );
    let r = raw(&fx, Some(&vm), Method::GET, &refs, b"").await;
    assert_eq!(r.0, StatusCode::SERVICE_UNAVAILABLE);

    // Pointed at a repo that works: only its own objects.
    let dir2 = tmp("api2");
    let (remote2, _) = remote(&dir2);
    run(std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q"])
        .args(["--allow-empty", "-m", "unique"])
        .current_dir(&remote2)
        .env("GIT_CONFIG_GLOBAL", "/dev/null"));
    sqlx::query("UPDATE core_project_repos SET remote_url = ? WHERE id = ?")
        .bind(remote2.to_str().unwrap())
        .bind(repo)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    let r = fetch(&fx, &fx.dev, id, repo).await;
    let new = r.1["repos"][0]["mirror"]["head"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new, old);
    let r = raw(&fx, Some(&vm), Method::GET, &refs, b"").await;
    let text = String::from_utf8_lossy(&r.2).into_owned();
    assert!(text.contains(&new) && !text.contains(&old));
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

/// What `info/refs` and `git-upload-pack` answer `dev` for `repo`.
async fn read_both(fx: &Fx, dev: &TestDevice, repo: i64, body: &[u8]) -> (StatusCode, StatusCode) {
    let refs = format!("/api/v1/mirrors/{repo}/info/refs?service=git-upload-pack");
    let pack = format!("/api/v1/mirrors/{repo}/git-upload-pack");
    (
        raw(fx, Some(dev), Method::GET, &refs, b"").await.0,
        raw(fx, Some(dev), Method::POST, &pack, body).await.0,
    )
}

#[tokio::test]
async fn a_copy_is_served_only_to_a_device_with_a_live_lease_while_its_project_is_active() {
    let (fx, id, repo, head, dir) = shop().await;
    let (vm, other) = (
        super::secrets::runner(&fx, "vm").await,
        super::secrets::runner(&fx, "other").await,
    );
    assert_eq!(fetch(&fx, &fx.dev, id, repo).await.0, StatusCode::OK);
    let body = want(&head);
    let read = |dev| read_both(&fx, dev, repo, &body);
    // No lease: a runner reads nothing, and cannot tell it from a repo that does not exist.
    let none = raw(&fx, Some(&vm), Method::GET, "/api/v1/mirrors/999/info/refs?service=git-upload-pack", b"").await;
    assert_eq!(read(&vm).await, (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    assert_eq!(none.0, StatusCode::NOT_FOUND);

    // A lease is one device's and one repo's.
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    assert_eq!(read(&vm).await, (StatusCode::OK, StatusCode::OK));
    assert_eq!(read(&other).await, (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    let second: i64 = sqlx::query_scalar(
        "INSERT INTO core_project_repos (project_id, name, remote_url, default_branch, is_primary) \
         VALUES (?, 'api', ?, 'main', 0) RETURNING id",
    )
    .bind(id)
    .bind(dir.join("remote").to_str().unwrap())
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let r = raw(&fx, Some(&vm), Method::GET, &format!("/api/v1/mirrors/{second}/info/refs?service=git-upload-pack"), b"").await;
    assert_eq!(r.0, StatusCode::NOT_FOUND, "a lease for one repo opens no other");

    // It runs out.
    let mirrors = fx.app.mirrors.as_ref().unwrap();
    mirrors.grant(&vm.id, repo, &crate::mirrors::key(id, &dir.join("remote").to_string_lossy()), fx.app.clock.unix() - crate::mirrors::LEASE_SECS - 1);
    assert_eq!(read(&vm).await, (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));

    // An archived project's copy is closed, lease or not.
    crate::mirrors::grant_now(&fx.app, &vm.id, repo).await;
    assert_eq!(read(&vm).await, (StatusCode::OK, StatusCode::OK));
    let r = send(
        &fx.app,
        req(Method::POST, &format!("/api/v1/projects/{id}/archive"), Some(&fx.dev), None),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(read(&vm).await, (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    let _ = std::fs::remove_dir_all(dir);
}
