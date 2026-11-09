//! The routes that decide where the server sends a credential (S6): a repo's forge names a
//! broker secret and an API URL on the call policy's allow-list, the operator adds hosts for
//! self-hosted forges, and a project's Linear link; every write is a step-up route and the
//! reads stay `admin`.

mod common;
mod gov_seed;

use axum::http::{Method, StatusCode};
use common::*;
use gov_seed::*;
use serde_json::{Value, json};

fn step_up_required(r: &(StatusCode, Value)) -> bool {
    r.0 == StatusCode::FORBIDDEN && r.1["code"] == "step_up_required"
}

fn repo(secret: Value, api: Value, token_file: &str) -> Value {
    json!({"name": "app", "url": "https://example.test/acme/app.git",
           "forge": {"kind": "github", "repo": "acme/app", "secret_name": secret,
                     "api_url": api, "token_file": token_file}})
}

#[tokio::test]
async fn a_repos_forge_names_a_broker_secret_and_an_allowed_host() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let uri = format!("/projects/{}/repos", s.project.0);
    let post = |body: Value| call(&fx, Some(&fx.dev), Method::POST, &uri, Some(body));
    // Refused: a token file, no secret, a secret outside the module, a host off the list.
    for (why, body) in [
        (
            "token file",
            repo(json!("citadel.forge.token"), Value::Null, "/etc/token"),
        ),
        ("no secret", repo(Value::Null, Value::Null, "")),
        (
            "platform secret",
            repo(json!("git.deploy"), Value::Null, ""),
        ),
        (
            "path-like secret",
            repo(json!("citadel/../x"), Value::Null, ""),
        ),
        (
            "unlisted host",
            repo(
                json!("citadel.forge.token"),
                json!("https://git.example.test/api"),
                "",
            ),
        ),
        (
            "loopback",
            repo(
                json!("citadel.forge.token"),
                json!("https://127.0.0.1/"),
                "",
            ),
        ),
        (
            "metadata",
            repo(
                json!("citadel.forge.token"),
                json!("https://169.254.169.254/"),
                "",
            ),
        ),
        (
            "http",
            repo(
                json!("citadel.forge.token"),
                json!("http://api.github.com"),
                "",
            ),
        ),
    ] {
        let r = post(body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {r:?}");
    }
    // A provider account's secret is not a forge's, whatever it is called.
    sqlx::query("INSERT INTO citadel_accounts (harness, label, secret_name) VALUES ('claude', 'a', 'citadel.forge.acct')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let r = post(repo(json!("citadel.forge.acct"), Value::Null, "")).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "account secret: {r:?}");
    // The public host with a broker secret is accepted, and the secret (never a path) comes back.
    let r = post(repo(json!("citadel.forge.token"), Value::Null, "")).await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(r.1["forge"]["secret_name"], "citadel.forge.token");
    assert_eq!(r.1["forge"]["token_file"], "");
    // A self-hosted forge needs its host added first, by the operator.
    let host = "/forge/hosts/git.example.test";
    let r = call(&fx, Some(&fx.dev), Method::PUT, host, None).await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(r.1["added"], json!(["git.example.test"]));
    let mut body = repo(
        json!("citadel.forge.token"),
        json!("https://git.example.test/api/v4"),
        "",
    );
    body["name"] = json!("self");
    body["url"] = json!("https://example.test/acme/self.git");
    assert_eq!(post(body).await.0, StatusCode::OK);
    let r = call(&fx, Some(&fx.dev), Method::DELETE, host, None).await;
    assert_eq!(r.1["added"], json!([]));
}

#[tokio::test]
async fn a_host_must_be_a_public_looking_name() {
    let fx = fx().await;
    for bad in [
        "127.0.0.1",
        "2130706433",
        "localhost",
        "intranet.local",
        "Git.Example.Test",
        "a..b",
        "nodot",
    ] {
        let r = call(
            &fx,
            Some(&fx.dev),
            Method::PUT,
            &format!("/forge/hosts/{bad}"),
            None,
        )
        .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad}: {r:?}");
    }
    let hosts = call(&fx, Some(&fx.dev), Method::GET, "/forge/hosts", None).await;
    assert_eq!(hosts.1["added"], json!([]));
}

#[tokio::test]
async fn linear_links_and_forge_hosts_are_step_up_and_admin_only() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "AAA").await;
    let link = format!("/projects/{}/linear", s.project.0);
    let body = json!({"team_id": "team-1", "secret_name": "citadel.linear.key"});
    let laptop = enroll(&fx.app, "laptop", &["admin"], true).await;
    let phone = enroll(&fx.app, "phone", &["read", "approve"], true).await;
    for (m, path, b) in [
        (Method::PUT, link.as_str(), Some(body.clone())),
        (Method::DELETE, link.as_str(), None),
        (Method::PUT, "/forge/hosts/git.example.test", None),
        (Method::DELETE, "/forge/hosts/git.example.test", None),
    ] {
        let r = call(&fx, Some(&laptop), m.clone(), path, b.clone()).await;
        assert!(step_up_required(&r), "{m} {path}: {r:?}");
        let r = call(&fx, Some(&phone), m.clone(), path, b).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{m} {path}: {r:?}");
        assert_eq!(r.1["code"], "forbidden_scope");
    }
    // The reads show where credentials go: admin only.
    for path in [link.as_str(), "/forge/hosts"] {
        let r = call(&fx, Some(&phone), Method::GET, path, None).await;
        assert_eq!(
            (r.0, &r.1["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden_scope")),
            "{path}"
        );
    }

    // Elevated: set, read back, refuse a bad secret or a host off the list, remove.
    let r = call(&fx, Some(&fx.dev), Method::PUT, &link, Some(body.clone())).await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(r.1["secret_name"], "citadel.linear.key");
    assert_eq!(r.1["api_url"], "https://api.linear.app/graphql");
    for bad in [
        json!({"team_id": "t", "secret_name": "git.deploy"}),
        json!({"team_id": "t", "secret_name": "citadel.forge.token"}),
        json!({"team_id": "t", "secret_name": "citadel.linear.key", "api_url": "https://evil.example/graphql"}),
        json!({"team_id": "t", "secret_name": "citadel.linear.key", "api_url": "https://127.0.0.1/graphql"}),
        json!({"team_id": "t", "secret_name": "citadel.linear.key", "token_file": "/etc/t"}),
    ] {
        let r = call(&fx, Some(&fx.dev), Method::PUT, &link, Some(bad.clone())).await;
        assert!(r.0.is_client_error(), "{bad}: {r:?}");
    }
    let r = call(&fx, Some(&fx.dev), Method::GET, &link, None).await;
    assert_eq!(
        r.1["team_id"], "team-1",
        "a refused change left the link alone"
    );
    assert_eq!(
        call(&fx, Some(&fx.dev), Method::DELETE, &link, None)
            .await
            .1,
        json!(true)
    );
    assert_eq!(
        call(&fx, Some(&fx.dev), Method::GET, &link, None).await.0,
        StatusCode::NOT_FOUND
    );
}
