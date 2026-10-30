//! Step-up and input checks the security review asked for (PR #47 F1, F3, F7), through the
//! Core's gate: an unelevated phone cannot widen spend, set runner commands or apply a profile
//! proposal, and a repo body cannot carry a control character, a `..` path or a loopback URL.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};

fn step_up_required(r: &(StatusCode, Value)) -> bool {
    r.0 == StatusCode::FORBIDDEN && r.1["code"] == "step_up_required"
}

/// F1: `decide` no longer takes a raise; the raise route needs a step-up even for an `approve`
/// device, and a plain decision still does not.
#[tokio::test]
async fn a_budget_raise_needs_a_step_up_and_decide_refuses_one() {
    let fx = fx().await;
    let phone = enroll(&fx.app, "phone", &["read", "approve"], true).await;
    let raise = json!({"raise_tokens": 1_000_000});
    let r = call(
        &fx,
        Some(&phone),
        Method::POST,
        "/approvals/1/raise",
        Some(raise.clone()),
    )
    .await;
    assert!(step_up_required(&r), "{r:?}");
    // A decision with a raise is a 400 for anyone; the elevated admin too.
    for dev in [&phone, &fx.dev] {
        let body = json!({"approve": true, "raise_tokens": 5});
        let (s, b) = call(
            &fx,
            Some(dev),
            Method::POST,
            "/approvals/1/decide",
            Some(body),
        )
        .await;
        assert_eq!(
            (s, &b["code"]),
            (StatusCode::BAD_REQUEST, &json!("bad_request")),
            "{b}"
        );
    }
    // A plain decision passes the gate (404: no such approval), no step-up needed.
    let (s, _) = call(
        &fx,
        Some(&phone),
        Method::POST,
        "/approvals/1/decide",
        Some(json!({"approve": false})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // The elevated admin reaches the raise (404: no such approval).
    let (s, _) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/approvals/1/raise",
        Some(raise),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A device with `read` only cannot even try.
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let (s, b) = call(
        &fx,
        Some(&reader),
        Method::POST,
        "/approvals/1/raise",
        Some(json!({"raise_tokens": 1})),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
}

/// F3 + F7: the routes that set runner commands, a forge secret and a forge URL, and the one that
/// applies a profile proposal, are step-up routes.
#[tokio::test]
async fn repo_writes_and_profile_proposals_need_a_step_up() {
    let fx = fx().await;
    let admin_no_elevation = enroll(&fx.app, "laptop", &["admin"], true).await;
    let repo = json!({"name": "app", "url": "git@example.test:a/app.git"});
    for (m, path, body) in [
        (Method::POST, "/projects/1/repos", Some(repo.clone())),
        (Method::PUT, "/repos/1", Some(repo.clone())),
        (
            Method::POST,
            "/projects/1/profile/proposals/1/decision",
            Some(json!({"accept": true})),
        ),
        (Method::POST, "/knowledge/1/accept", Some(json!({}))),
    ] {
        let r = call(&fx, Some(&admin_no_elevation), m.clone(), path, body).await;
        assert!(step_up_required(&r), "{m} {path}: {r:?}");
    }
}

/// F3: a repo body that cannot be right is a 400 before anything is written, for a create and
/// an update, even from the elevated admin.
#[tokio::test]
async fn a_repo_body_with_a_bad_command_path_or_url_is_refused() {
    let fx = fx().await;
    let base = |f: Value, c: Value| json!({"name": "app", "url": "git@example.test:a/app.git", "forge": f, "commands": c});
    let forge = |token: &str, api: Option<&str>| json!({"kind": "github", "repo": "a/app", "secret_name": token, "api_url": api});
    let ok_forge = forge("citadel.forge", None);
    let none = json!({});
    let bad = [
        base(ok_forge.clone(), json!({"build": "make\nrm -rf /"})),
        base(ok_forge.clone(), json!({"test": "a\u{0}b"})),
        base(ok_forge.clone(), json!({"lint": "x".repeat(3000)})),
        base(forge("relative/token", None), none.clone()),
        base(forge("git.deploy", None), none.clone()),
        base(
            forge("citadel.forge", Some("http://127.0.0.1:9/")),
            none.clone(),
        ),
        base(
            forge("citadel.forge", Some("https://localhost/")),
            none.clone(),
        ),
        base(
            forge("citadel.forge", Some("http://169.254.169.254/latest")),
            none.clone(),
        ),
        base(
            forge("citadel.forge", Some("https://u:p@host.example/")),
            none.clone(),
        ),
        base(
            forge("citadel.forge", Some("ftp://host.example/")),
            none.clone(),
        ),
        base(
            forge("citadel.forge", Some("https://host.example/?x=1")),
            none.clone(),
        ),
    ];
    for body in &bad {
        for (m, path) in [
            (Method::POST, "/projects/1/repos"),
            (Method::PUT, "/repos/1"),
        ] {
            let (s, b) = call(&fx, Some(&fx.dev), m.clone(), path, Some(body.clone())).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{m} {path} {body}: {b}");
        }
    }
    // A sane body gets past validation (404: no such project).
    let good = base(forge("citadel.forge", None), json!({"build": "make"}));
    let (s, _) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/projects/1/repos",
        Some(good),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
