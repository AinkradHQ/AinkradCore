//! The org_admin routes end to end through the Core's gate (ported from the monolith's
//! `api/v1/tests/{avatars,routing,companies}.rs`): avatars and logos, per-task routing, several
//! companies and the company scope.
//!
//! Seed data: the monolith's `seed` ran an agent through the run engine; here an active agent is
//! the raw writer's (`store::org::create_agent`, the `test-support` feature).
#![allow(dead_code, unused_imports)]

mod common;

use ainkrad_core_server::api::router;
use ainkrad_core_server::api::v1::BY;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use citadel_module::domain::ops::{NewChainPreset, NewRole};
use citadel_module::domain::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::store::org;
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0";
const WEBP: &[u8] = b"RIFF\x1a\0\0\0WEBPVP8L\x0d\0\0\0\x2f\0\0\0\x10\x07\x10\x11\x11";

async fn api(fx: &Fx, m: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), m, path, body).await
}

async fn get(fx: &Fx, path: &str) -> (StatusCode, Value) {
    api(fx, Method::GET, path, None).await
}

async fn post(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    api(fx, Method::POST, path, Some(body)).await
}

async fn put(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    api(fx, Method::PUT, path, Some(body)).await
}

async fn ok(fx: &Fx, path: &str) -> Value {
    let (status, body) = get(fx, path).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

async fn ok_post(fx: &Fx, path: &str, body: Value) -> Value {
    let (status, got) = post(fx, path, body).await;
    assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
    got
}

/// A raw request: `body` as `ct` (if any), working in `company` (if any).
async fn raw(
    fx: &Fx,
    method: Method,
    path: &str,
    body: &[u8],
    ct: Option<&str>,
    company: Option<i64>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    if let Some(c) = company {
        b = b.header("x-citadel-company", c.to_string());
    }
    for (name, value) in fx.dev.headers(method.as_str(), &uri, body) {
        b = b.header(name, value);
    }
    if let Some(ct) = ct {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let body = to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec();
    (status, headers, body)
}

async fn company(fx: &Fx, name: &str) -> CompanyId {
    org::create_company(&fx.app.pool, name).await.unwrap().id
}

async fn agent(fx: &Fx, company: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id: company,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    org::create_agent(&fx.app.pool, &a).await.unwrap().id
}

/// A project of the company (raw: the work slices own the writers).
async fn project(fx: &Fx, company: CompanyId, key: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO citadel_projects (company_id, name, key, mode, sprint_approval) \
         VALUES (?, 'P', ?, 'kanban', 'owner') RETURNING id",
    )
    .bind(company.0)
    .bind(key)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

// --- avatars.rs -----------------------------------------------------------------------------

#[tokio::test]
async fn appearance_is_listed_changed_and_drawn_until_an_image_is_uploaded() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let palettes = ok(&fx, "/avatars/palettes").await;
    assert_eq!(palettes.as_array().unwrap().len(), 17);
    assert_eq!(palettes[16], json!({"id": "steel", "name": "Steel"}));

    let uri = format!("/agents/{id}");
    let one = ok(&fx, &uri).await;
    assert_eq!(one["appearance"]["figure_version"], "v1");
    assert!(one["appearance"]["palette_id"].is_string());
    assert!(one["avatar_url"].is_null(), "no image: draw the figure");

    let set = |body: Value| {
        let path = format!("{uri}/appearance");
        let fx = &fx;
        async move { put(fx, &path, body).await }
    };
    let (status, got) = set(json!({"palette_id": "ember"})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["appearance"],
        json!({"figure_version": "v1", "palette_id": "ember"})
    );
    assert_eq!(
        set(json!({"palette_id": "muted"})).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, _) = set(json!({"palette_id": "aurora", "figure_version": "v9"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let chart = ok(&fx, &format!("/companies/{}/agents", a.0)).await;
    assert_eq!(chart[0]["appearance"]["palette_id"], "ember");
}

// The image upload and its download need the artifacts slice's blob store (S5): the routes are
// not built, so the test is the monolith's, adapted only where a Core call it used is gone.
#[tokio::test]
async fn an_uploaded_image_is_checked_served_safely_and_reset() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let uri = format!("/agents/{id}/avatar");
    let (status, _, _) = raw(&fx, Method::GET, &uri, b"", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no image yet");

    let put_img =
        |body: &'static [u8], ct: Option<&'static str>| raw(&fx, Method::PUT, &uri, body, ct, None);
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    let refused: [(&[u8], Option<&str>, StatusCode); 6] = [
        (
            svg,
            Some("image/svg+xml"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (svg, Some("image/png"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            b"<html><script>x</script>",
            None,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            b"<html>",
            Some("text/html"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (PNG, Some("image/webp"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            b"GIF89a......",
            Some("application/octet-stream"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ];
    for (body, ct, want) in refused {
        let (status, _, got) = put_img(body, ct).await;
        let got: Value = serde_json::from_slice(&got).unwrap_or_default();
        assert_eq!(status, want, "{ct:?}: {got}");
    }

    let (status, _, got) = put_img(WEBP, Some("image/webp")).await;
    assert_eq!(status, StatusCode::OK);
    let got: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(got["avatar_url"], format!("{BASE}{uri}"));
    let (status, _, got) = put_img(PNG, Some("image/png")).await;
    assert_eq!(status, StatusCode::OK);
    let one: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(one["avatar_url"], format!("{BASE}{uri}"));

    let (status, h, body) = raw(&fx, Method::GET, &uri, b"", None, None).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, PNG));
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::CACHE_CONTROL], "private, no-cache");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    // The monolith compared the ETag with `artifacts::sha256_hex(PNG)`; that helper is S5's.
    let etag = h[header::ETAG].to_str().unwrap().to_owned();
    assert!(etag.starts_with('"') && etag.len() == 66, "{etag}");
    let (status, _, got) = raw(&fx, Method::DELETE, &uri, b"", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let got: Value = serde_json::from_slice(&got).unwrap();
    assert!(got["avatar_url"].is_null());
    let (status, _, _) = raw(&fx, Method::GET, &uri, b"", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The monolith also set `avatar.max_bytes` per company through the settings API and checked
    // a 413; the module's setting is server-wide (`module.citadel.avatar.max_bytes`): S5 adds it.
}

#[tokio::test]
async fn another_companys_avatars_are_refused() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let b_agent = agent(&fx, b, "B dev").await;
    let uri = format!("/agents/{}/avatar", b_agent.0);
    // GET and PUT are not built (S5); DELETE is, and a method with no route is not a 404 of
    // the scope, so only the built one is walked.
    let (status, _, _) = raw(&fx, Method::DELETE, &uri, b"", None, Some(a.0)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "DELETE as A");
    let one = ok(&fx, &format!("/agents/{}", b_agent.0)).await;
    assert!(one["avatar_url"].is_null(), "nothing was uploaded as A");
}

#[tokio::test]
async fn the_figure_shows_what_the_agent_is_doing() {
    let fx = fx().await;
    let pool = fx.app.pool.clone();
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let p = project(&fx, a, "AAA").await;
    let issue: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_issues (project_id, number, kind, title, state, next_agent_id, rank) \
         VALUES (?, 1, 'task', 'work', 'todo', ?, 1.0) RETURNING id",
    )
    .bind(p)
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let uri = format!("/agents/{id}");
    let state = || async { ok(&fx, &uri).await["figure_state"].clone() };
    let sql = |q: &'static str| {
        let pool = pool.clone();
        async move { sqlx::query(q).execute(&pool).await.unwrap() }
    };

    // Adapted: with no run engine (S7) the figure is idle, listening, sleepy or at rest; the
    // thinking, working, loading, confused and success states need runs.
    assert_eq!(state().await, "idle");
    sqlx::query(
        "INSERT INTO citadel_questions (issue_id, agent_id, question) VALUES (?, ?, 'Which?')",
    )
    .bind(issue)
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(state().await, "listening", "waiting on the admin");
    sql("UPDATE citadel_questions SET state = 'cancelled'").await;
    assert_eq!(state().await, "idle");
    sql("UPDATE citadel_agents SET status = 'paused'").await;
    assert_eq!(state().await, "sleepy");
    sql("UPDATE citadel_agents SET status = 'terminated'").await;
    assert_eq!(state().await, "rest");
    let chart = ok(&fx, &format!("/companies/{}/org", a.0)).await;
    assert_eq!(chart["agents"][0]["figure_state"], "rest");
}

#[tokio::test]
#[ignore = "not ported yet: the thinking/working/loading/confused/success figure states read runs"]
async fn the_figure_shows_a_runs_state() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let state = ok(&fx, &format!("/agents/{id}")).await["figure_state"].clone();
    assert_eq!(state, "thinking", "running, no output yet");
}

#[tokio::test]
async fn a_company_logo_is_reset_and_audited() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let uri = format!("/companies/{}/logo", a.0);
    sqlx::query("UPDATE citadel_companies SET logo_sha256 = ? WHERE id = ?")
        .bind("a".repeat(64))
        .bind(a.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let listed = ok(&fx, "/companies").await;
    assert!(listed[0]["logo_url"].is_string());
    let (status, got) = api(&fx, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(got["logo_url"].is_null());
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'citadel.company.logo%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["citadel.company.logo_reset"]);
    assert_eq!(
        api(&fx, Method::DELETE, "/companies/99/logo", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_company_logo_follows_the_avatar_rules() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let uri = format!("/companies/{}/logo", a.0);
    let (status, _, _) = raw(&fx, Method::GET, &uri, b"", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no logo yet");
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
    let r = raw(&fx, Method::PUT, &uri, svg, Some("image/svg+xml"), None).await;
    assert_eq!(r.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, _, got) = raw(&fx, Method::PUT, &uri, PNG, Some("image/png"), None).await;
    assert_eq!(status, StatusCode::OK);
    let c: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(c["logo_url"], format!("{BASE}{uri}"));
    let (status, _, body) = raw(&fx, Method::GET, &uri, b"", None, None).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, PNG));
    let (status, _, got) = raw(&fx, Method::DELETE, &uri, b"", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let c: Value = serde_json::from_slice(&got).unwrap();
    assert!(c["logo_url"].is_null());
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'citadel.company.logo%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        ["citadel.company.logo_set", "citadel.company.logo_reset"]
    );
}

// --- routing.rs -----------------------------------------------------------------------------

#[tokio::test]
async fn tiers_and_rules_are_read_and_replaced() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let id = agent(&fx, a, "A dev").await.0;
    let p = project(&fx, a, "AAA").await;
    let uri = format!("/agents/{id}/tiers");
    assert_eq!(ok(&fx, &uri).await, json!([]));
    let tiers = json!([{"tier": "small", "harness": "opencode", "model": "opencode/mini"}]);
    let (status, set) = put(&fx, &uri, tiers.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set, tiers);
    let standard = json!([{"tier": "standard", "harness": "opencode", "model": "x"}]);
    assert_eq!(put(&fx, &uri, standard).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        put(&fx, "/agents/999/tiers", json!([])).await.0,
        StatusCode::NOT_FOUND
    );

    let rules_uri = format!("/projects/{p}/tier-rules");
    let defaults = ok(&fx, &rules_uri).await;
    assert_eq!(defaults["defaults"], true);
    assert_eq!(
        defaults["rules"][0],
        json!({"rule": "label:chore", "tier": "small"})
    );
    let rules = json!([{"rule": "kind:bug", "tier": "large"}]);
    let (status, set) = put(&fx, &rules_uri, rules.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set, json!({"rules": rules, "defaults": false}));
    let bad = json!([{"rule": "chore", "tier": "small"}]);
    assert_eq!(put(&fx, &rules_uri, bad).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "not ported yet: getTaskCosts is a cost report (a run's tier is tested in detectors.rs)"]
async fn a_run_shows_its_tier_and_tasks_are_reported() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let run = ok(&fx, "/runs/1").await;
    assert_eq!(run["tier"], "standard", "an unestimated task");
    let tasks = ok(&fx, &format!("/companies/{}/costs/tasks", a.0)).await;
    assert_eq!(tasks[0]["key"], "AAA-1");
    assert_eq!(tasks[0]["runs"], 1);
    assert_eq!(tasks[0]["tier"], "standard");
    let later = format!(
        "/companies/{}/costs/tasks?since=2099-01-01T00:00:00.000Z",
        a.0
    );
    assert_eq!(ok(&fx, &later).await, json!([]));
    let bad = format!("/companies/{}/costs/tasks?since=soon", a.0);
    assert_eq!(get(&fx, &bad).await.0, StatusCode::BAD_REQUEST);
}
