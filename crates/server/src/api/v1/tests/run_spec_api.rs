//! The run spec routes (P4-01): reading is `read`, a save is `admin` plus a step-up, a bad spec is
//! a 400 `invalid_spec` naming the field, and every save is a new version.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

async fn admin(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    call(fx, &fx.dev, m, uri, body).await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["code"].as_str().unwrap_or(""))
}

async fn shop(fx: &Fx) -> i64 {
    let r = admin(
        fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let id = r.1["id"].as_i64().unwrap();
    let repo = json!({"name": "web", "remote_url": "https://github.com/acme/web.git",
                      "default_branch": "main"});
    let r = admin(
        fx,
        Method::POST,
        &format!("/api/v1/projects/{id}/repos"),
        repo,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    crate::store::project_secrets::fixtures::seed(&fx.app.pool, id, &["db_password"]).await;
    id
}

fn spec() -> Value {
    json!({"services": {
        "db": {"image": "postgres:17", "env": {"POSTGRES_PASSWORD": "${secret:db_password}"}},
        "web": {"image": "node:22", "repo": "web", "depends_on": ["db"],
                "ports": [{"port": 3000, "expose": true}]}}})
}

#[tokio::test]
async fn reading_is_read_scope_and_a_save_needs_admin_and_a_step_up() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let plain = TestDevice::enroll(
        &fx.app.pool,
        "plain",
        "device",
        &["read", "admin"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let sess = fx.app.auth.issue_session(&plain.id, fx.clock.unix());
    plain.set_session(Some(sess.id));
    let id = shop(&fx).await;
    let uri = format!("/api/v1/projects/{id}/spec");
    let body = json!({"spec": spec()});
    let r = call(&fx, &phone, Method::PUT, &uri, body.clone()).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "forbidden_scope"));
    let r = call(&fx, &plain, Method::PUT, &uri, body).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "step_up_required"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_project_run_specs")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let saved = admin(&fx, Method::PUT, &uri, json!({"spec": spec()})).await;
    assert_eq!(saved.0, StatusCode::OK, "{}", saved.1);
    for u in [
        uri.clone(),
        format!("{uri}/versions"),
        format!("{uri}/versions/1"),
    ] {
        let r = call(&fx, &phone, Method::GET, &u, Value::Null).await;
        assert_eq!(r.0, StatusCode::OK, "{u}: {}", r.1);
    }
}

#[tokio::test]
async fn a_spec_is_saved_as_versions_listed_and_fetched() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let uri = format!("/api/v1/projects/{id}/spec");

    let none = admin(&fx, Method::GET, &uri, Value::Null).await;
    assert_eq!(code(&none), (StatusCode::NOT_FOUND, "not_found"));

    let v1 = admin(&fx, Method::PUT, &uri, json!({"spec": spec()})).await;
    assert_eq!(v1.0, StatusCode::OK, "{}", v1.1);
    assert_eq!(
        (v1.1["version"].as_i64(), v1.1["origin"].as_str()),
        (Some(1), Some("manual"))
    );
    assert_eq!(v1.1["spec"]["services"]["web"]["ports"][0]["port"], 3000);

    let mut two = spec();
    two["services"]["web"]["env"] = json!({"A": "1"});
    let v2 = admin(
        &fx,
        Method::PUT,
        &uri,
        json!({"spec": two, "origin": "compose"}),
    )
    .await;
    assert_eq!(v2.1["version"], 2, "{}", v2.1);

    let latest = admin(&fx, Method::GET, &uri, Value::Null).await.1;
    assert_eq!(latest["version"], 2);
    assert_eq!(latest["spec"]["services"]["web"]["env"]["A"], "1");
    let list = admin(&fx, Method::GET, &format!("{uri}/versions"), Value::Null)
        .await
        .1;
    assert_eq!(
        list.as_array()
            .unwrap()
            .iter()
            .map(|v| (
                v["version"].as_i64().unwrap(),
                v["origin"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        [(2, "compose"), (1, "manual")]
    );
    assert!(list[0].get("spec").is_none(), "a summary has no body");
    let old = admin(&fx, Method::GET, &format!("{uri}/versions/1"), Value::Null)
        .await
        .1;
    assert_eq!(old["spec"], v1.1["spec"]);
    let miss = admin(&fx, Method::GET, &format!("{uri}/versions/9"), Value::Null).await;
    assert_eq!(code(&miss), (StatusCode::NOT_FOUND, "not_found"));
    let nop = admin(&fx, Method::GET, "/api/v1/projects/999/spec", Value::Null).await;
    assert_eq!(code(&nop), (StatusCode::NOT_FOUND, "not_found"));
}

#[tokio::test]
async fn a_bad_spec_is_a_400_that_names_the_field_and_stores_nothing() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let uri = format!("/api/v1/projects/{id}/spec");
    let bad = [
        (
            json!({"spec": {"services": {"web": {"image": "node:22", "privileged": true}}}}),
            "privileged",
        ),
        (
            json!({"spec": {"services": {"web": {"image": "--privileged"}}}}),
            "services.web.image",
        ),
        (
            json!({"spec": {"services": {"web": {"image": "node:22", "ports": [{"port": 99999}]}}}}),
            "services.web.ports[0].port",
        ),
        (
            json!({"spec": {"services": {"web": {"image": "node:22", "env": {"K": "${nope}"}}}}}),
            "services.web.env.K",
        ),
        (
            json!({"spec": {"services": {"web": {"image": "node:22", "repo": "api"}}}}),
            "services.web.repo",
        ),
        (json!({"spec": spec(), "origin": "bogus"}), "origin"),
    ];
    for (body, path) in bad {
        let r = admin(&fx, Method::PUT, &uri, body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{path}: {}", r.1);
        assert!(
            r.1["message"].as_str().unwrap().contains(path),
            "{path}: {}",
            r.1
        );
    }
    let r = admin(
        &fx,
        Method::PUT,
        &uri,
        json!({"spec": {"services": {"web": {"image": "x y"}}}}),
    )
    .await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "invalid_spec"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_project_run_specs")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn an_archived_project_refuses_a_save_and_the_save_is_audited() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let uri = format!("/api/v1/projects/{id}/spec");
    admin(&fx, Method::PUT, &uri, json!({"spec": spec()})).await;
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'project.spec_saved'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(audited, 1);
    let ar = admin(
        &fx,
        Method::POST,
        &format!("/api/v1/projects/{id}/archive"),
        Value::Null,
    )
    .await;
    assert_eq!(ar.0, StatusCode::OK);
    let r = admin(&fx, Method::PUT, &uri, json!({"spec": spec()})).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "conflict"));
    let still = admin(&fx, Method::GET, &uri, Value::Null).await.1;
    assert_eq!(still["version"], 1, "history stays readable");
}
