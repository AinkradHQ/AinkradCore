//! The projects routes (P1-02): reading is `read`, every change is `admin`, remotes
//! are checked, an archived project is read-only, and mirror state shows in the project.

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

fn repo(name: &str) -> Value {
    json!({"name": name, "remote_url": format!("https://github.com/acme/{name}.git"),
           "default_branch": "main"})
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
    r.1["id"].as_i64().unwrap()
}

#[tokio::test]
async fn reading_is_read_scope_and_every_change_needs_admin_and_no_step_up() {
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
    let p = format!("/api/v1/projects/{id}");
    let writes = [
        (
            Method::POST,
            "/api/v1/projects".to_owned(),
            json!({"slug": "zz", "name": "Z"}),
        ),
        (Method::PATCH, p.clone(), json!({"name": "New"})),
        (Method::POST, format!("{p}/archive"), Value::Null),
        (Method::POST, format!("{p}/repos"), repo("web")),
        (Method::DELETE, format!("{p}/repos/1"), Value::Null),
        (Method::POST, format!("{p}/repos/1/primary"), Value::Null),
    ];
    for (m, uri, b) in &writes {
        let r = call(&fx, &phone, m.clone(), uri, b.clone()).await;
        assert_eq!(
            code(&r),
            (StatusCode::FORBIDDEN, "forbidden_scope"),
            "{m} {uri}"
        );
    }
    // An admin needs no step-up: its scope is enough, so the route answers (here not found).
    let r = call(&fx, &plain, Method::DELETE, &format!("{p}/repos/1"), Value::Null).await;
    assert_ne!(r.0, StatusCode::FORBIDDEN, "{}", r.1);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_projects")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "only the admin's project exists");
    for uri in ["/api/v1/projects".to_owned(), p] {
        let r = call(&fx, &phone, Method::GET, &uri, Value::Null).await;
        assert_eq!(r.0, StatusCode::OK, "{uri}: {}", r.1);
    }
}

#[tokio::test]
async fn a_project_is_created_changed_archived_and_listed() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let p = format!("/api/v1/projects/{id}");

    let dup = admin(
        &fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "shop", "name": "x"}),
    )
    .await;
    assert_eq!(code(&dup), (StatusCode::CONFLICT, "conflict"));
    for slug in ["Shop", "a", "core", "-x", "x-", "a_b"] {
        let r = admin(
            &fx,
            Method::POST,
            "/api/v1/projects",
            json!({"slug": slug, "name": "x"}),
        )
        .await;
        assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_request"), "{slug}");
    }
    let r = admin(
        &fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "ok", "name": "a\nb"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);

    let got = admin(&fx, Method::GET, &p, Value::Null).await.1;
    assert_eq!(
        (
            got["slug"].as_str(),
            got["state"].as_str(),
            got["source"].as_str(),
            got["expose"].as_bool()
        ),
        (Some("shop"), Some("active"), Some("manual"), Some(true))
    );
    assert_eq!(got["repos"], json!([]));

    let up = admin(
        &fx,
        Method::PATCH,
        &p,
        json!({"name": "Shop 2", "expose": false}),
    )
    .await;
    assert_eq!(up.0, StatusCode::OK, "{}", up.1);
    assert_eq!(
        (up.1["name"].as_str(), up.1["expose"].as_bool()),
        (Some("Shop 2"), Some(false))
    );
    assert_eq!(up.1["description"], "", "an omitted field is kept");

    let ar = admin(&fx, Method::POST, &format!("{p}/archive"), Value::Null).await;
    assert_eq!(ar.1["state"], "archived", "{}", ar.1);
    let again = admin(&fx, Method::POST, &format!("{p}/archive"), Value::Null).await;
    assert_eq!(code(&again), (StatusCode::CONFLICT, "conflict"));
    let ch = admin(&fx, Method::PATCH, &p, json!({"name": "x"})).await;
    assert_eq!(code(&ch), (StatusCode::CONFLICT, "conflict"));

    let active = admin(&fx, Method::GET, "/api/v1/projects", Value::Null)
        .await
        .1;
    assert_eq!(active, json!([]));
    let all = admin(
        &fx,
        Method::GET,
        "/api/v1/projects?archived=true",
        Value::Null,
    )
    .await
    .1;
    assert_eq!(all[0]["slug"], "shop");

    let miss = admin(&fx, Method::GET, "/api/v1/projects/999", Value::Null).await;
    assert_eq!(code(&miss), (StatusCode::NOT_FOUND, "not_found"));
    let junk = admin(&fx, Method::GET, "/api/v1/projects/abc", Value::Null).await;
    assert_eq!(junk.0, StatusCode::NOT_FOUND);

    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('project.created','project.updated','project.archived')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 3);
}

#[tokio::test]
async fn repos_are_added_made_primary_removed_and_show_their_mirror() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let p = format!("/api/v1/projects/{id}");

    let a = admin(&fx, Method::POST, &format!("{p}/repos"), repo("web")).await;
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a.1["repos"][0]["is_primary"], true, "the first is primary");
    assert_eq!(a.1["repos"][0]["mirror"], Value::Null, "not fetched yet");
    assert_eq!(
        a.1["room"],
        Value::Null,
        "Brain off: no room, the project works"
    );
    let b = admin(&fx, Method::POST, &format!("{p}/repos"), repo("api")).await;
    let web = b.1["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "web")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let api = b.1["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "api")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(b.1["repos"][0]["name"], "web", "primary first");

    let dup = admin(&fx, Method::POST, &format!("{p}/repos"), repo("web")).await;
    assert_eq!(code(&dup), (StatusCode::CONFLICT, "conflict"));

    // Every kind of bad remote is refused with a 400, and nothing is stored.
    for url in [
        "https://user:tok@github.com/acme/x.git",
        "file:///etc",
        "ext::sh -c id",
        "--upload-pack=x",
        "",
    ] {
        let mut body = repo("bad");
        body["remote_url"] = json!(url);
        let r = admin(&fx, Method::POST, &format!("{p}/repos"), body).await;
        assert_eq!(
            code(&r),
            (StatusCode::BAD_REQUEST, "bad_request"),
            "{url:?}"
        );
    }
    // An ssh remote is refused with its plain reason: the Core holds no key.
    let mut ssh = repo("ssh");
    ssh["remote_url"] = json!("git@github.com:acme/ssh.git");
    ssh["default_branch"] = json!("main");
    let r = admin(&fx, Method::POST, &format!("{p}/repos"), ssh).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
    assert!(r.1["message"].as_str().unwrap().contains("SSH"));
    let mut body = repo("../x");
    body["default_branch"] = json!("main");
    assert_eq!(
        admin(&fx, Method::POST, &format!("{p}/repos"), body)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    crate::store::projects::set_mirror(&fx.app.pool, web, Some("abc123"), Some(NOW), None)
        .await
        .unwrap();
    crate::store::projects::set_mirror(&fx.app.pool, api, None, None, Some("unreachable"))
        .await
        .unwrap();
    let got = admin(&fx, Method::GET, &p, Value::Null).await.1;
    assert_eq!(got["repos"][0]["mirror"]["head"], "abc123");
    assert_eq!(got["repos"][0]["mirror"]["fetched_at"], NOW);
    assert_eq!(got["repos"][1]["mirror"]["error"], "unreachable");

    let rm = admin(
        &fx,
        Method::DELETE,
        &format!("{p}/repos/{web}"),
        Value::Null,
    )
    .await;
    assert_eq!(
        code(&rm),
        (StatusCode::CONFLICT, "conflict"),
        "the primary goes last"
    );
    let pr = admin(
        &fx,
        Method::POST,
        &format!("{p}/repos/{api}/primary"),
        Value::Null,
    )
    .await;
    assert_eq!(pr.1["repos"][0]["name"], "api", "{}", pr.1);
    assert_eq!(pr.1["repos"][0]["is_primary"], true);
    assert_eq!(pr.1["repos"][1]["is_primary"], false);
    let rm = admin(
        &fx,
        Method::DELETE,
        &format!("{p}/repos/{web}"),
        Value::Null,
    )
    .await;
    assert_eq!(rm.1["repos"].as_array().unwrap().len(), 1, "{}", rm.1);
    let gone = admin(
        &fx,
        Method::DELETE,
        &format!("{p}/repos/{web}"),
        Value::Null,
    )
    .await;
    assert_eq!(code(&gone), (StatusCode::NOT_FOUND, "not_found"));
    let nop = admin(
        &fx,
        Method::POST,
        &format!("{p}/repos/999/primary"),
        Value::Null,
    )
    .await;
    assert_eq!(nop.0, StatusCode::NOT_FOUND);

    admin(&fx, Method::POST, &format!("{p}/archive"), Value::Null).await;
    let late = admin(&fx, Method::POST, &format!("{p}/repos"), repo("late")).await;
    assert_eq!(code(&late), (StatusCode::CONFLICT, "conflict"));
}

#[tokio::test]
async fn the_link_name_and_run_limits_change_through_the_update_route() {
    let fx = fx().await;
    let id = shop(&fx).await;
    let p = format!("/api/v1/projects/{id}");
    let r = admin(
        &fx,
        Method::PATCH,
        &p,
        json!({"slug": "store", "idle_minutes": 45, "cpu_limit": 1.5, "mem_limit_mb": 512}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (
            r.1["slug"].as_str(),
            r.1["idle_minutes"].as_i64(),
            r.1["cpu_limit"].as_f64(),
            r.1["mem_limit_mb"].as_i64()
        ),
        (Some("store"), Some(45), Some(1.5), Some(512))
    );
    for bad in [
        json!({"slug": "core"}),
        json!({"idle_minutes": 1}),
        json!({"cpu_limit": 0.0}),
        json!({"mem_limit_mb": 10}),
    ] {
        let r = admin(&fx, Method::PATCH, &p, bad.clone()).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    let other = admin(
        &fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "other", "name": "Other"}),
    )
    .await;
    assert_eq!(other.0, StatusCode::OK);
    let taken = admin(&fx, Method::PATCH, &p, json!({"slug": "other"})).await;
    assert_eq!(code(&taken), (StatusCode::CONFLICT, "conflict"));
}
