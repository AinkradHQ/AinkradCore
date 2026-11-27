//! Library paging, unarchive and the composer's request checks and reaper, through the Core's real gate (signed
//! requests into `api::router`). Each test fails if the property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use design_module::Design;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/design/v1";

struct Fx {
    app: App,
    admin: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "design-library-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Design::default())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    let admin = TestDevice::enroll_keys(
        &app.pool,
        "admin",
        "device",
        &["admin", "read"],
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    admin.set_session(Some(app.auth.issue_session(&admin.id, clock.unix()).id));
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    Fx { app, admin, dir }
}

async fn call(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let uri = format!("{BASE}{path}");
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in fx.admin.headers(method.as_str(), &uri, bytes.as_bytes()) {
        b = b.header(name, value);
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&text).unwrap_or(Value::Null))
}

async fn add(fx: &Fx, name: &str) -> String {
    let (s, v) = call(
        fx,
        Method::POST,
        "/docs",
        Some(json!({"kind": "design", "name": name})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

fn names(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn docs_and_collections_page_and_sort_by_last_change() {
    let fx = fx().await;
    for n in ["a", "b", "c", "d", "e"] {
        add(&fx, n).await;
    }
    let (_, all) = call(&fx, Method::GET, "/docs", None).await;
    assert_eq!(
        names(&all),
        ["a", "b", "c", "d", "e"],
        "the default is unchanged"
    );
    let (_, p1) = call(&fx, Method::GET, "/docs?limit=2", None).await;
    let (_, p2) = call(&fx, Method::GET, "/docs?limit=2&offset=2", None).await;
    let (_, p3) = call(&fx, Method::GET, "/docs?limit=2&offset=4", None).await;
    assert_eq!(
        (names(&p1), names(&p2), names(&p3)),
        (vec!["a", "b"], vec!["c", "d"], vec!["e"])
    );
    // a change moves a doc to the front of `sort=updated`
    let c = all[2]["id"].as_str().unwrap();
    sqlx::query("UPDATE design_docs SET updated_at = '2999-01-01T00:00:00.000Z' WHERE id = ?")
        .bind(c)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (_, u) = call(&fx, Method::GET, "/docs?sort=updated&limit=1", None).await;
    assert_eq!(names(&u), ["c"]);
    for bad in ["limit=0", "limit=501", "offset=-1", "sort=size", "limit=x"] {
        let (s, _) = call(&fx, Method::GET, &format!("/docs?{bad}"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    for n in ["x", "y", "z"] {
        let (s, v) = call(
            &fx,
            Method::POST,
            "/collections",
            Some(json!({"kind": "folder", "name": n})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (_, cs) = call(&fx, Method::GET, "/collections?limit=2&offset=1", None).await;
    assert_eq!(names(&cs), ["y", "z"]);
    let (s, _) = call(&fx, Method::GET, "/collections?sort=updated", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, a) = call(&fx, Method::GET, "/assets?limit=10&offset=0", None).await;
    assert_eq!((s, a), (StatusCode::OK, json!([])));
    assert_eq!(
        call(&fx, Method::GET, "/assets?limit=900", None).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_archived_doc_comes_back_with_unarchive() {
    let fx = fx().await;
    let id = add(&fx, "back").await;
    let (_, v) = call(&fx, Method::POST, &format!("/docs/{id}/archive"), None).await;
    assert_eq!(v["state"], "archived");
    for _ in 0..2 {
        let (s, v) = call(&fx, Method::POST, &format!("/docs/{id}/unarchive"), None).await;
        assert_eq!((s, &v["state"]), (StatusCode::OK, &json!("active")));
    }
    let (_, all) = call(&fx, Method::GET, "/docs", None).await;
    assert_eq!(names(&all), ["back"]);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'design.doc.unarchived'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 1, "unarchiving twice records once");
    let (s, _) = call(
        &fx,
        Method::POST,
        "/docs/dd_0000000000000000/unarchive",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_edit_of_a_frame_the_design_lacks_is_refused() {
    let fx = fx().await;
    let id = add(&fx, "screens").await;
    let url = format!("/docs/{id}/compose");
    for body in [
        json!({"prompt": "bigger title", "mode": "edit", "frame": "n_aaaaaaaaaaaa"}),
        json!({"prompt": "bigger title", "mode": "edit"}),
        json!({"prompt": "bigger title", "mode": "edit", "frame": "../x"}),
        json!({"prompt": "x", "mode": "remix"}),
    ] {
        let (s, v) = call(&fx, Method::POST, &url, Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} {v}");
    }
    // a plain compose gets past the checks and stops at the missing AI account
    let (s, v) = call(
        &fx,
        Method::POST,
        &url,
        Some(json!({"prompt": "a login screen"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
}

#[tokio::test]
async fn a_compose_stuck_past_six_minutes_fails_on_read_and_in_the_job() {
    let fx = fx().await;
    let id = add(&fx, "slow").await;
    let insert = |c: &'static str, state: &'static str, age: &'static str| {
        let (pool, id) = (fx.app.pool.clone(), id.clone());
        async move {
            sqlx::query(
                "INSERT INTO design_composes (id, doc, session, prompt, state, created_by, created_at) \
                 VALUES (?, ?, 'as_gone', 'x', ?, 'person:d_x', strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))",
            )
            .bind(c)
            .bind(&id)
            .bind(state)
            .bind(age)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    insert("dc_old", "drawing", "-7 minutes").await;
    insert("dc_placing", "applying", "-10 minutes").await;
    insert("dc_fresh", "applying", "-1 minutes").await;
    insert("dc_done", "done", "-60 minutes").await;
    assert_eq!(design_module::reap_composes(&fx.app).await.unwrap(), 2);
    assert_eq!(
        design_module::reap_composes(&fx.app).await.unwrap(),
        0,
        "once"
    );
    let (s, v) = call(
        &fx,
        Method::GET,
        &format!("/docs/{id}/compose/dc_old"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["state"].clone(), v["reason"].clone()),
        (json!("failed"), json!("the AI stopped answering"))
    );
    let (_, v) = call(
        &fx,
        Method::GET,
        &format!("/docs/{id}/compose/dc_fresh"),
        None,
    )
    .await;
    assert_eq!(
        (v["state"].clone(), v["stage"].clone()),
        (json!("applying"), json!("placing"))
    );
    let (_, v) = call(
        &fx,
        Method::GET,
        &format!("/docs/{id}/compose/dc_done"),
        None,
    )
    .await;
    assert_eq!(v["state"], "done");
    // a read reaps too: the fresh one, once it is old
    sqlx::query(
        "UPDATE design_composes SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = 'dc_fresh'",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (_, v) = call(
        &fx,
        Method::GET,
        &format!("/docs/{id}/compose/dc_fresh"),
        None,
    )
    .await;
    assert_eq!(v["state"], "failed");
}
