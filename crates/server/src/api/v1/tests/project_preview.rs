//! The preview proxy (API 110) against the Host router's fixture runner (`host_router::Local`):
//! a PRIVATE running project answers through a signed request, path and query as the app's;
//! unsigned, stopped, starting and read-only writes are refused; the device's signed headers never
//! reach the project; `Set-Cookie` stays host-only.

use super::host_router::{local, running};
use super::project_runs::w;
use super::*;
use crate::gateway::projects::Preview;
use crate::store::runs as store;

async fn private(fx: &Fx) -> i64 {
    let p = running(fx, "shop").await;
    let now = fx.app.clock.now();
    crate::store::projects::update(&fx.app.pool, p, None, None, Some(false), w(&now))
        .await
        .unwrap();
    p
}

#[tokio::test]
async fn a_private_run_answers_a_signed_request_with_its_own_path_and_query() {
    let mut fx = fx().await;
    let dial = local().await;
    fx.app.preview = Arc::new(Preview::with_dial(dial.clone()));
    let p = private(&fx).await;
    let uri = format!("/api/v1/projects/{p}/preview/a/b.js?v=3&lang=en");
    let (status, body) = send(&fx.app, req(Method::GET, &uri, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["uri"], "/a/b.js?v=3&lang=en");
    assert_eq!(body["headers"]["host"], "localhost");
    let seen = body["headers"].as_object().unwrap();
    assert!(
        !seen.keys().any(|k| k.starts_with("ainkrad-")),
        "the device's signed headers stay at the Core: {seen:?}"
    );
    let opened = dial.opened.lock().unwrap().clone();
    assert_eq!((opened[0].service.as_str(), opened[0].port), ("web", 3000));
    // The root.
    let root = format!("/api/v1/projects/{p}/preview/");
    let (status, body) = send(&fx.app, req(Method::GET, &root, Some(&fx.dev), None)).await;
    assert_eq!((status, body["uri"].clone()), (StatusCode::OK, json!("/")));
    // A body goes through; a project cookie stays on the preview's own host.
    let res = router(fx.app.clone())
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/projects/{p}/preview/form"),
            Some(&fx.dev),
            Some(json!({"a": 1})),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["set-cookie"], "sid=1; Path=/");
    // Unsigned: the gate's 401, nothing dialled.
    let n = dial.opened.lock().unwrap().len();
    let (status, _) = send(&fx.app, req(Method::GET, &uri, None, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(dial.opened.lock().unwrap().len(), n);
}

#[tokio::test]
async fn a_read_device_may_look_but_not_post() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(1000, 1.0),
    });
    fx.app.preview = Arc::new(Preview::with_dial(local().await));
    let p = private(&fx).await;
    let phone = fx.enroll("phone", &["read"]).await;
    let uri = format!("/api/v1/projects/{p}/preview/x");
    assert_eq!(
        send(&fx.app, req(Method::GET, &uri, Some(&phone), None))
            .await
            .0,
        StatusCode::OK
    );
    let post = req(Method::POST, &uri, Some(&phone), Some(json!({})));
    assert_eq!(send(&fx.app, post).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn not_running_is_a_409_in_words_and_nothing_is_dialled() {
    let mut fx = fx().await;
    let dial = local().await;
    fx.app.preview = Arc::new(Preview::with_dial(dial.clone()));
    let p = private(&fx).await;
    let now = fx.app.clock.now();
    let end = store::End {
        state: "stopped",
        reason: Some("user"),
        error: None,
    };
    assert!(
        store::finish(&fx.app.pool, "r_shop", end, w(&now))
            .await
            .unwrap()
    );
    let uri = format!("/api/v1/projects/{p}/preview/");
    let (status, body) = send(&fx.app, req(Method::GET, &uri, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "not_running");
    assert!(body["message"].as_str().unwrap().contains("not running"));
    assert!(dial.opened.lock().unwrap().is_empty());
    let (status, _) = fx.get("/api/v1/projects/999/preview/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
