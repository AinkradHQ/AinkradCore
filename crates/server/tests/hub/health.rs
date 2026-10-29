//! Runner health in the API and events (E1-11.6): `GET /api/v1/runners` and one runner show
//! live state, `POST …/noop` runs the no-op end to end and is audited, scopes hold, and the
//! hub's presence goes out as `runner.connected`, `runner.degraded`, `runner.disconnected`.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_proto::v2::*;
use serde_json::Value;

use super::{Core, Fake, exec_driver, quick};

async fn call(core: &Core, dev: &TestDevice, method: &str, path: &str) -> (u16, Value) {
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = reqwest::Client::new().request(m, format!("http://{}{path}", core.host));
    for (n, v) in dev.headers(method, path, b"") {
        req = req.header(n, v);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn kinds(core: &Core) -> Vec<String> {
    sqlx::query_scalar("SELECT kind FROM events WHERE kind LIKE 'runner.%' ORDER BY seq")
        .fetch_all(&core.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_api_shows_live_runners_and_runs_the_noop() {
    // A slow heartbeat: the fake sends none, and must not turn degraded mid-test.
    let hub = ainkrad_core_server::hub::HubConfig {
        heartbeat: Duration::from_secs(10),
        ..quick()
    };
    let core = Core::start("health", hub).await;
    let admin = core.device("device", &["read", "agent"]).await;
    let reader = core.device("device", &["read"]).await;
    let dev = core.runner().await;
    let path = format!("/api/v1/runners/{}", dev.id);

    // A claimant that was never approved is not a runner.
    let rejected = core.runner().await;
    sqlx::query("UPDATE core_devices SET status = 'rejected' WHERE id = ?")
        .bind(&rejected.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    let rejected_path = format!("/api/v1/runners/{}", rejected.id);
    assert_eq!(call(&core, &admin, "GET", &rejected_path).await.0, 404);
    let (status, list) = call(&core, &admin, "GET", "/api/v1/runners").await;
    assert_eq!(status, 200);
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["id"], dev.id.as_str());
    assert_eq!(
        (&list[0]["online"], &list[0]["load"]),
        (&Value::Bool(false), &Value::from(0))
    );

    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 3)]).await;
    let (status, one) = call(&core, &reader, "GET", &path).await;
    assert_eq!(status, 200, "{one}");
    assert_eq!(one["online"], true);
    assert_eq!(one["degraded"], false);
    assert_eq!(one["capacity"], 3);
    assert_eq!(one["version"], "test");
    assert_eq!(one["drivers"][0]["commands"][0], "noop");
    assert!(one["last_seen"].is_string());

    // The no-op over HTTP: the fake answers it.
    let noop_path = format!("{path}/noop");
    let answered = tokio::spawn(async move {
        let cmd = fake.next().await;
        assert_eq!(cmd.body().unwrap(), Some(Body::Command(Command::Noop)));
        fake.send_frame(&Frame::new(cmd.stream_id, 0, Body::Result(Reply::Noop)))
            .await;
        fake
    });
    let (status, ok) = call(&core, &admin, "POST", &noop_path).await;
    assert_eq!((status, &ok["ok"]), (200, &Value::Bool(true)), "{ok}");
    let fake = answered.await.unwrap();
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'runner.command'")
            .fetch_one(&core.app.pool)
            .await
            .unwrap();
    assert_eq!(audited, 1);

    // Scopes: reading is not commanding, and a runner reads nothing here.
    assert_eq!(call(&core, &reader, "POST", &noop_path).await.0, 403);
    assert_eq!(call(&core, &dev, "GET", "/api/v1/runners").await.0, 403);
    let (status, _) = call(
        &core,
        &admin,
        "GET",
        "/api/v1/runners/d_00000000000000000000000000",
    )
    .await;
    assert_eq!(status, 404);

    drop(fake);
    for _ in 0..200 {
        if !core.app.hub.online(&dev.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (status, err) = call(&core, &admin, "POST", &noop_path).await;
    assert_eq!(
        (status, &err["code"]),
        (409, &Value::from("runner_offline")),
        "{err}"
    );
    assert_eq!(
        kinds(&core).await,
        ["runner.connected", "runner.disconnected"]
    );
}

#[tokio::test]
async fn a_silent_runner_is_degraded_then_dropped() {
    let core = Core::start("degraded", quick()).await;
    let dev = core.runner().await;
    let _silent = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    let hub = Arc::clone(&core.app.hub);
    // Heartbeat 1 s: degraded past 2 s of silence, dropped past 3 s.
    let mut degraded = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if hub.runners().get(&dev.id).is_some_and(|s| s.degraded) {
            degraded = true;
            break;
        }
    }
    assert!(degraded, "degraded before it was dropped");
    for _ in 0..60 {
        if !hub.online(&dev.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!hub.online(&dev.id));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        kinds(&core).await,
        ["runner.connected", "runner.degraded", "runner.disconnected"]
    );
}
