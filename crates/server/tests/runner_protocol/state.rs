//! What a runner says of itself (protocol 1.20), end to end: its `Hello` and `Status` land on
//! its row, the app reads the tail of its log through the server (redacted), the admin's Power
//! Nap preference reaches it, and a drained runner takes no work until it is undrained.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::UserId;
use ainkrad_core_server::store::gov::issue_device_key;
use ainkrad_runner::{Config, FakeExecutor};
use serde_json::{Value, json};

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

/// The runner's name and key (long enough to be redacted).
const KEY: &str = "mac-runner-key-5f2a9c";

struct Api {
    base: String,
    key: String,
    http: reqwest::Client,
}

impl Api {
    async fn send(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.key);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let res = r.send().await.unwrap();
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn a_runner_reports_itself_sends_its_log_and_takes_its_power_nap_preference() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let id = runner(pool, KEY, &["macos"]).await;
    let dir = std::env::temp_dir().join(format!("ainkrad-runner-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("runner.log");
    std::fs::write(&log, format!("booting\nconnecting with key {KEY}\nready\n")).unwrap();
    let config = Config {
        log: Some(log),
        url: stack.url(),
        key: KEY.to_owned(),
        tags: vec!["macos".to_owned()],
        harnesses: [(
            "claude".to_owned(),
            ainkrad_harness::claude::VERSION.to_owned(),
        )]
        .into(),
    };
    tokio::spawn(ainkrad_runner::run(config, FakeExecutor::default()));
    until(
        pool,
        "its state",
        "SELECT count(*) FROM runners WHERE info IS NOT NULL",
    )
    .await;

    let (_, key) = issue_device_key(pool, "t", AuditActor::User(UserId(1)))
        .await
        .unwrap();
    let api = Api {
        base: format!("http://{}", stack.proxy.addr),
        key,
        http: reqwest::Client::new(),
    };
    let (status, all) = api
        .send(reqwest::Method::GET, "/api/v1/runners", None)
        .await;
    assert_eq!(status, 200, "{all}");
    let r = &all[0];
    assert_eq!(r["slots"], 1);
    assert_eq!(r["harnesses"]["claude"], ainkrad_harness::claude::VERSION);
    assert!(r["uptime_secs"].is_u64(), "{r}");
    assert_eq!(r["asleep"], false, "online");
    assert_eq!(r["os"], std::env::consts::OS, "{r}");
    assert_eq!(r["arch"], std::env::consts::ARCH, "{r}");

    // A probe makes it look again now and answers with the runner as it is.
    let probe = format!("/api/v1/runners/{}/probe", id.0);
    let (status, probed) = api.send(reqwest::Method::POST, &probe, None).await;
    assert_eq!(status, 200, "{probed}");
    assert_eq!(probed["os"], std::env::consts::OS);
    assert_eq!(
        probed["harnesses"]["claude"],
        ainkrad_harness::claude::VERSION
    );

    let logs = format!("/api/v1/runners/{}/logs?limit=2", id.0);
    let (status, tail) = api.send(reqwest::Method::GET, &logs, None).await;
    assert_eq!(status, 200, "{tail}");
    let lines = tail["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 2);
    assert!(
        !lines[0].as_str().unwrap().contains(KEY),
        "the key is redacted: {tail}"
    );
    assert_eq!(lines[1], "ready");

    let nap = format!("/api/v1/runners/{}/power-nap", id.0);
    let (status, _) = api
        .send(reqwest::Method::PUT, &nap, Some(json!({"enabled": true})))
        .await;
    assert_eq!(status, 200);
    let held = "SELECT count(*) FROM runners WHERE json_extract(info, '$.power_nap') = 1";
    until(pool, "the runner to hold its Power Nap preference", held).await;

    // Drained, it is offered nothing; undrained, it takes the work.
    let drain = format!("/api/v1/runners/{}/drain", id.0);
    assert_eq!(api.send(reqwest::Method::POST, &drain, None).await.0, 200);
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &["macos"], None).await;
    assign(pool, issue(pool, p).await, dev).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM runs")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(runs, 0, "a drained runner takes no run");
    assert_eq!(api.send(reqwest::Method::DELETE, &drain, None).await.0, 200);
    until(pool, "the run", "SELECT count(*) FROM runs").await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A runner on protocol 1.24 cannot probe: the admin is told it is too old, not left waiting.
#[tokio::test]
async fn a_runner_too_old_to_probe_is_a_conflict() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let stack = Stack::new().await;
    let pool = stack.pool();
    let id = runner(pool, KEY, &["macos"]).await;
    let mut req = stack.url().into_client_request().unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {KEY}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let hello = json!({"type": "hello", "protocol": "1.24", "runner_version": "old",
        "tags": ["macos"], "harnesses": {}, "runs": []});
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    let welcome = ws.next().await.unwrap().unwrap();
    assert!(welcome.to_text().unwrap().contains("welcome"), "{welcome}");

    let (_, key) = issue_device_key(pool, "t", AuditActor::User(UserId(1)))
        .await
        .unwrap();
    let api = Api {
        base: format!("http://{}", stack.proxy.addr),
        key,
        http: reqwest::Client::new(),
    };
    let probe = format!("/api/v1/runners/{}/probe", id.0);
    let drive = api.send(reqwest::Method::POST, &probe, None);
    // The session answers the request on its next poll; keep the socket reading meanwhile.
    let pump = async { while let Some(Ok(_)) = ws.next().await {} };
    let (status, body) = tokio::select! { r = drive => r, () = pump => unreachable!() };
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("too old"),
        "{body}"
    );
    let r = api
        .send(reqwest::Method::GET, "/api/v1/runners", None)
        .await
        .1;
    assert_eq!(r[0]["os"], Value::Null, "an older runner never says");
}
