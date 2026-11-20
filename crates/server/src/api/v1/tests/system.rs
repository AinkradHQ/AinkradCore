//! The Core machine routes (host-helper plan §4, story H3) against a fake helper on a Unix socket
//! (the real helper's root tests are H2): scope and step-up per route, the D4 matrix, the audit
//! rows around the helper call, helper-absent / busy / refusing answers, and what may reach the
//! helper at all.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use super::stepup::plain;
use super::*;
use crate::host::Client;

#[derive(Clone)]
enum Mode {
    /// Answers each action with a fixed sample result.
    Ok,
    /// Refuses with a code (and `retry_after`).
    Refuse(&'static str, Option<u64>),
    /// Answers every action with this result.
    Result(Value),
    /// Answers with these bytes, whatever was asked.
    Raw(Vec<u8>),
    /// Closes the connection without reading or writing (systemd past `MaxConnections`).
    Close,
    /// Reads the request, then says nothing for `secs`.
    Hang(u64),
}

type Seen = Arc<Mutex<Vec<Value>>>;

fn sample(action: &str) -> Value {
    match action {
        "status" => json!({
            "helper_version": "0.1.0", "host_id": "h_abc", "manifest": "ok", "bin_dir_safe": true,
            "binaries": [{"name": "ainkrad-core-server", "version": "0.1.0",
                          "sha256_12": "0123456789ab", "state": "ok"}],
            "units": {"core": {"load": "loaded", "active": "active", "sub": "running",
                               "since": "Tue 2026-11-10 10:00:00 UTC", "restarts": 0},
                      "backup_timer": {"load": "loaded", "active": "active", "sub": "waiting",
                                       "since": "", "restarts": null}}
        }),
        "logs" => json!({"lines": [
            {"at": "2026-11-10T10:00:00.000Z", "level": "info", "text": "started"},
            {"at": "2026-11-10T10:00:01.000Z", "level": "warn", "text": "slow"}],
            "next_before": "s=abc;i=1"}),
        "backup_info" => json!({
            "installed": true,
            "timer": {"active": "active", "calendar": "*-*-* 22:00:00",
                      "next": "@1795298400", "last": ""},
            "run": {"active": "inactive", "result": "success",
                    "started": "Thu 2026-11-19 22:00:01 UTC",
                    "finished": "Thu 2026-11-19 22:03:10 UTC", "exit_status": 0},
            "history": [{"at": 1_795_100_000u64, "bytes": 2_100_000u64}],
            "retention": 14,
        }),
        _ => json!({"accepted": true}),
    }
}

/// A fake helper in `fx`'s directory; every parsed request line is pushed to the returned list.
async fn fake(fx: &mut Fx, mode: Mode) -> Seen {
    let path: PathBuf = fx.dir.join("host.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    fx.app.host_helper = Arc::new(Client::at(&path));
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let (mode, log) = (mode.clone(), log.clone());
            tokio::spawn(async move {
                if matches!(mode, Mode::Close) {
                    return;
                }
                let mut line = String::new();
                BufReader::new(&mut s).read_line(&mut line).await.unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                log.lock().unwrap().push(req.clone());
                let id = req["id"].clone();
                let reply = match mode {
                    Mode::Ok => {
                        let a = req["action"].as_str().unwrap_or_default();
                        json!({"v": 1, "id": id, "ok": true, "result": sample(a)})
                    }
                    Mode::Refuse(code, after) => {
                        let mut v = json!({"v": 1, "id": id, "ok": false, "code": code,
                                           "message": "x"});
                        if let Some(a) = after {
                            v["retry_after"] = json!(a);
                        }
                        v
                    }
                    Mode::Result(result) => json!({"v": 1, "id": id, "ok": true, "result": result}),
                    Mode::Raw(bytes) => {
                        let _ = s.write_all(&bytes).await;
                        return;
                    }
                    Mode::Hang(secs) => {
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        return;
                    }
                    Mode::Close => unreachable!(),
                };
                s.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            });
        }
    });
    seen
}

fn calls(seen: &Seen) -> Vec<Value> {
    seen.lock().unwrap().clone()
}

async fn rows(fx: &Fx, action: &str) -> Vec<(i64, Value)> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT seq, details FROM audit_events WHERE action = ?1 ORDER BY seq")
            .bind(action)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    rows.into_iter()
        .map(|(s, d)| (s, serde_json::from_str(&d).unwrap()))
        .collect()
}

async fn restart(fx: &Fx, dev: &TestDevice, body: Value) -> (StatusCode, Value) {
    send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/system/restart",
            Some(dev),
            Some(body),
        ),
    )
    .await
}

async fn get(fx: &Fx, dev: &TestDevice, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(Method::GET, uri, Some(dev), None)).await
}

const LOGS: [&str; 4] = ["core", "helper", "runner", "backup"];

fn logs_uri(unit: &str) -> String {
    format!("/api/v1/system/logs/{unit}")
}

async fn fast(mut fx: Fx) -> Fx {
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    fx
}

/// The contract: all the routes are `admin`; only the restart, the runner and backup logs and the
/// backup retention write are destructive (D4, D-4).
#[tokio::test]
async fn the_contract_declares_admin_everywhere_and_step_up_only_where_d4_says() {
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut destructive = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        if !path.starts_with("/api/v1/system/") {
            continue;
        }
        for (method, op) in item.as_object().unwrap() {
            assert_eq!(op["x-ainkrad-scope"], "admin", "{method} {path}");
            if op.get("x-ainkrad-destructive") == Some(&json!(true)) {
                destructive.push(path.clone());
            }
        }
    }
    destructive.sort();
    assert_eq!(
        destructive,
        [
            "/api/v1/system/backups/retention",
            "/api/v1/system/logs/backup",
            "/api/v1/system/logs/runner",
            "/api/v1/system/restart"
        ]
    );
    let n = spec["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|p| p.starts_with("/api/v1/system/"))
        .count();
    assert_eq!(
        n, 9,
        "six, the backup start and schedule, and the retention"
    );
}

/// Only `admin` gets in: read, agent, terminal and runner devices get 403 on every route, and
/// the helper is never asked.
#[tokio::test]
async fn only_an_admin_device_reaches_the_helper() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let others = [
        fx.enroll("reader", &["read", "approve"]).await,
        fx.enroll("agent", &["read", "agent"]).await,
        fx.enroll("term", &["read", "terminal"]).await,
        TestDevice::enroll(
            &fx.app.pool,
            "vm",
            "runner",
            &["runner"],
            &fx.app.auth.identity.fp,
            fx.clock.clone(),
        )
        .await,
    ];
    let s = fx.app.auth.issue_session(&others[3].id, fx.clock.unix());
    others[3].set_session(Some(s.id));
    for dev in &others {
        let mut uris = vec!["/api/v1/system/host".to_owned()];
        uris.extend(LOGS.map(logs_uri));
        for uri in uris {
            let (s, b) = get(&fx, dev, &uri).await;
            assert_eq!(
                (s, &b["code"]),
                (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
            );
        }
        let (s, b) = restart(&fx, dev, json!({"target": "core"})).await;
        assert_eq!(
            (s, &b["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
        );
    }
    assert!(calls(&seen).is_empty());
    assert!(rows(&fx, "host.restart_requested").await.is_empty());
}

/// D4: without a step-up the restart and the runner and backup logs are 403 `step_up_required`
/// (no helper call, no audit row); status and the Core and helper logs answer; elevated, all do.
#[tokio::test]
async fn the_d4_matrix_needs_a_step_up_for_restart_and_runner_and_backup_logs() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let cold = plain(&fx, "cold", &ALL, true).await;
    let step = |c: (StatusCode, Value)| (c.0, c.1["code"].as_str().unwrap_or("").to_owned());
    let needs = (StatusCode::FORBIDDEN, "step_up_required".to_owned());
    assert_eq!(
        step(restart(&fx, &cold, json!({"target": "core"})).await),
        needs
    );
    for unit in ["runner", "backup"] {
        assert_eq!(
            step(get(&fx, &cold, &logs_uri(unit)).await),
            needs,
            "{unit}"
        );
    }
    assert!(calls(&seen).is_empty(), "refused before the helper");
    assert!(rows(&fx, "host.restart_requested").await.is_empty());
    for uri in [
        "/api/v1/system/host",
        &logs_uri("core"),
        &logs_uri("helper"),
    ] {
        let (s, b) = get(&fx, &cold, uri).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {b}");
    }
    assert_eq!(super::stepup::step_up(&fx, &cold).await.0, StatusCode::OK);
    for unit in LOGS {
        assert_eq!(
            get(&fx, &cold, &logs_uri(unit)).await.0,
            StatusCode::OK,
            "{unit}"
        );
    }
    assert_eq!(
        restart(&fx, &cold, json!({"target": "runner"})).await.0,
        StatusCode::ACCEPTED
    );
}

/// The restart row is committed before the helper is asked: the helper refuses, and the row is
/// there, the call carries its seq, and the outcome row follows.
#[tokio::test]
async fn a_restart_is_audited_before_the_helper_call_and_after() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Refuse("rate_limited", Some(42))).await;
    let r = router(fx.app.clone())
        .oneshot(req(
            Method::POST,
            "/api/v1/system/restart",
            Some(&fx.dev),
            Some(json!({"target": "core"})),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers()[header::RETRY_AFTER], "42");
    let call = calls(&seen).remove(0);
    let before = rows(&fx, "host.restart_requested").await;
    assert_eq!(before.len(), 1);
    assert_eq!(call["action"], "restart_core");
    assert_eq!(call["params"], json!({}));
    assert_eq!(call["actor"]["device"], fx.dev.id.as_str());
    assert_eq!(
        call["actor"]["audit_seq"], before[0].0,
        "the row existed to give its seq"
    );
    assert_eq!(before[0].1["request_id"], call["id"]);
    assert_eq!(before[0].1["target"], "core");
    let after = rows(&fx, "host.action_result").await;
    assert_eq!(after.len(), 1);
    assert!(after[0].0 > before[0].0);
    assert_eq!(after[0].1["code"], "rate_limited");
    assert_eq!(after[0].1["request_id"], call["id"]);
}

#[tokio::test]
async fn an_accepted_restart_answers_202_with_its_request_id() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    for (target, action) in [("core", "restart_core"), ("runner", "restart_runner")] {
        let (s, b) = restart(&fx, &fx.dev, json!({"target": target})).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let sent = calls(&seen).pop().unwrap();
        assert_eq!(
            (sent["action"].as_str(), &sent["id"]),
            (Some(action), &b["request_id"])
        );
        assert_eq!(b["request_id"].as_str().unwrap().len(), 26);
    }
    let result = rows(&fx, "host.action_result").await;
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|r| r.1["code"] == "accepted"));
}

#[tokio::test]
async fn helper_codes_map_to_typed_answers() {
    for (code, status, want) in [
        ("not_installed", StatusCode::CONFLICT, "not_installed"),
        ("busy", StatusCode::SERVICE_UNAVAILABLE, "host_helper_busy"),
        (
            "state_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
            "host_state_unavailable",
        ),
        (
            "forbidden_peer",
            StatusCode::SERVICE_UNAVAILABLE,
            "host_helper_unavailable",
        ),
        ("failed", StatusCode::BAD_GATEWAY, "host_helper_failed"),
    ] {
        let mut fx = fast(fx().await).await;
        fake(&mut fx, Mode::Refuse(code, None)).await;
        let (s, b) = restart(&fx, &fx.dev, json!({"target": "runner"})).await;
        assert_eq!((s, b["code"].as_str()), (status, Some(want)), "{code}");
        let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
        assert_eq!((s, b["code"].as_str()), (status, Some(want)), "{code} logs");
    }
}

/// No socket: a clear 503, never a hang; the status route says `absent`; the audit rows are there.
#[tokio::test]
async fn a_missing_helper_is_503_and_absent() {
    let mut fx = fast(fx().await).await;
    fx.app.host_helper = Arc::new(Client::at(fx.dir.join("none.sock")));
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("host_helper_unavailable")
        )
    );
    let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("host_helper_unavailable")
        )
    );
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/host").await;
    assert_eq!((s, b["helper"].as_str()), (StatusCode::OK, Some("absent")));
    assert_eq!(rows(&fx, "host.restart_requested").await.len(), 1);
    assert_eq!(rows(&fx, "host.action_result").await[0].1["code"], "absent");
    // A socket file nobody serves is not "absent": the status says `error`, restart says 503.
    let dead = fx.dir.join("dead.sock");
    drop(std::os::unix::net::UnixListener::bind(&dead).unwrap());
    fx.app.host_helper = Arc::new(Client::at(&dead));
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/host").await;
    assert_eq!((s, b["helper"].as_str()), (StatusCode::OK, Some("error")));
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("host_helper_unavailable")
        )
    );
}

/// A connection closed with no bytes is `busy`.
#[tokio::test]
async fn a_connection_closed_with_no_bytes_is_busy() {
    let mut fx = fast(fx().await).await;
    fake(&mut fx, Mode::Close).await;
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("host_helper_busy"))
    );
    assert_eq!(rows(&fx, "host.action_result").await[0].1["code"], "busy");
}

/// One call in flight: a second waits at most two seconds for its turn and is `busy`.
#[tokio::test]
async fn a_call_while_one_is_in_flight_is_busy_after_two_seconds() {
    let mut fx = fast(fx().await).await;
    fake(&mut fx, Mode::Hang(5)).await;
    let other = fx.enroll("other", &ALL).await;
    let slow = {
        let app = fx.app.clone();
        tokio::spawn(async move {
            send(
                &app,
                req(Method::GET, &logs_uri("core"), Some(&other), None),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t = std::time::Instant::now();
    let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("host_helper_busy"))
    );
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    // The status route reports a busy helper as `error`.
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/host").await;
    assert_eq!((s, b["helper"].as_str()), (StatusCode::OK, Some("error")));
    slow.abort();
}

#[tokio::test]
async fn the_host_route_reports_versions_and_units() {
    let mut fx = fast(fx().await).await;
    fake(&mut fx, Mode::Ok).await;
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/host").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["helper"], "present");
    assert_eq!(b["host_id"], "h_abc");
    assert_eq!(b["binaries"][0]["state"], "ok");
    assert_eq!(b["binaries"][0]["sha256_12"], "0123456789ab");
    assert_eq!(b["bin_dir_safe"], true);
    assert_eq!(b["units"]["core"]["state"], "active");
    assert_eq!(b["units"]["backup_timer"]["sub"], "waiting");
    assert!(b["units"]["runner"].is_null(), "no local runner");
}

/// What the caller may send is closed: bad bodies and parameters are 400 and never reach the
/// helper (or the audit log).
#[tokio::test]
async fn bad_input_is_400_and_never_reaches_the_helper() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    for body in [
        json!({"target": "all"}),
        json!({"target": "core;reboot"}),
        json!({"target": "core", "unit": "x"}),
        json!({"target": 1}),
        json!({}),
    ] {
        let (s, b) = restart(&fx, &fx.dev, body.clone()).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_request")),
            "{body}"
        );
    }
    let (s, _) = send(
        &fx.app,
        req(Method::POST, "/api/v1/system/restart", Some(&fx.dev), None),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let long = "a".repeat(257);
    let bad = [
        "lines=0".to_owned(),
        "lines=501".to_owned(),
        "lines=-1".to_owned(),
        "lines=abc".to_owned(),
        "before=-x".to_owned(),
        "before=-r".to_owned(),
        "before=--cursor-file%3D%2Fetc%2Fshadow".to_owned(),
        "before=a%20b".to_owned(),
        "before=a%2Fb".to_owned(),
        "before=".to_owned(),
        format!("before={long}"),
        // Not a parameter of this route: the gate refuses it by name.
        "unit=runner".to_owned(),
        "lines=5&unit=runner".to_owned(),
    ];
    for q in &bad {
        let (s, _) = get(&fx, &fx.dev, &format!("{}?{q}", logs_uri("core"))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}");
    }
    assert!(calls(&seen).is_empty(), "{:?}", calls(&seen));
    assert!(rows(&fx, "host.restart_requested").await.is_empty());
}

/// A page is passed on with its cursor; the helper gets the unit of the path, the count and the
/// cursor as given; the audit row holds the unit and the count, no log text.
#[tokio::test]
async fn logs_pass_through_and_are_audited_without_their_text() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["lines"][1]["text"], "slow");
    assert_eq!(b["next_before"], "s=abc;i=1");
    assert_eq!(
        calls(&seen)[0]["params"],
        json!({"unit": "core", "lines": 200})
    );
    let q = "lines=500&before=s%3Dabc%3Bi%3D1_Z";
    let (s, _) = get(&fx, &fx.dev, &format!("{}?{q}", logs_uri("runner"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        calls(&seen)[1]["params"],
        json!({"unit": "runner", "lines": 500, "before": "s=abc;i=1_Z"})
    );
    let audit = rows(&fx, "host.logs_read").await;
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].1["unit"], "core");
    assert_eq!(audit[0].1["lines"], 2);
    assert!(!audit[0].1.to_string().contains("started"));
    let (s, _) = get(&fx, &fx.dev, &logs_uri("helper")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(calls(&seen)[2]["params"]["unit"], "helper");
}

/// Refusals of reads are audited once per window, not once per call.
#[tokio::test]
async fn read_refusals_are_audited_once_per_window() {
    let mut fx = fast(fx().await).await;
    fake(&mut fx, Mode::Refuse("rate_limited", Some(5))).await;
    for _ in 0..20 {
        assert_eq!(
            get(&fx, &fx.dev, &logs_uri("core")).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(rows(&fx, "host.helper_refused").await.len(), 1);
    assert!(rows(&fx, "host.logs_read").await.is_empty());
}

/// The helper answers with something that is not one good line for this request: wrong id, wrong
/// version, a line over 512 KiB, not JSON, no `ok`. 502, never a hang or a panic.
#[tokio::test]
async fn a_garbled_helper_answer_is_502() {
    let good =
        |id: &str, v: u32| format!("{{\"v\":{v},\"id\":\"{id}\",\"ok\":true,\"result\":{{}}}}\n");
    let mut huge = vec![b'a'; 600 * 1024];
    huge.push(b'\n');
    for (what, bytes) in [
        (
            "wrong id",
            good("01ARZ3NDEKTSV4RRFFQ69G5FAV", 1).into_bytes(),
        ),
        ("wrong version", good("whatever", 2).into_bytes()),
        ("not json", b"hello\n".to_vec()),
        ("no newline", b"{\"v\":1}".to_vec()),
        ("over 512 KiB", huge),
        ("no ok", b"{\"v\":1,\"id\":\"x\"}\n".to_vec()),
    ] {
        let mut fx = fast(fx().await).await;
        fake(&mut fx, Mode::Raw(bytes)).await;
        let (s, b) = restart(&fx, &fx.dev, json!({"target": "runner"})).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::BAD_GATEWAY, Some("host_helper_failed")),
            "{what}"
        );
        let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::BAD_GATEWAY, Some("host_helper_failed")),
            "{what} logs"
        );
    }
}

/// A helper that reads the request and never answers is cut at the deadline: 504.
#[tokio::test]
async fn a_helper_that_never_answers_is_504() {
    let mut fx = fast(fx().await).await;
    fake(&mut fx, Mode::Hang(5)).await;
    fx.app.host_helper =
        Arc::new(Client::at(fx.dir.join("host.sock")).with_deadline(Duration::from_millis(300)));
    let t = std::time::Instant::now();
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::GATEWAY_TIMEOUT, Some("host_helper_timeout"))
    );
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(
        rows(&fx, "host.action_result").await[0].1["code"],
        "timeout"
    );
}

/// A restart whose request row cannot be written never reaches the helper; logs whose audit row
/// cannot be written are not handed out.
#[tokio::test]
async fn an_audit_write_failure_is_500_and_the_helper_is_never_asked() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    sqlx::query(
        "CREATE TRIGGER no_restart_rows BEFORE INSERT ON audit_events \
         WHEN NEW.action = 'host.restart_requested' BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("internal"))
    );
    assert!(
        calls(&seen).is_empty(),
        "the helper was asked: {:?}",
        calls(&seen)
    );
    sqlx::query(
        "CREATE TRIGGER no_log_rows BEFORE INSERT ON audit_events \
         WHEN NEW.action = 'host.logs_read' BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(b.get("lines").is_none(), "{b}");
}

/// A loop of restarts against a refusing helper (or an absent one) adds a bounded number of audit
/// rows: the helper's wait is remembered, repeats are answered 429 with the wait that is left and
/// counted, not audited. Once the wait is over the helper is asked again.
#[tokio::test]
async fn fifty_refused_restarts_add_at_most_one_refusal_row() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Refuse("rate_limited", Some(40))).await;
    for i in 0..50 {
        let r = router(fx.app.clone())
            .oneshot(req(
                Method::POST,
                "/api/v1/system/restart",
                Some(&fx.dev),
                Some(json!({"target": "core"})),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "{i}");
        if i == 1 {
            assert_eq!(r.headers()[header::RETRY_AFTER], "40");
        }
    }
    assert_eq!(calls(&seen).len(), 1, "the helper was asked once");
    assert_eq!(rows(&fx, "host.restart_requested").await.len(), 1);
    assert_eq!(rows(&fx, "host.action_result").await.len(), 1);
    assert!(rows(&fx, "host.helper_refused").await.len() <= 1);
    // The wait runs down with the clock, then the helper is asked again.
    fx.clock.advance(20);
    let r = router(fx.app.clone())
        .oneshot(req(
            Method::POST,
            "/api/v1/system/restart",
            Some(&fx.dev),
            Some(json!({"target": "core"})),
        ))
        .await
        .unwrap();
    assert_eq!(r.headers()[header::RETRY_AFTER], "20");
    fx.clock.advance(21);
    restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(calls(&seen).len(), 2);
    // Another target is not held back by this one.
    restart(&fx, &fx.dev, json!({"target": "runner"})).await;
    assert_eq!(calls(&seen).len(), 3);

    // An absent helper is held back the same way.
    let mut fx = fast(self::fx().await).await;
    fx.app.host_helper = Arc::new(Client::at(fx.dir.join("none.sock")));
    for _ in 0..50 {
        let (s, _) = restart(&fx, &fx.dev, json!({"target": "runner"})).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(rows(&fx, "host.restart_requested").await.len(), 1);
    assert!(rows(&fx, "host.helper_refused").await.len() <= 1);
}

/// An accepted Core restart holds the next one back for the helper's 60 s minimum gap.
#[tokio::test]
async fn an_accepted_core_restart_holds_the_next_for_the_helpers_gap() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    assert_eq!(
        restart(&fx, &fx.dev, json!({"target": "core"})).await.0,
        StatusCode::ACCEPTED
    );
    let (s, _) = restart(&fx, &fx.dev, json!({"target": "core"})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(calls(&seen).len(), 1);
}

/// What the helper sends is shown as plain text: control characters become `?`, a cursor that
/// could not be sent back is dropped, and unit strings are cleaned.
#[tokio::test]
async fn log_text_and_status_strings_are_plain_and_a_bad_cursor_is_dropped() {
    let mut fx = fast(fx().await).await;
    let evil = "red\u{1b}[31m\u{1b}]0;pwned\u{7}\nline2\tok";
    fake(
        &mut fx,
        Mode::Result(
            json!({"lines": [{"at": "t\u{1b}", "level": "i\u{7}", "text": evil}],
            "next_before": "-r", "units": {"core": {"active": "act\u{1b}[2J"}}}),
        ),
    )
    .await;
    let (s, b) = get(&fx, &fx.dev, &logs_uri("core")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let text = b["lines"][0]["text"].as_str().unwrap();
    assert_eq!(text, "red?[31m?]0;pwned??line2\tok");
    assert!(!b.to_string().contains("\\u001b"), "{b}");
    assert!(b["next_before"].is_null(), "{b}");
    let (_, b) = get(&fx, &fx.dev, "/api/v1/system/host").await;
    assert_eq!(b["units"]["core"]["state"], "act?[2J");
}

/// The socket must be served by root in production: a server of another uid is not the helper. Linux only: the check
/// (`SO_PEERCRED`) exists only there, and so does the helper.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_socket_served_by_the_wrong_user_is_refused() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let other = ainkrad_sys::getuid() + 1;
    fx.app.host_helper = Arc::new(Client::at(fx.dir.join("host.sock")).expecting_uid(other));
    let (s, b) = restart(&fx, &fx.dev, json!({"target": "runner"})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("host_helper_unavailable")
        )
    );
    assert!(calls(&seen).is_empty());
}

/// A backup now: no step-up (it starts the unit the timer starts), audited before and after the
/// helper call, the helper asked with no input, and a second start inside a minute held back.
#[tokio::test]
async fn a_backup_now_is_audited_and_asked_with_no_input() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    async fn post(fx: &Fx) -> (StatusCode, Value) {
        send(
            &fx.app,
            req(Method::POST, "/api/v1/system/backup", Some(&fx.dev), None),
        )
        .await
    }
    let (s, b) = post(&fx).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let call = calls(&seen).remove(0);
    assert_eq!(
        (call["action"].as_str(), &call["params"]),
        (Some("backup_now"), &json!({}))
    );
    assert_eq!(call["id"], b["request_id"]);
    let before = rows(&fx, "host.backup_requested").await;
    assert_eq!(before.len(), 1);
    assert_eq!(call["actor"]["audit_seq"], before[0].0);
    let after = rows(&fx, "host.action_result").await;
    assert_eq!(after[0].1["code"], "accepted");
    let (s, _) = post(&fx).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "held back for a minute");
    assert_eq!(calls(&seen).len(), 1, "the helper was not asked again");
}

#[tokio::test]
async fn the_backup_schedule_is_read_through_the_helper() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/backups").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(calls(&seen)[0]["action"], "backup_info");
    assert_eq!(b["helper"], "present");
    assert_eq!(b["schedule"], "*-*-* 22:00:00");
    assert_eq!(b["timer_active"], true);
    assert!(b["next_at"].is_string(), "{b}");
    assert_eq!(b["last_run"]["result"], "success");
    assert_eq!(b["history"][0]["bytes"], 2_100_000);
    assert_eq!(b["keep"], 14);
    // A reader may not see it.
    let phone = fx.enroll("phone", &["read"]).await;
    let (s, _) = get(&fx, &phone, "/api/v1/system/backups").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// The retention: read through `backup_info`, written by the Core itself into its own config
/// (never through the helper), audited before and after, a step-up for the write, and a bad body
/// touches nothing.
#[tokio::test]
async fn the_backup_retention_is_read_through_the_helper_and_written_by_the_core() {
    let mut fx = fast(fx().await).await;
    let seen = fake(&mut fx, Mode::Ok).await;
    let (s, b) = get(&fx, &fx.dev, "/api/v1/system/backups/retention").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(calls(&seen)[0]["action"], "backup_info");
    assert_eq!(
        (&b["helper"], &b["keep"], &b["min"], &b["max"]),
        (&json!("present"), &json!(14), &json!(1), &json!(60))
    );
    let config = fx.dir.join("config.toml");
    fx.app.health = std::sync::Arc::new(crate::health::Health::new(&fx.dir.join("core.db")));
    async fn put(fx: &Fx, dev: &TestDevice, body: Value) -> (StatusCode, Value) {
        send(
            &fx.app,
            req(
                Method::PUT,
                "/api/v1/system/backups/retention",
                Some(dev),
                Some(body),
            ),
        )
        .await
    }
    // No config yet: nothing to change.
    let (s, b) = put(&fx, &fx.dev, json!({"keep": 30})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_installed"))
    );
    let text = "home = \"/x\"\nbackup_keep_local = 7\nmodules = []\n";
    std::fs::write(&config, text).unwrap();
    for bad in [
        json!({}),
        json!({"keep": 0}),
        json!({"keep": 61}),
        json!({"keep": -3}),
        json!({"keep": "7"}),
        json!({"keep": 7, "path": "/etc"}),
    ] {
        let (s, _) = put(&fx, &fx.dev, bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(std::fs::read_to_string(&config).unwrap(), text);
    let (s, b) = put(&fx, &fx.dev, json!({"keep": 30})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["keep"], 30);
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "home = \"/x\"\nbackup_keep_local = 30\nmodules = []\n"
    );
    assert!(!fx.dir.join("config.toml.keep.tmp").exists());
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    put(&fx, &fx.dev, json!({"keep": 31})).await;
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "the mode is kept");
    }
    assert_eq!(calls(&seen).len(), 1, "the helper was asked only to read");
    let before = rows(&fx, "host.backup_retention_requested").await;
    assert!(before.len() >= 2);
    assert_eq!(before.last().unwrap().1["keep"], 31);
    assert_eq!(
        rows(&fx, "host.action_result").await[0].1["code"],
        "not_installed"
    );
    // A link in the config's place is never followed or replaced through.
    std::fs::remove_file(&config).unwrap();
    let target = fx.dir.join("elsewhere");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, &config).unwrap();
    let (s, _) = put(&fx, &fx.dev, json!({"keep": 5})).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
    // Without a step-up it is refused; a reader never gets in.
    let cold = plain(&fx, "cold", &ALL, true).await;
    let (s, b) = put(&fx, &cold, json!({"keep": 5})).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    let phone = fx.enroll("phone", &["read"]).await;
    let (s, _) = put(&fx, &phone, json!({"keep": 5})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
