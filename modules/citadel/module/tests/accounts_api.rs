//! Accounts on the secrets broker, uploads and the cost reports through the Core's gate (S9 and
//! the S5 leftovers): every mutating route is a step-up route, a credential value never reaches a
//! Citadel table or the audit, and an upload cannot escape its store or pass the allow-list.

mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;

const MARKER: &str = "TOPSECRET-VALUE-0451";

fn step_up_required(r: &(StatusCode, Value)) -> bool {
    r.0 == StatusCode::FORBIDDEN && r.1["code"] == "step_up_required"
}

async fn raw(
    fx: &Fx,
    dev: &TestDev,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (n, v) in dev.headers(method.as_str(), &uri, &body) {
        b = b.header(n, v);
    }
    b = b.header(header::CONTENT_TYPE, "application/octet-stream");
    let res = ainkrad_core_server::api::router(fx.app.clone())
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let s = res.status();
    (
        s,
        to_bytes(res.into_body(), 1 << 26).await.unwrap().to_vec(),
    )
}

type TestDev = ainkrad_core_server::auth::testing::TestDevice;

async fn broker_secret(fx: &Fx, name: &str) {
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, runners, delivery, version, key_id, sealed, size, \
         created_at, updated_at) VALUES (?, ?, '[\"runner-1\"]', 'file', 1, '0123456789abcdef', ?, 5, 'now', 'now')",
    )
    .bind(name)
    .bind(&fx.dev.id)
    .bind(MARKER.as_bytes())
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn every_mutating_account_and_upload_route_needs_a_step_up_and_a_scope() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", &["admin"], true).await;
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let routes = [
        (
            Method::POST,
            "/accounts",
            json!({"harness": "claude", "label": "a"}),
        ),
        (Method::DELETE, "/accounts/1", json!(null)),
        (Method::PUT, "/accounts/1/companies/1", json!(null)),
        (Method::DELETE, "/accounts/1/companies/1", json!(null)),
        (
            Method::PUT,
            "/accounts/1/status",
            json!({"status": "disabled"}),
        ),
        (Method::PUT, "/accounts/1/plan", json!({"plan_tier": "pro"})),
        (
            Method::PUT,
            "/accounts/1/limits",
            json!({"unit": "tokens", "window_secs": 60, "cap": 5}),
        ),
        (Method::DELETE, "/accounts/1/limits/tokens/60", json!(null)),
    ];
    for (m, path, body) in routes {
        let body = (!body.is_null()).then_some(body);
        let r = call(&fx, Some(&laptop), m.clone(), path, body.clone()).await;
        assert!(step_up_required(&r), "{m} {path}: {r:?}");
        let r = call(&fx, Some(&reader), m.clone(), path, body).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{m} {path}: {r:?}");
        assert_ne!(
            r.1["code"], "step_up_required",
            "{m} {path}: scope is checked first"
        );
    }
    let up = "/companies/1/artifacts?name=a.txt";
    let r = raw(&fx, &laptop, Method::POST, up, b"x".to_vec()).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "unelevated upload");
    assert!(String::from_utf8_lossy(&r.1).contains("step_up_required"));
    let r = raw(&fx, &reader, Method::POST, up, b"x".to_vec()).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "read-only upload");
    let png = b"\x89PNG\r\n\x1a\n".to_vec();
    for path in ["/agents/1/avatar", "/companies/1/logo"] {
        let r = raw(&fx, &laptop, Method::PUT, path, png.clone()).await;
        assert!(
            String::from_utf8_lossy(&r.1).contains("step_up_required"),
            "{path}"
        );
        let r = raw(&fx, &reader, Method::PUT, path, png.clone()).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{path}");
        assert!(
            !String::from_utf8_lossy(&r.1).contains("step_up_required"),
            "{path}"
        );
    }
    // A read-only device reads the usage report, but never the routing detail or the bytes.
    broker_secret(&fx, "claude-main").await;
    let body = json!({"harness": "claude", "label": "main", "secret_name": "claude-main", "config_dir": "accounts/main"});
    let (s, a) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    for p in ["/accounts/usage", "/companies/1/account-usage"] {
        let (s, body) = call(&fx, Some(&reader), Method::GET, p, None).await;
        assert!(
            s == StatusCode::OK || s == StatusCode::NOT_FOUND,
            "{p}: {s}"
        );
        let text = body.to_string();
        for leak in [
            "claude-main",
            "runner-1",
            "accounts/main",
            "secret_name",
            "runners",
            "delivery",
            "config_dir",
            "\"note\"",
        ] {
            assert!(!text.contains(leak), "{p} leaks {leak}: {text}");
        }
    }
    let usage = call(&fx, Some(&reader), Method::GET, "/accounts/usage", None).await;
    assert_eq!(usage.0, StatusCode::OK, "the report itself is a read");
    let r = call(&fx, Some(&reader), Method::GET, "/accounts", None).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "the full list is admin");
    let r = raw(&fx, &reader, Method::GET, "/artifacts/1/content", vec![]).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "artifact bytes are admin");
}

#[tokio::test]
async fn an_account_names_one_broker_secret_and_no_value_is_stored_or_audited() {
    let fx = fx().await;
    broker_secret(&fx, "claude-main").await;
    let (s, a) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/accounts",
        Some(json!({"harness": "claude", "label": "main", "secret_name": "claude-main"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(a["secret_name"], "claude-main");
    assert_eq!(a["delivery"], "file", "delivery type comes from the broker");
    assert_eq!(
        a["runners"],
        json!(["runner-1"]),
        "runner list comes from the broker"
    );
    // A name the broker does not hold is refused, as is a malformed one.
    for name in ["no-such-secret", "../etc/passwd", "UPPER"] {
        let (s, b) = call(
            &fx,
            Some(&fx.dev),
            Method::POST,
            "/accounts",
            Some(json!({"harness": "claude", "label": "x", "secret_name": name})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name}: {b}");
    }
    assert!(
        call(&fx, Some(&fx.dev), Method::GET, "/accounts", None)
            .await
            .1
            .to_string()
            .contains("claude-main")
    );
    // One broker secret backs one account.
    let again = json!({"harness": "claude", "label": "second", "secret_name": "claude-main"});
    let (s, _) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(again)).await;
    assert!(
        s.is_client_error(),
        "a second account on the same secret: {s}"
    );

    // No table but the broker's own holds the value; neither does an audit row or an event.
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'core_secret%' \
         AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    for t in tables {
        let cols: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT name FROM pragma_table_info('{t}')"
        )))
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
        let cat = cols
            .iter()
            .map(|c| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join("||");
        let dump: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT group_concat({cat}) FROM \"{t}\""
        )))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
        assert!(
            !dump.unwrap_or_default().contains(MARKER),
            "value leaked into {t}"
        );
    }
}

#[tokio::test]
async fn an_upload_round_trips_and_abuse_is_refused() {
    let fx = fx().await;
    let (_, c) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let cid = c["id"].as_i64().unwrap();
    let up = |name: &str| format!("/companies/{cid}/artifacts?name={name}");
    let (s, body) = raw(
        &fx,
        &fx.dev,
        Method::POST,
        &up("notes.txt"),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (s, got) = raw(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("/artifacts/{id}/content"),
        vec![],
    )
    .await;
    assert_eq!((s, got.as_slice()), (StatusCode::OK, &b"hello"[..]));
    let uri = format!("{BASE}/artifacts/{id}/content");
    let res = ainkrad_core_server::api::router(fx.app.clone())
        .oneshot({
            let mut b = Request::builder().uri(&uri).header(header::HOST, HOST);
            for (n, v) in fx.dev.headers("GET", &uri, b"") {
                b = b.header(n, v);
            }
            b.body(Body::empty()).unwrap()
        })
        .await
        .unwrap();
    let h = res.headers();
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    assert!(
        h[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );

    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM citadel_artifacts")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap()
    };
    let before = count().await;
    for name in [
        "..%2Fescape.txt",
        "a%2Fb.txt",
        "..%5Cx.txt",
        ".hidden.txt",
        "evil.exe",
        "noext",
        "x.sh",
        "a%00b.txt",
    ] {
        let (s, _) = raw(&fx, &fx.dev, Method::POST, &up(name), b"x".to_vec()).await;
        assert!(s.is_client_error(), "{name} -> {s}");
    }
    let (s, _) = raw(
        &fx,
        &fx.dev,
        Method::POST,
        &up("big.txt"),
        vec![b'a'; 13_000_000],
    )
    .await;
    assert!(s.is_client_error(), "oversize -> {s}");
    assert_eq!(count().await, before, "no abusive upload left a row");
    // The digest column only holds 64 hex characters, so a download cannot be pointed outside
    // the blob store by a forged row.
    let forged = sqlx::query("UPDATE citadel_artifacts SET sha256 = '../../../../etc/passwd'")
        .execute(&fx.app.pool)
        .await;
    assert!(
        forged.is_err(),
        "a path-shaped digest must be refused by the schema"
    );
}

#[tokio::test]
async fn cost_reports_start_empty_and_are_company_scoped() {
    let fx = fx().await;
    let (_, c) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let cid = c["id"].as_i64().unwrap();
    let r = fx.ok(&format!("/companies/{cid}/costs")).await;
    assert_eq!(
        (r["runs"].as_i64(), r["cost_usd_micros"].as_i64()),
        (Some(0), Some(0))
    );
    assert_eq!(fx.ok(&format!("/companies/{cid}/ledger")).await, json!([]));
    let (s, _) = call(
        &fx,
        Some(&fx.dev),
        Method::GET,
        "/companies/999/ledger",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

async fn company(fx: &Fx, name: &str) -> i64 {
    let (s, c) = call(
        fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": name})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    c["id"].as_i64().unwrap()
}

/// M-03: below `admin` a usage report names no account label (often an email) and no provider
/// error text; the admin keeps both.
#[tokio::test]
async fn a_read_device_sees_no_account_label_or_status_reason_in_usage() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let a = company(&fx, "A").await;
    broker_secret(&fx, "claude-main").await;
    let body =
        json!({"harness": "claude", "label": "owner-main", "secret_name": "claude-main"});
    let (_, acc) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    let id = acc["id"].as_i64().unwrap_or_else(|| panic!("{acc}"));
    for (m, p) in [(Method::PUT, format!("/accounts/{id}/companies/{a}"))] {
        assert_eq!(
            call(&fx, Some(&fx.dev), m, &p, None).await.0,
            StatusCode::OK
        );
    }
    let st = json!({"status": "disabled", "reason": "429 for owner@example.com"});
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        &format!("/accounts/{id}/status"),
        Some(st),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    for p in [
        "/accounts/usage".to_owned(),
        format!("/companies/{a}/account-usage"),
    ] {
        let (s, admin) = call(&fx, Some(&fx.dev), Method::GET, &p, None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            admin[0]["label"], "owner-main",
            "{p}: admin keeps the label"
        );
        assert_eq!(admin[0]["status_reason"], "429 for owner@example.com");
        let (s, phone) = call(&fx, Some(&reader), Method::GET, &p, None).await;
        assert_eq!(s, StatusCode::OK, "{p}");
        let text = phone.to_string();
        assert!(
            !text.contains("owner-main") && !text.contains("429"),
            "{p}: {text}"
        );
        assert!(phone[0]["status_reason"].is_null(), "{p}");
        assert_eq!(phone[0]["id"], id, "{p}: the rest of the report is kept");
    }
}

/// M-03: an account assigned to company A is not readable or changeable by id from company B.
#[tokio::test]
async fn another_companys_account_is_not_found_by_id() {
    let fx = fx().await;
    let (a, b) = (company(&fx, "A").await, company(&fx, "B").await);
    broker_secret(&fx, "claude-main").await;
    let body = json!({"harness": "claude", "label": "main", "secret_name": "claude-main"});
    let (_, acc) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    let id = acc["id"].as_i64().unwrap();
    let assign = format!("/accounts/{id}/companies/{a}");
    assert_eq!(
        call(&fx, Some(&fx.dev), Method::PUT, &assign, None).await.0,
        StatusCode::OK
    );
    let writes = [
        (
            Method::PUT,
            format!("/accounts/{id}/status"),
            Some(json!({"status": "disabled"})),
        ),
        (
            Method::PUT,
            format!("/accounts/{id}/plan"),
            Some(json!({"plan_tier": "pro"})),
        ),
        (
            Method::PUT,
            format!("/accounts/{id}/limits"),
            Some(json!({"unit": "tokens", "window_secs": 60, "cap": 5})),
        ),
        (
            Method::DELETE,
            format!("/accounts/{id}/limits/tokens/60"),
            None,
        ),
        (Method::PUT, format!("/accounts/{id}/companies/{b}"), None),
        (
            Method::DELETE,
            format!("/accounts/{id}/companies/{a}"),
            None,
        ),
        (Method::DELETE, format!("/accounts/{id}"), None),
    ];
    let b = b.to_string();
    for (m, p, body) in writes.clone() {
        let (s, v) = call_in(&fx, Some(&fx.dev), Some(&b), m.clone(), &p, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {p}: {v}");
    }
    let (_, list) = call_in(&fx, Some(&fx.dev), Some(&b), Method::GET, "/accounts", None).await;
    assert!(
        list.as_array().unwrap().is_empty(),
        "the list already hid it"
    );
    // Nothing changed, and company A itself still reaches it.
    let (_, kept) = call(&fx, Some(&fx.dev), Method::GET, "/accounts", None).await;
    assert_eq!(kept[0]["status"], "active");
    assert_eq!(kept[0]["company_ids"], json!([a]));
    let a = a.to_string();
    let (s, v) = call_in(
        &fx,
        Some(&fx.dev),
        Some(&a),
        Method::PUT,
        &format!("/accounts/{id}/plan"),
        Some(json!({"plan_tier": "pro"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// A2: with a company acting, an account is assigned to or taken from that company only.
#[tokio::test]
async fn an_account_cannot_be_assigned_to_or_from_another_company() {
    let fx = fx().await;
    let (a, b) = (company(&fx, "A").await, company(&fx, "B").await);
    broker_secret(&fx, "claude-main").await;
    let body = json!({"harness": "claude", "label": "main", "secret_name": "claude-main"});
    let (_, acc) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    let id = acc["id"].as_i64().unwrap();
    let ha = a.to_string();
    for (m, cid) in [(Method::PUT, b), (Method::DELETE, b)] {
        let p = format!("/accounts/{id}/companies/{cid}");
        let (s, v) = call_in(&fx, Some(&fx.dev), Some(&ha), m.clone(), &p, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {p}: {v}");
    }
    let (_, kept) = call(&fx, Some(&fx.dev), Method::GET, "/accounts", None).await;
    assert_eq!(kept[0]["company_ids"], json!([]), "nothing was assigned");
    let p = format!("/accounts/{id}/companies/{a}");
    let (s, v) = call_in(&fx, Some(&fx.dev), Some(&ha), Method::PUT, &p, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}
