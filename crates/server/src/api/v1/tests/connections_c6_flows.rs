//! C6: sign-in flows under an adversary: near-miss `state` values, parallel callbacks, a parallel
//! burst of starts, a flow used from another device or after another one finished, and two
//! workspaces claiming one GitHub installation at the same instant.

use axum::http::{Method, StatusCode};
use futures_util::future::join_all;
use serde_json::{Value, json};

use super::connections_apps::pem;
use super::connections_fx::*;

const URI: &str = "/api/v1/connections";

async fn begin(cx: &Cx) -> (String, String) {
    let (s, v) = start(cx, "jira", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (
        v["id"].as_str().unwrap().to_owned(),
        v["state"].as_str().unwrap().to_owned(),
    )
}

async fn callback(cx: &Cx, id: &str, code: &str, state: &str) -> (StatusCode, Value) {
    cx.admin(
        Method::POST,
        &format!("{URI}/flows/{id}/callback"),
        json!({"code": code, "state": state}),
    )
    .await
}

async fn step(cx: &Cx, id: &str) -> String {
    let v = cx
        .ok(Method::GET, &format!("{URI}/flows/{id}"), Value::Null)
        .await;
    v["step"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_state_that_is_almost_right_is_refused_and_the_flow_still_finishes_with_the_right_one() {
    let cx = cx().await;
    cx.configure().await;
    let (id, state) = begin(&cx).await;
    let flipped: String = state
        .chars()
        .map(|c| match c.is_ascii_lowercase() {
            true => c.to_ascii_uppercase(),
            false => c.to_ascii_lowercase(),
        })
        .collect();
    let near = [
        state[..state.len() - 1].to_owned(),
        format!("{state}x"),
        format!("{state} "),
        format!(" {state}"),
        format!("{state}\n"),
        format!("{state}\0"),
        format!("{state}{state}"),
        flipped,
        state.replace(|c: char| c.is_ascii_alphanumeric(), "%"),
        "x".repeat(10_000),
        "\u{ff53}\u{ff54}".to_owned(),
        "null".to_owned(),
        "undefined".to_owned(),
    ];
    for (i, wrong) in near.iter().enumerate() {
        let r = callback(&cx, &id, CODE, wrong).await;
        assert_eq!(
            code(&r),
            (400, "bad_request".to_owned()),
            "near miss {i} ({} bytes of {}): {}",
            wrong.len(),
            state.len(),
            r.1
        );
    }
    assert_eq!(
        cx.jf.count("POST /oauth/token"),
        0,
        "a wrong state reached the service"
    );
    assert_eq!(step(&cx, &id).await, "waiting");
    assert!(connections(&cx).await.is_empty());
    let done = callback(&cx, &id, CODE, &state).await;
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    // A finished flow's state finishes nothing on a new flow.
    let (id2, state2) = begin(&cx).await;
    assert_ne!(state, state2);
    let r = callback(&cx, &id2, CODE, &state).await;
    assert_eq!(code(&r), (400, "bad_request".to_owned()), "{}", r.1);
    cx.assert_clean().await;
}

#[tokio::test]
async fn eight_callbacks_at_once_make_one_connection_and_one_exchange() {
    let cx = cx().await;
    cx.configure().await;
    let (id, state) = begin(&cx).await;
    let calls: Vec<_> = (0..8).map(|_| callback(&cx, &id, CODE, &state)).collect();
    let all = join_all(calls).await;
    let connected = all
        .iter()
        .filter(|r| r.0 == StatusCode::OK && r.1["step"] == "connected")
        .count();
    assert!(connected >= 1, "nobody connected: {all:?}");
    for r in &all {
        assert!(
            r.0 == StatusCode::OK || r.0 == StatusCode::CONFLICT,
            "{} {}",
            r.0,
            r.1
        );
    }
    assert_eq!(
        connections(&cx).await.len(),
        1,
        "more than one connection came of one flow"
    );
    assert_eq!(
        cx.jf.count("POST /oauth/token"),
        1,
        "the code was exchanged more than once"
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_burst_of_starts_never_holds_more_than_four_waiting() {
    let cx = cx().await;
    cx.configure().await;
    let all = join_all((0..12).map(|_| start(&cx, "jira", json!({})))).await;
    let ok = all.iter().filter(|r| r.0 == StatusCode::OK).count();
    let many = all
        .iter()
        .filter(|r| code(r) == (429, "too_many_flows".to_owned()))
        .count();
    assert_eq!((ok, many), (4, 8), "{all:?}");
}

#[tokio::test]
async fn a_flow_of_this_user_is_unreachable_from_another_device_even_with_its_state() {
    let cx = cx().await;
    cx.configure().await;
    let (id, state) = begin(&cx).await;
    // Same user, another admin device.
    let twin = super::stepup::plain(&cx.fx, "twin", &["read", "admin"], true).await;
    let uri = format!("{URI}/flows/{id}");
    let attempts = [
        (Method::GET, uri.clone(), Value::Null),
        (Method::DELETE, uri.clone(), Value::Null),
        (
            Method::POST,
            format!("{uri}/callback"),
            json!({"code": CODE, "state": state}),
        ),
        (Method::POST, format!("{uri}/choose"), json!({"site": "x"})),
    ];
    for (m, u, b) in attempts {
        let r = cx.call(&twin, m.clone(), &u, b).await;
        assert_eq!(code(&r), (404, "not_found".to_owned()), "{m} {u}: {}", r.1);
    }
    assert_eq!(cx.jf.count("POST /oauth/token"), 0);
    assert_eq!(
        step(&cx, &id).await,
        "waiting",
        "the owner's flow was touched"
    );
    // Not an id at all.
    for bad in [
        "cf_",
        "cf_x",
        "../connections",
        "cf_%2e%2e",
        "CF_00000000000000000000000000",
    ] {
        let r = cx
            .admin(Method::GET, &format!("{URI}/flows/{bad}"), Value::Null)
            .await;
        assert!(matches!(r.0.as_u16(), 400 | 404), "{bad}: {} {}", r.0, r.1);
    }
    cx.assert_clean().await;
}

fn install(cx: &Cx, installation: i64, token: &str) {
    let account = format!(r#"{{"id":{installation},"account":{{"login":"octo-org"}}}}"#);
    cx.gh.push(200, &[], &account);
    cx.gh.push(
        201,
        &[],
        &format!(r#"{{"token":"{token}","expires_at":"2026-10-22T11:00:00Z"}}"#),
    );
    cx.gh.push(
        403,
        &[],
        r#"{"message":"Resource not accessible by integration"}"#,
    );
    cx.gh.push(
        200,
        &[],
        r#"{"repositories":[{"owner":{"login":"octo-org","id":9}}]}"#,
    );
}

#[tokio::test]
async fn two_workspaces_claiming_one_installation_at_once_leave_it_with_at_most_one() {
    let cx = cx().await;
    let key = pem();
    let set = json!({"fields": {"app_id": "123456", "app_key": key, "app_slug": "ainkrad-test"}});
    cx.ok(Method::PUT, "/api/v1/connection-apps/github", set)
        .await;
    let other = other_admin(&cx).await;
    for round in 0..3 {
        let n = 900 + round;
        for _ in 0..2 {
            install(&cx, n, "c6inst-aaaa1111bbbb2222");
        }
        let body = |name: &str| json!({"kind": "github", "name": name, "auth_method": "app_install", "installation_id": n});
        let (a, b) = (
            cx.admin(Method::POST, URI, body("mine")),
            cx.call(&other, Method::POST, URI, body("theirs")),
        );
        let (a, b) = tokio::join!(a, b);
        let won: Vec<i64> = [(1, &a), (2, &b)]
            .iter()
            .filter(|(_, r)| r.0 == StatusCode::OK)
            .map(|(w, _)| *w)
            .collect();
        assert!(
            won.len() <= 1,
            "round {round}: both workspaces hold installation {n}: {a:?} {b:?}"
        );
        let held: i64 =
            sqlx::query_scalar("SELECT count(*) FROM core_connections WHERE installation_id = ?")
                .bind(n)
                .fetch_one(&cx.fx.app.pool)
                .await
                .unwrap();
        assert!(
            held <= 1,
            "round {round}: {held} connections hold installation {n}"
        );
        let owner = crate::store::connections::apps::claimed_by(&cx.fx.app.pool, n)
            .await
            .unwrap();
        if let [w] = won.as_slice() {
            assert_eq!(owner, Some(*w), "round {round}");
        }
    }
    cx.assert_clean_also(&[
        "c6inst-aaaa1111bbbb2222",
        &super::connections_apps::mark(&key),
    ])
    .await;
}
