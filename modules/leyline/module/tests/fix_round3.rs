//! #308 review round 3: confirm on every rule, step-up to drop `confirm` on a read-only command,
//! the shared text redaction, `$VAR` values on a card, literal secrets refused in steps.

mod common;

use std::time::Duration;

use ainkrad_core_server::ops_catalog::{decide_approval, pending};
use axum::http::{Method, StatusCode};
use common::*;
use leyline_module::gate::{Action, authorize, authorize_confirmed};
use serde_json::json;

async fn parked(fx: &Fx, session: &str) -> String {
    for _ in 0..200 {
        if let Some(p) = pending(&fx.app, session).await.unwrap().pop() {
            return p.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing is waiting for approval");
}

#[tokio::test]
async fn a_confirm_command_from_a_session_asks_on_a_read_only_host_too() {
    let fx = fx().await;
    add(&fx, "ro", "read_only").await;
    let c = mk(
        &fx,
        json!({"name": "c", "steps": ["one"], "confirm": true, "read_only": true}),
    )
    .await;
    let (ai, dev) = session(&fx, "as_ro").await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let app = fx.app.clone();
    let h = tokio::spawn(async move { authorize(&app, &ai, "ro", &action).await });
    let req = parked(&fx, "as_ro").await;
    decide_approval(&fx.app, "as_ro", &req, false, &dev)
        .await
        .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err());
}

#[tokio::test]
async fn dropping_confirm_on_a_read_only_command_needs_a_step_up() {
    let fx = fx().await;
    let c = mk(
        &fx,
        json!({"name": "c", "steps": ["one"], "confirm": true, "read_only": true}),
    )
    .await;
    let path = format!("/commands/{}", c["id"].as_str().unwrap());
    let body = Some(json!({"confirm": false}));
    let (s, v) = call(&fx, &fx.weak, Method::PATCH, &path, body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = call(&fx, &fx.admin, Method::PATCH, &path, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn the_gate_judges_confirm_on_the_command_it_reads() {
    let fx = fx().await;
    add(&fx, "web", "allowed").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"], "confirm": true})).await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let who = person(&fx).await;
    let e = authorize_confirmed(&fx.app, &who, "web", &action, false)
        .await
        .unwrap_err();
    assert_eq!(e.code, "confirm_required");
    authorize_confirmed(&fx.app, &who, "web", &action, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_literal_secret_in_a_step_is_refused_but_a_variable_is_not() {
    let fx = fx().await;
    for step in [
        "curl -H \"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\" x",
        "export DB_PASSWORD=hunter2",
    ] {
        let (s, v) = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/commands",
            Some(json!({"name": "bad", "steps": [step]})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(v.to_string().contains("contains a secret"), "{v}");
    }
    let c = mk(&fx, json!({"name": "ok", "steps": ["export DB_PASSWORD=$DB_PASSWORD", "curl -H \"Authorization: Bearer ${TOKEN}\" x", "login --pw=$(cat /run/pw)"]})).await;
    let path = format!("/commands/{}", c["id"].as_str().unwrap());
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &path,
        Some(json!({"steps": ["export API_TOKEN=abc123"]})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v.to_string().contains("contains a secret"), "{v}");
}

#[tokio::test]
async fn a_variable_value_is_shown_on_the_card_and_a_literal_one_is_refused() {
    let fx = fx().await;
    add(&fx, "ask", "ask").await;
    let (ai, dev) = session(&fx, "as_card").await;
    let e = authorize(
        &fx.app,
        &ai,
        "ask",
        &Action::Exec("export DB_PASSWORD=hunter2".into()),
    )
    .await
    .unwrap_err();
    assert_eq!(e.message, "the command contains a secret");
    let app = fx.app.clone();
    let h = tokio::spawn(async move {
        authorize(
            &app,
            &ai,
            "ask",
            &Action::Exec("export DB_PASSWORD=$DB_PASSWORD".into()),
        )
        .await
    });
    let req = parked(&fx, "as_card").await;
    decide_approval(&fx.app, "as_card", &req, false, &dev)
        .await
        .unwrap();
    assert!(h.await.unwrap().is_err()); // parked (shown), then the person said no
}
