//! Y4-02 review, LOW: what `still_valid` re-checks and what the gate decides on: a revoked person
//! stops, a jump hop's connection is part of the host, a command's scope is checked and hashed by
//! the gate (so a fleet run inherits it), and a session needs a person for a `confirm` command
//! even on an `allowed` host.

mod common;

use std::time::Duration;

use ainkrad_core_server::ops_catalog::{decide_approval, pending};
use axum::http::{Method, StatusCode};
use common::*;
use leyline_module::gate::{Action, authorize, authorize_confirmed, authorize_many, still_valid};
use serde_json::json;

#[tokio::test]
async fn a_revoked_person_stops_between_steps() {
    let fx = fx().await;
    let h = add(&fx, "web", "allowed").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let id = c["id"].as_str().unwrap();
    let who = person(&fx).await;
    let a = authorize(&fx.app, &who, &h, &Action::Preset(id.into()))
        .await
        .unwrap();
    still_valid(&fx.app, &a).await.unwrap();
    sqlx::query("UPDATE core_devices SET revoked_at = '2026-11-18T00:00:00Z' WHERE id = ?")
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        still_valid(&fx.app, &a).await.unwrap_err().code,
        "gate_refused"
    );
}

#[tokio::test]
async fn a_jump_hops_connection_is_part_of_the_host() {
    let fx = fx().await;
    let hop = add(&fx, "bastion", "allowed").await;
    let body = json!({"name": "inner", "address": "inner.example.com", "username": "deploy",
        "ai_rule": "allowed", "jump_chain": [hop]});
    let (s, v) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let inner = v["id"].as_str().unwrap().to_owned();
    let c = mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let id = c["id"].as_str().unwrap();
    let who = person(&fx).await;
    let a = authorize(&fx.app, &who, &inner, &Action::Preset(id.into()))
        .await
        .unwrap();
    still_valid(&fx.app, &a).await.unwrap();
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/hosts/{hop}"),
        Some(json!({"address": "evil.example.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        still_valid(&fx.app, &a).await.unwrap_err().code,
        "gate_refused"
    );
}

#[tokio::test]
async fn the_gate_checks_the_commands_scope_per_host() {
    let fx = fx().await;
    let inside = add(&fx, "inside", "allowed").await;
    let outside = add(&fx, "outside", "allowed").await;
    let c = mk(
        &fx,
        json!({"name": "c", "steps": ["one"], "scope": {"kind": "host", "value": inside}}),
    )
    .await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let who = person(&fx).await;
    let g = authorize_many(&fx.app, &who, &[&inside, &outside], &action)
        .await
        .unwrap();
    assert_eq!(g.authorized.len(), 1);
    assert_eq!(g.authorized[0].host_id(), inside);
    assert_eq!(g.refused.len(), 1);
    assert_eq!(g.refused[0].0, outside);
    // one host: the same refusal as before the move, a 409
    let e = authorize(&fx.app, &who, &outside, &action)
        .await
        .unwrap_err();
    assert_eq!(e.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_confirm_command_from_a_session_asks_even_on_an_allowed_host() {
    let fx = fx().await;
    add(&fx, "web", "allowed").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"], "confirm": true})).await;
    let (ai, dev) = session(&fx, "as_cf").await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let app = fx.app.clone();
    let h = tokio::spawn(async move { authorize_confirmed(&app, &ai, "web", &action, true).await });
    // It parks for a person instead of running at once.
    let req = parked(&fx, "as_cf").await;
    decide_approval(&fx.app, "as_cf", &req, false, &dev)
        .await
        .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err(), "denied by the person");
}

/// The request id the session waits on, once parked.
async fn parked(fx: &Fx, session: &str) -> String {
    for _ in 0..200 {
        if let Some(p) = pending(&fx.app, session).await.unwrap().pop() {
            return p.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing is waiting for approval");
}
