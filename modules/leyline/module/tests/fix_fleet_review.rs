//! #315 review fixes: tag targets are case-insensitive, a project target goes through the Projects
//! store, a run waiting for approval can be cancelled (and its approval is voided), the fleet card
//! shows a count and a label, and a session reaches only its own runs.

mod common;

use std::time::Duration;

use ainkrad_core_server::ops_catalog::{Pending, decide_approval, pending};
use axum::http::{Method, StatusCode};
use common::*;
use leyline_module::gate::{Action, authorize};
use serde_json::json;

async fn parked(fx: &Fx, session: &str) -> Pending {
    for _ in 0..200 {
        if let Some(p) = pending(&fx.app, session).await.unwrap().pop() {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing is waiting for approval");
}

#[tokio::test]
async fn a_tag_target_is_case_insensitive_and_a_bad_project_is_refused() {
    let fx = fx().await;
    let body = json!({"name": "web1", "address": "web1.example.com", "username": "deploy",
        "ai_rule": "allowed", "tags": ["web"]});
    let (s, v) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/fleet/runs",
        Some(json!({"command": "c", "tag": "WEB"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["started"], 1);
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/fleet/runs",
        Some(json!({"command": "c", "project": "999999"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_run_waiting_for_approval_can_be_cancelled_and_its_approval_is_void() {
    let fx = fx().await;
    add(&fx, "ask1", "ask").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let (ai, _dev) = session(&fx, "as_w").await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let app = fx.app.clone();
    let h = tokio::spawn(async move { authorize(&app, &ai, "ask1", &action).await });
    let req = parked(&fx, "as_w").await;
    let run = states(
        &fx,
        "SELECT id FROM leyline_runs WHERE principal = ?",
        "session:as_w",
    )
    .await
    .remove(0);
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/runs/{run}/cancel"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let r = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
    assert!(r.is_err(), "the parked call ends");
    assert_eq!(
        states(&fx, "SELECT state FROM leyline_runs WHERE id = ?", &run).await,
        ["cancelled"]
    );
    assert_eq!(
        states(
            &fx,
            "SELECT state FROM core_code_mode_approvals WHERE id = ?",
            &req.id
        )
        .await,
        ["void"]
    );
}

#[tokio::test]
async fn the_fleet_card_shows_a_count_and_a_label_not_every_host() {
    let fx = fx().await;
    for n in ["a1", "a2", "a3"] {
        let body = json!({"name": n, "address": format!("{n}.example.com"), "username": "deploy",
            "ai_rule": "ask", "group": "edge"});
        let (s, v) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let (ai, dev) = session(&fx, "as_f").await;
    let me = caller(&fx, &dev, "code_mode:as_f").await;
    let _ = ai;
    let fx2 = std::sync::Arc::new(fx);
    let f = fx2.clone();
    let h = tokio::spawn(async move {
        as_caller(
            &f,
            me,
            Method::POST,
            "/fleet/runs",
            Some(json!({"command": "c", "group": "edge"})),
        )
        .await
    });
    let p = parked(&fx2, "as_f").await;
    assert_eq!(p.args["hosts"], 3, "{}", p.args);
    assert!(
        p.args["fleet"].as_str().unwrap().contains("group edge"),
        "{}",
        p.args
    );
    assert!(!p.args.to_string().contains("a1"), "{}", p.args);
    decide_approval(&fx2.app, "as_f", &p.id, false, &dev)
        .await
        .unwrap();
    let _ = h.await;
}

#[tokio::test]
async fn a_session_reaches_only_its_own_runs() {
    let fx = fx().await;
    add(&fx, "web", "allowed").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let (a, _) = session(&fx, "as_a").await;
    let (_, dev_b) = session(&fx, "as_b").await;
    let action = Action::Preset(c["id"].as_str().unwrap().into());
    let run = authorize(&fx.app, &a, "web", &action)
        .await
        .unwrap()
        .run_id()
        .to_owned();
    let b = caller(&fx, &dev_b, "code_mode:as_b").await;
    let (s, _) = as_caller(&fx, b.clone(), Method::GET, &format!("/runs/{run}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = as_caller(&fx, b, Method::POST, &format!("/runs/{run}/cancel"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // a person still reads and cancels everything
    let (s, _) = call(&fx, &fx.admin, Method::GET, &format!("/runs/{run}"), None).await;
    assert_eq!(s, StatusCode::OK);
}
