//! A session naming no chain and no agent, with no account of its own, gets the user's default
//! chain (e2e round 1: a fresh Core's first session was refused `no_account`).

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::super::agents::sched::default_chain;
use super::chains::{make, pool, setup};
use super::*;
use crate::store::agents::SessionSecret;
use crate::store::chains as ch;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

#[tokio::test]
async fn a_plain_session_with_no_account_gets_the_default_chain() {
    let fx = setup().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let dev = fx.dev.id.clone();
    let none: &[SessionSecret] = &[];
    // No default chain yet: nothing to fall back to.
    let got = default_chain(&fx.app, &dev, true, &vm.id, "claude", none)
        .await
        .unwrap();
    assert_eq!(got, None);
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    ch::set_default(&fx.app.pool, c.id, "d_x", BY, NOW)
        .await
        .unwrap();
    for harness in ["claude", "codex", ""] {
        let got = default_chain(&fx.app, &dev, true, &vm.id, harness, none)
            .await
            .unwrap();
        assert_eq!(got, Some(c.id), "{harness}");
    }
    // An account of its own, a pinned account, a harness with no account, or no admin: none.
    let own = [SessionSecret {
        name: "k".into(),
        var: "ANTHROPIC_API_KEY".into(),
    }];
    let pinned = [SessionSecret {
        name: "acct.anthropic.1".into(),
        var: "ANTHROPIC_API_KEY".into(),
    }];
    for (harness, secrets, admin) in [
        ("claude", &own[..], true),
        ("", &pinned[..], true),
        ("opencode", none, true),
        ("claude", none, false),
    ] {
        let got = default_chain(&fx.app, &dev, admin, &vm.id, harness, secrets)
            .await
            .unwrap();
        assert_eq!(got, None, "{harness} {admin}");
    }
    // Over the API: a create naming no harness used to be a 400; it now goes the chain's way and
    // reaches the runner (not connected here).
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let body = json!({"runner": vm.id, "policy": policy});
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/agent-sessions",
            Some(&fx.dev),
            Some(body),
        ),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline")),
        "{}",
        r.1
    );
}
