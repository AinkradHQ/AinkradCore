//! The chain routes' guards (S7): the non-admin 403, the missing step-up, another user's chains,
//! the contract's marks, the deprecation of the pool bindings, and that nothing holds a key.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::chains::{make, pool, setup};
use super::chains_api::{call, refusal, routes, second_user};
use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::accounts as acc;
use crate::store::chains as ch;
use crate::store::pools as pl;

const KEY: &str = "throwaway-chain-value-3f7a19c2";
const BY: ainkrad_core::audit::AuditActor = super::super::BY;

#[tokio::test]
async fn a_non_admin_is_refused_everywhere_and_a_write_needs_a_step_up() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let reader = fx.enroll("reader", &["read", "approve"]).await;
    let agent = super::stepup::plain(&fx, "agent", &["agent", "read"], true).await;
    super::stepup::step_up(&fx, &agent).await;
    for dev in [&reader, &agent] {
        for (m, uri, body, _) in routes(c.id, a) {
            let r = call(&fx, dev, m.clone(), &uri, body).await;
            assert_eq!(refusal(&r), (403, "forbidden_scope"), "{m} {uri}: {}", r.1);
        }
    }
    // An admin that never stepped up reads, and every write needs one.
    let plain = super::stepup::plain(&fx, "plain", &["read", "admin"], true).await;
    for (m, uri, body, write) in routes(c.id, a) {
        let r = call(&fx, &plain, m.clone(), &uri, body).await;
        match write {
            true => assert_eq!(refusal(&r), (403, "step_up_required"), "{m} {uri}: {}", r.1),
            false => assert_eq!(r.0, StatusCode::OK, "{m} {uri}: {}", r.1),
        }
    }
    // Nothing changed.
    let all = ch::list(&fx.app.pool).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!((all[0].name.as_str(), all[0].is_default), ("main", false));
    assert!(ch::list_bindings(&fx.app.pool).await.unwrap().is_empty());
}

#[tokio::test]
async fn another_users_chains_pools_and_bindings_do_not_exist_for_a_caller() {
    let fx = setup().await;
    let (a, b) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "b", "anthropic").await,
    );
    let mine = make(&fx, "main", &[a]).await;
    ch::bind(&fx.app.pool, "agent-1", mine.id, "d_x", BY, NOW)
        .await
        .unwrap();
    let other = second_user(&fx).await;
    // A list is the caller's own; a read, edit, delete, default or bind of mine is 404.
    assert_eq!(
        call(&fx, &other, Method::GET, "/api/v1/chains", Value::Null)
            .await
            .1,
        json!([])
    );
    assert_eq!(
        call(
            &fx,
            &other,
            Method::GET,
            "/api/v1/chains/bindings",
            Value::Null
        )
        .await
        .1,
        json!([])
    );
    let one = format!("/api/v1/chains/{}", mine.id);
    for (m, uri, body) in [
        (Method::GET, one.clone(), Value::Null),
        (
            Method::PUT,
            one.clone(),
            json!({"name": "stolen", "entries": [{"pool": a}]}),
        ),
        (Method::DELETE, one.clone(), Value::Null),
        (Method::PUT, format!("{one}/default"), Value::Null),
        (
            Method::PUT,
            "/api/v1/chains/bindings/agent-2".to_owned(),
            json!({"chain": mine.id}),
        ),
        (
            Method::DELETE,
            "/api/v1/chains/bindings/agent-1".to_owned(),
            Value::Null,
        ),
    ] {
        let r = call(&fx, &other, m.clone(), &uri, body).await;
        assert_eq!(refusal(&r), (404, "not_found"), "{m} {uri}: {}", r.1);
    }
    // A pool of mine answers as a missing one (404, the same as a pool that is not there); the name
    // is checked first and names are global, so a taken name is a 409 (an accepted oracle).
    let r = call(
        &fx,
        &other,
        Method::POST,
        "/api/v1/chains",
        json!({"name": "theirs", "entries": [{"pool": b}]}),
    )
    .await;
    assert_eq!(refusal(&r), (404, "not_found"), "{}", r.1);
    let ghost = call(
        &fx,
        &other,
        Method::POST,
        "/api/v1/chains",
        json!({"name": "theirs", "entries": [{"pool": 9999}]}),
    )
    .await;
    assert_eq!(refusal(&ghost), (404, "not_found"));
    let same = |v: &Value, n: i64| {
        v["message"]
            .as_str()
            .map(|m| m.replace(&n.to_string(), "N"))
    };
    assert_eq!(
        same(&r.1, b),
        same(&ghost.1, 9999),
        "no difference to tell them apart"
    );
    let r = call(
        &fx,
        &other,
        Method::POST,
        "/api/v1/chains",
        json!({"name": "main", "entries": [{"pool": b}]}),
    )
    .await;
    assert_eq!(refusal(&r), (409, "conflict"), "{}", r.1);
    // Mine are untouched.
    let c = ch::get(&fx.app.pool, mine.id).await.unwrap();
    assert_eq!((c.name.as_str(), c.entries.len()), ("main", 1));
    assert_eq!(ch::list_bindings(&fx.app.pool).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_contract_marks_every_chain_route_admin_and_each_write_destructive() {
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let id = 1;
    for (m, uri, _, write) in routes(id, 1) {
        let template = uri
            .replace(&format!("/chains/{id}"), "/chains/{id}")
            .replace("agent-9", "{agent}");
        let op = &spec["paths"][template.as_str()][m.as_str().to_lowercase()];
        assert_eq!(op["x-ainkrad-scope"], "admin", "{m} {template}");
        assert_eq!(
            op["x-ainkrad-destructive"] == json!(true),
            write,
            "{m} {template}: destructive only when it writes"
        );
    }
    // The routes that overlap by shape resolve to their own template.
    use crate::api::v1::scopes::{destructive, required};
    for (m, p, d) in [
        (Method::PUT, "/api/v1/chains/bindings/default", true),
        (Method::PUT, "/api/v1/chains/default/default", true),
        (Method::GET, "/api/v1/chains/bindings", false),
        (Method::GET, "/api/v1/chains/7", false),
    ] {
        assert_eq!(required(&m, p, &[]), Some("admin"), "{m} {p}");
        assert_eq!(destructive(&m, p, &[]), d, "{m} {p}");
    }
}

#[tokio::test]
async fn the_pool_bindings_are_deprecated_and_still_answer() {
    let fx = fx().await;
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    for (m, p) in [
        ("get", "/api/v1/bindings"),
        ("put", "/api/v1/bindings"),
        ("delete", "/api/v1/bindings/{agent}/{provider}"),
    ] {
        let op = &spec["paths"][p][m];
        assert_eq!(op["deprecated"], true, "{m} {p}");
        assert!(
            op["x-ainkrad-sunset"]
                .as_str()
                .unwrap()
                .ends_with("2027 00:00:00 GMT")
        );
    }
    // The chains' own routes are not.
    assert!(spec["paths"]["/api/v1/chains/bindings"]["get"]["deprecated"].is_null());
    let r = crate::api::router(fx.app.clone())
        .oneshot(req(Method::GET, "/api/v1/bindings", Some(&fx.dev), None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["deprecation"], "@1793923200");
    assert!(r.headers()["sunset"].to_str().unwrap().contains("May 2027"));
    let r = crate::api::router(fx.app.clone())
        .oneshot(req(
            Method::GET,
            "/api/v1/chains/bindings",
            Some(&fx.dev),
            None,
        ))
        .await
        .unwrap();
    assert!(r.headers().get("deprecation").is_none());
}

#[tokio::test]
async fn no_chain_route_and_no_event_or_audit_row_holds_a_key() {
    let fx = setup().await;
    crate::store::settings::set(
        &fx.app.pool,
        ainkrad_core::settings::Key::SecretsMode,
        ainkrad_core::settings::Scope::Server,
        "1",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let new = acc::NewAccount {
        provider: "anthropic",
        label: "claude-main",
        value: KEY,
        runners: &[],
        cap: None,
    };
    let account = acc::create(
        &fx.app.pool,
        &SecretBox::new(&[7; 32]),
        &new,
        &fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
    let p = pool(&fx, "a", "anthropic").await;
    pl::add_member(&fx.app.pool, p, account.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let c = make(&fx, "main", &[p]).await;
    let mut seen = Vec::new();
    for (m, uri, body, _) in routes(c.id, p) {
        // Writes run against the one chain too: the answers are swept, whatever they are.
        seen.push(call(&fx, &fx.dev, m, &uri, body).await.1.to_string());
    }
    for uri in [
        "/api/v1/chains",
        "/api/v1/chains/bindings",
        "/api/v1/accounts",
        "/api/v1/pools",
    ] {
        seen.push(fx.ok(uri).await.to_string());
    }
    // The load and health of an account are for admins: a reader sees none (it would show what
    // other users run).
    let reader = fx.enroll("reader", &["read"]).await;
    let theirs = call(&fx, &reader, Method::GET, "/api/v1/accounts", Value::Null)
        .await
        .1;
    assert!(
        theirs[0]["live"].is_null() && theirs[0]["health"].is_null(),
        "{theirs}"
    );
    assert_eq!(fx.ok("/api/v1/accounts").await[0]["live"], 0);
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events UNION ALL SELECT payload FROM events")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    let rows_at = rows.len();
    seen.extend(rows);
    for (i, text) in seen.iter().enumerate() {
        assert!(!text.contains(KEY), "{i} leaked the key: {text}");
    }
    // The broker secret's name is not an API field either.
    for text in &seen[..seen.len() - rows_at] {
        assert!(!text.contains("acct."), "a response named a secret: {text}");
    }
}
