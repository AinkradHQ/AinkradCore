//! The chain routes (S7; design 2026-11-06 §13): every route's success, the wrong user's 404, the
//! non-admin 403, the missing step-up, the 400s of validation and the 409s of conflict, the
//! contract's scope and destructive marks, and that nothing a route, an event or an audit row says
//! holds a key.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::chains::{make, pool, setup};
use super::*;
use crate::store::chains as ch;

pub(super) async fn call(
    fx: &Fx,
    dev: &TestDevice,
    m: Method,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

pub(super) fn refusal(r: &(StatusCode, Value)) -> (u16, &str) {
    (r.0.as_u16(), r.1["code"].as_str().unwrap_or_default())
}

/// A second user's admin device.
pub(super) async fn second_user(fx: &Fx) -> TestDevice {
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let dev = fx.enroll("second", &["read", "admin", "agent"]).await;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&dev.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    dev
}

#[tokio::test]
async fn a_chain_is_written_read_replaced_defaulted_bound_and_deleted() {
    let fx = setup().await;
    let (a, o) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
    );
    let (s, made) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/chains",
        json!({"name": "main", "entries": [{"pool": a}, {"pool": o, "model": "gpt-test"}]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let id = made["id"].as_i64().unwrap();
    assert_eq!(
        (&made["name"], &made["is_default"]),
        (&json!("main"), &json!(false))
    );
    assert_eq!(
        made["entries"],
        json!([{"pool": a, "provider": "anthropic", "harness": "claude", "model": null},
               {"pool": o, "provider": "openai", "harness": "codex", "model": "gpt-test"}])
    );
    let one = format!("/api/v1/chains/{id}");
    assert_eq!(fx.ok("/api/v1/chains").await, json!([made]));
    assert_eq!(fx.ok(&one).await, made);

    // Replace: the name and the whole list, in the new order.
    let (s, edited) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &one,
        json!({"name": "main2", "entries": [{"pool": o, "model": "gpt-test"}]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{edited}");
    assert_eq!(edited["name"], "main2");
    assert_eq!(edited["entries"].as_array().unwrap().len(), 1);
    assert_eq!(edited["entries"][0]["pool"], o);

    // Default, then a second default moves it.
    let (s, d) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{one}/default"),
        Value::Null,
    )
    .await;
    assert_eq!((s, &d["is_default"]), (StatusCode::OK, &json!(true)), "{d}");
    let other = make(&fx, "other", &[a]).await;
    let (s, d2) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("/api/v1/chains/{}/default", other.id),
        Value::Null,
    )
    .await;
    assert_eq!(
        (s, &d2["is_default"]),
        (StatusCode::OK, &json!(true)),
        "{d2}"
    );
    assert_eq!(fx.ok(&one).await["is_default"], false);

    // Bindings: bind, rebind replaces, list, unbind.
    let bind = "/api/v1/chains/bindings/agent-1";
    for chain in [id, other.id] {
        let (s, b) = call(&fx, &fx.dev, Method::PUT, bind, json!({"chain": chain})).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b, json!({"agent": "agent-1", "chain": chain}));
    }
    assert_eq!(
        fx.ok("/api/v1/chains/bindings").await,
        json!([{"agent": "agent-1", "chain": other.id}])
    );
    let (s, b) = call(&fx, &fx.dev, Method::DELETE, bind, Value::Null).await;
    assert_eq!((s, &b["deleted"]), (StatusCode::OK, &json!(true)), "{b}");
    assert_eq!(fx.ok("/api/v1/chains/bindings").await, json!([]));

    // Delete, and it is gone.
    let (s, b) = call(&fx, &fx.dev, Method::DELETE, &one, Value::Null).await;
    assert_eq!((s, &b["deleted"]), (StatusCode::OK, &json!(true)), "{b}");
    assert_eq!(
        call(&fx, &fx.dev, Method::GET, &one, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );

    // Every write is audited, by name and id.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'chain.%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    for want in [
        "chain.created",
        "chain.updated",
        "chain.default_set",
        "chain.bound",
        "chain.unbound",
        "chain.deleted",
    ] {
        assert!(actions.iter().any(|a| a == want), "{want} in {actions:?}");
    }
}

#[tokio::test]
async fn validation_refuses_with_400_and_conflicts_with_409_and_a_missing_row_is_404() {
    let fx = setup().await;
    let (a, b, o) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "b", "anthropic").await,
        pool(&fx, "o", "openai").await,
    );
    let post = |body: Value| call(&fx, &fx.dev, Method::POST, "/api/v1/chains", body);
    let bad = [
        (
            "a name",
            json!({"name": "Bad Name", "entries": [{"pool": a}]}),
        ),
        ("no entries", json!({"name": "c0", "entries": []})),
        (
            "five entries",
            json!({"name": "c5", "entries": [{"pool": a}, {"pool": b}, {"pool": o},
                {"pool": a}, {"pool": b}]}),
        ),
        (
            "a pool twice",
            json!({"name": "twice", "entries": [{"pool": a}, {"pool": a}]}),
        ),
        (
            "an unpriced model",
            json!({"name": "unpriced", "entries": [{"pool": a, "model": "no-such-model"}]}),
        ),
        (
            "a bad model id",
            json!({"name": "badmodel", "entries": [{"pool": a, "model": "has space"}]}),
        ),
        ("no entries field", json!({"name": "noentries"})),
        (
            "a pool of the wrong type",
            json!({"name": "wrongtype", "entries": [{"pool": "a"}]}),
        ),
    ];
    for (why, body) in bad {
        let r = post(body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // Not an object at all: one fixed message that never quotes the body.
    let junk = Value::String("{not json: sk-ant-xyz".to_owned());
    let r = post(junk).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    assert!(!r.1.to_string().contains("sk-ant"));
    // A pool that is not there: 404.
    let r = post(json!({"name": "ghost", "entries": [{"pool": 9999}]})).await;
    assert_eq!(refusal(&r), (404, "not_found"), "{}", r.1);
    // A taken name, and a chain a live session walks: 409.
    let main = make(&fx, "main", &[a]).await;
    let r = post(json!({"name": "main", "entries": [{"pool": a}]})).await;
    assert_eq!(refusal(&r), (409, "conflict"), "{}", r.1);
    let r = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("/api/v1/chains/{}", main.id),
        json!({"name": "main", "entries": [{"pool": b}]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "a chain keeps its own name: {}", r.1);
    let session = super::chains_session::session(
        &fx,
        &[],
        None,
        ch::Request {
            user_id: 1,
            chain: Some(main.id),
            agent: None,
        },
    )
    .await
    .unwrap();
    let r = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        &format!("/api/v1/chains/{}", main.id),
        Value::Null,
    )
    .await;
    assert_eq!(refusal(&r), (409, "conflict"), "{}", r.1);
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&session.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    // The 65th chain: 409 limit_reached.
    for n in 0..ch::MAX_CHAINS - 1 {
        make(&fx, &format!("fill{n}"), &[a]).await;
    }
    let r = post(json!({"name": "overflow", "entries": [{"pool": a}]})).await;
    assert_eq!(refusal(&r), (409, "limit_reached"), "{}", r.1);
    // Missing and non-numeric ids, an unbound agent, a bad agent id, a missing chain on a bind.
    for (m, uri, body) in [
        (Method::GET, "/api/v1/chains/9999", Value::Null),
        (Method::GET, "/api/v1/chains/abc", Value::Null),
        (
            Method::PUT,
            "/api/v1/chains/9999",
            json!({"name": "x", "entries": [{"pool": a}]}),
        ),
        (Method::DELETE, "/api/v1/chains/9999", Value::Null),
        (Method::PUT, "/api/v1/chains/9999/default", Value::Null),
        (
            Method::PUT,
            "/api/v1/chains/bindings/agent-1",
            json!({"chain": 9999}),
        ),
        (
            Method::DELETE,
            "/api/v1/chains/bindings/never-bound",
            Value::Null,
        ),
    ] {
        let r = call(&fx, &fx.dev, m.clone(), uri, body).await;
        assert_eq!(refusal(&r), (404, "not_found"), "{m} {uri}: {}", r.1);
    }
    let r = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/chains/bindings/bad%20agent",
        json!({"chain": main.id}),
    )
    .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
}

/// Every chain route, with a body where it takes one, and whether it writes.
pub(super) fn routes(id: i64, pool: i64) -> Vec<(Method, String, Value, bool)> {
    let body = json!({"name": "other", "entries": [{"pool": pool}]});
    vec![
        (Method::GET, "/api/v1/chains".to_owned(), Value::Null, false),
        (
            Method::POST,
            "/api/v1/chains".to_owned(),
            body.clone(),
            true,
        ),
        (
            Method::GET,
            "/api/v1/chains/bindings".to_owned(),
            Value::Null,
            false,
        ),
        (
            Method::PUT,
            "/api/v1/chains/bindings/agent-9".to_owned(),
            json!({"chain": id}),
            true,
        ),
        (
            Method::DELETE,
            "/api/v1/chains/bindings/agent-9".to_owned(),
            Value::Null,
            true,
        ),
        (
            Method::GET,
            format!("/api/v1/chains/{id}"),
            Value::Null,
            false,
        ),
        (Method::PUT, format!("/api/v1/chains/{id}"), body, true),
        (
            Method::DELETE,
            format!("/api/v1/chains/{id}"),
            Value::Null,
            true,
        ),
        (
            Method::PUT,
            format!("/api/v1/chains/{id}/default"),
            Value::Null,
            true,
        ),
    ]
}
