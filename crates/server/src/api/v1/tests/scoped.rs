//! Scoped event streams (E1-04.3): a read-only device, over the HTTP replay and the socket,
//! never gets a kind its scopes may not see (terminal output, the audit stream), and its
//! numbering is gap-free, so it cannot tell that one exists or how many there were.

use super::events::{connect, next, quick, serve};
use super::*;

/// Five rounds of: terminal output, a read-level line, an audited change, more output.
async fn mixed(fx: &Fx) {
    let pool = &fx.app.pool;
    let mut tx = crate::store::begin_write(pool).await.unwrap();
    crate::store::kinds::register(&mut tx, "term", &[("term.out", "terminal")], &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    for n in 0..5 {
        let mut tx = crate::store::begin_write(pool).await.unwrap();
        for kind in ["term.out", "ops.line", "term.out"] {
            crate::store::events::append(&mut tx, kind, &json!({"n": n}))
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let e = ainkrad_core::audit::NewAuditEvent {
            actor: ainkrad_core::audit::AuditActor::System,
            action: "thing.done".to_owned(),
            entity: None,
            details: json!({}).to_string(),
        };
        crate::store::audit::append_one(pool, &e).await.unwrap();
    }
}

#[tokio::test]
async fn a_read_only_device_neither_sees_nor_can_count_hidden_events() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read", "approve"]).await;
    mixed(&fx).await;
    let as_phone = |uri: &str| req(Method::GET, uri, Some(&phone), None);

    let (s, page) = send(&fx.app, as_phone("/api/v1/events?after=0")).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let items = page["items"].as_array().unwrap();
    assert!(items.iter().all(|e| e["kind"] == "ops.line"), "{page}");
    let seqs: Vec<i64> = items.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5], "gap-free in its own view");
    let (_, latest) = send(&fx.app, as_phone("/api/v1/events/latest")).await;
    assert_eq!(latest, json!({"seq": 5, "floor": 0}));
    let (_, page) = send(&fx.app, as_phone("/api/v1/events?after=3")).await;
    assert_eq!(page["items"][0]["seq"], json!(4));

    // The socket: the same view, from 0 and from the head (live).
    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &phone, Some("0")).await.unwrap();
    for want in 1..=5 {
        let e = next(&mut ws).await;
        assert_eq!(
            (e["seq"].as_i64(), e["kind"].as_str()),
            (Some(want), Some("ops.line"))
        );
    }
    let mut live = connect(&app, &phone, None).await.unwrap();
    mixed(&fx).await;
    for ws in [&mut ws, &mut live] {
        for want in 6..=10 {
            let e = next(ws).await;
            assert_eq!(
                (e["seq"].as_i64(), e["kind"].as_str()),
                (Some(want), Some("ops.line"))
            );
        }
    }

    // The admin's Mac sees everything, numbered as the log itself.
    let (_, page) = send(
        &fx.app,
        req(Method::GET, "/api/v1/events?after=0", Some(&fx.dev), None),
    )
    .await;
    let all = page["items"].as_array().unwrap();
    let head = crate::store::events::last_event_seq(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(all.len() as i64, head);
    assert!(
        all.iter().any(|e| e["kind"] == "term.out") && all.iter().any(|e| e["kind"] == "audit")
    );
    let seqs: Vec<i64> = all.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    assert_eq!(seqs, (1..=head).collect::<Vec<_>>());
    // A terminal-scoped device sees terminal output but not the audit stream.
    let term = fx.enroll("term", &["read", "terminal"]).await;
    let (_, page) = send(
        &fx.app,
        req(Method::GET, "/api/v1/events?after=0", Some(&term), None),
    )
    .await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 30);
    assert!(items.iter().all(|e| e["kind"] != "audit"));
}

/// T-EV-1 for the platform's own terminal events (E2-01): a `read` device never sees a
/// `terminal.*` event, in replay or live; a `terminal` device does.
#[tokio::test]
async fn terminal_events_are_hidden_from_a_read_device() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read", "approve"]).await;
    let term = fx.enroll("term", &["read", "terminal"]).await;
    let mut tx = crate::store::begin_write(&fx.app.pool).await.unwrap();
    for kind in ["terminal.opened", "terminal.attached", "terminal.closed"] {
        crate::store::events::append(&mut tx, kind, &json!({"terminal": "t_x"}))
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let page = |dev| req(Method::GET, "/api/v1/events?after=0", Some(dev), None);
    let (s, seen) = send(&fx.app, page(&phone)).await;
    assert_eq!(s, StatusCode::OK, "{seen}");
    assert!(
        seen["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| !e["kind"].as_str().unwrap().starts_with("terminal.")),
        "{seen}"
    );
    let (_, seen) = send(&fx.app, page(&term)).await;
    let kinds: Vec<&str> = seen["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert_eq!(
        kinds,
        ["terminal.opened", "terminal.attached", "terminal.closed"]
    );
}
