//! Attachments of AI sessions (E4) at the Core's routes and store, without a runner: an upload is
//! kept with its session and audited, sizes and names are checked, a message may name only its own
//! session's attachments, a pending message keeps them for its supervisor, and they go with the
//! session. The runner end to end is `tests/hub/attachments.rs`.

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};

use super::*;
use crate::store::agents as sessions;
use crate::store::attachments;

async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(m, uri, Some(&fx.dev), Some(body))).await
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

async fn upload(fx: &Fx, s: &sessions::Session, name: &str, data: &[u8]) -> (StatusCode, Value) {
    let uri = format!("/api/v1/agent-sessions/{}/attachments", s.id);
    call(
        fx,
        Method::POST,
        &uri,
        json!({"name": name, "data": b64(data)}),
    )
    .await
}

async fn held(fx: &Fx, s: &sessions::Session) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM core_agent_attachments WHERE session = ?")
        .bind(&s.id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_upload_is_kept_with_its_session_and_audited_by_id_and_size_only() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = super::folder::session(&fx, &vm.id).await;
    let (status, body) = upload(&fx, &s, "shot.png", b"abc").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_str().unwrap();
    assert!(id.starts_with("at_"));
    assert_eq!(body["size"], 3);
    assert_eq!(
        body["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let (name, data) = attachments::load(&fx.app.pool, &s.id, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((name.as_str(), data.as_slice()), ("shot.png", &b"abc"[..]));
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'agent.attachment_added'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(
        details.contains(id) && details.contains("\"bytes\":3"),
        "{details}"
    );
    assert!(
        !details.contains("shot.png"),
        "the name is the user's: {details}"
    );
}

#[tokio::test]
async fn sizes_and_names_are_checked() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = super::folder::session(&fx, &vm.id).await;
    let code = |r: (StatusCode, Value)| (r.0, r.1["code"].as_str().unwrap_or("").to_owned());
    for bad in ["", ".", "..", "a/b", "..\\x", "a\u{0}b", &"x".repeat(256)] {
        assert_eq!(
            code(upload(&fx, &s, bad, b"x").await),
            (StatusCode::BAD_REQUEST, "bad_attachment_name".into()),
            "{bad:?}"
        );
    }
    assert_eq!(upload(&fx, &s, "e", b"").await.0, StatusCode::BAD_REQUEST);
    let big = vec![7u8; ainkrad_proto::v2::MAX_ATTACHMENT_BYTES + 1];
    assert_eq!(
        code(upload(&fx, &s, "big.bin", &big).await),
        (StatusCode::PAYLOAD_TOO_LARGE, "attachment_too_large".into())
    );
    let most = vec![7u8; ainkrad_proto::v2::MAX_ATTACHMENT_BYTES];
    assert_eq!(upload(&fx, &s, "most.bin", &most).await.0, StatusCode::OK);

    // The session's own cap: what it holds counts, by size.
    sqlx::query("UPDATE core_agent_attachments SET size = ? WHERE session = ?")
        .bind(attachments::MAX_PER_SESSION - 2)
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(upload(&fx, &s, "two", b"ab").await.0, StatusCode::OK);
    assert_eq!(
        code(upload(&fx, &s, "one", b"a").await),
        (StatusCode::PAYLOAD_TOO_LARGE, "attachments_full".into())
    );
    assert_eq!(held(&fx, &s).await, 2);
}

#[tokio::test]
async fn a_message_names_only_its_own_sessions_attachments_and_a_pending_one_keeps_them() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let mine = super::folder::session(&fx, &vm.id).await;
    let other = super::folder::session(&fx, &vm.id).await;
    let theirs = upload(&fx, &other, "x.txt", b"x").await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let uri = format!("/api/v1/agent-sessions/{}/messages", mine.id);
    for ids in [json!([theirs]), json!(["at_nosuch"]), json!(["../etc"])] {
        let r = call(
            &fx,
            Method::POST,
            &uri,
            json!({"text": "hi", "attachments": ids}),
        )
        .await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("unknown_attachment")),
            "{ids}"
        );
    }

    // A live session whose harness is gone: the message and its attachments wait together.
    sessions::configure(&fx.app.pool, &mine.id, true, None)
        .await
        .unwrap();
    sessions::set_state(&fx.app.pool, &mine.id, "interrupted", "test", false, NOW)
        .await
        .unwrap();
    let a = upload(&fx, &mine, "a.png", b"a").await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = upload(&fx, &mine, "b.png", b"b").await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = call(
        &fx,
        Method::POST,
        &uri,
        json!({"text": "", "attachments": [a]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let pending = attachments::pending(&fx.app.pool, &mine.id).await.unwrap();
    assert_eq!(pending, std::slice::from_ref(&a));
    // A later message replaces the pending one, and its attachments too.
    let r = call(
        &fx,
        Method::POST,
        &uri,
        json!({"text": "this one", "attachments": [b]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        attachments::pending(&fx.app.pool, &mine.id).await.unwrap(),
        [b]
    );
    // Delivered: no longer pending.
    sessions::clear_pending(&fx.app.pool, &mine.id, "this one")
        .await
        .unwrap();
    assert!(
        attachments::pending(&fx.app.pool, &mine.id)
            .await
            .unwrap()
            .is_empty()
    );
    // Neither text nor attachments: refused.
    let r = call(&fx, Method::POST, &uri, json!({"text": ""})).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attachments_go_with_their_session_and_a_week_after_it_ended() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let ended = super::folder::session(&fx, &vm.id).await;
    let running = super::folder::session(&fx, &vm.id).await;
    let gone = super::folder::session(&fx, &vm.id).await;
    for s in [&ended, &running, &gone] {
        assert_eq!(upload(&fx, s, "f", b"f").await.0, StatusCode::OK);
    }
    sessions::set_state(&fx.app.pool, &ended.id, "ended", "test", false, NOW)
        .await
        .unwrap();
    // Within the week: kept.
    assert_eq!(attachments::sweep(&fx.app.pool, NOW).await.unwrap(), 0);
    let later = crate::scheduler::iso_of_unix(
        crate::scheduler::unix_secs(NOW).unwrap() + attachments::RETENTION_SECS + 1,
    );
    assert_eq!(attachments::sweep(&fx.app.pool, &later).await.unwrap(), 1);
    assert_eq!(held(&fx, &ended).await, 0);
    assert_eq!(
        held(&fx, &running).await,
        1,
        "a running session keeps its own"
    );

    // The session row going takes them with it.
    sqlx::query("DELETE FROM core_agent_sessions WHERE id = ?")
        .bind(&gone.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(held(&fx, &gone).await, 0);
}
