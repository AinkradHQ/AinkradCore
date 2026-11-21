//! Distils and the runner's agent capacity: a start the runner refused because it was full is not a
//! failure (the distil waits for a slot, no backoff), and a distil never takes the last free slot of
//! a runner that has more than one, so the person's own AI session can still start.

use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::{AGENT_DRIVER, DriverInfo, IsolationCaps, Kvm, RunnerHello};
use axum::http::Method;
use serde_json::json;

use super::common::*;

const DOCS: &[(&str, &str)] = &[("Billing", "we decided to export invoices as CSV")];
const WAITING: &str = "waiting for a free AI session slot";

async fn count(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn distils(fx: &Fx, room: &str) -> serde_json::Value {
    ok(fx, Method::GET, &format!("/rooms/{room}/distils"), None).await
}

/// The admin device online as a sandboxed runner whose agent driver runs `capacity` sessions.
fn runner(fx: &Fx, capacity: u32) -> tokio::sync::mpsc::Receiver<ainkrad_proto::v2::Frame> {
    fx.app.hub.fake_runner(
        &fx.admin.id,
        RunnerHello {
            drivers: vec![DriverInfo {
                name: AGENT_DRIVER.to_owned(),
                commands: vec!["agent.start".to_owned()],
                capacity,
                ..DriverInfo::default()
            }],
            isolation: Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable)),
            os: Some("linux".to_owned()),
            ..RunnerHello::default()
        },
    )
}

#[tokio::test]
async fn a_start_refused_because_the_runner_was_full_waits_for_a_slot_and_is_no_failure() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let session = chain_session(&fx, &["anthropic"]).await;
    // What the Core stores when the runner answered the start `busy` (`agents::RUNNER_BUSY`).
    let outcome = json!({"kind": "failed", "reason": "the agent driver is at its capacity",
        "fingerprint": "core", "code": "runner_busy"});
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended', outcome = ? WHERE id = ?")
        .bind(outcome.to_string())
        .bind(&session)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO brain_distils (id, room, state, session, requested_by, sources) VALUES ('dst-busy', ?, 'running', ?, ?, 1)")
        .bind(&room)
        .bind(&session)
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let p = canon_pool(&fx, &room).await;
    sqlx::query("UPDATE sources SET distilled = 'dst-busy'")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    fx.brain.distil_step().await.unwrap();
    let l = distils(&fx, &room).await;
    assert_eq!(
        (&l[0]["state"], &l[0]["detail"], &l[0]["session"]),
        (&json!("queued"), &json!(WAITING), &json!(null)),
        "{l}"
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM brain_distils WHERE state = 'failed'"
        )
        .await,
        0
    );
    let p = canon_pool(&fx, &room).await;
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM sources WHERE distilled IS NOT NULL")
        .fetch_one(&p)
        .await
        .unwrap();
    p.close().await;
    assert_eq!(taken, 0, "the sources go back to be read by the next start");
    // The refused session's prompt (room text) is not kept in the Core.
    let prompt: Option<String> =
        sqlx::query_scalar("SELECT prompt FROM core_agent_sessions WHERE id = ?")
            .bind(&session)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(prompt, None);
}

#[tokio::test]
async fn a_distil_leaves_the_last_free_slot_and_starts_once_one_is_spare() {
    let fx = fx().await;
    let _rx = runner(&fx, 2);
    // The person's own AI session holds one of the two slots.
    let mine = chain_session(&fx, &["anthropic"]).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let room = committed_room(&fx, DOCS).await;
    let v = ok(&fx, Method::POST, &format!("/rooms/{room}/distil"), None).await;
    assert_eq!(
        (&v["state"], &v["detail"]),
        (&json!("queued"), &json!(WAITING)),
        "{v}"
    );
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_agent_sessions").await,
        1,
        "no session is made while only the last slot is free"
    );
    // The person's session ends: one slot is spare, so the next tick starts the distil.
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&mine)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    fx.brain.distil_step().await.unwrap();
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_agent_sessions").await,
        2
    );
    let l = distils(&fx, &room).await;
    assert_ne!(l[0]["detail"], WAITING, "{l}");
    assert!(l[0]["session"].is_string(), "{l}");
}
