//! One room, several dreaming-sweep batches at once (`auto_distil::MAX_PER_ROOM`): each takes a
//! disjoint set of sources, both admit, a fact found by two batches is one record, a failed batch
//! gives back only its own sources, and the global caps still hold. Every item here is synthetic.

use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::{AGENT_DRIVER, DriverInfo, IsolationCaps, Kvm, RunnerHello};
use axum::http::Method;
use serde_json::json;

use super::common::*;

const DOCS: &[(&str, &str)] = &[("Billing", "we decided to export invoices as CSV")];
const BODY: &str = "We decided to export invoices as CSV.";

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

/// A room of 101 unread sources (one batch reads 30), auto-saving decisions, with a distil chain.
async fn big_room(fx: &Fx) -> String {
    bind_distil_chain(fx, make_chain(fx, &["anthropic"]).await).await;
    let room = committed_room(fx, DOCS).await;
    ok(
        fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"auto_accept": ["decision"]})),
    )
    .await;
    let p = canon_pool(fx, &room).await;
    for i in 0..100 {
        sqlx::query(
            "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
             title, text, started_at, run, assigned_by) VALUES (?, ?, 'note', 'd', '/p', 'user', 'a', 't', ?, ?, 'r', 'rule')",
        )
        .bind(format!("p{i:03}"))
        .bind(format!("h{i:03}"))
        .bind(DOCS[0].1)
        .bind(format!("2020-01-01T00:{:02}:{:02}Z", i / 60, i % 60))
        .execute(&p)
        .await
        .unwrap();
    }
    p.close().await;
    room
}

/// `(distil, sources it took)` for every distil holding sources, by distil id.
async fn taken(fx: &Fx, room: &str) -> Vec<(String, Vec<String>)> {
    let p = canon_pool(fx, room).await;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT distilled, item_id FROM sources WHERE distilled IS NOT NULL ORDER BY distilled, item_id",
    )
    .fetch_all(&p)
    .await
    .unwrap();
    p.close().await;
    let mut out: Vec<(String, Vec<String>)> = vec![];
    for (d, item) in rows {
        match out.last_mut() {
            Some((last, items)) if *last == d => items.push(item),
            _ => out.push((d, vec![item])),
        }
    }
    out
}

async fn scalar(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// Launches what is queued, and keeps the started sessions working: the fixture has no account, so
/// a started session ends at once, and here it must hold its slot until the test ends it.
async fn launch(fx: &Fx) {
    fx.brain.distil_step().await.unwrap();
    sqlx::query(
        "UPDATE core_agent_sessions SET state = 'running', outcome = NULL \
         WHERE id IN (SELECT session FROM brain_distils WHERE state = 'running')",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

/// Ends `session` with `answer` as the model's last words (`None`: it said nothing).
async fn end_with(fx: &Fx, session: &str, answer: Option<&str>) {
    if let Some(a) = answer {
        sqlx::query("INSERT INTO core_agent_transcript (session, user_id, seq, at, body) VALUES (?, 1, 1, 0, ?)")
            .bind(session)
            .bind(json!({"type": "assistant_text", "text": a}).to_string())
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(session)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn one_room_runs_several_sweep_batches_on_disjoint_sources_and_admits_them_safely() {
    let fx = fx().await;
    let _rx = runner(&fx, 4);
    let room = big_room(&fx).await;
    let t = fx.app.clock.unix();
    // One batch per sweep (60 s apart), each launched before the next is queued.
    for i in 0..3 {
        assert_eq!(
            fx.brain.auto_distil_step_at(t + 61 * i).await.unwrap(),
            1,
            "{i}"
        );
        launch(&fx).await;
    }
    assert_eq!(
        scalar(&fx, "SELECT count(*) FROM brain_distils WHERE state = 'running' AND \"trigger\" = 'threshold'").await,
        3
    );
    // Three open: the sweep adds no fourth, though 11 sources are left.
    assert_eq!(fx.brain.auto_distil_step_at(t + 61 * 3).await.unwrap(), 0);
    let held = taken(&fx, &room).await;
    assert_eq!(held.len(), 3, "{held:?}");
    let mut all: Vec<&String> = held.iter().flat_map(|(_, s)| s).collect();
    assert_eq!(all.len(), 90);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 90, "no source is in two batches");

    // Batches A and B both find the same fact in their own sources; C says nothing.
    let session_of = |d: &str| {
        let d = d.to_owned();
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT session FROM brain_distils WHERE id = ?")
                .bind(d)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    for (d, sources) in &held[..2] {
        let a =
            json!({"candidates": [{"type": "decision", "body": BODY, "sources": [sources[0]]}]});
        end_with(&fx, &session_of(d).await, Some(&a.to_string())).await;
    }
    let (failed, _) = &held[2];
    end_with(&fx, &session_of(failed).await, None).await;
    fx.brain.distil_step().await.unwrap();

    let state = |d: &str| {
        let d = d.to_owned();
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT state FROM brain_distils WHERE id = ?")
                .bind(d)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(state(&held[0].0).await, "done");
    assert_eq!(state(&held[1].0).await, "done");
    assert_eq!(state(failed).await, "failed");
    // The fact both batches found is one record in memory, citing a source of each.
    let p = canon_pool(&fx, &room).await;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM memory WHERE body = ?")
        .bind(BODY)
        .fetch_all(&p)
        .await
        .unwrap();
    assert_eq!(ids.len(), 1, "{ids:?}");
    let cited: Vec<String> =
        sqlx::query_scalar("SELECT source FROM record_sources WHERE record = ? ORDER BY source")
            .bind(&ids[0])
            .fetch_all(&p)
            .await
            .unwrap();
    p.close().await;
    let mut want = vec![held[0].1[0].clone(), held[1].1[0].clone()];
    want.sort();
    assert_eq!(cited, want);
    // The failed batch gave back only its own sources; A's and B's stay read.
    let after = taken(&fx, &room).await;
    assert!(after.iter().all(|(d, _)| d != failed), "{after:?}");
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].1.len() + after[1].1.len(), 60);
}

#[tokio::test]
async fn a_second_batch_waits_for_a_free_slot_and_the_sweep_adds_none_while_it_waits() {
    let fx = fx().await;
    // Two slots: the Brain may hold one (KEEP_FREE_SLOTS).
    let _rx = runner(&fx, 2);
    let room = big_room(&fx).await;
    let t = fx.app.clock.unix();
    assert_eq!(fx.brain.auto_distil_step_at(t).await.unwrap(), 1);
    launch(&fx).await;
    assert_eq!(fx.brain.auto_distil_step_at(t + 61).await.unwrap(), 1);
    launch(&fx).await;
    assert_eq!(
        scalar(
            &fx,
            "SELECT count(*) FROM brain_distils WHERE state = 'running'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar(
            &fx,
            "SELECT count(*) FROM brain_distils WHERE state = 'queued'"
        )
        .await,
        1
    );
    // The queued one has taken nothing, so the sweep coalesces into it.
    assert_eq!(fx.brain.auto_distil_step_at(t + 122).await.unwrap(), 0);
    assert_eq!(taken(&fx, &room).await.len(), 1);
}

#[tokio::test]
async fn a_manual_start_still_finds_the_open_batch() {
    let fx = fx().await;
    let _rx = runner(&fx, 4);
    let room = big_room(&fx).await;
    let t = fx.app.clock.unix();
    assert_eq!(fx.brain.auto_distil_step_at(t).await.unwrap(), 1);
    launch(&fx).await;
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/distil"),
        None,
    )
    .await;
    assert_eq!(st, axum::http::StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "distil_open", "{v}");
}
