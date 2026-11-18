//! B6-01: re-distil and purge. A batch's model answer is written into a session by hand (as
//! `distil.rs` does); the Core's own job code does the rest. Every record here is made up.

use axum::http::{Method, StatusCode};
use brain_module::changes::image;
use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::ai::{ALPHA, as_session, session};
use super::common::*;

const DOCS: &[(&str, &str)] = &[
    ("Billing", "we decided to export invoices as CSV"),
    ("Deploy", "the deploy runs on Fridays only"),
];
const KEEP: &str = "Invoices are exported as CSV files for the accounting team every month.";
const NEW: &str = "Production deploys only run on Fridays after the release checklist is signed.";

async fn seed(pool: &SqlitePool, id: &str, body: &str, src: &str, extra: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO records (id, type, status, body, body_norm, tags, source_ids, created_at, valid_from, support) \
         VALUES (?1, 'decision', 'accepted', ?2, lower(?2), '[]', '[]', '2026-11-10T10:00:00.000Z', '2026-11-10T10:00:00.000Z', 1); \
         {extra}"
    )))
    .bind(id)
    .bind(body)
    .execute(pool)
    .await
    .ok();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES (?, ?, 0)")
        .bind(id)
        .bind(src)
        .execute(pool)
        .await
        .unwrap();
}

struct Room {
    id: String,
    pool: SqlitePool,
    ids: Vec<String>,
}

/// An open room whose two sources were distilled before, holding: `keep` (the pipeline re-derives
/// it), `junk` (nothing does), `person` and `edited` (a person's), `target` (contested by `person2`),
/// and `unread` (cites a source this run cannot read).
async fn room(fx: &Fx) -> Room {
    let id = committed_room(fx, DOCS).await;
    ok(fx, Method::POST, &format!("/rooms/{id}/open"), None).await;
    let pool = canon_pool(fx, &id).await;
    sqlx::query("UPDATE sources SET distilled = 'old'")
        .execute(&pool)
        .await
        .unwrap();
    let ids: Vec<String> = sqlx::query_scalar("SELECT item_id FROM sources ORDER BY item_id")
        .fetch_all(&pool)
        .await
        .unwrap();
    for (rid, body) in [
        ("keep", KEEP),
        ("junk", "ok thanks, that works now"),
        ("person", "A person wrote this by hand."),
        ("edited", "A person edited this one."),
        ("target", "The contested target stays."),
        ("person2", "The contester, written by a person."),
        ("unread", "Its evidence was compacted away."),
    ] {
        seed(
            &pool,
            rid,
            body,
            if rid == "unread" {
                "gone-source"
            } else {
                &ids[0]
            },
            "",
        )
        .await;
    }
    for sql in [
        "UPDATE records SET origin = 'person' WHERE id IN ('person', 'person2')",
        "UPDATE records SET edited_by_person = 1 WHERE id = 'edited'",
        "UPDATE records SET contests = 'target' WHERE id = 'person2'",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    Room { id, pool, ids }
}

async fn start(fx: &Fx, room: &str, dry: bool) -> (StatusCode, Value) {
    let p = if dry {
        format!("/rooms/{room}/redistil/dry-run")
    } else {
        format!("/rooms/{room}/redistil")
    };
    call(fx, &fx.admin, Method::POST, &p, None).await
}

/// The queued batch distil of the open run: answers it with `answer`, taking `n` sources.
async fn answer_batch(fx: &Fx, r: &Room, n: usize, answer: Value) {
    let (distil,): (String,) = sqlx::query_as(
        "SELECT id FROM brain_distils WHERE \"trigger\" = 'redistil' AND session IS NULL",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let run: String = sqlx::query_scalar("SELECT redistil FROM brain_distils WHERE id = ?")
        .bind(&distil)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let seq: i64 =
        sqlx::query_scalar("SELECT coalesce(max(seq), 0) + 1 FROM redistil_batches WHERE run = ?")
            .bind(&run)
            .fetch_one(&r.pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO redistil_batches (run, seq, distil) VALUES (?, ?, ?)")
        .bind(&run)
        .bind(seq)
        .bind(&distil)
        .execute(&r.pool)
        .await
        .unwrap();
    let unread: Vec<String> = sqlx::query_scalar(
        "SELECT item_id FROM redistil_sources WHERE run = ? AND batch IS NULL ORDER BY item_id LIMIT ?",
    )
    .bind(&run).bind(n as i64).fetch_all(&r.pool).await.unwrap();
    for id in &unread {
        sqlx::query("UPDATE redistil_sources SET batch = ? WHERE run = ? AND item_id = ?")
            .bind(seq)
            .bind(&run)
            .bind(id)
            .execute(&r.pool)
            .await
            .unwrap();
    }
    let session = chain_session(fx, &["anthropic"]).await;
    let (st, v) = call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{}/claims", r.id),
        Some(json!({"session": session})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    for (seq, body) in [
        (1, json!({"type": "message", "text": "SECRET SOURCE TEXT"})),
        (
            2,
            json!({"type": "assistant_text", "text": answer.to_string()}),
        ),
    ] {
        sqlx::query("INSERT INTO core_agent_transcript (session, user_id, seq, at, body) VALUES (?, 1, ?, 0, ?)")
            .bind(&session).bind(seq).bind(body.to_string()).execute(&fx.app.pool).await.unwrap();
    }
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&session)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE brain_distils SET session = ?, state = 'running' WHERE id = ?")
        .bind(&session)
        .bind(&distil)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    fx.brain.distil_step().await.unwrap();
}

fn answer(r: &Room, with_new: bool) -> Value {
    let mut c = vec![json!({"type": "decision", "body": KEEP, "sources": [r.ids[0]]})];
    if with_new {
        c.push(json!({"type": "decision", "body": NEW, "sources": [r.ids[1]]}));
    }
    json!({"candidates": c})
}

/// Runs a whole room in one batch: start, queue, answer, commit.
async fn run(fx: &Fx, r: &Room, dry: bool) -> Value {
    let (st, v) = start(fx, &r.id, dry).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let now = fx.app.clock.unix();
    assert_eq!(fx.brain.redistil_step_at(now).await.unwrap(), 1);
    answer_batch(fx, r, 30, answer(r, true)).await;
    assert_eq!(fx.brain.redistil_step_at(now + 60).await.unwrap(), 1);
    let l = ok(fx, Method::GET, &format!("/rooms/{}/redistil", r.id), None).await;
    assert_eq!(l[0]["state"], "done", "{l}");
    l[0].clone()
}

async fn dump(pool: &SqlitePool) -> Vec<String> {
    let mut c = pool.acquire().await.unwrap();
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM records ORDER BY id")
        .fetch_all(&mut *c)
        .await
        .unwrap();
    let mut out = vec![];
    for id in ids {
        out.push(image(&mut c, &id).await.unwrap().unwrap());
    }
    out
}

async fn n(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn archived(pool: &SqlitePool, id: &str) -> bool {
    sqlx::query_scalar::<_, Option<String>>("SELECT archived_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn a_dry_run_reports_counts_and_writes_nothing() {
    let fx = fx().await;
    let r = room(&fx).await;
    let before = dump(&r.pool).await;
    let src: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT item_id, distilled, redistil FROM sources ORDER BY item_id")
            .fetch_all(&r.pool)
            .await
            .unwrap();
    let v = run(&fx, &r, true).await;
    // keep re-derived; person, edited, target (contested), person2 and unread stay; junk would go; one new.
    assert_eq!(
        (
            v["kept"].as_i64(),
            v["new_facts"].as_i64(),
            v["archived"].as_i64()
        ),
        (Some(6), Some(1), Some(1)),
        "{v}"
    );
    assert!(
        v["summary"]
            .as_str()
            .unwrap()
            .starts_with("Would keep 7 facts, archive 1 item"),
        "{v}"
    );
    assert_eq!(v["change"], Value::Null);
    assert_eq!(dump(&r.pool).await, before);
    assert_eq!(n(&r.pool, "SELECT count(*) FROM changes").await, 0);
    let after: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT item_id, distilled, redistil FROM sources ORDER BY item_id")
            .fetch_all(&r.pool)
            .await
            .unwrap();
    assert_eq!(after, src);
    // The staging is gone and no content is in the Core's rows.
    assert_eq!(n(&r.pool, "SELECT count(*) FROM redistil_batches").await, 0);
    let stored: String = sqlx::query_scalar(
        "SELECT group_concat(detail || coalesce(change, '')) FROM brain_redistils",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(!stored.contains("CSV"), "{stored}");
}

#[tokio::test]
async fn apply_writes_one_change_set_and_undo_puts_everything_back() {
    let fx = fx().await;
    let r = room(&fx).await;
    let before = dump(&r.pool).await;
    let v = run(&fx, &r, false).await;
    assert_eq!(v["summary"], "Kept 7 facts, archived 1 item");
    assert!(archived(&r.pool, "junk").await);
    assert_eq!(
        n(
            &r.pool,
            &format!("SELECT count(*) FROM memory WHERE body = '{NEW}'")
        )
        .await,
        1
    );
    assert_eq!(n(&r.pool, "SELECT count(*) FROM changes").await, 1);
    // Re-reading the same source is not new evidence.
    assert_eq!(
        n(&r.pool, "SELECT support FROM records WHERE id = 'keep'").await,
        1
    );
    // `redistil` is cleared on what it read.
    assert_eq!(
        n(
            &r.pool,
            "SELECT count(*) FROM sources WHERE redistil IS NOT NULL"
        )
        .await,
        0
    );
    let change = v["change"].as_str().unwrap();
    let (st, u) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{}/changes/{change}/undo", r.id),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{u}");
    assert_eq!(dump(&r.pool).await, before);
    // Undo is capped at 30 days.
    sqlx::query("UPDATE changes SET at = '2020-01-01T00:00:00.000Z', undone_at = NULL")
        .execute(&r.pool)
        .await
        .unwrap();
    let (st, u) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{}/changes/{change}/undo", r.id),
        None,
    )
    .await;
    assert_eq!(
        (st, u["code"].as_str()),
        (StatusCode::CONFLICT, Some("undo_expired")),
        "{u}"
    );
}

#[tokio::test]
async fn a_persons_records_and_a_contested_target_are_never_archived() {
    let fx = fx().await;
    let r = room(&fx).await;
    run(&fx, &r, false).await;
    for id in ["person", "edited", "person2", "target", "unread", "keep"] {
        assert!(!archived(&r.pool, id).await, "{id}");
    }
    assert!(archived(&r.pool, "junk").await);
}

#[tokio::test]
async fn a_run_that_derived_nothing_archives_nothing() {
    let fx = fx().await;
    let r = room(&fx).await;
    start(&fx, &r.id, false).await;
    let now = fx.app.clock.unix();
    fx.brain.redistil_step_at(now).await.unwrap();
    answer_batch(&fx, &r, 30, json!({"candidates": []})).await;
    fx.brain.redistil_step_at(now + 60).await.unwrap();
    assert!(!archived(&r.pool, "junk").await);
}

#[tokio::test]
async fn a_killed_run_resumes_without_saving_twice() {
    let fx = fx().await;
    let r = room(&fx).await;
    let (st, v) = start(&fx, &r.id, false).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let now = fx.app.clock.unix();
    // Batch 1 reads one source; the Core dies; the next step queues batch 2 for the other one only.
    fx.brain.redistil_step_at(now).await.unwrap();
    answer_batch(
        &fx,
        &r,
        1,
        json!({"candidates": [{"type": "decision", "body": KEEP, "sources": [r.ids[0]]}]}),
    )
    .await;
    assert_eq!(
        n(
            &r.pool,
            "SELECT count(*) FROM redistil_sources WHERE batch IS NULL"
        )
        .await,
        1
    );
    // Starting the same run again returns it, it does not make a second.
    let (_, again) = start(&fx, &r.id, false).await;
    assert_eq!(again["id"], v["id"]);
    assert_eq!(fx.brain.redistil_step_at(now + 60).await.unwrap(), 1);
    answer_batch(
        &fx,
        &r,
        1,
        json!({"candidates": [{"type": "decision", "body": NEW, "sources": [r.ids[1]]}]}),
    )
    .await;
    assert_eq!(fx.brain.redistil_step_at(now + 120).await.unwrap(), 1);
    assert_eq!(
        n(
            &r.pool,
            &format!("SELECT count(*) FROM records WHERE body = '{NEW}'")
        )
        .await,
        1
    );
    assert_eq!(n(&r.pool, "SELECT count(*) FROM changes").await, 1);
    // A crash after the commit but before the run row moved: the commit is not made again.
    sqlx::query("UPDATE brain_redistils SET state = 'committing'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    fx.brain.redistil_step_at(now + 180).await.unwrap();
    assert_eq!(
        n(
            &r.pool,
            &format!("SELECT count(*) FROM records WHERE body = '{NEW}'")
        )
        .await,
        1
    );
    assert_eq!(n(&r.pool, "SELECT count(*) FROM changes").await, 1);
    let state: String = sqlx::query_scalar("SELECT state FROM brain_redistils")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(state, "done");
}

#[tokio::test]
async fn the_daily_and_global_caps_stop_new_batches_until_the_window_rolls_over() {
    for (room_cap, global_cap) in [(1, 99), (99, 1)] {
        let fx = fx().await;
        let r = room(&fx).await;
        start(&fx, &r.id, true).await;
        let now = fx.app.clock.unix();
        assert_eq!(
            fx.brain
                .redistil_step_capped(now, room_cap, global_cap)
                .await
                .unwrap(),
            1
        );
        answer_batch(&fx, &r, 1, answer(&r, false)).await;
        // One source is still unread, but the cap is used.
        assert_eq!(
            fx.brain
                .redistil_step_capped(now + 60, room_cap, global_cap)
                .await
                .unwrap(),
            0
        );
        let rows = n(
            &fx.app.pool,
            "SELECT count(*) FROM brain_distils WHERE \"trigger\" = 'redistil'",
        )
        .await;
        assert_eq!(rows, 1);
        let detail: String = sqlx::query_scalar("SELECT detail FROM brain_redistils")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
        assert!(detail.contains("daily limit"), "{detail}");
        // A day later the run goes on.
        assert_eq!(
            fx.brain
                .redistil_step_capped(now + 86_500, room_cap, global_cap)
                .await
                .unwrap(),
            1
        );
    }
}

#[tokio::test]
async fn only_a_person_with_a_step_up_may_apply_and_one_room_runs_at_a_time() {
    let fx = fx().await;
    let r = room(&fx).await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    for (m, p) in [
        (Method::POST, format!("/rooms/{}/redistil", r.id)),
        (Method::POST, format!("/rooms/{}/redistil/dry-run", r.id)),
        (Method::GET, format!("/rooms/{}/redistil", r.id)),
    ] {
        let (st, v) = as_session(&fx, &s, m, &p, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{p}: {v}");
    }
    assert_eq!(
        n(&fx.app.pool, "SELECT count(*) FROM brain_redistils").await,
        0
    );
    // A device without a live step-up cannot apply; it may run the dry run.
    let (st, _) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &format!("/rooms/{}/redistil", r.id),
        None,
    )
    .await;
    assert_ne!(st, StatusCode::OK);
    let (st, v) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &format!("/rooms/{}/redistil/dry-run", r.id),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    // The open dry run refuses a real one in the same room.
    let (st, v) = start(&fx, &r.id, false).await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("redistil_open")),
        "{v}"
    );
}
