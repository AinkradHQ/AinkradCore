//! B5-02: mid-session checkpoints, `brainAiCheckpoint`, and the no-echo guard. Time is the `now`
//! the step is given; the Core's session and event tables are real. Every text here is synthetic.

use ainkrad_core::untrusted::{OPEN, wrap};
use ainkrad_core_server::store::events;
use axum::http::{Method, StatusCode};
use serde_json::json;

use super::ai::{as_session, op, put_record};
use super::common::*;
use super::sync::{room_alpha, say, session};

const ALPHA: &str = "/h/Projects/Alpha/a";

/// About `n` characters of plain words, led by `tag`.
fn pad(tag: &str, n: usize) -> String {
    format!("{tag} {}", "alpha beta gamma ".repeat(n / 17))
}

async fn quiet_room(fx: &Fx) -> (String, i64) {
    let room = room_alpha(fx).await;
    mark_read(fx, &room).await;
    let now = fx.app.clock.unix();
    // The first step only starts the event cursor.
    assert_eq!(fx.brain.auto_distil_step_at(now).await.unwrap(), 0);
    (room, now)
}

async fn mark_read(fx: &Fx, room: &str) {
    let p = canon_pool(fx, room).await;
    sqlx::query("UPDATE sources SET distilled = 'old' WHERE distilled IS NULL")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

/// Every distil done and every source read: the next trigger starts from nothing open.
async fn settle(fx: &Fx, room: &str) {
    sqlx::query("UPDATE brain_distils SET state = 'done'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    mark_read(fx, room).await;
}

async fn waiting(fx: &Fx, id: &str, since: i64) {
    sqlx::query("UPDATE core_agent_sessions SET waiting_since = ? WHERE id = ?")
        .bind(since)
        .bind(id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

async fn turns(fx: &Fx, id: &str, tag: &str, pairs: usize, chars: usize) {
    for i in 0..pairs {
        say(
            fx,
            id,
            &[
                ("user", &pad(&format!("{tag} question {i}"), chars)),
                ("assistant", &pad(&format!("{tag} answer {i}"), chars)),
            ],
        )
        .await;
    }
}

async fn rows(fx: &Fx, filter: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM brain_distils WHERE {filter}"
    )))
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

/// The texts one session left in the room, oldest first.
async fn texts(fx: &Fx, room: &str, id: &str) -> Vec<String> {
    let p = canon_pool(fx, room).await;
    let t = sqlx::query_scalar("SELECT text FROM sources WHERE path = ? ORDER BY rowid")
        .bind(format!("core://ai-session/{id}"))
        .fetch_all(&p)
        .await
        .unwrap();
    p.close().await;
    t
}

/// `(first, last)` entry of a part, from its header `... entries a-b`.
fn range(text: &str) -> (u64, u64) {
    let head = text.lines().next().unwrap();
    let r = head.rsplit("entries ").next().unwrap();
    let (a, b) = r.split_once('-').unwrap();
    (a.parse().unwrap(), b.parse().unwrap())
}

#[tokio::test]
async fn a_live_session_distils_twice_then_its_end_takes_only_the_rest() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    session(&fx, "as_live", Some(ALPHA), "running", None, &[]).await;
    waiting(&fx, "as_live", now - 100).await;
    turns(&fx, "as_live", "ONE", 3, 6_000).await;

    assert_eq!(fx.brain.auto_distil_step_at(now + 10).await.unwrap(), 1);
    assert_eq!(
        rows(&fx, "\"trigger\" = 'checkpoint' AND of_session = 'as_live'").await,
        1
    );
    settle(&fx, &room).await;

    turns(&fx, "as_live", "TWO", 3, 6_000).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 700).await.unwrap(), 1);
    assert_eq!(
        rows(&fx, "\"trigger\" = 'checkpoint' AND of_session = 'as_live'").await,
        2
    );
    settle(&fx, &room).await;

    // The end: one more answered turn, then the session is over.
    say(
        &fx,
        "as_live",
        &[("user", "THREE question"), ("assistant", "THREE answer")],
    )
    .await;
    sqlx::query(
        "UPDATE core_agent_sessions SET state = 'ended', waiting_since = NULL WHERE id = 'as_live'",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let mut c = fx.app.pool.acquire().await.unwrap();
    events::append(
        &mut c,
        "agent.ended",
        &json!({"session": "as_live", "state": "ended", "outcome": "completed"}),
    )
    .await
    .unwrap();
    drop(c);
    assert_eq!(fx.brain.auto_distil_step_at(now + 2000).await.unwrap(), 1);
    assert_eq!(
        rows(
            &fx,
            "\"trigger\" = 'session_end' AND of_session = 'as_live'"
        )
        .await,
        1
    );

    let t = texts(&fx, &room, "as_live").await;
    assert_eq!(
        t.len(),
        3,
        "{:?}",
        t.iter().map(|x| x.lines().next()).collect::<Vec<_>>()
    );
    for (i, tag) in ["ONE", "TWO", "THREE"].iter().enumerate() {
        for (j, other) in ["ONE", "TWO", "THREE"].iter().enumerate() {
            assert_eq!(
                t[i].contains(other),
                i == j,
                "part {i} holds {tag} / {other}"
            );
        }
    }
    // No entry is in two parts.
    let r: Vec<_> = t.iter().map(|x| range(x)).collect();
    assert!(r[0].1 < r[1].0 && r[1].1 < r[2].0, "{r:?}");
}

#[tokio::test]
async fn a_checkpoint_needs_the_floor_a_calm_session_and_a_finished_answer() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    // Under the floor: nothing.
    session(&fx, "as_small", Some(ALPHA), "running", None, &[]).await;
    waiting(&fx, "as_small", now - 100).await;
    turns(&fx, "as_small", "SMALL", 3, 2_000).await;
    // Over the floor but only just stopped (inside the idle wait): nothing.
    session(&fx, "as_hot", Some(ALPHA), "running", None, &[]).await;
    waiting(&fx, "as_hot", now + 5).await;
    turns(&fx, "as_hot", "HOT", 2, 20_000).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 10).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 0);

    // Over the floor, with a question still unanswered at the end: whole turns only.
    session(&fx, "as_cut", Some(ALPHA), "running", None, &[]).await;
    waiting(&fx, "as_cut", now - 100).await;
    turns(&fx, "as_cut", "CUT", 1, 20_000).await;
    say(&fx, "as_cut", &[("user", "PENDING QUESTION")]).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 20).await.unwrap(), 1);
    assert_eq!(rows(&fx, "of_session = 'as_cut'").await, 1);
    assert_eq!(rows(&fx, "of_session != 'as_cut'").await, 0);
    let t = texts(&fx, &room, "as_cut").await;
    assert_eq!(t.len(), 1);
    assert!(!t[0].contains("PENDING QUESTION") && t[0].contains("CUT answer 0"));
    assert_eq!(range(&t[0]), (1, 2));
    assert!(texts(&fx, &room, "as_small").await.is_empty());
    assert!(texts(&fx, &room, "as_hot").await.is_empty());
}

#[tokio::test]
async fn the_ai_op_only_requests_for_its_own_session_under_a_rate_cap_and_the_caps_still_rule() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let ws = json!({"repo": ALPHA, "base": "main", "branch": "b"});
    let s = chain_session_in(&fx, &["anthropic"], Some(&ws)).await;
    sqlx::query("UPDATE core_devices SET scopes = '[\"admin\",\"read\",\"agent\"]' WHERE id = ?")
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    say(
        &fx,
        &s,
        &[
            ("user", &pad("HOOK question", 1_500)),
            ("assistant", &pad("HOOK answer", 1_500)),
        ],
    )
    .await;

    // Through Code Mode: it only requests. Nothing is distilled by the call itself.
    let (ok_, v, code) = op(&fx, &s, "brainAiCheckpoint", json!({})).await;
    assert!(ok_, "{code}");
    assert_eq!(v["requested"], json!(true), "{v}");
    assert_eq!(rows(&fx, "1 = 1").await, 0);
    // Asking again inside ten minutes is refused, and still nothing is distilled.
    let (st, v) = as_session(&fx, &s, Method::POST, "/ai/checkpoint", None).await;
    assert_eq!(
        (st, v["requested"].as_bool(), v["reason"].as_str()),
        (StatusCode::OK, Some(false), Some("rate_limited"))
    );
    assert_eq!(rows(&fx, "1 = 1").await, 0);
    // The audit row names the session and carries no text.
    let d: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'brain.ai.checkpoint_requested'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(d.contains(&s) && !d.contains("HOOK"), "{d}");

    // The Core acts at its next tick, and the room's daily cap still rules: no distil, nothing forced.
    sqlx::query("UPDATE brain_room_policy SET daily_distils = 0 WHERE room = ?")
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        fx.brain.auto_distil_step_at(now + 10).await.unwrap(),
        0,
        "the room cap stops it"
    );
    assert_eq!(rows(&fx, "1 = 1").await, 0);

    // A session that is over is not eligible; a refusal is a normal answer.
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&s)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (st, v) = as_session(&fx, &s, Method::POST, "/ai/checkpoint", None).await;
    assert_eq!(
        (st, v["reason"].as_str()),
        (StatusCode::OK, Some("not_eligible"))
    );
}

#[tokio::test]
async fn a_hook_checkpoint_queues_one_hook_distil() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let ws = json!({"repo": ALPHA, "base": "main", "branch": "b"});
    let s = chain_session_in(&fx, &["anthropic"], Some(&ws)).await;
    say(
        &fx,
        &s,
        &[
            ("user", &pad("HOOK question", 1_500)),
            ("assistant", &pad("HOOK answer", 1_500)),
        ],
    )
    .await;
    let (_, v) = as_session(&fx, &s, Method::POST, "/ai/checkpoint", None).await;
    assert_eq!(v["requested"], json!(true), "{v}");
    assert_eq!(fx.brain.auto_distil_step_at(now + 10).await.unwrap(), 1);
    assert_eq!(
        rows(&fx, &format!("\"trigger\" = 'hook' AND of_session = '{s}'")).await,
        1
    );
    assert_eq!(texts(&fx, &room, &s).await.len(), 1);
}

#[tokio::test]
async fn memory_loaded_into_a_session_is_never_a_source() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let body = "Deploys go out on Fridays after the change freeze ends.";
    put_record(&fx, &room, "rec-1", "fact", "accepted", body).await;
    let ws = json!({"repo": ALPHA, "base": "main", "branch": "b"});
    let s = chain_session_in(&fx, &["anthropic"], Some(&ws)).await;
    sqlx::query("INSERT INTO brain_session_loaded (session, room, record) VALUES (?, ?, 'rec-1')")
        .bind(&s)
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let envelope = wrap("record rec-9", "Evidence text the model was shown.");
    say(
        &fx,
        &s,
        &[
            ("user", "How do we ship?"),
            (
                "assistant",
                &format!(
                    "{body} {envelope} We decided to keep the cache in SQLite. {}",
                    pad("more", 2_500)
                ),
            ),
            // A turn that was nothing but loaded memory leaves no turn at all.
            ("user", "ok"),
            ("assistant", body),
        ],
    )
    .await;
    let (_, v) = as_session(&fx, &s, Method::POST, "/ai/checkpoint", None).await;
    assert_eq!(v["requested"], json!(true), "{v}");
    assert_eq!(fx.brain.auto_distil_step_at(now + 10).await.unwrap(), 1);
    let t = texts(&fx, &room, &s).await;
    assert_eq!(t.len(), 1);
    assert!(
        !t[0].contains("Deploys go out") && !t[0].contains(OPEN) && !t[0].contains("Evidence text"),
        "{}",
        t[0]
    );
    assert!(t[0].contains("keep the cache in SQLite"), "{}", t[0]);
    assert!(
        !t[0].contains("Assistant: \n") && !t[0].ends_with("Assistant:"),
        "{}",
        t[0]
    );
}
