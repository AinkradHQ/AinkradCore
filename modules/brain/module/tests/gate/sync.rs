//! E5-1 and E7-2 (Core half): the Core's AI session transcripts as Brain items, cursors, "Sync
//! now", routing into known rooms and the one notice for what needs a review.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::common::*;

const ALPHA: &str = "/h/Projects/Alpha/a";

/// An AI session row with transcript entries `(role, text)`, as the runner would have stored them.
pub async fn session(
    fx: &Fx,
    id: &str,
    repo: Option<&str>,
    state: &str,
    owner: Option<&str>,
    said: &[(&str, &str)],
) {
    sqlx::query(
        "INSERT INTO core_agent_sessions (id, runner, harness, state, last_seq, created_by, created_at, updated_at, \
         ended_at, workspace, title, owner_module) VALUES (?, ?, 'claude', ?, ?, ?, '2026-11-12T08:00:00.000Z', \
         '2026-11-12T08:30:00.000Z', '2026-11-12T08:30:00.000Z', ?, ?, ?)",
    )
    .bind(id)
    .bind(&fx.admin.id)
    .bind(state)
    .bind(0)
    .bind(&fx.admin.id)
    .bind(repo.map(|r| json!({"repo": r, "base": "main", "branch": "b"}).to_string()))
    .bind(format!("About {id}"))
    .bind(owner)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    say(fx, id, said).await;
}

/// More entries on a session, numbered after its last.
pub async fn say(fx: &Fx, id: &str, said: &[(&str, &str)]) {
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    for (i, (role, text)) in said.iter().enumerate() {
        let body = json!({"type": role, "message": {"role": role, "content": [{"type": "text", "text": text}]}});
        sqlx::query(
            "INSERT INTO core_agent_transcript (session, seq, at, body) VALUES (?, ?, 1, ?)",
        )
        .bind(id)
        .bind(last + 1 + i as i64)
        .bind(body.to_string())
        .execute(&fx.app.pool)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE core_agent_sessions SET last_seq = ? WHERE id = ?")
        .bind(last + said.len() as i64)
        .bind(id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

async fn sync(fx: &Fx) -> Value {
    ok(fx, Method::POST, "/sync", Some(json!({}))).await
}

async fn notices(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 'brain.inbox'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// A committed room made from one full-run item; returns its id.
pub async fn room_alpha(fx: &Fx) -> String {
    let run = start(fx).await;
    send(fx, &run, vec![item(1, ALPHA, "a", "alpha text")]).await;
    finish(fx, &run).await;
    let id = proposals(fx, &run).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{id}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn canon_rows(fx: &Fx, room: &str) -> Vec<(String, String)> {
    let key = key_of(fx).await;
    let pool = brain_module::files::open_migrated(
        &brain_module::files::room_path(&brain_module::files::root(&fx.app), room),
        &key,
        false,
        brain_module::files::CANON,
    )
    .await
    .unwrap();
    let rows = sqlx::query_as("SELECT text, assigned_by FROM sources ORDER BY item_id")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    rows
}

#[tokio::test]
async fn finished_ai_sessions_become_items_and_a_rerun_imports_nothing_twice() {
    let fx = fx().await;
    session(
        &fx,
        "as_one",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "fix the build"), ("assistant", "fixed it")],
    )
    .await;
    session(
        &fx,
        "as_two",
        None,
        "lost",
        None,
        &[("user", "second chat")],
    )
    .await;
    session(
        &fx,
        "as_live",
        None,
        "running",
        None,
        &[("user", "still going")],
    )
    .await;
    session(
        &fx,
        "as_brain",
        None,
        "ended",
        Some("brain"),
        &[("user", "the brain's own work")],
    )
    .await;
    let first = sync(&fx).await;
    assert_eq!(
        (first["found"].as_u64(), first["stored"].as_u64()),
        (Some(2), Some(2)),
        "{first}"
    );
    assert_eq!(first["state"], "review");
    let run = first["run"].as_str().unwrap();
    let stored = everything_stored(&fx).await;
    assert!(
        stored.contains("User: fix the build\\n\\nAssistant: fixed it"),
        "{stored}"
    );
    assert!(!stored.contains("still going") && !stored.contains("the brain's own work"));
    let items = ok(&fx, Method::GET, &format!("/imports/{run}"), None).await;
    assert_eq!(items["counts"]["stored"], 2);
    // Rerun: nothing new, no second run.
    let again = sync(&fx).await;
    assert_eq!(
        (again["idle"].as_str(), again["run"].is_null()),
        (Some("nothing_new"), true),
        "{again}"
    );
    // The live session ends: now it is taken, and only it.
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = 'as_live'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let third = sync(&fx).await;
    assert_eq!(third["found"], 1, "{third}");
}

#[tokio::test]
async fn a_resumed_session_gives_only_its_new_entries() {
    let fx = fx().await;
    session(
        &fx,
        "as_one",
        None,
        "ended",
        None,
        &[("user", "first question")],
    )
    .await;
    assert_eq!(sync(&fx).await["found"], 1);
    say(&fx, "as_one", &[("assistant", "a later answer")]).await;
    let v = sync(&fx).await;
    assert_eq!(v["found"], 1, "{v}");
    let stored = everything_stored(&fx).await;
    assert_eq!(stored.matches("first question").count(), 1, "{stored}");
    assert!(stored.contains("entries 2-2"));
}

#[tokio::test]
async fn new_items_for_a_known_room_go_straight_in_and_unsorted_raises_one_notice() {
    let fx = fx().await;
    let room = room_alpha(&fx).await;
    session(
        &fx,
        "as_alpha",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "more alpha work")],
    )
    .await;
    session(
        &fx,
        "as_stray",
        None,
        "ended",
        None,
        &[("user", "unrelated chat")],
    )
    .await;
    let v = sync(&fx).await;
    assert_eq!(v["routed"], json!([{"room": room, "sources": 1}]), "{v}");
    assert_eq!(
        (
            v["unsorted"].as_i64(),
            v["notice"].as_bool(),
            v["state"].as_str()
        ),
        (Some(1), Some(true), Some("review"))
    );
    assert_eq!(notices(&fx).await, 1);
    let rows = canon_rows(&fx, &room).await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|(t, by)| t.contains("more alpha work") && by == "rule")
    );
    assert!(!rows.iter().any(|(t, _)| t.contains("unrelated chat")));
    // Nothing new: no second notice. The run waits for review and shows in the status.
    assert_eq!(sync(&fx).await["idle"], "nothing_new");
    assert_eq!(notices(&fx).await, 1);
    let status = ok(&fx, Method::GET, "/sync", None).await;
    assert_eq!(status["review"], json!([v["run"]]));
    assert_eq!(status["every_secs"], 3600);
    // A later session for the known room alone needs no review and no notice.
    session(
        &fx,
        "as_alpha2",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "even more alpha")],
    )
    .await;
    let w = sync(&fx).await;
    assert_eq!(
        (
            w["state"].as_str(),
            w["notice"].as_bool(),
            w["unsorted"].as_i64()
        ),
        (Some("committed"), Some(false), Some(0)),
        "{w}"
    );
    assert_eq!(notices(&fx).await, 1);
    assert_eq!(canon_rows(&fx, &room).await.len(), 3);
}

#[tokio::test]
async fn an_incremental_run_from_any_collector_routes_the_same_way() {
    let fx = fx().await;
    let room = room_alpha(&fx).await;
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"kind": "incremental", "sources": ["claude_code"]})),
    )
    .await["run"]
        .as_str()
        .unwrap()
        .to_owned();
    send(&fx, &run, vec![item(2, ALPHA, "b", "a new alpha session")]).await;
    let v = finish(&fx, &run).await;
    assert_eq!(v["state"], "committed", "{v}");
    assert_eq!(canon_rows(&fx, &room).await.len(), 2);
    assert_eq!(notices(&fx).await, 0);
}

#[tokio::test]
async fn sources_hold_cursors_and_the_switch_stops_the_core_collector() {
    let fx = fx().await;
    let list = ok(&fx, Method::GET, "/sources", None).await;
    assert_eq!(list[0]["id"], "core_transcript");
    let put = ok(
        &fx,
        Method::PUT,
        "/sources/mac_claude",
        Some(json!({"device": "mac-1", "kind": "claude_code", "roots": ["/h/.claude"], "cursor": {"mtime": 5}})),
    )
    .await;
    assert_eq!(
        (&put["cursor"], &put["enabled"]),
        (&json!({"mtime": 5}), &json!(true))
    );
    // A missing field keeps its value.
    let put = ok(
        &fx,
        Method::PUT,
        "/sources/mac_claude",
        Some(json!({"device": "mac-1", "kind": "claude_code", "enabled": false})),
    )
    .await;
    assert_eq!(
        (&put["cursor"], &put["enabled"], &put["roots"]),
        (&json!({"mtime": 5}), &json!(false), &json!(["/h/.claude"]))
    );
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/sources/x",
        Some(json!({"device": "d", "kind": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    session(&fx, "as_one", None, "ended", None, &[("user", "hello")]).await;
    ok(
        &fx,
        Method::PUT,
        "/sources/core_transcript",
        Some(json!({"device": "x", "kind": "doc", "enabled": false})),
    )
    .await;
    assert_eq!(sync(&fx).await["idle"], "disabled");
    let list = ok(&fx, Method::GET, "/sources", None).await;
    assert_eq!(
        list.as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == "core_transcript")
            .unwrap()["device"],
        "core"
    );
}

#[tokio::test]
async fn a_full_run_can_take_the_core_sessions_and_a_read_device_sees_the_status() {
    let fx = fx().await;
    session(
        &fx,
        "as_one",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "from the wizard")],
    )
    .await;
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"kind": "full", "sources": ["core_transcript"]})),
    )
    .await["run"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = ok(&fx, Method::POST, "/sync", Some(json!({"run": run}))).await;
    assert_eq!(
        (v["stored"].as_u64(), v["state"].as_str()),
        (Some(1), Some("review")),
        "{v}"
    );
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let (s, _) = call(&fx, &reader, Method::GET, "/sync", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&fx, &reader, Method::POST, "/sync", Some(json!({}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_cursor_moves_only_on_commit_so_a_dropped_run_loses_nothing() {
    let fx = fx().await;
    session(
        &fx,
        "as_one",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "alpha one")],
    )
    .await;
    session(&fx, "as_two", None, "ended", None, &[("user", "stray two")]).await;
    let cursor = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT cursor FROM brain_sources WHERE id = 'core_transcript'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let first = sync(&fx).await;
    assert_eq!(first["found"], 2, "{first}");
    assert_eq!(cursor(&fx).await, "{}", "staged is not taken");
    // While the run is open its sessions are not collected again.
    assert_eq!(sync(&fx).await["idle"], "nothing_new");
    // Dropped without commit: the same sessions come back.
    let r1 = first["run"].as_str().unwrap();
    sqlx::query("UPDATE brain_import_runs SET state = 'abandoned' WHERE id = ?")
        .bind(r1)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let second = sync(&fx).await;
    assert_eq!(second["found"], 2, "{second}");
    // An open run older than the 30-day staging lifetime no longer holds them either.
    let r2 = second["run"].as_str().unwrap();
    sqlx::query(
        "UPDATE brain_import_runs SET started_at = '2026-01-01T00:00:00.000Z' WHERE id = ?",
    )
    .bind(r2)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let third = sync(&fx).await;
    assert_eq!(third["found"], 2, "{third}");
    // Commit it: the cursor moves and a rerun imports nothing.
    let r3 = third["run"].as_str().unwrap();
    let p = proposals(&fx, r3).await;
    let alpha = by_name(&p, "Alpha")["id"].as_str().unwrap().to_owned();
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{r3}/proposals/{alpha}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    ok(&fx, Method::POST, &format!("/imports/{r3}/commit"), None).await;
    let c = cursor(&fx).await;
    assert!(c.contains("as_one") && c.contains("as_two"), "{c}");
    assert_eq!(sync(&fx).await["idle"], "nothing_new");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_run_cursors WHERE run = ?")
        .bind(r3)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
