//! B2-02: change sets, Undo and the 30-day purge. Every record here is made up.

use axum::http::{Method, StatusCode};
use brain_module::changes::{ChangeSet, image};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::ai::{ALPHA, as_session, session};
use super::common::*;

async fn seed(pool: &SqlitePool, id: &str, status: &str, body: &str) {
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at) \
         VALUES (?, 'fact', ?, ?, '[]', '[\"s1\"]', '2026-11-10T10:00:00Z')",
    )
    .bind(id)
    .bind(status)
    .bind(body)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES (?, 's1', 0)")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

/// Every record's image, by id.
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

/// An open room holding r1 (accepted) and r2 (accepted), and its file.
async fn room(fx: &Fx) -> (String, SqlitePool) {
    let room = committed_room(fx, &[("A", "alpha text")]).await;
    ok(fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let pool = canon_pool(fx, &room).await;
    seed(&pool, "r1", "accepted", "Deploy on Fridays").await;
    seed(&pool, "r2", "accepted", "We use Rust").await;
    (room, pool)
}

/// The writer API: archives r1, replaces r2's body, creates r3; one change set.
async fn apply(fx: &Fx, pool: &SqlitePool) -> String {
    let mut tx = pool.begin().await.unwrap();
    let mut cs = ChangeSet::new("tidy", &fx.app.clock.now());
    for id in ["r1", "r2", "r3"] {
        cs.touch(&mut tx, id).await.unwrap();
    }
    sqlx::query("UPDATE records SET archived_at = ? WHERE id = 'r1'")
        .bind(fx.app.clock.now())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET body = 'We use Rust 1.99', support = 2 WHERE id = 'r2'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM record_sources WHERE record = 'r2'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO records (id, type, status, body, created_at, admit_score) VALUES ('r3', 'fact', 'accepted', 'New fact', 't', 0.7)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let id = cs
        .commit(
            &mut tx,
            "Archived 1 · replaced 1 · saved 1",
            json!({"archived": 1, "replaced": 1, "saved": 1}),
        )
        .await
        .unwrap()
        .expect("rows changed");
    tx.commit().await.unwrap();
    id
}

async fn undo(fx: &Fx, room: &str, id: &str) -> (StatusCode, Value) {
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/changes/{id}/undo"),
        None,
    )
    .await
}

#[tokio::test]
async fn apply_then_undo_restores_byte_equal_rows_and_a_second_undo_is_a_no_op() {
    let fx = fx().await;
    let (room, pool) = room(&fx).await;
    let before = dump(&pool).await;
    let id = apply(&fx, &pool).await;
    let after = dump(&pool).await;
    assert_ne!(before, after);

    let (s, v) = undo(&fx, &room, &id).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["already_undone"], false);
    assert_eq!(v["skipped"], json!([]));
    let mut restored: Vec<&str> = v["restored"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    restored.sort();
    assert_eq!(restored, ["r1", "r2", "r3"]);
    assert_eq!(dump(&pool).await, before);

    // A person edits r1 afterwards; a second Undo changes nothing.
    sqlx::query("UPDATE records SET body = 'edited' WHERE id = 'r1'")
        .execute(&pool)
        .await
        .unwrap();
    let edited = dump(&pool).await;
    let (s, v) = undo(&fx, &room, &id).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (v["already_undone"].as_bool(), v["restored"].clone()),
        (Some(true), json!([]))
    );
    assert_eq!(dump(&pool).await, edited);
    pool.close().await;
}

#[tokio::test]
async fn undo_keeps_a_row_changed_since_and_lists_it() {
    let fx = fx().await;
    let (room, pool) = room(&fx).await;
    let id = apply(&fx, &pool).await;
    sqlx::query(
        "UPDATE records SET body = 'edited by a person', edited_by_person = 1 WHERE id = 'r2'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let (s, v) = undo(&fx, &room, &id).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["skipped"], json!(["r2"]));
    let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id = 'r2'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(body, "edited by a person");
    // The others came back: r1 unarchived, r3 gone.
    let archived: Option<String> =
        sqlx::query_scalar("SELECT archived_at FROM records WHERE id = 'r1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(archived.is_none());
    let r3: i64 = sqlx::query_scalar("SELECT count(*) FROM records WHERE id = 'r3'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(r3, 0);
    pool.close().await;
}

#[tokio::test]
async fn a_write_that_changes_nothing_stores_no_change_set() {
    let fx = fx().await;
    let (_room, pool) = room(&fx).await;
    let mut tx = pool.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", &fx.app.clock.now());
    cs.touch(&mut tx, "r1").await.unwrap();
    assert_eq!(
        cs.commit(&mut tx, "nothing", json!({})).await.unwrap(),
        None
    );
    tx.commit().await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM changes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    pool.close().await;
}

#[tokio::test]
async fn the_list_and_see_changes_routes_show_lines_and_before_after_rows() {
    let fx = fx().await;
    let (room, pool) = room(&fx).await;
    let first = apply(&fx, &pool).await;
    sqlx::query("DELETE FROM records WHERE id = 'r3'")
        .execute(&pool)
        .await
        .unwrap();
    let second = apply(&fx, &pool).await;
    undo(&fx, &room, &second).await;

    let list = ok(&fx, Method::GET, &format!("/rooms/{room}/changes"), None).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [second.as_str(), first.as_str()],
        "newest first: {list}"
    );
    assert_eq!(list[0]["summary"], "Archived 1 · replaced 1 · saved 1");
    assert_eq!(
        list[1]["counts"],
        json!({"archived": 1, "replaced": 1, "saved": 1})
    );
    assert!(list[0]["undone_at"].is_string() && list[1]["undone_at"].is_null());
    let page = ok(
        &fx,
        Method::GET,
        &format!("/rooms/{room}/changes?after={second}"),
        None,
    )
    .await;
    assert_eq!(page.as_array().unwrap().len(), 1);

    let one = ok(
        &fx,
        Method::GET,
        &format!("/rooms/{room}/changes/{first}"),
        None,
    )
    .await;
    let rows = one["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{one}");
    assert_eq!(one["more"], false);
    let r2 = rows.iter().find(|r| r["record"] == "r2").unwrap();
    assert_eq!(r2["before"]["body"], "We use Rust");
    assert_eq!(r2["after"]["body"], "We use Rust 1.99");
    assert_eq!(r2["before"]["_sources"], json!([["s1", 0]]));
    let r3 = rows.iter().find(|r| r["record"] == "r3").unwrap();
    assert!(r3["before"].is_null() && r3["after"].is_object());
    let two = ok(
        &fx,
        Method::GET,
        &format!("/rooms/{room}/changes/{first}?limit=2"),
        None,
    )
    .await;
    assert_eq!(
        (two["rows"].as_array().unwrap().len(), two["more"].clone()),
        (2, json!(true))
    );
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{room}/changes/nope"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = undo(&fx, &room, "nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    pool.close().await;
}

#[tokio::test]
async fn an_ai_session_cannot_list_see_or_undo_changes() {
    let fx = fx().await;
    let (room, pool) = room(&fx).await;
    let id = apply(&fx, &pool).await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    let before = dump(&pool).await;
    for (m, p) in [
        (Method::GET, format!("/rooms/{room}/changes")),
        (Method::GET, format!("/rooms/{room}/changes/{id}")),
        (Method::POST, format!("/rooms/{room}/changes/{id}/undo")),
    ] {
        let (st, v) = as_session(&fx, &s, m, &p, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{p}: {v}");
    }
    assert_eq!(dump(&pool).await, before);
    pool.close().await;
}

#[tokio::test]
async fn the_purge_removes_records_archived_over_30_days_ago_and_nothing_else() {
    let fx = fx().await;
    let (room, pool) = room(&fx).await;
    let id = apply(&fx, &pool).await; // r1 archived now, r2 replaced, r3 new
    seed(&pool, "old", "accepted", "Archived long ago").await;
    seed(&pool, "recent", "accepted", "Archived last week").await;
    sqlx::query("UPDATE records SET archived_at = '2020-01-01T00:00:00.000Z' WHERE id = 'old'")
        .execute(&pool)
        .await
        .unwrap();
    let week = brain_module_iso(fx.app.clock.unix() - 7 * 86_400);
    sqlx::query("UPDATE records SET archived_at = ? WHERE id = 'recent'")
        .bind(week)
        .execute(&pool)
        .await
        .unwrap();
    // A dropped candidate's body is kept 30 days.
    for (at, n) in [
        ("2020-01-01T00:00:00.000Z", "old"),
        (fx.app.clock.now().as_str(), "new"),
    ] {
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('admit.dropped', ?, ?)")
            .bind(json!({"reason": "noise", "body": format!("body {n}")}).to_string())
            .bind(at)
            .execute(&pool)
            .await
            .unwrap();
    }
    // The old record sits in a change set too (its row images must go with it).
    sqlx::query("INSERT INTO changes (id, kind, summary, at) VALUES ('chg_old', 'archive', 'Archived 1', '2020-01-01T00:00:00.000Z')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO change_rows (change, seq, record, before, after) VALUES ('chg_old', 0, 'old', '{\"body\":\"secret\"}', NULL)").execute(&pool).await.unwrap();

    assert_eq!(fx.brain.purge_step().await.unwrap(), 1);
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM records ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, ["r1", "r2", "r3", "recent"]);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM change_rows WHERE record = 'old'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let src: i64 = sqlx::query_scalar("SELECT count(*) FROM record_sources WHERE record = 'old'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((rows, src), (0, 0));
    let audits: Vec<(String, String)> = sqlx::query_as(
        "SELECT at, detail FROM room_audit WHERE action = 'admit.dropped' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !audits[0].1.contains("body") && audits[0].1.contains("noise"),
        "{audits:?}"
    );
    assert!(audits[1].1.contains("body new"));
    // The purge line: counts, no text, and it cannot be undone. The earlier change set still can.
    let list = ok(&fx, Method::GET, &format!("/rooms/{room}/changes"), None).await;
    let purge = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "purge")
        .expect("a purge line");
    assert_eq!(
        (purge["counts"]["purged"].clone(), purge["rows"].clone()),
        (json!(1), json!(0))
    );
    let (s, v) = undo(&fx, &room, purge["id"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(undo(&fx, &room, &id).await.0, StatusCode::OK);
    // Nothing left to purge: no second line.
    assert_eq!(fx.brain.purge_step().await.unwrap(), 0);
    let purges: i64 = sqlx::query_scalar("SELECT count(*) FROM changes WHERE kind = 'purge'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(purges, 1);
    pool.close().await;
}

fn brain_module_iso(unix: i64) -> String {
    ainkrad_core_server::scheduler::iso_of_unix(unix)
}
