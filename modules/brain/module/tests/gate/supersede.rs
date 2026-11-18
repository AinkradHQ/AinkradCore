//! B4-02: a replaced record leaves memory (`valid_to`), keeps its row as history linked to its
//! successor, and Undo restores both; a `replaces` of any kind needs a grounded candidate of the same
//! kind, else the target stays and the two are contested; Undo after a later reinforce unlinks the
//! successor; the SQL staleness test equals the pure one; a contested record ranks last and says
//! what it contests. Every record here is made up.

use brain_model::merge::{Grounding, STALE_SQL, is_stale};
use brain_module::changes::{ChangeSet, image, undo};
use brain_module::files::{self, CANON};
use brain_module::merge::{Replace, reinforce, supersede};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::ai::{ALPHA, open_room, put_record, read, session};
use super::common::{canon_pool, committed_room_named, fx};

const KEY: [u8; 32] = [7; 32];
const T0: &str = "2026-11-10T10:00:00Z";
const NOW: &str = "2026-11-12T10:00:00Z";
const NONE: Grounding = Grounding {
    user_turn: false,
    structured_item: false,
};
const USER: Grounding = Grounding {
    user_turn: true,
    structured_item: false,
};
const ITEM: Grounding = Grounding {
    user_turn: false,
    structured_item: true,
};

async fn pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
        .await
        .unwrap();
    (dir, p)
}

async fn record(p: &SqlitePool, id: &str, kind: &str, at: &str) {
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, body_norm, last_seen_at) \
         VALUES (?, ?, 'accepted', ?, '[]', '[]', ?, ?, ?)",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("body of {id}"))
    .bind(at)
    .bind(format!("body of {id}"))
    .bind(at)
    .execute(p)
    .await
    .unwrap();
}

async fn source(p: &SqlitePool, id: &str, record: &str, at: &str) {
    sqlx::query(
        "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
         title, text, started_at, run, assigned_by) VALUES (?, ?, 'note', 'd', '/p', 'user', 'a', 't', 'x', ?, 'r', 'rule')",
    )
    .bind(id)
    .bind(format!("h-{id}"))
    .bind(at)
    .execute(p)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES (?, ?, 0)")
        .bind(record)
        .bind(id)
        .execute(p)
        .await
        .unwrap();
}

/// Runs `supersede(old, new)` in its own change set; returns (what it did, change id when written).
async fn run_g(p: &SqlitePool, old: &str, new: &str, g: Grounding) -> (Replace, Option<String>) {
    let mut tx = p.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", NOW);
    let done = supersede(&mut tx, &mut cs, old, new, g, NOW).await.unwrap();
    let id = cs
        .commit(&mut tx, "Saved 1 · replaced 1", serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (done, id)
}

/// `run_g`, user-grounded; true when it superseded.
async fn run(p: &SqlitePool, old: &str, new: &str) -> (bool, Option<String>) {
    let (done, id) = run_g(p, old, new, USER).await;
    (done == Replace::Superseded, id)
}

async fn contests(p: &SqlitePool, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT contests FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(p)
        .await
        .unwrap()
}

async fn in_memory(p: &SqlitePool, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memory WHERE id = ?")
        .bind(id)
        .fetch_one(p)
        .await
        .unwrap()
        > 0
}

async fn row(
    p: &SqlitePool,
    id: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    sqlx::query_as(
        "SELECT valid_from, valid_to, supersedes, superseded_by FROM records WHERE id = ?",
    )
    .bind(id)
    .fetch_one(p)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_replaced_record_leaves_memory_stays_as_history_and_undo_restores_both() {
    let (_d, p) = pool().await;
    record(&p, "old", "project-state", T0).await;
    record(&p, "new", "project-state", NOW).await;
    source(&p, "s-new", "new", "2026-11-11T09:00:00Z").await;
    let mut conn = p.acquire().await.unwrap();
    let (old_img, new_img) = (
        image(&mut conn, "old").await.unwrap(),
        image(&mut conn, "new").await.unwrap(),
    );
    drop(conn);

    let (done, change) = run(&p, "old", "new").await;
    assert!(done);
    // The moment the new fact began: its earliest cited source.
    let at = Some("2026-11-11T09:00:00Z".to_owned());
    // `old` never had a `valid_from` here (a row from before B2-01's backfill would); the link and
    // `valid_to` are what B4-02 sets.
    assert_eq!(
        row(&p, "old").await,
        (None, at.clone(), None, Some("new".into()))
    );
    assert_eq!(
        row(&p, "new").await,
        (at.clone(), None, Some("old".into()), None)
    );
    assert!(!in_memory(&p, "old").await);
    assert!(in_memory(&p, "new").await);
    // History: still readable by id, with its successor named.
    let status: String = sqlx::query_scalar("SELECT status FROM records WHERE id = 'old'")
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(status, "accepted");

    let mut tx = p.begin().await.unwrap();
    undo(&mut tx, &change.unwrap(), "2026-11-13T10:00:00Z")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    let mut conn = p.acquire().await.unwrap();
    assert_eq!(image(&mut conn, "old").await.unwrap(), old_img);
    assert_eq!(image(&mut conn, "new").await.unwrap(), new_img);
    drop(conn);
    assert!(in_memory(&p, "old").await);
}

#[tokio::test]
async fn the_moment_never_precedes_the_old_record_began() {
    let (_d, p) = pool().await;
    record(&p, "old", "task", "2026-11-10T10:00:00Z").await;
    record(&p, "new", "task", NOW).await;
    source(&p, "s-early", "new", "2026-01-01T00:00:00Z").await;
    assert!(run(&p, "old", "new").await.0);
    let (_, to, _, _) = row(&p, "old").await;
    assert_eq!(to.as_deref(), Some("2026-11-10T10:00:00Z"));
}

#[tokio::test]
async fn without_a_cited_source_the_moment_is_now() {
    let (_d, p) = pool().await;
    record(&p, "old", "fact", T0).await;
    record(&p, "new", "fact", NOW).await;
    assert!(run(&p, "old", "new").await.0);
    assert_eq!(row(&p, "new").await.0.as_deref(), Some(NOW));
}

#[tokio::test]
async fn a_weakly_grounded_replaces_of_any_kind_only_contests() {
    for kind in [
        "rule",
        "preference",
        "fact",
        "decision",
        "task",
        "project-state",
    ] {
        let (_d, p) = pool().await;
        record(&p, "old", kind, T0).await;
        record(&p, "new", kind, NOW).await;
        let (done, change) = run_g(&p, "old", "new", NONE).await;
        assert_eq!(
            done,
            Replace::Contested,
            "{kind} must survive an ungrounded replaces"
        );
        assert!(
            in_memory(&p, "old").await && in_memory(&p, "new").await,
            "{kind}"
        );
        assert_eq!(row(&p, "old").await, (None, None, None, None), "{kind}");
        assert_eq!(contests(&p, "new").await.as_deref(), Some("old"), "{kind}");
        // The link is in the change set: Undo takes it back with the save.
        let mut tx = p.begin().await.unwrap();
        undo(&mut tx, &change.unwrap(), NOW)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(contests(&p, "new").await, None, "{kind}");
        assert!(run(&p, "old", "new").await.0, "{kind}");
        assert!(!in_memory(&p, "old").await, "{kind}");
    }
}

#[tokio::test]
async fn a_jira_or_github_item_grounds_only_a_task_or_project_state() {
    for (kind, ok) in [
        ("task", true),
        ("project-state", true),
        ("fact", false),
        ("rule", false),
    ] {
        let (_d, p) = pool().await;
        record(&p, "old", kind, T0).await;
        record(&p, "new", kind, NOW).await;
        let want = if ok {
            Replace::Superseded
        } else {
            Replace::Contested
        };
        assert_eq!(run_g(&p, "old", "new", ITEM).await.0, want, "{kind}");
        assert_eq!(in_memory(&p, "old").await, !ok, "{kind}");
    }
}

#[tokio::test]
async fn a_replaces_across_kinds_never_supersedes() {
    let (_d, p) = pool().await;
    record(&p, "old", "rule", T0).await;
    record(&p, "new", "fact", NOW).await;
    assert_eq!(run_g(&p, "old", "new", USER).await.0, Replace::Contested);
    assert!(in_memory(&p, "old").await);
}

#[tokio::test]
async fn undo_after_a_later_reinforce_does_not_leave_a_chain_in_force() {
    // (a) The successor was saved by the undone change set: Undo archives it.
    let (_d, p) = pool().await;
    record(&p, "old", "decision", T0).await;
    let mut tx = p.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", NOW);
    cs.touch(&mut tx, "new").await.unwrap();
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, body_norm, last_seen_at) \
         VALUES ('new', 'decision', 'accepted', 'body of new', '[]', '[]', ?, 'body of new', ?)",
    )
    .bind(NOW)
    .bind(NOW)
    .execute(&mut *tx)
    .await
    .unwrap();
    let done = supersede(&mut tx, &mut cs, "old", "new", USER, NOW)
        .await
        .unwrap();
    assert_eq!(done, Replace::Superseded);
    let change = cs
        .commit(&mut tx, "Saved 1 · replaced 1", serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    reinforce_later(&p, "new").await;
    let skipped = undo_all(&p, &change.unwrap()).await;
    assert_eq!(skipped, ["new"]);
    assert!(in_memory(&p, "old").await);
    assert!(
        !in_memory(&p, "new").await,
        "archived, not a second fact in force"
    );

    // (b) The successor existed before: Undo puts its link back instead.
    let (_d, p) = pool().await;
    record(&p, "old", "decision", T0).await;
    record(&p, "new", "decision", NOW).await;
    let (done, change) = run(&p, "old", "new").await;
    assert!(done);
    reinforce_later(&p, "new").await;
    assert_eq!(undo_all(&p, &change.unwrap()).await, ["new"]);
    assert!(in_memory(&p, "old").await && in_memory(&p, "new").await);
    assert_eq!(row(&p, "new").await, (None, None, None, None));
    assert_eq!(row(&p, "old").await, (None, None, None, None));
}

/// A later save reinforces `id` in its own change set.
async fn reinforce_later(p: &SqlitePool, id: &str) {
    let later = "2026-11-12T12:00:00Z";
    let mut tx = p.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", later);
    reinforce(&mut tx, &mut cs, id, &[], later).await.unwrap();
    cs.commit(&mut tx, "Reinforced 1", serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Undoes `change`; returns the skipped records.
async fn undo_all(p: &SqlitePool, change: &str) -> Vec<String> {
    let mut tx = p.begin().await.unwrap();
    let done = undo(&mut tx, change, "2026-11-13T10:00:00Z")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    done.skipped
}

#[tokio::test]
async fn a_target_outside_memory_or_the_record_itself_is_ignored() {
    let (_d, p) = pool().await;
    record(&p, "a", "fact", T0).await;
    record(&p, "b", "fact", NOW).await;
    record(&p, "c", "fact", NOW).await;
    assert_eq!(run_g(&p, "a", "a", USER).await.0, Replace::Ignored);
    assert_eq!(run_g(&p, "nope", "b", USER).await.0, Replace::Ignored);
    // Already superseded: a second replace of the same target does nothing.
    assert!(run(&p, "a", "b").await.0);
    assert_eq!(run_g(&p, "a", "c", USER).await.0, Replace::Ignored);
    assert_eq!(row(&p, "a").await.3.as_deref(), Some("b"));
    // Archived targets are not in memory either.
    sqlx::query("UPDATE records SET archived_at = ? WHERE id = 'c'")
        .bind(NOW)
        .execute(&p)
        .await
        .unwrap();
    record(&p, "d", "fact", NOW).await;
    assert_eq!(run_g(&p, "c", "d", USER).await.0, Replace::Ignored);
}

#[tokio::test]
async fn the_sql_staleness_test_equals_the_pure_one() {
    let (_d, p) = pool().await;
    let cut = "2026-08-01T00:00:00Z";
    let mut n = 0;
    for kind in ["project-state", "task", "decision", "rule", "fact"] {
        for at in ["2026-07-01T00:00:00Z", "2026-09-01T00:00:00Z"] {
            n += 1;
            record(&p, &format!("r{n}"), kind, at).await;
            let sql: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT {STALE_SQL} FROM records WHERE id = ?"
            )))
            .bind(cut)
            .bind(format!("r{n}"))
            .fetch_one(&p)
            .await
            .unwrap();
            assert_eq!(sql != 0, is_stale(kind, at, cut), "{kind} {at}");
        }
    }
}

/// B4-02 round 3: a contested record never steers. Search and the lists put it after everything
/// else, and its text names the record it contests.
#[tokio::test]
async fn a_contested_record_ranks_last_and_says_what_it_contests() {
    let fx = fx().await;
    let room = committed_room_named(&fx, "Alpha", &[("Notes", "a note")]).await;
    // `rec-a` would come first on its id alone (equal times): only the demotion puts it last.
    put_record(
        &fx,
        &room,
        "rec-a",
        "decision",
        "accepted",
        "ship on friday",
    )
    .await;
    put_record(
        &fx,
        &room,
        "rec-b",
        "decision",
        "accepted",
        "ship on friday with billing",
    )
    .await;
    put_record(
        &fx,
        &room,
        "rec-c",
        "decision",
        "accepted",
        "ship on friday with billing export",
    )
    .await;
    let p = canon_pool(&fx, &room).await;
    sqlx::query("UPDATE records SET contests = 'rec-c' WHERE id = 'rec-a'")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    open_room(&fx, &room).await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;

    let ids = |v: &Value, list: &str| -> Vec<String> {
        v[list]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let d = read(&fx, &s, "brainAiDecisions", json!({})).await;
    assert_eq!(ids(&d, "records"), ["rec-b", "rec-c", "rec-a"], "{d}");
    let label = "contests record rec-c (decision), unresolved";
    let text = |v: &Value, list: &str, id: &str| -> String {
        v[list]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(text(&d, "records", "rec-a").contains(label), "{d}");
    assert!(
        !text(&d, "records", "rec-b").contains("contests record"),
        "{d}"
    );

    let hits = read(
        &fx,
        &s,
        "brainAiSearch",
        json!({"q": "friday", "mode": "keyword"}),
    )
    .await;
    assert_eq!(
        ids(&hits, "hits").last().map(String::as_str),
        Some("rec-a"),
        "{hits}"
    );
    assert!(text(&hits, "hits", "rec-a").contains(label), "{hits}");

    let one = read(
        &fx,
        &s,
        "brainAiRecord",
        json!({"room": room, "id": "rec-a"}),
    )
    .await;
    assert!(one["text"].as_str().unwrap().contains(label), "{one}");
}
