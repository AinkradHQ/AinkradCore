//! R3-01: Lore notes feed the Brain through `lore_feed_v1`, the only contract between the two. The
//! view is stood up here as the module defines it; every note is synthetic.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::projects::{self, Who};
use axum::http::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::common::*;

const OLD: &str = "2026-11-01T08:00:00.000Z";

async fn lore_tables(fx: &Fx) {
    sqlx::query(
        "CREATE TABLE lore_notes (id TEXT PRIMARY KEY, project TEXT, kind TEXT NOT NULL DEFAULT 'note', \
         title TEXT NOT NULL, text TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL, trashed_at TEXT, \
         updated_by TEXT NOT NULL DEFAULT 'person:d_test')",
    )
    .execute(&fx.app.pool)
    .await
    .unwrap();
    sqlx::query("CREATE VIEW lore_feed_v1 AS SELECT id, project, kind, title, text, rev, updated_at, trashed_at, updated_by FROM lore_notes")
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

async fn note(fx: &Fx, id: &str, project: Option<i64>, text: &str, rev: i64, at: &str) {
    sqlx::query(
        "INSERT INTO lore_notes (id, project, title, text, rev, updated_at) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET project = excluded.project, text = excluded.text, rev = excluded.rev, updated_at = excluded.updated_at",
    )
    .bind(id)
    .bind(project.map(|p| p.to_string()))
    .bind(format!("Title of {id}"))
    .bind(text)
    .bind(rev)
    .bind(at)
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

async fn trash(fx: &Fx, id: &str) {
    sqlx::query("UPDATE lore_notes SET trashed_at = ? WHERE id = ?")
        .bind(OLD)
        .bind(id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

async fn project(fx: &Fx, slug: &str, name: &str) -> (i64, String) {
    let now = fx.app.clock.now();
    let who = Who {
        by_device: &fx.admin.id,
        actor: AuditActor::System,
        now: &now,
    };
    let id = projects::create(&fx.app.pool, slug, name, "", "manual", who)
        .await
        .unwrap()
        .id;
    fx.brain.project_rooms_step().await.unwrap();
    let room = sqlx::query_scalar("SELECT room FROM brain_project_rooms WHERE project = ?")
        .bind(id.to_string())
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    (id, room)
}

/// A `personal` room as a commit would make it (its id is the one its name gives).
async fn personal_room(fx: &Fx) -> String {
    let name = "Me";
    let hash: String = Sha256::digest(name.to_lowercase().as_bytes())[..3]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let id = format!("me-{hash}");
    sqlx::query("INSERT INTO brain_rooms (id, name, kind) VALUES (?, ?, 'personal')")
        .bind(&id)
        .bind(name)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO brain_room_policy (room) VALUES (?)")
        .bind(&id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    id
}

async fn lore_sync(fx: &Fx) -> Value {
    ok(fx, Method::POST, "/sync", Some(json!({"source": "lore"}))).await
}

/// `(title, text)` of every source in a room; the room's file may not exist yet.
async fn sources(fx: &Fx, room: &str) -> Vec<(String, String)> {
    let path = brain_module::files::room_path(&brain_module::files::root(&fx.app), room);
    if !path.exists() {
        return vec![];
    }
    let pool = canon_pool(fx, room).await;
    let rows = sqlx::query_as("SELECT title, text FROM sources ORDER BY item_id")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    rows
}

/// A Core that has a brain key (made by one ordinary sync), with Lore stood up.
async fn fx_lore() -> Fx {
    let fx = fx().await;
    lore_tables(&fx).await;
    fx
}

#[tokio::test]
async fn lore_absent_is_reported_and_nothing_fails() {
    let fx = fx().await;
    let v = lore_sync(&fx).await;
    assert_eq!(v["idle"], "lore_not_installed", "{v}");
}

#[tokio::test]
async fn a_project_note_lands_in_its_room_and_a_personal_note_in_the_personal_room() {
    let fx = fx_lore().await;
    let (p, room) = project(&fx, "shop", "Shop").await;
    let me = personal_room(&fx).await;
    note(
        &fx,
        "ln_project0001",
        Some(p),
        "Ship the cart on Friday.",
        1,
        OLD,
    )
    .await;
    note(&fx, "ln_personal001", None, "Buy oat milk.", 1, OLD).await;
    let v = lore_sync(&fx).await;
    assert_eq!(v["found"], 2, "{v}");
    assert_eq!(v["state"], "committed", "no review needed: {v}");
    assert_eq!(v["unsorted"], 0);
    assert_eq!(
        sources(&fx, &room).await,
        vec![(
            "Title of ln_project0001".into(),
            "Ship the cart on Friday.".into()
        )]
    );
    assert_eq!(sources(&fx, &me).await.len(), 1);
    // The origin names the note, and the source kind is `note`.
    let c = canon_pool(&fx, &room).await;
    let (path, kind, by): (String, String, String) =
        sqlx::query_as("SELECT path, source_kind, assigned_by FROM sources")
            .fetch_one(&c)
            .await
            .unwrap();
    assert_eq!(
        (path.as_str(), kind.as_str(), by.as_str()),
        ("lore://note/ln_project0001", "note", "rule")
    );
    // Nothing changed: nothing is taken again.
    assert_eq!(lore_sync(&fx).await["idle"], "nothing_new");
}

async fn author_kind(fx: &Fx, room: &str) -> String {
    let c = canon_pool(fx, room).await;
    let k: String = sqlx::query_scalar("SELECT author_kind FROM sources")
        .fetch_one(&c)
        .await
        .unwrap();
    c.close().await;
    k
}

/// B3-04 review: a note an AI session edited last is an `agent` source (it never grounds an AI
/// proposal); a person's later edit makes it a `person` one again.
#[tokio::test]
async fn a_note_last_edited_by_an_ai_session_is_an_agent_source() {
    let fx = fx_lore().await;
    let (p, room) = project(&fx, "shop", "Shop").await;
    note(
        &fx,
        "ln_aiedit00001",
        Some(p),
        "Ship the cart on Friday.",
        1,
        OLD,
    )
    .await;
    sqlx::query("UPDATE lore_notes SET updated_by = 'session:as_1' WHERE id = 'ln_aiedit00001'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(lore_sync(&fx).await["found"], 1);
    assert_eq!(author_kind(&fx, &room).await, "agent");
    note(
        &fx,
        "ln_aiedit00001",
        Some(p),
        "Ship the cart on Monday.",
        2,
        OLD,
    )
    .await;
    sqlx::query("UPDATE lore_notes SET updated_by = 'person:d_test' WHERE id = 'ln_aiedit00001'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(lore_sync(&fx).await["found"], 1);
    assert_eq!(
        author_kind(&fx, &room).await,
        "person",
        "the update carries the new editor"
    );
}

#[tokio::test]
async fn a_note_is_taken_only_once_it_has_settled() {
    let fx = fx_lore().await;
    let (p, room) = project(&fx, "shop", "Shop").await;
    let now = fx.app.clock.now();
    note(
        &fx,
        "ln_fresh0000001",
        Some(p),
        "Still typing this.",
        1,
        &now,
    )
    .await;
    assert_eq!(lore_sync(&fx).await["idle"], "nothing_new");
    assert!(sources(&fx, &room).await.is_empty());
    note(
        &fx,
        "ln_fresh0000001",
        Some(p),
        "Still typing this.",
        1,
        OLD,
    )
    .await;
    assert_eq!(lore_sync(&fx).await["found"], 1);
}

#[tokio::test]
async fn an_edited_note_replaces_its_source_and_a_trashed_note_leaves_the_room() {
    let fx = fx_lore().await;
    let (p, room) = project(&fx, "shop", "Shop").await;
    note(
        &fx,
        "ln_edit00000001",
        Some(p),
        "First draft of the plan.",
        1,
        OLD,
    )
    .await;
    lore_sync(&fx).await;
    note(
        &fx,
        "ln_edit00000001",
        Some(p),
        "Second draft of the plan.",
        2,
        "2026-11-02T08:00:00.000Z",
    )
    .await;
    let v = lore_sync(&fx).await;
    assert_eq!(v["found"], 1, "{v}");
    assert_eq!(
        sources(&fx, &room).await,
        vec![(
            "Title of ln_edit00000001".into(),
            "Second draft of the plan.".into()
        )],
        "one source per note"
    );
    // Trashed: removed at the next sync, with an op-log row; a later sync changes nothing.
    trash(&fx, "ln_edit00000001").await;
    lore_sync(&fx).await;
    assert!(sources(&fx, &room).await.is_empty());
    let c = canon_pool(&fx, &room).await;
    let ops: Vec<String> = sqlx::query_scalar("SELECT op FROM op_log ORDER BY seq")
        .fetch_all(&c)
        .await
        .unwrap();
    assert_eq!(
        ops.last().map(String::as_str),
        Some("source.remove"),
        "{ops:?}"
    );
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_seen WHERE room = ?")
        .bind(&room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(seen, 0);
    assert_eq!(lore_sync(&fx).await["idle"], "nothing_new");
}

#[tokio::test]
async fn a_note_follows_only_its_own_project() {
    let fx = fx_lore().await;
    let (a, room_a) = project(&fx, "acme", "Acme").await;
    let (b, room_b) = project(&fx, "bolt", "Bolt").await;
    note(
        &fx,
        "ln_acme00000001",
        Some(a),
        "Acme contract terms.",
        1,
        OLD,
    )
    .await;
    note(&fx, "ln_bolt00000001", Some(b), "Bolt launch plan.", 1, OLD).await;
    lore_sync(&fx).await;
    assert_eq!(sources(&fx, &room_a).await[0].1, "Acme contract terms.");
    assert_eq!(sources(&fx, &room_b).await[0].1, "Bolt launch plan.");
    // Moved to the other project: the source leaves the first room and joins the second.
    note(
        &fx,
        "ln_acme00000001",
        Some(b),
        "Acme contract terms.",
        2,
        "2026-11-02T08:00:00.000Z",
    )
    .await;
    lore_sync(&fx).await;
    assert!(sources(&fx, &room_a).await.is_empty());
    assert_eq!(sources(&fx, &room_b).await.len(), 2);
}

#[tokio::test]
async fn a_note_with_no_room_waits_in_unsorted_for_review() {
    let fx = fx_lore().await;
    // No personal room, and a project that has no room (never linked): both wait.
    note(
        &fx,
        "ln_nobody00001",
        None,
        "A thought with no room.",
        1,
        OLD,
    )
    .await;
    note(
        &fx,
        "ln_orphan00001",
        Some(999),
        "A note of a project with no room.",
        1,
        OLD,
    )
    .await;
    let v = lore_sync(&fx).await;
    assert_eq!(
        (v["unsorted"].as_i64(), v["state"].as_str()),
        (Some(2), Some("review")),
        "{v}"
    );
    assert_eq!(v["routed"], json!([]));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 'brain.inbox'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    // The run holds its notes, so they are not taken again.
    assert_eq!(lore_sync(&fx).await["idle"], "nothing_new");
    // Trashed while waiting: never committed later.
    trash(&fx, "ln_nobody00001").await;
    lore_sync(&fx).await;
    let run = v["run"].as_str().unwrap();
    let st = staging_pool(&fx, run).await;
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
        .fetch_one(&st)
        .await
        .unwrap();
    assert_eq!(left, 1);
}

#[tokio::test]
async fn intake_cleans_a_note_like_any_other_item_and_the_switch_stops_the_source() {
    let fx = fx_lore().await;
    let (p, room) = project(&fx, "shop", "Shop").await;
    note(
        &fx,
        "ln_secret00001",
        Some(p),
        "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 here",
        1,
        OLD,
    )
    .await;
    lore_sync(&fx).await;
    let text = &sources(&fx, &room).await[0].1;
    assert!(
        !text.contains("abcdefghijklmnopqrstuvwxyz0123456789"),
        "{text}"
    );
    ok(
        &fx,
        Method::PUT,
        "/sources/lore",
        Some(json!({"device": "core", "kind": "note", "enabled": false})),
    )
    .await;
    note(&fx, "ln_other000001", Some(p), "A newer note.", 1, OLD).await;
    assert_eq!(lore_sync(&fx).await["idle"], "disabled");
}
