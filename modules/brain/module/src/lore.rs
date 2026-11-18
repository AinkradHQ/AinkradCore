//! The Lore collector (R3-01): notes feed the Brain. The only contract with Lore is its view
//! `lore_feed_v1` (id, project, kind, title, text, rev, updated_at, trashed_at); Lore absent means
//! the source reports `lore_not_installed` and skips, and Brain off leaves Lore untouched.
//!
//! - A note is taken when it has settled (no save for 10 minutes), has text, and its rev passed the
//!   cursor, which holds the last rev taken per note.
//! - Its item id is derived from the note id, so a newer text replaces the older source in its
//!   room (the commit updates by item id); the origin is `lore://note/<id>`.
//! - A project note goes to the room linked in `brain_project_rooms` and a personal or daily note
//!   to the one `personal` room; both are routed by the same `route_known` as every incremental
//!   run (no review). A note with no such room waits in Unsorted. A note follows only its
//!   project, so the two-employer rule is untouched.
//! - A trashed or deleted note's source leaves its room, as does a source whose note moved to
//!   another room (it is then added where it now belongs).
//! - Items pass the same intake (rules, dedupe, clean-up) as every other collector.
//!
//! ponytail: a note restored from the trash without an edit is not sent again until its next edit
//! (the cursor holds its rev); a removed source keeps the records distilled from it and its
//! sentence vector; an id that left the feed stays in the cursor (one lookup per sync).

use std::collections::{BTreeMap, BTreeSet};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::scheduler::{iso_of_unix, unix_secs};
use ainkrad_core_server::store::begin_write;
use brain_model::group::UNSORTED;
use brain_model::item::{Author, AuthorKind, Item, MAX_TEXT, Origin, SourceKind, hash_of};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::files::{self, CANON};
use crate::review::room_id;
use crate::sync::{Busy, STAGING_DAYS, SyncResult, ensure_core_source, merge_cursor, result_of};
use crate::{Brain, code};

pub const LORE_SOURCE: &str = "lore";
/// A note is sent once it has not been saved for this long.
const SETTLE_SECS: i64 = 600;
/// Notes taken per sync; the rest wait for the next one (the cursor is per note).
const MAX_NOTES: usize = 200;

struct Room {
    id: String,
    name: String,
    kind: String,
}

/// The stable item id of a note: 26 characters of the ULID alphabet from a hash of the note id.
fn item_id(note: &str) -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    Sha256::digest(format!("lore-note:{note}"))
        .iter()
        .take(26)
        .map(|b| char::from(A[usize::from(*b) % 32]))
        .collect()
}

/// The room a note belongs in: its project's linked room; a personal or daily note's `personal`
/// room when there is exactly one. None means Unsorted. Only a room whose id is the one its name
/// gives is reachable (`route_known` and the commit find rooms by name).
async fn room_for(app: &App, project: Option<&str>) -> Result<Option<Room>, ApiError> {
    let rows: Vec<(String, String, String)> = match project {
        Some(p) => {
            sqlx::query_as(
                "SELECT r.id, r.name, r.kind FROM brain_project_rooms l JOIN brain_rooms r ON r.id = l.room \
                 WHERE l.project = ? AND r.state = 'active'",
            )
            .bind(p)
            .fetch_all(&app.pool)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT id, name, kind FROM brain_rooms WHERE kind = 'personal' AND state = 'active'",
            )
            .fetch_all(&app.pool)
            .await?
        }
    };
    Ok(match <[_; 1]>::try_from(rows) {
        Ok([(id, name, kind)]) if room_id(&name) == id => Some(Room { id, name, kind }),
        _ => None,
    })
}

/// The room a note's source lives in now, if any.
async fn home_of(app: &App, item: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT room FROM brain_seen WHERE item_id = ? AND room != 'refused' ORDER BY rowid DESC LIMIT 1",
    )
    .bind(item)
    .fetch_optional(&app.pool)
    .await?)
}

/// Takes `item`'s source out of `room` (op-log and outbox row included) and forgets its hash.
async fn remove_source(app: &App, key: &[u8; 32], room: &str, item: &str) -> Result<(), ApiError> {
    let canon = files::open_migrated(&files::room_path(&files::root(app), room), key, false, CANON)
        .await
        .map_err(|e| code(500, "room_unavailable", e.to_string()))?;
    let mut tx = canon.begin().await?;
    let gone = sqlx::query("DELETE FROM sources WHERE item_id = ?")
        .bind(item)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone > 0 {
        let seq: i64 = sqlx::query_scalar(
            "INSERT INTO op_log (op, ref, at) VALUES ('source.remove', ?, ?) RETURNING seq",
        )
        .bind(item)
        .bind(app.clock.now())
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO outbox (op_seq) VALUES (?)")
            .bind(seq)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    canon.close().await;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("DELETE FROM brain_seen WHERE item_id = ? AND room = ?")
        .bind(item)
        .bind(room)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Drops staged copies of `items` from the runs that still wait for review, so a trashed note is
/// never committed later.
async fn unstage(app: &App, b: &Brain, items: &[String]) -> Result<(), ApiError> {
    let runs: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT c.run FROM brain_run_cursors c JOIN brain_import_runs r ON r.id = c.run \
         WHERE c.source = ? AND r.state = 'review'",
    )
    .bind(LORE_SOURCE)
    .fetch_all(&app.pool)
    .await?;
    for run in runs {
        let st = crate::imports::staging(app, b, &run, false).await?;
        for i in items {
            sqlx::query("DELETE FROM items WHERE item_id = ?")
                .bind(i)
                .execute(&st)
                .await?;
        }
        st.close().await;
    }
    Ok(())
}

fn note_item(id: &str, title: &str, text: &str, updated: &str) -> Item {
    let mut end = text.len().min(MAX_TEXT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let text = text[..end].trim_end();
    Item {
        item_id: item_id(id),
        source_kind: SourceKind::Note,
        content_hash: hash_of(text),
        origin: Origin {
            device: "core".to_owned(),
            path: format!("lore://note/{id}"),
            range: None,
        },
        project_hint: None,
        author: Author {
            kind: AuthorKind::Person,
            name: "lore".to_owned(),
        },
        title: title.chars().take(200).collect(),
        text: text.to_owned(),
        links: vec![],
        started_at: updated.to_owned(),
        ended_at: None,
    }
}

type Feed = (String, Option<String>, i64, String, Option<String>, bool);

/// Takes the settled, changed notes of Lore into a new incremental run, routes them (see the
/// module doc) and removes the sources of trashed or deleted notes.
pub(crate) async fn sync_lore(
    app: &App,
    b: &Brain,
    owner: Option<&str>,
) -> Result<SyncResult, ApiError> {
    let Some(_busy) = Busy::take(&b.inner.syncing) else {
        return Ok(SyncResult::idle("running"));
    };
    ensure_core_source(app).await?;
    let row = sqlx::query("SELECT enabled, cursor FROM brain_sources WHERE id = ?")
        .bind(LORE_SOURCE)
        .fetch_one(&app.pool)
        .await?;
    if row.try_get::<i64, _>("enabled")? != 1 {
        return Ok(SyncResult::idle("disabled"));
    }
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'view' AND name = 'lore_feed_v1'",
    )
    .fetch_one(&app.pool)
    .await?;
    if present == 0 {
        return Ok(SyncResult::idle("lore_not_installed"));
    }
    let mut cursor: Value =
        serde_json::from_str(&row.try_get::<String, _>("cursor")?).unwrap_or(json!({}));
    // What a run still open already holds is not taken again.
    let cutoff = iso_of_unix(app.clock.unix() - STAGING_DAYS * 86_400);
    let open: Vec<String> = sqlx::query_scalar(
        "SELECT c.cursor FROM brain_run_cursors c JOIN brain_import_runs r ON r.id = c.run \
         WHERE c.source = ? AND r.state IN ('collecting','discovering','review','committing') AND r.started_at > ?",
    )
    .bind(LORE_SOURCE)
    .bind(&cutoff)
    .fetch_all(&app.pool)
    .await?;
    for c in open {
        merge_cursor(&mut cursor, &serde_json::from_str(&c).unwrap_or(json!({})));
    }
    let key = b.key_for(app, owner).await?;
    let feed: Vec<Feed> = sqlx::query_as(
        "SELECT id, project, rev, updated_at, trashed_at, trim(text) != '' FROM lore_feed_v1 ORDER BY updated_at, id",
    )
    .fetch_all(&app.pool)
    .await?;
    // Trashed or deleted notes: the ones in the feed as trashed, and the ones taken once that the
    // feed no longer lists.
    let listed: BTreeSet<&str> = feed.iter().map(|n| n.0.as_str()).collect();
    let mut gone: BTreeSet<&str> = feed
        .iter()
        .filter(|n| n.4.is_some())
        .map(|n| n.0.as_str())
        .collect();
    if let Some(taken) = cursor["notes"].as_object() {
        gone.extend(taken.keys().map(String::as_str).filter(|k| !listed.contains(k)));
    }
    let mut removed = vec![];
    for note in gone {
        let item = item_id(note);
        if let Some(room) = home_of(app, &item).await?
            && let Err(e) = remove_source(app, &key, &room, &item).await
        {
            tracing::warn!(code = e.code, "lore: a trashed note's source stays: {}", e.message);
            continue;
        }
        removed.push(item);
    }
    unstage(app, b, &removed).await?;
    // Changed, settled and not empty.
    let settled = app.clock.unix() - SETTLE_SECS;
    let due = feed
        .iter()
        .filter(|n| n.4.is_none() && n.5 && n.2 > cursor["notes"][&n.0].as_i64().unwrap_or(0))
        .filter(|n| unix_secs(&n.3).is_some_and(|t| t <= settled))
        .take(MAX_NOTES);
    let mut taken = json!({"notes": {}});
    let mut items = vec![];
    let mut place: BTreeMap<String, Option<Room>> = BTreeMap::new();
    for (id, project, rev, updated, ..) in due {
        let room = room_for(app, project.as_deref()).await?;
        // A source in another room than the note belongs in is taken out and added where it belongs.
        let item = item_id(id);
        if let Some(home) = home_of(app, &item).await?
            && room.as_ref().map(|r| &r.id) != Some(&home)
            && remove_source(app, &key, &home, &item).await.is_err()
        {
            continue;
        }
        let (title, text): (String, String) =
            sqlx::query_as("SELECT title, text FROM lore_feed_v1 WHERE id = ?")
                .bind(id)
                .fetch_one(&app.pool)
                .await?;
        taken["notes"][id.as_str()] = json!(rev);
        let i = note_item(id, &title, &text, updated);
        place.insert(i.item_id.clone(), room);
        items.push(i);
    }
    if items.is_empty() {
        sqlx::query("UPDATE brain_sources SET last_run = ? WHERE id = ?")
            .bind(app.clock.now())
            .bind(LORE_SOURCE)
            .execute(&app.pool)
            .await?;
        return Ok(SyncResult::idle("nothing_new"));
    }
    let run =
        crate::imports::start_run(app, b, "incremental", &[LORE_SOURCE.to_owned()], owner).await?;
    crate::imports::stage_items(app, b, &run, &items).await?;
    sqlx::query(
        "INSERT INTO brain_run_cursors (run, source, cursor) VALUES (?, ?, ?) \
         ON CONFLICT(run, source) DO UPDATE SET cursor = excluded.cursor",
    )
    .bind(&run)
    .bind(LORE_SOURCE)
    .bind(taken.to_string())
    .execute(&app.pool)
    .await?;
    sqlx::query("UPDATE brain_sources SET last_run = ? WHERE id = ?")
        .bind(app.clock.now())
        .bind(LORE_SOURCE)
        .execute(&app.pool)
        .await?;
    propose(app, b, &run, &place).await?;
    let outcome = crate::sync::route_known(app, b, &run).await?;
    if outcome.unsorted > 0 {
        crate::suggest::start(app, b, &run).await;
    }
    result_of(app, run, Some(outcome)).await
}

/// One proposal per target room (named after it, so `route_known` commits into it) and one
/// Unsorted, over the items that passed intake; the run moves to `review`.
async fn propose(
    app: &App,
    b: &Brain,
    run: &str,
    place: &BTreeMap<String, Option<Room>>,
) -> Result<(), ApiError> {
    crate::imports::mark_done(app, run, LORE_SOURCE, &[LORE_SOURCE.to_owned()]).await?;
    let st = crate::imports::staging(app, b, run, false).await?;
    let staged: BTreeSet<String> = sqlx::query_scalar("SELECT item_id FROM items")
        .fetch_all(&st)
        .await?
        .into_iter()
        .collect();
    let mut tx = st.begin().await?;
    let mut made = BTreeSet::new();
    for (item, room) in place.iter().filter(|(i, _)| staged.contains(*i)) {
        let (pid, name, kind) = match room {
            Some(r) => (format!("p-lore-{}", r.id), r.name.as_str(), r.kind.as_str()),
            None => (UNSORTED.to_owned(), "Unsorted", "general"),
        };
        if made.insert(pid.clone()) {
            sqlx::query("INSERT INTO proposals (id, name, kind_guess, kind) VALUES (?, ?, ?, ?)")
                .bind(&pid)
                .bind(name)
                .bind(kind)
                .bind(kind)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ?")
            .bind(&pid)
            .bind(item)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    st.close().await;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE brain_import_runs SET state = 'review', stage = 'review' WHERE id = ?")
        .bind(run)
        .execute(&mut *tx)
        .await?;
    let counts = crate::imports::load_counts(app, run).await?;
    crate::imports::record_progress(&mut tx, run, "review", &counts).await?;
    tx.commit().await?;
    Ok(())
}
