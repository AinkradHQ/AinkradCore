//! Commit (E2-4): "Import accepted rooms". Creates each accepted room, writes its cleaned items as
//! `sources` into the room's encrypted `canon.db` with an op-log and outbox row, records hashes in
//! `brain_seen`, turns refused rooms into rules and closes the run. Idempotent: a crash mid-commit
//! is resumed by committing again, text already in any room is never written again, and an item
//! (by its stable id) imported again with new text is updated in its room, never copied.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::files::{self, CANON};
use crate::imports::run_state;
use crate::review::{RoomConfig, draft_rules, mixed, parse, room_id};
use crate::{Brain, ROOM_BACKUP_READY, code, record};

#[derive(Serialize, ToSchema)]
pub struct RoomMade {
    pub proposal: String,
    pub room: String,
    pub name: String,
    pub kind: String,
    /// Sources written to the room by this commit.
    pub sources: i64,
    /// False when the room already existed (a resumed commit or a later run).
    pub created: bool,
}

#[derive(Serialize, ToSchema)]
pub struct CommitResult {
    pub rooms: Vec<RoomMade>,
    /// Accepted proposals that wait: employer and client rooms until `room_backup` exists.
    pub held: Vec<String>,
    pub rules_enabled: i64,
    pub state: String,
}

/// The Review's one decision (API minor 73): the rooms to import; every other room is refused.
#[derive(Deserialize, ToSchema)]
pub struct CommitKeep {
    /// The proposals to import. Every other open proposal is refused (its items wiped, their hashes
    /// kept so they never come back), Unsorted aside. A room imported already may be named again.
    pub keep: Vec<String>,
    /// Unsorted's items wait in "No room yet" (true, the default) or are refused and deleted (false).
    #[serde(default)]
    pub keep_unsorted: Option<bool>,
}

#[utoipa::path(post, path = "/imports/{run}/commit", operation_id = "brainCommit", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    request_body(content = Option<CommitKeep>, description = "Optional (API minor 73): import exactly `keep` and refuse every other room in the same call. Without a body the accepted rooms are imported"),
    responses((status = 200, description = "Import accepted rooms (step-up; audited as `brain.room.created` per room)", body = CommitResult)))]
pub(crate) async fn commit(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
    body: Bytes,
) -> ApiResult<CommitResult> {
    let keep: Option<CommitKeep> = if body.is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice(&body)
                .map_err(|_| ApiError::bad_request("a body of keep and keep_unsorted"))?,
        )
    };
    let (state, _) = run_state(&app, &run).await?;
    if state != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    let key = b.key(&app).await?;
    let st = crate::imports::staging(&app, &b, &run, false).await?;
    if let Some(k) = &keep {
        decide(&app, &b, &st, &run, k).await?;
    }
    let accepted =
        sqlx::query("SELECT * FROM proposals WHERE state IN ('accepted','held') ORDER BY id")
            .fetch_all(&st)
            .await?;
    // The employer guard, again at the door: nothing is written when any accepted room mixes two.
    for r in &accepted {
        let id: String = r.try_get("id")?;
        if mixed(&st, &id).await? {
            return Err(code(
                409,
                "mixed_employers",
                "an accepted room mixes two employers",
            ));
        }
    }
    let mut result = CommitResult {
        rooms: vec![],
        held: vec![],
        rules_enabled: 0,
        state: "review".to_owned(),
    };
    for r in &accepted {
        let id: String = r.try_get("id")?;
        let kind: String = r.try_get("kind")?;
        if (kind == "employer" || kind == "client") && !ROOM_BACKUP_READY {
            sqlx::query("UPDATE proposals SET state = 'held' WHERE id = ?")
                .bind(&id)
                .execute(&st)
                .await?;
            result.held.push(id);
            continue;
        }
        if let Some(made) = commit_room(&app, &key, &st, &run, r, "user").await? {
            crate::vectors::note_committed(&app, &b, &st, &made.room, &made.proposal).await;
            result.rooms.push(made);
        }
    }
    refused(&app, &st, &run, &mut result).await?;
    let open: i64 =
        sqlx::query_scalar("SELECT count(*) FROM proposals WHERE state IN ('accepted','held')")
            .fetch_one(&st)
            .await?;
    st.close().await;
    if open == 0 {
        close_run(&app, &run, result.rooms.len()).await?;
        result.state = "committed".to_owned();
    }
    Ok(Json(result))
}

/// `keep` accepted, every other open room refused, in one staging transaction. Checked before any
/// write: an unknown or merged id, Unsorted in `keep`, or a kept room that mixes two employers.
/// Idempotent: a resumed call finds the same states (a committed room stays committed).
async fn decide(
    app: &App,
    b: &Brain,
    st: &SqlitePool,
    run: &str,
    k: &CommitKeep,
) -> Result<(), ApiError> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, state, signals FROM proposals")
            .fetch_all(st)
            .await?;
    let state_of = |id: &str| rows.iter().find(|r| r.0 == id).map(|r| r.1.as_str());
    for id in &k.keep {
        if id == UNSORTED || matches!(state_of(id), None | Some("merged")) {
            return Err(ApiError::bad_request(
                "keep names a room that is not in this run",
            ));
        }
        if state_of(id) != Some("committed") && mixed(st, id).await? {
            return Err(code(
                409,
                "mixed_employers",
                "a kept room mixes two employers",
            ));
        }
    }
    let mut refused: Vec<&(String, String, String)> = vec![];
    let mut tx = st.begin().await?;
    for r in &rows {
        let (id, state) = (r.0.as_str(), r.1.as_str());
        if matches!(state, "merged" | "committed") {
            continue;
        }
        let to = if id == UNSORTED {
            if k.keep_unsorted.unwrap_or(true) {
                "proposed"
            } else {
                "refused"
            }
        } else if k.keep.iter().any(|x| x == id) {
            // A held room waits for its backup as it did.
            if state == "held" { "held" } else { "accepted" }
        } else {
            "refused"
        };
        if to != state {
            sqlx::query("UPDATE proposals SET state = ? WHERE id = ?")
                .bind(to)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            if to == "refused" && id != UNSORTED {
                refused.push(r);
            }
        }
    }
    tx.commit().await?;
    for r in refused {
        draft_rules(app, run, &parse::<Vec<String>>(&r.2)).await?;
    }
    crate::vectors::forget_refused(app, b, st).await;
    Ok(())
}

/// Rooms an import held for a room backup, before that hold was dropped (`ROOM_BACKUP_READY`,
/// 0.8.5): the person accepted them at the time, so they are imported now as their commit would
/// be today. Only `held` rooms move; a run's undecided rooms and its state stay as they are. A
/// room that mixes two employers stays held. The number of rooms imported.
pub(crate) async fn release_held(app: &App, b: &Brain) -> Result<usize, ApiError> {
    let runs: Vec<String> =
        sqlx::query_scalar("SELECT id FROM brain_import_runs WHERE state = 'review' ORDER BY id")
            .fetch_all(&app.pool)
            .await?;
    let mut made = 0;
    for run in runs {
        let st = crate::imports::staging(app, b, &run, false).await?;
        let held = sqlx::query("SELECT * FROM proposals WHERE state = 'held' ORDER BY id")
            .fetch_all(&st)
            .await?;
        if !held.is_empty() {
            let key = b.key(app).await?;
            for r in &held {
                let id: String = r.try_get("id")?;
                if mixed(&st, &id).await? {
                    continue;
                }
                if let Some(m) = commit_room(app, &key, &st, &run, r, "user").await? {
                    crate::vectors::note_committed(app, b, &st, &m.room, &m.proposal).await;
                    made += 1;
                }
            }
        }
        st.close().await;
    }
    Ok(made)
}

/// The run is done: every accepted proposal is committed.
pub(crate) async fn close_run(app: &App, run: &str, rooms: usize) -> Result<(), ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE brain_import_runs SET state = 'committed', stage = 'committed', committed_at = ? WHERE id = ?")
        .bind(app.clock.now())
        .bind(run)
        .execute(&mut *tx)
        .await?;
    crate::sync::promote_cursor(&mut tx, run).await?;
    let counts = crate::imports::load_counts(app, run).await?;
    record(
        &mut tx,
        "brain.import.committed",
        json!({"run": run, "rooms": rooms}),
        None,
    )
    .await?;
    crate::imports::record_progress(&mut tx, run, "committed", &counts).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn commit_room(
    app: &App,
    key: &[u8; 32],
    st: &SqlitePool,
    run: &str,
    p: &SqliteRow,
    assigned_by: &str,
) -> Result<Option<RoomMade>, ApiError> {
    let (pid, name, kind): (String, String, String) =
        (p.try_get("id")?, p.try_get("name")?, p.try_get("kind")?);
    let cfg: RoomConfig =
        serde_json::from_str(&p.try_get::<String, _>("config")?).unwrap_or_default();
    let items = sqlx::query("SELECT * FROM items WHERE proposal = ? AND (mark IS NULL OR mark != 'refused') ORDER BY started_at, item_id")
        .bind(&pid)
        .fetch_all(st)
        .await?;
    if items.is_empty() {
        return Ok(None);
    }
    let room = room_id(&name);
    let now = app.clock.now();
    // 1. The room exists in the control plane first, so a crash leaves a room that a second commit fills.
    let mut tx = begin_write(&app.pool).await?;
    let created = sqlx::query(
        "INSERT OR IGNORE INTO brain_rooms (id, name, kind, review_days) VALUES (?, ?, ?, ?)",
    )
    .bind(&room)
    .bind(&name)
    .bind(&kind)
    .bind(cfg.review_days.unwrap_or(90))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let providers = if cfg.allowed_models.as_deref() == Some("local_only") {
        r#"["local"]"#
    } else {
        r#"["approved_cloud"]"#
    };
    let lease = if kind == "employer" || kind == "client" {
        8
    } else {
        24
    };
    sqlx::query("INSERT OR IGNORE INTO brain_room_policy (room, allowed_providers, lease_hours, auto_accept) VALUES (?, ?, ?, ?)")
        .bind(&room)
        .bind(providers)
        .bind(lease)
        .bind(crate::policy::AUTO_ACCEPT_ALL)
        .execute(&mut *tx)
        .await?;
    if created {
        record(
            &mut tx,
            "brain.room.created",
            json!({"room": room, "kind": kind, "run": run}),
            Some((
                "brain.room",
                json!({"op": "created", "room": room, "name": name, "kind": kind}),
            )),
        )
        .await?;
    }
    tx.commit().await?;
    // 2. The sources, in the room's own file, with their op-log and outbox rows in one transaction.
    // Never twice: text already stored in any room is skipped (another run, a resumed commit, a
    // re-sort between two imports), and an item imported before with other text is updated in
    // place, in the room it already lives in (unless the stored text is the newer one).
    let mut by_room: std::collections::BTreeMap<String, Vec<&SqliteRow>> = Default::default();
    by_room.insert(room.clone(), vec![]);
    for r in &items {
        let (id, hash): (String, String) = (r.try_get("item_id")?, r.try_get("content_hash")?);
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT room FROM brain_seen WHERE content_hash = ? AND room != 'refused' LIMIT 1",
        )
        .bind(&hash)
        .fetch_optional(&app.pool)
        .await?;
        if stored.is_some() {
            continue;
        }
        let home: Option<String> = sqlx::query_scalar(
            "SELECT room FROM brain_seen WHERE item_id = ? AND room != 'refused' ORDER BY rowid DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(&app.pool)
        .await?;
        by_room
            .entry(home.unwrap_or_else(|| room.clone()))
            .or_default()
            .push(r);
    }
    let mut written = 0;
    let mut placed: Vec<(String, String, String)> = vec![];
    for (to, rows) in &by_room {
        let canon =
            files::open_migrated(&files::room_path(&files::root(app), to), key, true, CANON)
                .await
                .map_err(|e| code(500, "room_unavailable", e.to_string()))?;
        let mut ctx = canon.begin().await?;
        for r in rows {
            let (id, hash): (String, String) = (r.try_get("item_id")?, r.try_get("content_hash")?);
            let had: bool =
                sqlx::query_scalar("SELECT count(*) > 0 FROM sources WHERE item_id = ?")
                    .bind(&id)
                    .fetch_one(&mut *ctx)
                    .await?;
            let changed = sqlx::query(
                "INSERT INTO sources (item_id, content_hash, source_kind, device, path, project_hint, author_kind, author_name, \
                 title, text, links, started_at, ended_at, run, assigned_by, needed, pointer) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(item_id) DO UPDATE SET content_hash = excluded.content_hash, path = excluded.path, \
                 project_hint = excluded.project_hint, title = excluded.title, text = excluded.text, links = excluded.links, \
                 started_at = excluded.started_at, ended_at = excluded.ended_at, run = excluded.run, \
                 pointer = excluded.pointer, distilled = NULL, compacted_at = NULL \
                 WHERE content_hash != excluded.content_hash AND excluded.started_at >= started_at \
                 ON CONFLICT(content_hash) DO NOTHING",
            )
            .bind(&id)
            .bind(&hash)
            .bind(r.try_get::<String, _>("source_kind")?)
            .bind(r.try_get::<String, _>("device")?)
            .bind(r.try_get::<String, _>("path")?)
            .bind(r.try_get::<Option<String>, _>("project_hint")?)
            .bind(r.try_get::<String, _>("author_kind")?)
            .bind(r.try_get::<String, _>("author_name")?)
            .bind(r.try_get::<String, _>("title")?)
            .bind(r.try_get::<String, _>("text")?)
            .bind(r.try_get::<String, _>("links")?)
            .bind(r.try_get::<String, _>("started_at")?)
            .bind(r.try_get::<Option<String>, _>("ended_at")?)
            .bind(run)
            .bind(assigned_by)
            .bind(i64::from(r.try_get::<Option<String>, _>("mark")?.as_deref() == Some("needed")))
            .bind(r.try_get::<i64, _>("pointer")?)
            .execute(&mut *ctx)
            .await?
            .rows_affected();
            if changed == 1 {
                written += 1;
                let seq: i64 = sqlx::query_scalar(
                    "INSERT INTO op_log (op, ref, at) VALUES (?, ?, ?) RETURNING seq",
                )
                .bind(if had { "source.update" } else { "source.add" })
                .bind(&id)
                .bind(&now)
                .fetch_one(&mut *ctx)
                .await?;
                sqlx::query("INSERT INTO outbox (op_seq) VALUES (?)")
                    .bind(seq)
                    .execute(&mut *ctx)
                    .await?;
            }
            // What the room holds now (this text, or a newer one kept over an older run's).
            let now_hash: Option<String> =
                sqlx::query_scalar("SELECT content_hash FROM sources WHERE item_id = ?")
                    .bind(&id)
                    .fetch_optional(&mut *ctx)
                    .await?;
            if let Some(h) = now_hash {
                placed.push((h, to.clone(), id));
            }
        }
        ctx.commit().await?;
        canon.close().await;
    }
    // 3. Hashes and item ids (never text) into the control plane, then the proposal is closed. An
    // updated item's older hash in its room goes, so the room counts it once.
    let mut tx = begin_write(&app.pool).await?;
    for (hash, to, id) in &placed {
        sqlx::query("DELETE FROM brain_seen WHERE item_id = ? AND room = ? AND content_hash != ?")
            .bind(id)
            .bind(to)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO brain_seen (content_hash, room, run, item_id) VALUES (?, ?, ?, ?)")
            .bind(hash)
            .bind(to)
            .bind(run)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    for h in sqlx::query_scalar::<_, String>(
        "SELECT content_hash FROM items WHERE proposal = ? AND mark = 'refused'",
    )
    .bind(&pid)
    .fetch_all(st)
    .await?
    {
        sqlx::query(
            "INSERT OR IGNORE INTO brain_seen (content_hash, room, run) VALUES (?, 'refused', ?)",
        )
        .bind(h)
        .bind(run)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    sqlx::query("UPDATE proposals SET state = 'committed', room = ? WHERE id = ?")
        .bind(&room)
        .bind(&pid)
        .execute(st)
        .await?;
    Ok(Some(RoomMade {
        proposal: pid,
        room,
        name,
        kind,
        sources: written,
        created,
    }))
}

/// Refused rooms become rules and their hashes are remembered as refused.
async fn refused(
    app: &App,
    st: &SqlitePool,
    run: &str,
    result: &mut CommitResult,
) -> Result<(), ApiError> {
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT content_hash FROM items WHERE proposal IN (SELECT id FROM proposals WHERE state = 'refused')",
    )
    .fetch_all(st)
    .await?;
    let mut tx = begin_write(&app.pool).await?;
    for h in hashes {
        sqlx::query(
            "INSERT OR IGNORE INTO brain_seen (content_hash, room, run) VALUES (?, 'refused', ?)",
        )
        .bind(h)
        .bind(run)
        .execute(&mut *tx)
        .await?;
    }
    // Staging keeps only the hash of what was refused (Q5): no title, text, path or folder.
    sqlx::query(
        "UPDATE items SET text = '', title = '[refused]', path = '', project_hint = NULL, links = '[]' \
         WHERE mark = 'refused' OR proposal IN (SELECT id FROM proposals WHERE state = 'refused')",
    )
    .execute(st)
    .await?;
    let enabled = sqlx::query(
        "UPDATE brain_rules SET enabled = 1, reason = ? WHERE enabled = 0 AND reason = ?",
    )
    .bind(format!("Refused room, run {run}"))
    .bind(format!("draft:{run}"))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if enabled > 0 {
        record(
            &mut tx,
            "brain.rule.changed",
            json!({"run": run, "enabled": enabled, "origin": "refused_rooms"}),
            None,
        )
        .await?;
    }
    tx.commit().await?;
    result.rules_enabled = enabled as i64;
    Ok(())
}
