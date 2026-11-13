//! Commit (E2-4): "Import accepted rooms". Creates each accepted room, writes its cleaned items as
//! `sources` into the room's encrypted `canon.db` with an op-log and outbox row, records hashes in
//! `brain_seen`, turns refused rooms into rules and closes the run. Idempotent per room: a crash
//! mid-commit is resumed by committing again, and `sources.content_hash` is unique, so nothing is
//! written twice.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::files::{self, CANON};
use crate::imports::run_state;
use crate::review::{RoomConfig, mixed, room_id};
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

#[utoipa::path(post, path = "/imports/{run}/commit", operation_id = "brainCommit", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "Import accepted rooms (step-up; audited as `brain.room.created` per room)", body = CommitResult)))]
pub(crate) async fn commit(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<CommitResult> {
    let (state, _) = run_state(&app, &run).await?;
    if state != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    let key = b.key(&app).await?;
    let st = crate::imports::staging(&app, &b, &run, false).await?;
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
    sqlx::query("INSERT OR IGNORE INTO brain_room_policy (room, allowed_providers, lease_hours) VALUES (?, ?, ?)")
        .bind(&room)
        .bind(providers)
        .bind(lease)
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
    let canon = files::open_migrated(
        &files::room_path(&files::root(app), &room),
        key,
        true,
        CANON,
    )
    .await
    .map_err(|e| code(500, "room_unavailable", e.to_string()))?;
    let mut ctx = canon.begin().await?;
    let mut written = 0;
    for r in &items {
        let hash: String = r.try_get("content_hash")?;
        let added = sqlx::query(
            "INSERT INTO sources (item_id, content_hash, source_kind, device, path, project_hint, author_kind, author_name, \
             title, text, links, started_at, ended_at, run, assigned_by, needed, pointer) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(content_hash) DO NOTHING",
        )
        .bind(r.try_get::<String, _>("item_id")?)
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
        if added == 1 {
            written += 1;
            let seq: i64 = sqlx::query_scalar(
                "INSERT INTO op_log (op, ref, at) VALUES ('source.add', ?, ?) RETURNING seq",
            )
            .bind(r.try_get::<String, _>("item_id")?)
            .bind(&now)
            .fetch_one(&mut *ctx)
            .await?;
            sqlx::query("INSERT INTO outbox (op_seq) VALUES (?)")
                .bind(seq)
                .execute(&mut *ctx)
                .await?;
        }
    }
    ctx.commit().await?;
    canon.close().await;
    // 3. Hashes (never text) into the control plane, then the proposal is closed.
    let mut tx = begin_write(&app.pool).await?;
    for r in &items {
        sqlx::query("INSERT OR IGNORE INTO brain_seen (content_hash, room, run) VALUES (?, ?, ?)")
            .bind(r.try_get::<String, _>("content_hash")?)
            .bind(&room)
            .bind(run)
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
