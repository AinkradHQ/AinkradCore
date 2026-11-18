//! Change sets (Brain v2, B2-02): every automatic write to a room's memory (save, merge, replace,
//! tidy, archive, purge) records one change set, so Undo can put the rows back.
//!
//! A writer calls `ChangeSet::touch` for each record id BEFORE it writes the record (a new id is
//! fine), writes, then `commit` in the same transaction. `commit` stores the before and after row
//! images (the `records` row plus its `record_sources`) of every touched record that really changed,
//! and nothing at all when none did.
//!
//! Undo restores the before image of each row whose current image still equals the change's after
//! image. A row changed since (by a person, or by a later change set) is left alone and listed as
//! skipped (a skipped successor of a record Undo put back is archived or unlinked, `unlink_successor`).
//! Undo is idempotent: a change set is undone once, then it is a no-op.
//!
//! Security model: person-only. Every route here refuses an AI session (`person_only`), because a
//! change set holds record bodies and Undo rewrites memory. Routes need the room open (lease), like
//! the Inbox. Purge deletes the row images of purged records, so a purge leaves counts, not text.

use std::sync::Arc;

use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection, SqlitePool};

use crate::distil::log_op;
use crate::files::{self, CANON};
use crate::{Brain, rand_id, record};

/// What a change set can be (`changes.kind`).
pub const KINDS: &[&str] = &["distil", "checkpoint", "ai", "tidy", "purge", "archive"];
/// Archived records are purged this many days after `archived_at` (and Undo lasts as long).
pub const PURGE_DAYS: i64 = 30;
/// Daily, 03:17 UTC.
const PURGE_CRON: &str = "17 3 * * *";

/// The `records` row of `id` and its citations as one JSON text; none when there is no such row.
/// Columns come from the file itself, so a later migration's columns are covered without a change here.
pub async fn image(conn: &mut SqliteConnection, id: &str) -> Result<Option<String>, sqlx::Error> {
    let cols = columns(conn).await?;
    let obj = cols
        .iter()
        .map(|c| format!("'{c}', \"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let row: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT json_object({obj}) FROM records WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let mut v: Value = serde_json::from_str(&row).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let sources: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT source, position, echo FROM record_sources WHERE record = ? ORDER BY position, source",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    // `[source, position]`, plus a third `1` for an echo citation (canon_0009): images written
    // before echo existed compare equal to today's.
    v["_sources"] = sources
        .into_iter()
        .map(|(s, p, echo)| if echo == 0 { json!([s, p]) } else { json!([s, p, 1]) })
        .collect();
    Ok(Some(v.to_string()))
}

async fn columns(conn: &mut SqliteConnection) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT name FROM pragma_table_info('records') ORDER BY cid")
        .fetch_all(conn)
        .await
}

/// Puts `id` back as `img` says (its row and citations), or removes it when `img` is none.
async fn restore(
    conn: &mut SqliteConnection,
    id: &str,
    img: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM record_sources WHERE record = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let Some(img) = img else {
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        return Ok(());
    };
    let v: Value = serde_json::from_str(img).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let obj = v
        .as_object()
        .ok_or_else(|| sqlx::Error::Protocol("a change row image is not an object".into()))?;
    let cols: Vec<String> = columns(conn)
        .await?
        .into_iter()
        .filter(|c| obj.contains_key(c))
        .collect();
    let names = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let marks = vec!["?"; cols.len()].join(", ");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT OR REPLACE INTO records ({names}) VALUES ({marks})"
    )));
    for c in &cols {
        q = match &obj[c] {
            Value::Null => q.bind(None::<String>),
            Value::Number(n) => match n.as_i64() {
                Some(i) => q.bind(i),
                None => q.bind(n.as_f64()),
            },
            Value::String(s) => q.bind(s.clone()),
            other => q.bind(other.to_string()),
        };
    }
    q.execute(&mut *conn).await?;
    for s in obj["_sources"].as_array().into_iter().flatten() {
        if let (Some(src), Some(pos)) = (s[0].as_str(), s[1].as_i64()) {
            sqlx::query("INSERT OR REPLACE INTO record_sources (record, source, position, echo) VALUES (?, ?, ?, ?)")
                .bind(id)
                .bind(src)
                .bind(pos)
                .bind(s[2].as_i64().unwrap_or(0))
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

/// One change set being written. See the module comment for the call order.
pub struct ChangeSet {
    id: String,
    kind: &'static str,
    at: String,
    /// Touched record ids and their image before the write, in touch order.
    seen: Vec<(String, Option<String>)>,
}

impl ChangeSet {
    /// `kind` is one of `KINDS`; `now` is the writer's clock reading (RFC 3339).
    pub fn new(kind: &'static str, now: &str) -> Self {
        debug_assert!(KINDS.contains(&kind), "unknown change kind {kind}");
        // Sortable by time, so the list pages by id.
        let stamp: String = now.chars().filter(char::is_ascii_digit).collect();
        Self {
            id: format!("chg_{stamp}{}", &rand_id("")[..8]),
            kind,
            at: now.to_owned(),
            seen: vec![],
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Records the row's image before the writer changes it (once per id; a new id has none).
    pub async fn touch(&mut self, conn: &mut SqliteConnection, record: &str) -> Result<(), sqlx::Error> {
        if self.seen.iter().all(|(r, _)| r != record) {
            let before = image(conn, record).await?;
            self.seen.push((record.to_owned(), before));
        }
        Ok(())
    }

    /// Stores the set with the after images, in the writer's transaction. Returns its id, or none
    /// (nothing stored) when no touched record changed.
    pub async fn commit(
        self,
        conn: &mut SqliteConnection,
        summary: &str,
        counts: Value,
    ) -> Result<Option<String>, sqlx::Error> {
        let mut rows = vec![];
        for (record, before) in self.seen {
            let after = image(conn, &record).await?;
            if before != after {
                rows.push((record, before, after));
            }
        }
        if rows.is_empty() {
            return Ok(None);
        }
        sqlx::query("INSERT INTO changes (id, kind, summary, counts, at) VALUES (?, ?, ?, ?, ?)")
            .bind(&self.id)
            .bind(self.kind)
            .bind(summary)
            .bind(counts.to_string())
            .bind(&self.at)
            .execute(&mut *conn)
            .await?;
        for (seq, (record, before, after)) in rows.into_iter().enumerate() {
            sqlx::query("INSERT INTO change_rows (change, seq, record, before, after) VALUES (?, ?, ?, ?, ?)")
                .bind(&self.id)
                .bind(seq as i64)
                .bind(record)
                .bind(before)
                .bind(after)
                .execute(&mut *conn)
                .await?;
        }
        Ok(Some(self.id))
    }
}

/// What Undo did to a change set.
#[derive(Debug, PartialEq, Eq)]
pub struct Undone {
    /// Records put back as they were.
    pub restored: Vec<String>,
    /// Records changed since, left as they are.
    pub skipped: Vec<String>,
    /// The change set had been undone before: nothing happened now.
    pub already_undone: bool,
}

/// Undoes `change` in the caller's transaction. None: no such change set. Err(()): a purge, which
/// holds no row images and cannot be undone.
pub async fn undo(
    tx: &mut SqliteConnection,
    change: &str,
    now: &str,
) -> Result<Option<Result<Undone, ()>>, sqlx::Error> {
    // The claim is the first write, so two Undo calls cannot both restore.
    let claimed = sqlx::query(
        "UPDATE changes SET undone_at = ? WHERE id = ? AND undone_at IS NULL AND kind <> 'purge'",
    )
    .bind(now)
    .bind(change)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        let row = sqlx::query("SELECT kind, undone_at FROM changes WHERE id = ?")
            .bind(change)
            .fetch_optional(&mut *tx)
            .await?;
        return Ok(row.map(|r| {
            if r.get::<String, _>("kind") == "purge" {
                Err(())
            } else {
                Ok(Undone {
                    restored: vec![],
                    skipped: vec![],
                    already_undone: true,
                })
            }
        }));
    }
    let rows = sqlx::query("SELECT record, before, after FROM change_rows WHERE change = ? ORDER BY seq DESC")
        .bind(change)
        .fetch_all(&mut *tx)
        .await?;
    let mut out = Undone {
        restored: vec![],
        skipped: vec![],
        already_undone: false,
    };
    let mut changed = vec![];
    for r in rows {
        let record: String = r.try_get("record")?;
        let before: Option<String> = r.try_get("before")?;
        let after: Option<String> = r.try_get("after")?;
        if image(&mut *tx, &record).await? == after {
            restore(&mut *tx, &record, before.as_deref()).await?;
            log_op(&mut *tx, "record.restored", &record, now).await?;
            out.restored.push(record);
        } else {
            changed.push((record, before, after));
        }
    }
    for (record, before, after) in changed {
        unlink_successor(&mut *tx, &record, before.as_deref(), after.as_deref(), &out.restored, now)
            .await?;
        out.skipped.push(record);
    }
    Ok(Some(Ok(out)))
}

/// B4-02 review: Undo put a superseded record back, but its successor was changed since (say, a later
/// save reinforced it) and so is skipped. Two records in force as a chain would be wrong, so the
/// successor is archived when this change set created it, else its `supersedes` / `valid_from` go
/// back to the before image. It stays listed as skipped.
async fn unlink_successor(
    tx: &mut SqliteConnection,
    record: &str,
    before: Option<&str>,
    after: Option<&str>,
    restored: &[String],
    now: &str,
) -> Result<(), sqlx::Error> {
    let parse = |img: Option<&str>| img.and_then(|i| serde_json::from_str::<Value>(i).ok());
    let (before, after) = (parse(before), parse(after));
    let Some(old) = after.as_ref().and_then(|a| a["supersedes"].as_str()) else {
        return Ok(());
    };
    let was = before.as_ref().and_then(|b| b["supersedes"].as_str());
    if was == Some(old) || !restored.iter().any(|r| r == old) {
        return Ok(());
    }
    match &before {
        None => {
            sqlx::query("UPDATE records SET archived_at = ? WHERE id = ? AND archived_at IS NULL")
                .bind(now)
                .bind(record)
                .execute(&mut *tx)
                .await?;
            log_op(&mut *tx, "record.archived", record, now).await
        }
        Some(b) => {
            sqlx::query("UPDATE records SET supersedes = ?, valid_from = ? WHERE id = ?")
                .bind(b["supersedes"].as_str())
                .bind(b["valid_from"].as_str())
                .bind(record)
                .execute(&mut *tx)
                .await?;
            log_op(&mut *tx, "record.edited", record, now).await
        }
    }
}

/// Deletes the records archived before `cutoff`, with their citations and their row images in every
/// change set, and clears the bodies kept in `admit.dropped` audit rows older than `cutoff`. One
/// `purge` change set (counts only) says so. Returns (records purged, audit bodies cleared).
/// ponytail: the dropped-candidate body is the `body` or `bodies` key of the audit detail; B3-03
/// writes it, rename here if it picks another key.
pub async fn purge_room(
    pool: &SqlitePool,
    now: &str,
    cutoff: &str,
) -> Result<(usize, usize), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM records WHERE archived_at IS NOT NULL AND archived_at < ?")
            .bind(cutoff)
            .fetch_all(&mut *tx)
            .await?;
    for id in &ids {
        sqlx::query("DELETE FROM change_rows WHERE record = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        restore(&mut tx, id, None).await?;
        log_op(&mut tx, "record.purged", id, now).await?;
    }
    let bodies = sqlx::query(
        "UPDATE room_audit SET detail = json_remove(detail, '$.body', '$.bodies') \
         WHERE action = 'admit.dropped' AND at < ? AND json_valid(detail) \
         AND (json_type(detail, '$.body') IS NOT NULL OR json_type(detail, '$.bodies') IS NOT NULL)",
    )
    .bind(cutoff)
    .execute(&mut *tx)
    .await?
    .rows_affected() as usize;
    if ids.is_empty() && bodies == 0 {
        return Ok((0, 0));
    }
    let summary = format!(
        "Purged {} archived records older than {PURGE_DAYS} days",
        ids.len()
    );
    sqlx::query("INSERT INTO changes (id, kind, summary, counts, at) VALUES (?, 'purge', ?, ?, ?)")
        .bind(ChangeSet::new("purge", now).id)
        .bind(summary)
        .bind(json!({"purged": ids.len(), "dropped_bodies_cleared": bodies}).to_string())
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((ids.len(), bodies))
}

impl Brain {
    /// Purges every active room's archived records older than 30 days (the daily `brain_purge` job).
    /// Returns the records purged. A room whose file is missing or newer is left for the next run.
    pub async fn purge_step(&self) -> Result<usize, ApiError> {
        let Some(app) = self.inner.app.get() else {
            return Ok(0);
        };
        let Ok(key) = self.key(app).await else {
            return Ok(0);
        };
        let now = app.clock.now();
        let cutoff = iso_of_unix(app.clock.unix() - PURGE_DAYS * 86_400);
        let rooms: Vec<String> =
            sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
                .fetch_all(&app.pool)
                .await?;
        let mut total = 0;
        for room in rooms {
            let Ok(pool) =
                files::open_migrated(&files::room_path(&files::root(app), &room), &key, false, CANON).await
            else {
                continue;
            };
            let done = purge_room(&pool, &now, &cutoff).await;
            pool.close().await;
            let (records, bodies) = done?;
            if records + bodies > 0 {
                total += records;
                let mut ctl = begin_write(&app.pool).await?;
                record(
                    &mut ctl,
                    "brain.room.purged",
                    json!({"room": room, "records": records, "dropped_bodies": bodies}),
                    None,
                )
                .await?;
                ctl.commit().await?;
            }
        }
        Ok(total)
    }
}

struct PurgeJob(Brain);

impl JobHandler for PurgeJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            match self.0.purge_step().await {
                Ok(0) => {
                    run.idle();
                    Ok(())
                }
                Ok(_) => Ok(()),
                Err(e) => Err(e.message),
            }
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_purge",
        Schedule::Cron(PURGE_CRON.to_owned()),
        Arc::new(PurgeJob(b.clone())),
    )
}
