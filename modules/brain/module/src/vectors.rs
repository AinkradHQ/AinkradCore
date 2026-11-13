//! Stored sentence vectors (`<brain dir>/vectors.db`, encrypted with the brain key): loaded lazily
//! for the items of a run, saved after a step, deleted when an item is refused.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use sqlx::{Row, SqlitePool};

use crate::files::{self, VECTORS};
use crate::{Brain, code};

async fn pool(app: &App, b: &Brain) -> Result<SqlitePool, ApiError> {
    let key = b.key(app).await?;
    files::open_migrated(&files::vectors_path(&files::root(app)), &key, true, VECTORS)
        .await
        .map_err(|e| code(500, "vectors_unavailable", e.to_string()))
}

fn encode(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn decode(b: &[u8]) -> Vec<f32> {
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_le_bytes(*c))
        .collect()
}

/// The stored vectors of `model` for these content hashes.
pub(crate) async fn load(
    app: &App,
    b: &Brain,
    model: &str,
    hashes: &[String],
) -> Result<Vec<(String, Vec<f32>)>, ApiError> {
    if hashes.is_empty() {
        return Ok(vec![]);
    }
    let p = pool(app, b).await?;
    let mut out = Vec::new();
    for h in hashes {
        let row = sqlx::query("SELECT vec FROM vectors WHERE model = ? AND content_hash = ?")
            .bind(model)
            .bind(h)
            .fetch_optional(&p)
            .await?;
        if let Some(r) = row {
            out.push((h.clone(), decode(&r.try_get::<Vec<u8>, _>("vec")?)));
        }
    }
    p.close().await;
    Ok(out)
}

/// Stores `rows` for `model` and drops every other model's rows: a new model starts clean.
pub(crate) async fn save(
    app: &App,
    b: &Brain,
    model: &str,
    rows: &[(String, Vec<f32>)],
) -> Result<(), ApiError> {
    let p = pool(app, b).await?;
    let mut tx = p.begin().await?;
    for q in [
        "DELETE FROM vectors WHERE model != ?",
        "DELETE FROM room_members WHERE model != ?",
        "DELETE FROM room_centroids WHERE model != ?",
    ] {
        sqlx::query(q).bind(model).execute(&mut *tx).await?;
    }
    for (h, v) in rows {
        sqlx::query("INSERT OR REPLACE INTO vectors (model, content_hash, vec) VALUES (?, ?, ?)")
            .bind(model)
            .bind(h)
            .bind(encode(v))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    p.close().await;
    Ok(())
}

/// Adds items to a room's centroid; an item already in the room is not counted again.
pub(crate) async fn centroid_add(
    app: &App,
    b: &Brain,
    model: &str,
    room: &str,
    rows: &[(String, Vec<f32>)],
) -> Result<(), ApiError> {
    let p = pool(app, b).await?;
    let mut tx = p.begin().await?;
    let cur = sqlx::query("SELECT n, vec FROM room_centroids WHERE model = ? AND room = ?")
        .bind(model)
        .bind(room)
        .fetch_optional(&mut *tx)
        .await?;
    let (mut n, mut sum) = match cur {
        Some(r) => (
            r.try_get::<i64, _>("n")?,
            decode(&r.try_get::<Vec<u8>, _>("vec")?),
        ),
        None => (0, vec![]),
    };
    for (h, v) in rows {
        let new = sqlx::query(
            "INSERT OR IGNORE INTO room_members (model, room, content_hash) VALUES (?, ?, ?)",
        )
        .bind(model)
        .bind(room)
        .bind(h)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if new {
            if sum.is_empty() {
                sum = vec![0.0; v.len()];
            }
            sum.iter_mut().zip(v).for_each(|(a, b)| *a += b);
            n += 1;
        }
    }
    sqlx::query("INSERT OR REPLACE INTO room_centroids (model, room, n, vec) VALUES (?, ?, ?, ?)")
        .bind(model)
        .bind(room)
        .bind(n)
        .bind(encode(&sum))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    p.close().await;
    Ok(())
}

/// Every room's centroid (unit length) for `model`.
pub(crate) async fn centroids(
    app: &App,
    b: &Brain,
    model: &str,
) -> Result<Vec<(String, Vec<f32>)>, ApiError> {
    let p = pool(app, b).await?;
    let rows = sqlx::query("SELECT room, vec FROM room_centroids WHERE model = ? AND n > 0")
        .bind(model)
        .fetch_all(&p)
        .await?;
    p.close().await;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get("room")?,
                brain_model::semantic::normalized(decode(&r.try_get::<Vec<u8>, _>("vec")?)),
            ))
        })
        .collect()
}

/// A room just received items (a commit): keeps its centroid current from the vectors of the items
/// of staging proposal `proposal` (embedded now when not stored). Needs the local model and
/// `semantic.enabled`. Best effort: a failure only leaves the centroid behind.
pub(crate) async fn note_committed(
    app: &App,
    b: &Brain,
    st: &SqlitePool,
    room: &str,
    proposal: &str,
) {
    let Some(e) = b.embedder() else { return };
    if !crate::suggest::enabled(app, b).await {
        return;
    }
    let r: Result<(), ApiError> = async {
        let rows = sqlx::query("SELECT * FROM items WHERE proposal = ? AND mark IS NOT 'refused'")
            .bind(proposal)
            .fetch_all(st)
            .await?;
        let mut pairs = Vec::new();
        for r in &rows {
            let item = crate::review::item_of(r)?;
            if brain_model::semantic::eligible(&item) {
                pairs.push((
                    item.content_hash.clone(),
                    brain_model::semantic::embed_text(&item),
                ));
            }
        }
        let vs = b.embed_texts(&pairs).await?;
        let rows: Vec<(String, Vec<f32>)> = pairs.into_iter().map(|p| p.0).zip(vs).collect();
        centroid_add(app, b, e.model_id(), room, &rows).await
    }
    .await;
    if let Err(e) = r {
        tracing::warn!(error = ?e, "a room's centroid could not be updated");
    }
}

/// Deletes the vectors of the items in staging `st` that are refused (the item or its room), from
/// disk and memory. A failure is logged, never fatal: the next step simply finds nothing to reuse.
pub(crate) async fn forget_refused(app: &App, b: &Brain, st: &SqlitePool) {
    let r: Result<(), ApiError> = async {
        let hashes: Vec<String> = sqlx::query_scalar(
            "SELECT content_hash FROM items WHERE mark = 'refused' \
             OR proposal IN (SELECT id FROM proposals WHERE state = 'refused')",
        )
        .fetch_all(st)
        .await?;
        if hashes.is_empty() {
            return Ok(());
        }
        {
            let mut c = b
                .inner
                .sem
                .cache()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            hashes.iter().for_each(|h| c.forget(h));
        }
        let p = pool(app, b).await?;
        for h in &hashes {
            sqlx::query("DELETE FROM vectors WHERE content_hash = ?")
                .bind(h)
                .execute(&p)
                .await?;
        }
        p.close().await;
        Ok(())
    }
    .await;
    if let Err(e) = r {
        tracing::warn!(error = ?e, "stored vectors of refused items could not be deleted");
    }
}
