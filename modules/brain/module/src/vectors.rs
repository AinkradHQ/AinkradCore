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
    sqlx::query("DELETE FROM vectors WHERE model != ?")
        .bind(model)
        .execute(&mut *tx)
        .await?;
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
