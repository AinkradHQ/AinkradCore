//! Closest-room backfill: a room committed before centroids existed has none, so "closest room"
//! never offers it. When its owner opens it, a background job reads the room (the lease is live, and
//! is checked again when the job runs), embeds what has no vector through the one worker and stores
//! the centroid. One audit row per backfill: room id, count, time; never text.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::Row;

use crate::semantic::service::Service;
use crate::{Brain, record};

/// ponytail: the first sources by id; a room larger than this gets a centroid of its first part.
const MAX_ITEMS: i64 = 2000;

impl Brain {
    /// Queues the backfill of `room` (just opened). Returns at once; does nothing without the model.
    pub(crate) fn queue_backfill(&self, app: &App, room: &str) {
        let (b, app, room) = (self.clone(), app.clone(), room.to_owned());
        let sem: &Service = &self.inner.sem;
        sem.enqueue(async move {
            if let Err(e) = backfill(&app, &b, &room).await {
                tracing::warn!(error = ?e, "a room's centroid could not be backfilled");
            }
        });
    }
}

async fn backfill(app: &App, b: &Brain, room: &str) -> Result<(), ApiError> {
    let Some(e) = b.embedder() else { return Ok(()) };
    if !crate::suggest::enabled(app, b).await {
        return Ok(());
    }
    let model = e.model_id().to_owned();
    if crate::vectors::centroids(app, b, &model)
        .await?
        .iter()
        .any(|(r, _)| r == room)
    {
        return Ok(());
    }
    // Never a room without a lease: `access` refuses a closed room.
    let key = b.key(app).await?;
    let Ok(access) = b.rooms().access(app, &key, room).await else {
        return Ok(());
    };
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT content_hash, title, text FROM sources WHERE trim(text) != '' ORDER BY item_id LIMIT {MAX_ITEMS}"
    )))
    .fetch_all(access.pool())
    .await?;
    access.pool().close().await;
    let mut pairs = Vec::with_capacity(rows.len());
    for r in &rows {
        let text: String = r.try_get("text")?;
        let mut end = text.len().min(brain_model::semantic::EMBED_CHARS);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        pairs.push((
            r.try_get::<String, _>("content_hash")?,
            format!("{}\n{}", r.try_get::<String, _>("title")?, &text[..end]),
        ));
    }
    if pairs.is_empty() {
        return Ok(());
    }
    // This job is the worker, so it embeds directly (queueing behind itself would never finish).
    let vs = b.embed_now(app, e, &pairs).await?;
    let vecs: Vec<(String, Vec<f32>)> = pairs.iter().map(|p| p.0.clone()).zip(vs).collect();
    crate::vectors::centroid_add(app, b, &model, room, &vecs).await?;
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.room.centroid_backfilled",
        json!({"room": room, "count": vecs.len(), "at": app.clock.unix()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
