//! Ask Brain (Brain redesign, section 5): the best matches in the open places for a question, by
//! meaning when the local model is on, else by words. Nothing is stored but a count in the audit log.
//! ponytail: no written answer yet (`answer` is always null); the distil runner is asynchronous, so a
//! synchronous answer needs its own short-session helper. Add it when the app shows the sources alone
//! is not enough.

use std::collections::HashMap;
use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;

use crate::access::Visible;
use crate::areas::open_rooms;
use crate::{Brain, record};

const MAX_Q: usize = 300;
const MAX_SOURCES: usize = 8;
const BODY_CHARS: usize = 1000;
const BUDGET: Duration = Duration::from_secs(60);

#[derive(Deserialize, ToSchema)]
pub struct AskBody {
    /// The question, 1 to 300 characters.
    pub q: String,
    /// Only this place (a room id).
    pub room: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AskSource {
    pub id: String,
    pub room: String,
    pub room_name: String,
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    pub body: String,
}

#[derive(Serialize, ToSchema)]
pub struct Asked {
    /// A short written answer, or null when none could be written (this Core does not write one yet).
    pub answer: Option<String>,
    /// The best matches, best first, at most 8.
    pub sources: Vec<AskSource>,
}

#[utoipa::path(post, path = "/ask", operation_id = "brainAsk", tag = "brain", request_body = AskBody,
    responses((status = 200, description = "The best matching current records of the open places for the question, plus a written answer when one can be made (null otherwise, never an error). Bounded to 60 seconds and 8 sources; nothing is stored", body = Asked)))]
pub(crate) async fn ask(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Json(req): Json<AskBody>,
) -> ApiResult<Asked> {
    let q = req.q.trim();
    if q.is_empty() || q.chars().count() > MAX_Q {
        return Err(ApiError::bad_request("q is 1 to 300 characters"));
    }
    let sources = tokio::time::timeout(BUDGET, find(&app, &b, q, req.room.as_deref()))
        .await
        .unwrap_or_else(|_| Ok(vec![]))?;
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.ask",
        serde_json::json!({"sources": sources.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Asked {
        answer: None,
        sources,
    }))
}

async fn find(
    app: &App,
    b: &Brain,
    q: &str,
    room: Option<&str>,
) -> Result<Vec<AskSource>, ApiError> {
    let (mut open, _) = open_rooms(app, b).await?;
    if let Some(r) = room {
        if !open.iter().any(|(x, _)| x.id == r) {
            for (_, a) in &open {
                a.pool().close().await;
            }
            return Err(crate::code(409, "room_closed", "that place is not open"));
        }
        open.retain(|(x, _)| x.id == r);
    }
    let names: HashMap<String, String> = open
        .iter()
        .map(|(r, _)| (r.id.clone(), r.name.clone()))
        .collect();
    let visible: Vec<_> = open
        .into_iter()
        .map(|(r, a)| {
            (
                Visible {
                    id: r.id,
                    name: r.name,
                    kind: r.kind,
                },
                a,
            )
        })
        .collect();
    // (room, id) best first: by meaning when the model is on, else by words.
    let mut ids: Vec<(String, String)> =
        match crate::ai_semantic::rank(app, b, q, &visible, MAX_SOURCES).await {
            Some((hits, _)) => hits.into_iter().map(|h| (h.room, h.id)).collect(),
            None => vec![],
        };
    let words: Vec<String> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 3)
        .map(str::to_lowercase)
        .take(12)
        .collect();
    let mut out = vec![];
    for (v, a) in &visible {
        if ids.is_empty() && !words.is_empty() {
            let rows = sqlx::query("SELECT id, type, body FROM memory ORDER BY support DESC, created_at DESC LIMIT 3000")
                .fetch_all(a.pool())
                .await?;
            let mut scored: Vec<(usize, String)> = vec![];
            for r in rows {
                let low = r.try_get::<String, _>("body")?.to_lowercase();
                let n = words.iter().filter(|w| low.contains(w.as_str())).count();
                if n > 0 {
                    scored.push((n, r.try_get("id")?));
                }
            }
            scored.sort_by_key(|x| std::cmp::Reverse(x.0));
            out.extend(
                scored
                    .into_iter()
                    .take(MAX_SOURCES)
                    .map(|(n, id)| (n, v.id.clone(), id)),
            );
        }
    }
    if ids.is_empty() {
        out.sort_by_key(|x| std::cmp::Reverse(x.0));
        ids = out
            .into_iter()
            .take(MAX_SOURCES)
            .map(|(_, r, i)| (r, i))
            .collect();
    }
    let mut sources = vec![];
    for (r, id) in ids.into_iter().take(MAX_SOURCES) {
        let Some((_, a)) = visible.iter().find(|(v, _)| v.id == r) else {
            continue;
        };
        if let Some(row) = sqlx::query("SELECT type, body FROM memory WHERE id = ?")
            .bind(&id)
            .fetch_optional(a.pool())
            .await?
        {
            sources.push(AskSource {
                room_name: names.get(&r).cloned().unwrap_or_default(),
                room: r,
                kind: row.try_get("type")?,
                body: row
                    .try_get::<String, _>("body")?
                    .chars()
                    .take(BODY_CHARS)
                    .collect(),
                id,
            });
        }
    }
    for (_, a) in &visible {
        a.pool().close().await;
    }
    Ok(sources)
}
