//! Places and topics (Brain redesign, sections 3 and 4): every room with what it holds, and the
//! subjects the knowledge is about. Counts and the person's own record text; rooms that are not
//! open show their name and `locked`, never their counts.

use std::collections::BTreeMap;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::extract::{Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::Brain;
use crate::areas::{Area, open_rooms};
use crate::lens::area_cond;

const DEFAULT_TOPICS: u32 = 8;
const MAX_TOPICS: u32 = 50;
const EXAMPLE_CHARS: usize = 240;

#[derive(Serialize, ToSchema)]
pub struct Place {
    pub room: String,
    pub name: String,
    /// Current facts and decisions.
    pub knowledge: i64,
    /// Current rules and preferences.
    pub rules: i64,
    /// Current project state, tasks and summaries.
    pub timeline: i64,
    /// When the newest record was learned.
    pub last_learned_at: Option<String>,
    /// A distil for this place is running or queued.
    pub learning: bool,
    /// The place is not open, so its counts are 0.
    pub locked: bool,
}

#[utoipa::path(get, path = "/places", operation_id = "brainPlaces", tag = "brain",
    responses((status = 200, description = "One row per active place (room), the private `me` place included, with what it holds. A place that is not open shows `locked` and zero counts", body = Vec<Place>)))]
pub(crate) async fn places(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Vec<Place>> {
    let (rooms, _) = open_rooms(&app, &b).await?;
    let all: Vec<(String, String)> =
        sqlx::query_as("SELECT id, name FROM brain_rooms WHERE state = 'active' ORDER BY name, id")
            .fetch_all(&app.pool)
            .await?;
    let busy: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT room FROM brain_distils WHERE state IN ('queued','running')",
    )
    .fetch_all(&app.pool)
    .await?;
    let mut out = vec![];
    for (id, name) in all {
        let mut p = Place {
            learning: busy.contains(&id),
            room: id.clone(),
            name,
            knowledge: 0,
            rules: 0,
            timeline: 0,
            last_learned_at: None,
            locked: true,
        };
        if let Some((_, a)) = rooms.iter().find(|(r, _)| r.id == id) {
            let (k, r, t, last): (i64, i64, i64, Option<String>) = sqlx::query_as(
                "SELECT coalesce(sum(type IN ('fact','decision')), 0), \
                        coalesce(sum(type IN ('rule','preference')), 0), \
                        coalesce(sum(type IN ('project-state','task','summary')), 0), \
                        max(created_at) FROM memory",
            )
            .fetch_one(a.pool())
            .await?;
            (
                p.knowledge,
                p.rules,
                p.timeline,
                p.last_learned_at,
                p.locked,
            ) = (k, r, t, last, false);
        }
        out.push(p);
    }
    for (_, a) in &rooms {
        a.pool().close().await;
    }
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct Topic {
    /// The tag.
    pub name: String,
    /// Current knowledge records with this tag.
    pub count: i64,
    /// The text of the best supported of them.
    pub example: String,
    /// The names of the places that hold some.
    pub rooms: Vec<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopicsQuery {
    /// At most this many topics: 1 to 50 (default 8).
    pub limit: Option<u32>,
}

#[utoipa::path(get, path = "/topics", operation_id = "brainTopics", tag = "brain",
    params(TopicsQuery),
    responses((status = 200, description = "The subjects the knowledge is about, from the tags of current facts and decisions in the open rooms, most records first. Filter the records with `GET /areas/knowledge?topic=<name>`", body = Vec<Topic>)))]
pub(crate) async fn topics(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Query(q): Query<TopicsQuery>,
) -> ApiResult<Vec<Topic>> {
    let limit = q.limit.unwrap_or(DEFAULT_TOPICS);
    if !(1..=MAX_TOPICS).contains(&limit) {
        return Err(ApiError::bad_request("limit is 1 to 50"));
    }
    let (rooms, _) = open_rooms(&app, &b).await?;
    const TAGS: &str = "json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END)";
    let mut by: BTreeMap<String, (i64, Vec<String>)> = BTreeMap::new();
    for (room, a) in &rooms {
        let Some(cond) = area_cond(Area::Knowledge, &room.kind, None) else {
            continue;
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT j.value AS t, count(*) AS n \
             FROM (SELECT tags FROM memory WHERE {cond}) m, \
                  json_each(CASE WHEN json_valid(m.tags) THEN m.tags ELSE '[]' END) j \
             WHERE j.type = 'text' AND trim(j.value) <> '' GROUP BY t"
        )))
        .fetch_all(a.pool())
        .await?;
        for r in rows {
            let e = by.entry(r.try_get("t")?).or_default();
            e.0 += r.try_get::<i64, _>("n")?;
            e.1.push(room.name.clone());
        }
    }
    let mut top: Vec<_> = by.into_iter().collect();
    top.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    top.truncate(limit as usize);
    let mut out = vec![];
    for (name, (count, names)) in top {
        let mut best: Option<(i64, String)> = None;
        for (room, a) in &rooms {
            let Some(cond) = area_cond(Area::Knowledge, &room.kind, None) else {
                continue;
            };
            let row: Option<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT support, body FROM memory WHERE {cond} AND EXISTS \
                 (SELECT 1 FROM {TAGS} WHERE value = ?) \
                 ORDER BY support DESC, coalesce(last_seen_at, created_at) DESC, id LIMIT 1"
            )))
            .bind(&name)
            .fetch_optional(a.pool())
            .await?;
            if let Some(r) = row.filter(|r| best.as_ref().is_none_or(|b| r.0 > b.0)) {
                best = Some(r);
            }
        }
        let mut places = names;
        places.sort();
        places.dedup();
        out.push(Topic {
            name,
            count,
            example: best
                .map(|b| b.1.chars().take(EXAMPLE_CHARS).collect())
                .unwrap_or_default(),
            rooms: places,
        });
    }
    for (_, a) in &rooms {
        a.pool().close().await;
    }
    Ok(Json(out))
}
