//! What Brain did, day by day (Brain redesign, section 7): the data behind the Activity page. Counts
//! and room names only, never text. Room files that are not open are skipped, like the area routes.

use std::collections::{BTreeMap, BTreeSet};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::extract::{Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::Brain;
use crate::areas::open_rooms;
use crate::lens::local_days;

const DEFAULT_DAYS: u32 = 14;
const MAX_DAYS: u32 = 90;

#[derive(Serialize, ToSchema)]
pub struct DayEvent {
    /// `learned`, `tidied`, `merged`, `overview`, `asked` or `imported`.
    pub kind: String,
    pub count: i64,
    /// The names of the places it happened in.
    pub rooms: Vec<String>,
    /// How long the work took, when the Core knows.
    pub took_s: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct ActivityDay {
    /// The Core's local day, `YYYY-MM-DD`.
    pub day: String,
    /// Records learned that day.
    pub learned: i64,
    /// Records the Core tidied that day (archived).
    pub tidied: i64,
    pub events: Vec<DayEvent>,
}

#[derive(Serialize, ToSchema)]
pub struct ActivityDays {
    /// Newest day first.
    pub days: Vec<ActivityDay>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DaysQuery {
    /// How many days back, today included: 1 to 90 (default 14).
    pub days: Option<u32>,
}

#[derive(Default)]
struct Acc {
    count: i64,
    rooms: BTreeSet<String>,
    took: Option<i64>,
}

#[utoipa::path(get, path = "/activity/days", operation_id = "brainActivityDays", tag = "brain",
    params(DaysQuery),
    responses((status = 200, description = "What Brain learned, tidied, merged, wrote, answered and imported on each of the last days, newest first (counts and place names only). Places that are not open are left out", body = ActivityDays)))]
pub(crate) async fn days(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Query(q): Query<DaysQuery>,
) -> ApiResult<ActivityDays> {
    let n = q.days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&n) {
        return Err(ApiError::bad_request("days is 1 to 90"));
    }
    let labels = local_days(&app, n).await?;
    let since = iso_of_unix(app.clock.unix() - (i64::from(n) + 1) * 86_400);
    let mut acc: BTreeMap<(String, &'static str), Acc> = BTreeMap::new();
    let (rooms, _) = open_rooms(&app, &b).await?;
    for (room, access) in &rooms {
        let rows = sqlx::query(
            "SELECT date(at, 'localtime') AS d, kind, counts FROM changes \
             WHERE at >= ? AND undone_at IS NULL",
        )
        .bind(&since)
        .fetch_all(access.pool())
        .await?;
        for r in rows {
            let kind: String = r.try_get("kind")?;
            let counts: serde_json::Value =
                serde_json::from_str(&r.try_get::<String, _>("counts")?).unwrap_or_default();
            let get = |k: &str| counts[k].as_i64().unwrap_or(0);
            let day: String = r.try_get("d")?;
            let mut add = |what: &'static str, n: i64| {
                if n > 0 {
                    let a = acc.entry((day.clone(), what)).or_default();
                    a.count += n;
                    a.rooms.insert(room.name.clone());
                }
            };
            match kind.as_str() {
                "distil" | "checkpoint" | "ai" => add("learned", get("saved")),
                "tidy" => {
                    add("tidied", get("archived"));
                    add("merged", get("merged"));
                }
                _ => {}
            }
        }
        access.pool().close().await;
    }
    // How long the day's distils took, on its learned line.
    let took: Vec<(String, i64)> = sqlx::query_as(
        "SELECT date(updated_at, 'localtime'), \
                sum(strftime('%s', updated_at) - strftime('%s', created_at)) FROM brain_distils \
         WHERE state = 'done' AND updated_at >= ? AND \"trigger\" NOT IN ('redistil','tidy','judge') GROUP BY 1",
    )
    .bind(&since)
    .fetch_all(&app.pool)
    .await?;
    for (d, s) in took {
        if let Some(a) = acc.get_mut(&(d, "learned")) {
            a.took = Some(s);
        }
    }
    let overviews: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT date(q.updated_at, 'localtime'), r.name, \
                strftime('%s', q.updated_at) - strftime('%s', q.created_at) \
         FROM brain_overview_queue q JOIN brain_rooms r ON r.id = q.room \
         WHERE q.state = 'done' AND q.updated_at >= ?",
    )
    .bind(&since)
    .fetch_all(&app.pool)
    .await?;
    for (d, name, s) in overviews {
        let a = acc.entry((d, "overview")).or_default();
        a.count += 1;
        a.rooms.insert(name);
        a.took = Some(a.took.unwrap_or(0) + s);
    }
    let imports: Vec<(String, i64)> = sqlx::query_as(
        "SELECT date(started_at, 'localtime'), coalesce(json_extract(counts, '$.stored'), 0) \
         FROM brain_import_runs WHERE state = 'committed' AND started_at >= ?",
    )
    .bind(&since)
    .fetch_all(&app.pool)
    .await?;
    for (d, stored) in imports {
        acc.entry((d, "imported")).or_default().count += stored;
    }
    let asked: Vec<(String, i64)> = sqlx::query_as(
        "SELECT date(at, 'localtime'), count(*) FROM audit_events \
         WHERE action = 'brain.ask' AND at >= ? GROUP BY 1",
    )
    .bind(&since)
    .fetch_all(&app.pool)
    .await?;
    for (d, c) in asked {
        acc.entry((d, "asked")).or_default().count += c;
    }
    let days = labels
        .into_iter()
        .rev()
        .map(|day| {
            let events: Vec<DayEvent> = acc
                .iter()
                .filter(|((d, _), a)| *d == day && a.count > 0)
                .map(|((_, kind), a)| DayEvent {
                    kind: (*kind).to_owned(),
                    count: a.count,
                    rooms: a.rooms.iter().cloned().collect(),
                    took_s: a.took,
                })
                .collect();
            let of = |k: &str| events.iter().find(|e| e.kind == k).map_or(0, |e| e.count);
            ActivityDay {
                learned: of("learned"),
                tidied: of("tidied"),
                day,
                events,
            }
        })
        .collect();
    Ok(Json(ActivityDays { days }))
}
