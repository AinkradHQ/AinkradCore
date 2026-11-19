//! Structure v3 (E9-3, D-25): the Brain's six areas are a lens over what is already stored, no new
//! tables. Me, Rules and preferences, Knowledge and Timeline come from the current records
//! (`memory`) of the rooms that are open; Places are the rooms; Evidence is the sources.
//!
//! Each record lands in exactly one area:
//! - `rule` and `preference`: Rules and preferences, in any room (a global-safe room's are the
//!   "everywhere" ones);
//! - anything else in a personal or global-safe room: Me;
//! - `fact` and `decision`: Knowledge;
//! - `project-state`, `task` and `summary`: Timeline.
//!
//! A room that is not open is skipped and counted in `locked_rooms`, never read around its lease.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::{Brain, code};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;
const LATEST_CHARS: usize = 160;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Area {
    Me,
    Rules,
    Knowledge,
    Timeline,
}

impl Area {
    const ALL: [Area; 4] = [Area::Me, Area::Rules, Area::Knowledge, Area::Timeline];

    fn name(self) -> &'static str {
        match self {
            Area::Me => "me",
            Area::Rules => "rules",
            Area::Knowledge => "knowledge",
            Area::Timeline => "timeline",
        }
    }

    fn parse(s: &str) -> Option<Area> {
        Self::ALL.into_iter().find(|a| a.name() == s)
    }
}

/// The record types of a room of `kind` that belong to `area`.
pub(crate) fn types_for(area: Area, kind: &str) -> &'static [&'static str] {
    let own = matches!(kind, "personal" | "global-safe");
    match (area, own) {
        (Area::Rules, _) => &["rule", "preference"],
        (Area::Me, true) => &["fact", "decision", "project-state", "summary", "task"],
        (Area::Knowledge, false) => &["fact", "decision"],
        (Area::Timeline, false) => &["project-state", "task", "summary"],
        _ => &[],
    }
}

/// `'a','b'` for a SQL `IN`: the types are this file's constants, never input.
fn in_list(types: &[&str]) -> String {
    types
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Serialize, ToSchema)]
pub struct AreaSummary {
    /// `me`, `rules`, `knowledge` or `timeline`.
    pub area: String,
    pub count: i64,
    /// Records added in the last 24 hours.
    pub today: i64,
    /// The newest record's text, cut short.
    pub latest: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Areas {
    pub areas: Vec<AreaSummary>,
    /// Active rooms (the Places area).
    pub places: i64,
    /// Sources stored across all rooms (the Evidence area, shown under Explore).
    pub evidence: i64,
    /// Rooms not read because they are not open.
    pub locked_rooms: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AreaRecord {
    pub id: String,
    pub room: String,
    pub room_name: String,
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    pub body: String,
    pub tags: Vec<String>,
    /// How many sources back it.
    pub support: i64,
    pub created_at: String,
    /// When a source last showed it.
    pub seen_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct AreaPage {
    pub records: Vec<AreaRecord>,
    /// Records of the area in the open rooms, before the limit.
    pub total: i64,
    pub locked_rooms: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AreaQuery {
    /// Only this record type (for example `fact` or `decision` in Knowledge).
    #[serde(rename = "type")]
    #[param(rename = "type")]
    pub kind: Option<String>,
    /// At most this many records (default 50, most 200), best supported first.
    pub limit: Option<u32>,
}

struct RoomRef {
    id: String,
    name: String,
    kind: String,
}

/// The active rooms and how many are closed; open ones come with a handle.
async fn open_rooms(
    app: &App,
    b: &Brain,
) -> Result<(Vec<(RoomRef, crate::rooms::RoomAccess)>, i64), ApiError> {
    let rows = sqlx::query("SELECT id, name, kind FROM brain_rooms WHERE state = 'active' ORDER BY id")
        .fetch_all(&app.pool)
        .await?;
    let (mut open, mut locked) = (vec![], 0);
    for r in rows {
        let room = RoomRef {
            id: r.try_get("id")?,
            name: r.try_get("name")?,
            kind: r.try_get("kind")?,
        };
        if !b.rooms().is_open(&room.id, app.clock.unix()) {
            locked += 1;
            continue;
        }
        match crate::inbox::open_room(app, b, &room.id).await {
            Ok(a) => open.push((room, a)),
            Err(_) => locked += 1,
        }
    }
    Ok((open, locked))
}

#[utoipa::path(get, path = "/areas", operation_id = "brainAreas", tag = "brain",
    responses((status = 200, description = "The Brain's areas (Me, Rules, Knowledge, Timeline) with their counts across the open rooms, plus the Places and Evidence counts", body = Areas)))]
pub(crate) async fn summary(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Areas> {
    let (rooms, locked_rooms) = open_rooms(&app, &b).await?;
    let day = iso_of_unix(app.clock.unix() - 86_400);
    let mut out = vec![];
    for area in Area::ALL {
        let (mut count, mut today, mut newest): (i64, i64, Option<(String, String)>) = (0, 0, None);
        for (room, access) in &rooms {
            let types = in_list(types_for(area, &room.kind));
            if types.is_empty() {
                continue;
            }
            let (n, t): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT count(*), coalesce(sum(created_at >= ?), 0) FROM memory WHERE type IN ({types})"
            )))
            .bind(&day)
            .fetch_one(access.pool())
            .await?;
            count += n;
            today += t;
            let top: Option<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT created_at, body FROM memory WHERE type IN ({types}) ORDER BY created_at DESC, id DESC LIMIT 1"
            )))
            .fetch_optional(access.pool())
            .await?;
            if let Some(t) = top.filter(|t| newest.as_ref().is_none_or(|n| t.0 > n.0)) {
                newest = Some(t);
            }
        }
        out.push(AreaSummary {
            area: area.name().to_owned(),
            count,
            today,
            latest: newest.map(|(_, body)| body.chars().take(LATEST_CHARS).collect()),
        });
    }
    for (_, a) in &rooms {
        a.pool().close().await;
    }
    let places: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE state = 'active'")
        .fetch_one(&app.pool)
        .await?;
    let evidence: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_seen")
        .fetch_one(&app.pool)
        .await?;
    Ok(Json(Areas {
        areas: out,
        places,
        evidence,
        locked_rooms,
    }))
}

#[utoipa::path(get, path = "/areas/{area}", operation_id = "brainArea", tag = "brain",
    params(("area" = String, Path, description = "`me`, `rules`, `knowledge` or `timeline`"), AreaQuery),
    responses((status = 200, description = "The current records of an area across the open rooms, best supported first. `unknown_area` (404) for any other name: Places are `GET /rooms` and Evidence is a room's `latest`", body = AreaPage)))]
pub(crate) async fn records(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(area): Path<String>,
    Query(q): Query<AreaQuery>,
) -> ApiResult<AreaPage> {
    let area = Area::parse(&area).ok_or_else(|| code(404, "unknown_area", "no such area"))?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
    let (rooms, locked_rooms) = open_rooms(&app, &b).await?;
    let mut all: Vec<AreaRecord> = vec![];
    for (room, access) in &rooms {
        let types: Vec<&str> = types_for(area, &room.kind)
            .iter()
            .copied()
            .filter(|t| q.kind.as_deref().is_none_or(|k| k == *t))
            .collect();
        if types.is_empty() {
            continue;
        }
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, type, body, tags, support, created_at, coalesce(last_seen_at, created_at) AS seen \
             FROM memory WHERE type IN ({}) ORDER BY support DESC, seen DESC, id LIMIT {MAX_LIMIT}",
            in_list(&types)
        )))
        .fetch_all(access.pool())
        .await?;
        for r in rows {
            all.push(AreaRecord {
                id: r.try_get("id")?,
                room: room.id.clone(),
                room_name: room.name.clone(),
                kind: r.try_get("type")?,
                body: r.try_get("body")?,
                tags: serde_json::from_str(&r.try_get::<String, _>("tags")?).unwrap_or_default(),
                support: r.try_get("support")?,
                created_at: r.try_get("created_at")?,
                seen_at: r.try_get("seen")?,
            });
        }
        access.pool().close().await;
    }
    all.sort_by(|a, b| {
        b.support
            .cmp(&a.support)
            .then_with(|| b.seen_at.cmp(&a.seen_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let total = all.len() as i64;
    all.truncate(limit);
    Ok(Json(AreaPage {
        records: all,
        total,
        locked_rooms,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_record_type_lands_in_exactly_one_area_per_room_kind() {
        for kind in ["personal", "global-safe", "product", "employer"] {
            for t in [
                "rule",
                "preference",
                "fact",
                "decision",
                "project-state",
                "task",
                "summary",
            ] {
                let n = Area::ALL
                    .into_iter()
                    .filter(|a| types_for(*a, kind).contains(&t))
                    .count();
                assert_eq!(n, 1, "{t} in a {kind} room");
            }
        }
    }

    #[test]
    fn me_is_the_personal_rooms_and_rules_are_rules_everywhere() {
        assert!(types_for(Area::Me, "personal").contains(&"fact"));
        assert!(types_for(Area::Knowledge, "personal").is_empty());
        assert!(types_for(Area::Rules, "global-safe").contains(&"rule"));
        assert!(types_for(Area::Me, "product").is_empty());
    }
}
