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
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::lens::{PlaceRef, area_cond, is_rule, local_days, rule_kind, rule_places};
use crate::{Brain, code};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;
const LATEST_CHARS: usize = 160;
const SERIES_DAYS: u32 = 14;
const MAX_Q: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Area {
    Me,
    Rules,
    Knowledge,
    Timeline,
}

impl Area {
    pub(crate) const ALL: [Area; 4] = [Area::Me, Area::Rules, Area::Knowledge, Area::Timeline];

    pub(crate) fn name(self) -> &'static str {
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
pub(crate) fn in_list(types: &[&str]) -> String {
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
    /// Records accepted into the area on each of the last 14 local days, oldest first, today last.
    #[schema(required = false)]
    pub series: Vec<i64>,
}

#[derive(Serialize, ToSchema, Default)]
pub struct RuleKinds {
    pub always: i64,
    pub never: i64,
    pub prefer: i64,
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
    /// How many current rules are `always`, `never` and `prefer`.
    #[schema(required = false)]
    pub rule_kinds: RuleKinds,
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
    /// A rule's kind: `always`, `never` or `prefer`. Absent on other records.
    #[serde(rename = "kind", skip_serializing_if = "Option::is_none")]
    #[schema(rename = "kind", required = false)]
    pub rule_kind: Option<String>,
    /// False once the person unfollowed it: it stays, but AI sessions are not given it.
    #[schema(required = false)]
    pub following: bool,
    /// A rule worded the same in two or more places.
    #[schema(required = false)]
    pub everywhere: bool,
    /// Those places, when `everywhere`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rooms: Option<Vec<PlaceRef>>,
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
    /// Only this room's records (a room id), so one room's list is not cut by the other rooms'.
    pub room: Option<String>,
    /// Rules only: `always`, `never` or `prefer`.
    #[serde(rename = "kind")]
    #[param(rename = "kind")]
    pub rule_kind: Option<String>,
    /// Knowledge: only records tagged with this topic.
    pub topic: Option<String>,
    /// Only records whose text contains this (1 to 200 characters).
    pub q: Option<String>,
}

pub(crate) struct RoomRef {
    pub id: String,
    pub name: String,
    pub kind: String,
}

/// The active rooms and how many are closed; open ones come with a handle.
pub(crate) async fn open_rooms(
    app: &App,
    b: &Brain,
) -> Result<(Vec<(RoomRef, crate::rooms::RoomAccess)>, i64), ApiError> {
    let rows =
        sqlx::query("SELECT id, name, kind FROM brain_rooms WHERE state = 'active' ORDER BY id")
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
    let days = local_days(&app, SERIES_DAYS).await?;
    let since = iso_of_unix(app.clock.unix() - (i64::from(SERIES_DAYS) + 1) * 86_400);
    let mut out = vec![];
    for area in Area::ALL {
        let (mut count, mut today, mut newest): (i64, i64, Option<(String, String)>) = (0, 0, None);
        let mut series = vec![0i64; days.len()];
        for (room, access) in &rooms {
            let Some(cond) = area_cond(area, &room.kind, None) else {
                continue;
            };
            let (n, t): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT count(*), coalesce(sum(created_at >= ?), 0) FROM memory WHERE {cond}"
            )))
            .bind(&day)
            .fetch_one(access.pool())
            .await?;
            count += n;
            today += t;
            let per_day: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT date(created_at, 'localtime') AS d, count(*) FROM memory \
                 WHERE {cond} AND created_at >= ? GROUP BY d"
            )))
            .bind(&since)
            .fetch_all(access.pool())
            .await?;
            for (d, c) in per_day {
                if let Some(i) = days.iter().position(|x| *x == d) {
                    series[i] += c;
                }
            }
            let top: Option<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT created_at, body FROM memory WHERE {cond} ORDER BY created_at DESC, id DESC LIMIT 1"
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
            series,
        });
    }
    let mut rule_kinds = RuleKinds::default();
    for (room, access) in &rooms {
        let Some(cond) = area_cond(Area::Rules, &room.kind, None) else {
            continue;
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT type, body, tags FROM memory WHERE {cond}"
        )))
        .fetch_all(access.pool())
        .await?;
        for r in rows {
            match rule_kind(
                &r.try_get::<String, _>("type")?,
                &r.try_get::<String, _>("body")?,
                &r.try_get::<String, _>("tags")?,
            ) {
                "never" => rule_kinds.never += 1,
                "prefer" => rule_kinds.prefer += 1,
                _ => rule_kinds.always += 1,
            }
        }
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
        rule_kinds,
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
    if q.rule_kind
        .as_deref()
        .is_some_and(|k| !matches!(k, "always" | "never" | "prefer"))
    {
        return Err(ApiError::bad_request(
            "kind is `always`, `never` or `prefer`",
        ));
    }
    let text = q.q.as_deref().map(str::trim).filter(|t| !t.is_empty());
    if text.is_some_and(|t| t.chars().count() > MAX_Q)
        || q.topic
            .as_deref()
            .is_some_and(|t| t.is_empty() || t.chars().count() > 80)
    {
        return Err(ApiError::bad_request(
            "q is 1 to 200 characters and topic 1 to 80",
        ));
    }
    let like = text.map(|t| {
        format!(
            "%{}%",
            t.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let (rooms, locked_rooms) = open_rooms(&app, &b).await?;
    let everywhere = if area == Area::Rules {
        rule_places(&rooms).await?
    } else {
        Default::default()
    };
    // A rule kind is derived, so it filters after the read: read them all then.
    let fetch = if q.rule_kind.is_some() {
        5000
    } else {
        MAX_LIMIT as usize
    };
    let mut all: Vec<AreaRecord> = vec![];
    for (room, access) in &rooms {
        if q.room.as_deref().is_some_and(|r| r != room.id) {
            continue;
        }
        let Some(cond) = area_cond(area, &room.kind, q.kind.as_deref()) else {
            continue;
        };
        let mut sql = format!(
            "SELECT id, type, body, tags, support, created_at, following, \
                    coalesce(body_norm, lower(trim(body))) AS norm, coalesce(last_seen_at, created_at) AS seen \
             FROM memory WHERE {cond}"
        );
        if q.topic.is_some() {
            sql += " AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END) WHERE value = ?)";
        }
        if like.is_some() {
            sql += " AND body LIKE ? ESCAPE '\\'";
        }
        sql += &format!(" ORDER BY support DESC, seen DESC, id LIMIT {fetch}");
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        if let Some(t) = &q.topic {
            query = query.bind(t);
        }
        if let Some(l) = &like {
            query = query.bind(l);
        }
        for r in query.fetch_all(access.pool()).await? {
            let kind: String = r.try_get("type")?;
            let body: String = r.try_get("body")?;
            let tags: String = r.try_get("tags")?;
            let rk = is_rule(&kind).then(|| rule_kind(&kind, &body, &tags).to_owned());
            if q.rule_kind.is_some() && rk != q.rule_kind {
                continue;
            }
            let places = rk
                .as_ref()
                .and_then(|_| everywhere.get(&r.get::<String, _>("norm")));
            all.push(AreaRecord {
                id: r.try_get("id")?,
                room: room.id.clone(),
                room_name: room.name.clone(),
                kind,
                body,
                tags: serde_json::from_str(&tags).unwrap_or_default(),
                support: r.try_get("support")?,
                created_at: r.try_get("created_at")?,
                seen_at: r.try_get("seen")?,
                rule_kind: rk,
                following: r.try_get::<i64, _>("following")? == 1,
                everywhere: places.is_some(),
                rooms: places.cloned(),
            });
        }
    }
    for (_, a) in &rooms {
        a.pool().close().await;
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

/// `GET /areas/rules` is the `rules` area; a literal route is needed because `POST /areas/rules` shares the path.
pub(crate) async fn rules_records(
    state: State<App>,
    b: Extension<Brain>,
    Query(q): Query<AreaQuery>,
) -> ApiResult<AreaPage> {
    records(state, b, Path("rules".to_owned()), Query(q)).await
}

#[derive(Serialize, ToSchema)]
pub struct Learned {
    pub id: String,
    pub room: String,
    pub room_name: String,
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    /// `me`, `rules`, `knowledge` or `timeline`.
    pub area: String,
    pub body: String,
    pub created_at: String,
    /// A rule's kind: `always`, `never` or `prefer`. Absent on other records.
    #[serde(rename = "kind", skip_serializing_if = "Option::is_none")]
    #[schema(rename = "kind", required = false)]
    pub rule_kind: Option<String>,
    #[schema(required = false)]
    pub everywhere: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rooms: Option<Vec<PlaceRef>>,
}

/// The area a record of `kind` in a room of `room_kind` lands in.
pub(crate) fn area_of(room_kind: &str, kind: &str, id: &str) -> Option<Area> {
    // A profile answer is About you, whatever its type says (`lens::area_cond`).
    if matches!(room_kind, "personal" | "global-safe")
        && kind == "preference"
        && id.starts_with("me-")
    {
        return Some(Area::Me);
    }
    Area::ALL
        .into_iter()
        .find(|a| types_for(*a, room_kind).contains(&kind))
}

#[utoipa::path(get, path = "/learned", operation_id = "brainLearned", tag = "brain",
    responses((status = 200, description = "Records accepted in the last 24 hours across the open rooms, newest first (at most 12), each with its area. Archive one with `POST /rooms/{room}/records/{id}/archive`", body = Vec<Learned>)))]
pub(crate) async fn learned(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Vec<Learned>> {
    let (rooms, _) = open_rooms(&app, &b).await?;
    let day = iso_of_unix(app.clock.unix() - 86_400);
    let everywhere = rule_places(&rooms).await?;
    let mut all = vec![];
    for (room, access) in &rooms {
        let rows = sqlx::query(
            "SELECT id, type, body, tags, created_at, coalesce(body_norm, lower(trim(body))) AS norm FROM memory WHERE created_at >= ? \
             ORDER BY created_at DESC, id LIMIT 12",
        )
        .bind(&day)
        .fetch_all(access.pool())
        .await?;
        for r in rows {
            let kind: String = r.try_get("type")?;
            let id: String = r.try_get("id")?;
            let Some(area) = area_of(&room.kind, &kind, &id) else {
                continue;
            };
            let body: String = r.try_get("body")?;
            let rk = (area == Area::Rules)
                .then(|| rule_kind(&kind, &body, &r.get::<String, _>("tags")).to_owned());
            let places = rk
                .as_ref()
                .and_then(|_| everywhere.get(&r.get::<String, _>("norm")));
            all.push(Learned {
                everywhere: places.is_some(),
                rooms: places.cloned(),
                rule_kind: rk,
                id,
                room: room.id.clone(),
                room_name: room.name.clone(),
                area: area.name().to_owned(),
                kind,
                body,
                created_at: r.try_get("created_at")?,
            });
        }
        access.pool().close().await;
    }
    all.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    all.truncate(12);
    Ok(Json(all))
}

#[derive(Serialize, ToSchema)]
pub struct Archived {
    /// False when it was archived already.
    pub archived: bool,
}

#[utoipa::path(post, path = "/rooms/{room}/records/{id}/archive", operation_id = "brainArchiveRecord", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Record id")),
    responses((status = 200, description = "The record leaves memory (archived, kept for the retention window; never deleted). Person only; the room must be open", body = Archived)))]
pub(crate) async fn archive(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
) -> ApiResult<Archived> {
    crate::change_routes::person_only(&me)?;
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let now = app.clock.now();
    let mut tx = access.pool().begin().await?;
    let n = sqlx::query("UPDATE records SET archived_at = ? WHERE id = ? AND archived_at IS NULL")
        .bind(&now)
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 1 {
        crate::distil::log_op(&mut *tx, "record.archived", &id, &now).await?;
    }
    tx.commit().await?;
    access.pool().close().await;
    Ok(Json(Archived { archived: n == 1 }))
}

#[derive(Serialize, ToSchema)]
pub struct TraceStep {
    /// `record.candidate`, `record.accepted`, `record.edited`, `record.archived`, `record.restored` or `record.purged`.
    pub op: String,
    pub at: String,
}

#[derive(Serialize, ToSchema)]
pub struct TraceRecord {
    pub id: String,
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    pub body: String,
    pub archived: bool,
    /// The record's history from the room's op-log, oldest first.
    pub history: Vec<TraceStep>,
}

#[derive(Serialize, ToSchema)]
pub struct SourceTrace {
    /// The start of the source's text (as outside data); empty once the text was compacted.
    pub excerpt: String,
    /// The records that cite this source, at most 5.
    pub records: Vec<TraceRecord>,
}

const EXCERPT_CHARS: usize = 400;

#[utoipa::path(get, path = "/rooms/{room}/sources/{item}/trace", operation_id = "brainSourceTrace", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("item" = String, Path, description = "Source item id")),
    responses((status = 200, description = "What a source produced: the start of its text and the records that cite it, each with its change history. The room must be open", body = SourceTrace)))]
pub(crate) async fn trace(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((room, item)): Path<(String, String)>,
) -> ApiResult<SourceTrace> {
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let text: Option<String> = sqlx::query_scalar("SELECT text FROM sources WHERE item_id = ?")
        .bind(&item)
        .fetch_optional(access.pool())
        .await?;
    let Some(text) = text else {
        access.pool().close().await;
        return Err(code(404, "no_such_source", "no such source in this room"));
    };
    let recs = sqlx::query(
        "SELECT r.id, r.type, r.body, r.archived_at IS NOT NULL AS archived FROM records r \
         JOIN record_sources rs ON rs.record = r.id WHERE rs.source = ? ORDER BY r.created_at, r.id LIMIT 5",
    )
    .bind(&item)
    .fetch_all(access.pool())
    .await?;
    let mut records = vec![];
    for r in recs {
        let id: String = r.try_get("id")?;
        let history = sqlx::query("SELECT op, at FROM op_log WHERE ref = ? ORDER BY seq")
            .bind(&id)
            .fetch_all(access.pool())
            .await?
            .iter()
            .map(|h| {
                Ok(TraceStep {
                    op: h.try_get("op")?,
                    at: h.try_get("at")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        records.push(TraceRecord {
            archived: r.try_get::<i64, _>("archived")? == 1,
            kind: r.try_get("type")?,
            body: r.try_get("body")?,
            id,
            history,
        });
    }
    access.pool().close().await;
    Ok(Json(SourceTrace {
        excerpt: text.chars().take(EXCERPT_CHARS).collect(),
        records,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct Restored {
    /// False when it was not archived.
    pub restored: bool,
}

#[utoipa::path(post, path = "/rooms/{room}/records/{id}/restore", operation_id = "brainRestoreRecord", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Record id")),
    responses((status = 200, description = "Puts an archived record back in memory (the Undo of an archive). Person only; the room must be open", body = Restored)))]
pub(crate) async fn restore(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
) -> ApiResult<Restored> {
    crate::change_routes::person_only(&me)?;
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let now = app.clock.now();
    let mut tx = access.pool().begin().await?;
    let n = sqlx::query(
        "UPDATE records SET archived_at = NULL WHERE id = ? AND archived_at IS NOT NULL",
    )
    .bind(&id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 1 {
        crate::distil::log_op(&mut *tx, "record.restored", &id, &now).await?;
    }
    tx.commit().await?;
    access.pool().close().await;
    Ok(Json(Restored { restored: n == 1 }))
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
