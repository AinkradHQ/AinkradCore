//! Follow and write a rule (Brain redesign, section 9). A rule the person stops following stays and
//! is shown, but is not handed to AI sessions. A rule the person writes is a record of their own:
//! accepted, support 5, source "you" (no cited source).
//!
//! The contract first named `POST /rules`, which already exists for intake rules (`rules_api`), so a
//! written rule is `POST /areas/rules`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::merge::body_norm;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::areas::open_rooms;
use crate::lens::PlaceRef;
use crate::{Brain, code, rand_id};

const MAX_BODY: usize = 500;
const MAX_PLACES: usize = 50;

#[derive(Deserialize, ToSchema)]
pub struct FollowBody {
    pub on: bool,
}

#[derive(Serialize, ToSchema)]
pub struct Followed {
    pub following: bool,
}

#[utoipa::path(put, path = "/rooms/{room}/records/{id}/follow", operation_id = "brainFollowRecord", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Record id")),
    request_body = FollowBody,
    responses((status = 200, description = "Follow a rule again (`on`) or stop following it: it stays and is shown, but AI sessions are not given it. Person only; the room must be open; 404 for a record not in memory", body = Followed)))]
pub(crate) async fn follow(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
    Json(req): Json<FollowBody>,
) -> ApiResult<Followed> {
    crate::change_routes::person_only(&me)?;
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let now = app.clock.now();
    let mut tx = access.pool().begin().await?;
    let n = sqlx::query("UPDATE records SET following = ? WHERE id = ? AND archived_at IS NULL AND status = 'accepted'")
        .bind(i64::from(req.on))
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 1 {
        crate::distil::log_op(
            &mut tx,
            if req.on {
                "record.followed"
            } else {
                "record.unfollowed"
            },
            &id,
            &now,
        )
        .await?;
    }
    tx.commit().await?;
    access.pool().close().await;
    if n == 0 {
        return Err(ApiError::not_found("no such record in memory"));
    }
    Ok(Json(Followed { following: req.on }))
}

#[derive(Deserialize, ToSchema)]
pub struct WriteRule {
    /// The rule as one plain sentence, 1 to 500 characters.
    pub body: String,
    /// `always`, `never` or `prefer`.
    pub kind: String,
    /// A list of room ids, or the string `everywhere` (every open place).
    #[schema(value_type = Object)]
    pub rooms: Value,
}

#[derive(Serialize, ToSchema)]
pub struct RuleWritten {
    /// The records made, one per place.
    pub written: Vec<WrittenRule>,
    /// Places that already had this rule.
    pub skipped: i64,
}

#[derive(Serialize, ToSchema)]
pub struct WrittenRule {
    pub id: String,
    #[serde(flatten)]
    pub place: PlaceRef,
}

#[utoipa::path(post, path = "/areas/rules", operation_id = "brainWriteRule", tag = "brain", request_body = WriteRule,
    responses((status = 200, description = "A rule the person wrote, saved as an accepted record (support 5, source `you`) in each named place, or in every open place for `everywhere`. A place that has it already is skipped. Person only; named places must be open", body = RuleWritten)))]
pub(crate) async fn write_rule(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Json(req): Json<WriteRule>,
) -> ApiResult<RuleWritten> {
    crate::change_routes::person_only(&me)?;
    let body = Redactor::new().text(req.body.trim());
    let named: Option<Vec<String>> = match &req.rooms {
        Value::String(s) if s == "everywhere" => None,
        Value::Array(a) if (1..=MAX_PLACES).contains(&a.len()) => Some(
            a.iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| ApiError::bad_request("rooms are ids"))?,
        ),
        _ => {
            return Err(ApiError::bad_request(
                "rooms is a list of 1 to 50 room ids or \"everywhere\"",
            ));
        }
    };
    if body.is_empty()
        || body.chars().count() > MAX_BODY
        || !matches!(req.kind.as_str(), "always" | "never" | "prefer")
    {
        return Err(ApiError::bad_request(
            "a rule of 1 to 500 characters, kind always, never or prefer",
        ));
    }
    let (open, _) = open_rooms(&app, &b).await?;
    let missing = named
        .as_ref()
        .and_then(|n| n.iter().find(|r| !open.iter().any(|(o, _)| &o.id == *r)));
    if let Some(r) = missing {
        for (_, a) in &open {
            a.pool().close().await;
        }
        return Err(code(
            409,
            "room_closed",
            format!("place {r} is not open or does not exist"),
        ));
    }
    let (kind, tags) = match req.kind.as_str() {
        "prefer" => ("preference", json!(["you"])),
        k => ("rule", json!(["you", format!("kind:{k}")])),
    };
    let (norm, now) = (body_norm(&body), app.clock.now());
    let (mut written, mut skipped) = (vec![], 0);
    for (room, a) in &open {
        if named.as_ref().is_some_and(|n| !n.contains(&room.id)) {
            continue;
        }
        let mut tx = a.pool().begin().await?;
        let have: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM memory WHERE type IN ('rule','preference') AND body_norm = ?",
        )
        .bind(&norm)
        .fetch_one(&mut *tx)
        .await?;
        if have > 0 {
            skipped += 1;
        } else {
            let id = rand_id("you-");
            sqlx::query(
                "INSERT INTO records (id, type, status, body, tags, created_at, reviewed_at, decided_by, body_norm, \
                 last_seen_at, origin, edited_by_person, support) \
                 VALUES (?, ?, 'accepted', ?, ?, ?, ?, ?, ?, ?, 'person', 1, 5)",
            )
            .bind(&id)
            .bind(kind)
            .bind(&body)
            .bind(tags.to_string())
            .bind(&now)
            .bind(&now)
            .bind(&me.device.id)
            .bind(&norm)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            crate::distil::log_op(&mut tx, "record.accepted", &id, &now).await?;
            written.push(WrittenRule {
                id,
                place: PlaceRef {
                    room: room.id.clone(),
                    name: room.name.clone(),
                },
            });
        }
        tx.commit().await?;
    }
    for (_, a) in &open {
        a.pool().close().await;
    }
    b.queue_record_vectors(&[(Some(norm), body)]);
    Ok(Json(RuleWritten { written, skipped }))
}
