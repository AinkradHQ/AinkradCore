//! "About you" from the Mac app's setup wizard (E3-2): the person's own answers, kept as accepted
//! `preference` records in the personal room, so the me card (`me_card.rs`) carries them into every session.
//!
//! One record per answered question, id `me-<key>`, so a second `PUT` replaces the first instead of piling up.
//! They are written as the person's own (`origin = 'person'`, decided by the device), which is what the card
//! asks of a record that has no transcript citations. A question left out of a later `PUT` is retired
//! (`rejected`, never deleted: a decision keeps its row, Q-8). Only a count reaches the control-plane audit.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::State;
use axum::{Extension, Json};
use brain_model::merge::body_norm;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::distil::log_op;
use crate::files::{self, CANON};
use crate::review::room_id;
use crate::{Brain, code, record};

/// Every record this route owns starts with this.
const PREFIX: &str = "me-";
const ROOM_NAME: &str = "Me";
/// The card keeps 200 characters of a line and 300 tokens in all.
const MAX_BODY: usize = 200;
const MAX_ITEMS: usize = 16;

#[derive(Deserialize, ToSchema)]
pub struct ProfileItem {
    /// The question, `[a-z][a-z0-9-]{0,31}`, such as `role` or `hours`.
    pub key: String,
    /// The answer as one plain sentence, 1 to 200 characters.
    pub body: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ProfileBody {
    /// The whole profile: up to 16 answers. A question missing here is retired.
    pub items: Vec<ProfileItem>,
}

#[derive(Serialize, ToSchema)]
pub struct ProfileSaved {
    /// The personal room the answers went to.
    pub room: String,
    /// Answers written or changed.
    pub saved: i64,
    /// Earlier answers retired because this `PUT` left them out.
    pub removed: i64,
}

fn key_ok(k: &str) -> bool {
    k.len() <= 32
        && k.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn validate(req: &ProfileBody) -> Result<(), ApiError> {
    let mut seen = std::collections::HashSet::new();
    let ok = req.items.len() <= MAX_ITEMS
        && req.items.iter().all(|i| {
            key_ok(&i.key)
                && seen.insert(i.key.as_str())
                && (1..=MAX_BODY).contains(&i.body.trim().chars().count())
        });
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "items: up to 16 answers, each with a distinct key of letters, digits and dashes and a body of 1 to 200 characters",
        ))
    }
}

/// The active personal room, made on first use.
async fn personal_room(app: &App) -> Result<(String, bool), ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id FROM brain_rooms WHERE kind = 'personal' AND state = 'active' ORDER BY id LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(id) = found {
        tx.commit().await?;
        return Ok((id, false));
    }
    // A room of that id exists already (archived, or of another kind): make this one apart.
    let mut room = room_id(ROOM_NAME);
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        room = room_id("Me personal");
    }
    sqlx::query("INSERT INTO brain_rooms (id, name, kind) VALUES (?, ?, 'personal')")
        .bind(&room)
        .bind(ROOM_NAME)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO brain_room_policy (room, auto_accept) VALUES (?, ?)")
        .bind(&room)
        .bind(crate::policy::AUTO_ACCEPT_ALL)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        "brain.room.created",
        json!({"room": room, "kind": "personal"}),
        Some((
            "brain.room",
            json!({"op": "created", "room": room, "name": ROOM_NAME, "kind": "personal"}),
        )),
    )
    .await?;
    tx.commit().await?;
    Ok((room, true))
}

/// Writes `items` into the room file as the person's accepted preferences and retires the rest, in one
/// transaction. Returns `(saved, removed)`; an answer that is already there word for word is neither.
pub(crate) async fn write(
    pool: &SqlitePool,
    by: &str,
    items: &[ProfileItem],
    now: &str,
) -> Result<(i64, i64), sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let redactor = Redactor::new();
    let (mut saved, mut kept) = (0, vec![]);
    for it in items {
        let id = format!("{PREFIX}{}", it.key);
        let body = redactor.text(it.body.trim());
        let norm = body_norm(&body);
        let tags = json!(["profile", it.key]).to_string();
        let was: Option<(String, String)> =
            sqlx::query_as("SELECT status, body FROM records WHERE id = ?")
                .bind(&id)
                .fetch_optional(&mut *tx)
                .await?;
        match was {
            Some((status, old)) if status == "accepted" && old == body => {}
            Some(_) => {
                sqlx::query(
                    "UPDATE records SET type = 'preference', status = 'accepted', body = ?, body_norm = ?, tags = ?, \
                     reviewed_at = ?, decided_by = ?, origin = 'person', edited_by_person = 1, last_seen_at = ?, \
                     valid_to = NULL, archived_at = NULL WHERE id = ?",
                )
                .bind(&body)
                .bind(&norm)
                .bind(&tags)
                .bind(now)
                .bind(by)
                .bind(now)
                .bind(&id)
                .execute(&mut *tx)
                .await?;
                log_op(&mut tx, "record.edited", &id, now).await?;
                saved += 1;
            }
            None => {
                sqlx::query(
                    "INSERT INTO records (id, type, status, body, tags, created_at, reviewed_at, decided_by, body_norm, \
                     last_seen_at, origin, edited_by_person) \
                     VALUES (?, 'preference', 'accepted', ?, ?, ?, ?, ?, ?, ?, 'person', 1)",
                )
                .bind(&id)
                .bind(&body)
                .bind(&tags)
                .bind(now)
                .bind(now)
                .bind(by)
                .bind(&norm)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                log_op(&mut tx, "record.accepted", &id, now).await?;
                saved += 1;
            }
        }
        kept.push(id);
    }
    let old: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM records WHERE substr(id, 1, 3) = ? AND status = 'accepted'",
    )
    .bind(PREFIX)
    .fetch_all(&mut *tx)
    .await?;
    let mut removed = 0;
    for id in old.iter().filter(|id| !kept.contains(id)) {
        sqlx::query("UPDATE records SET status = 'rejected', reviewed_at = ?, decided_by = ? WHERE id = ?")
            .bind(now)
            .bind(by)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        log_op(&mut tx, "record.rejected", id, now).await?;
        removed += 1;
    }
    tx.commit().await?;
    Ok((saved, removed))
}

#[utoipa::path(put, path = "/me/profile", operation_id = "brainPutMeProfile", tag = "brain",
    request_body = ProfileBody,
    responses((status = 200, description = "The answers are now accepted preferences in the personal room, and so on the me card", body = ProfileSaved)))]
pub(crate) async fn put_profile(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Json(req): Json<ProfileBody>,
) -> ApiResult<ProfileSaved> {
    validate(&req)?;
    let key = b.key_for(&app, Some(&me.device.id)).await?;
    let (room, _) = personal_room(&app).await?;
    let pool = files::open_migrated(&files::room_path(&files::root(&app), &room), &key, true, CANON)
        .await
        .map_err(|e| code(500, "room_unavailable", e.to_string()))?;
    let done = write(&pool, &me.device.id, &req.items, &app.clock.now()).await;
    pool.close().await;
    let (saved, removed) = done?;
    if saved + removed > 0 {
        let texts: Vec<(Option<String>, String)> = req
            .items
            .iter()
            .map(|i| (None, i.body.trim().to_owned()))
            .collect();
        b.queue_record_vectors(&texts);
    }
    // Counts only: what the person said stays in the room file.
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.me.profile",
        json!({"room": room, "saved": saved, "removed": removed}),
        None,
    )
    .await?;
    ctl.commit().await?;
    Ok(Json(ProfileSaved {
        room,
        saved,
        removed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::me_card;

    const KEY: [u8; 32] = [9; 32];

    async fn room() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
            .await
            .unwrap();
        (dir, p)
    }

    fn item(key: &str, body: &str) -> ProfileItem {
        ProfileItem {
            key: key.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn keys_and_sizes_are_checked() {
        let one = |k: &str, b: &str| ProfileBody {
            items: vec![item(k, b)],
        };
        assert!(validate(&one("role", "Builds software.")).is_ok());
        assert!(validate(&one("Role", "x")).is_err());
        assert!(validate(&one("1role", "x")).is_err());
        assert!(validate(&one("role", "   ")).is_err());
        assert!(validate(&one("role", &"x".repeat(201))).is_err());
        let twice = ProfileBody {
            items: vec![item("role", "a"), item("role", "b")],
        };
        assert!(validate(&twice).is_err());
    }

    #[tokio::test]
    async fn the_answers_reach_the_me_card_and_a_second_put_replaces_them() {
        let (_dir, p) = room().await;
        let first = [
            item("role", "Builds software and runs a small team."),
            item("tone", "Wants short, direct answers."),
        ];
        assert_eq!(write(&p, "dev-1", &first, "2026-11-19T10:00:00Z").await.unwrap(), (2, 0));
        let on_card: Vec<String> = me_card::candidates(&p)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.body)
            .collect();
        assert_eq!(on_card.len(), 2, "{on_card:?}");
        assert!(on_card.iter().any(|b| b.starts_with("Wants short")));

        // The same answers again change nothing; a changed one is edited; a missing one is retired.
        assert_eq!(write(&p, "dev-1", &first, "2026-11-19T11:00:00Z").await.unwrap(), (0, 0));
        let second = [item("role", "Designs interfaces.")];
        assert_eq!(write(&p, "dev-1", &second, "2026-11-19T12:00:00Z").await.unwrap(), (1, 1));
        let on_card: Vec<String> = me_card::candidates(&p)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.body)
            .collect();
        assert_eq!(on_card, ["Designs interfaces."]);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(rows, 2, "a retired answer keeps its row");
    }
}
