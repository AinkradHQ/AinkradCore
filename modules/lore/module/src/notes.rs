//! Lore notes: list, create, read, move to a project, trash and restore, and today's daily note.
//! A note's `text` is the Markdown document. The save path (R1-02) and the index (R1-04) come later.
//! Every refusal is a fixed sentence; nothing a caller sent is echoed back. Audit and events carry
//! ids only, never a title or text.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write, events, projects};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, FromRequest, Path, Query, Request, State};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection, SqlitePool};
use utoipa::ToSchema;

const LIST_MAX: i64 = 500;
const TEXT_MAX: usize = 2_000_000;
/// Notes trashed longer than this are deleted for good by the sweep job.
pub const TRASH_DAYS: i64 = 30;

/// A JSON body whose parse failure is one fixed sentence (serde's own text quotes the input).
pub(crate) struct In<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for In<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| In(v))
            .map_err(|_| ApiError::bad_request("the request body is not valid"))
    }
}

/// `"field": null` clears; an absent field keeps.
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

pub(crate) fn bad() -> ApiError {
    ApiError::bad_request("the note is not valid")
}

pub(crate) fn none() -> ApiError {
    ApiError::not_found("no such note")
}

/// `ln_` and 12 base32 characters (lowercase a-z, 2-7).
fn new_id() -> String {
    rand_id("ln_")
}

/// `prefix` and 12 base32 characters (lowercase a-z, 2-7).
pub(crate) fn rand_id(prefix: &str) -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    let n = u64::from_le_bytes(b);
    let s: String = (0..12)
        .map(|i| b"abcdefghijklmnopqrstuvwxyz234567"[((n >> (5 * i)) & 31) as usize] as char)
        .collect();
    format!("{prefix}{s}")
}

pub(crate) fn id_ok(s: &str) -> bool {
    id_has("ln_", s)
}

/// `prefix` and 12 base32 characters, as [`rand_id`] makes them.
pub(crate) fn id_has(prefix: &str, s: &str) -> bool {
    s.len() == prefix.len() + 12
        && s.starts_with(prefix)
        && s[prefix.len()..]
            .bytes()
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

/// Parse a note's Markdown (R1-03): its title, links and tags. Too large = the one refusal.
pub(crate) fn parsed(text: &str) -> Result<lore_model::Parsed, ApiError> {
    lore_model::parse(text).map_err(|_| bad())
}

/// `(year, month, day)` of a real `YYYY-MM-DD` date, years 1900 to 2999.
fn parse_day(s: &str) -> Option<(i64, i64, i64)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        s.get(r)
            .filter(|p| p.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + i64::from(leap),
        _ => return None,
    };
    ((1900..=2999).contains(&y) && (1..=max).contains(&d)).then_some((y, m, d))
}

/// `Tuesday, 17 November 2026`.
fn long_date((y, m, d): (i64, i64, i64)) -> String {
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    // Sakamoto's weekday (0 = Sunday).
    const T: [i64; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let yy = if m < 3 { y - 1 } else { y };
    let wd = (yy + yy / 4 - yy / 100 + yy / 400 + T[(m - 1) as usize] + d) % 7;
    format!(
        "{}, {d} {} {y}",
        DAYS[wd as usize],
        MONTHS[(m - 1) as usize]
    )
}

#[derive(Serialize, ToSchema)]
pub struct NoteSummary {
    /// `ln_` and 12 base32 characters.
    pub id: String,
    /// `note` or `daily`.
    pub kind: String,
    /// A daily note's local date, `YYYY-MM-DD`.
    pub day: Option<String>,
    /// The project id (as text); `null` = personal.
    pub project: Option<String>,
    /// Derived from the text; not set directly.
    pub title: String,
    pub rev: i64,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: String,
    pub updated_at: String,
    /// Set while the note is in the trash.
    pub trashed_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct NoteView {
    #[serde(flatten)]
    pub note: NoteSummary,
    /// The Markdown document.
    pub text: String,
}

fn summary(r: &sqlx::sqlite::SqliteRow) -> Result<NoteSummary, sqlx::Error> {
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(NoteSummary {
        id: text("id")?,
        kind: text("kind")?,
        day: r.try_get("day")?,
        project: r.try_get("project")?,
        title: text("title")?,
        rev: r.try_get("rev")?,
        created_by: text("created_by")?,
        updated_by: text("updated_by")?,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
        trashed_at: r.try_get("trashed_at")?,
    })
}

pub(crate) async fn view(conn: &mut SqliteConnection, id: &str) -> Result<NoteView, ApiError> {
    let r = sqlx::query("SELECT * FROM lore_notes WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(none)?;
    Ok(NoteView {
        note: summary(&r)?,
        text: r.try_get("text")?,
    })
}

/// A table refusal is the second layer answering: a fixed sentence, never the database's text.
pub(crate) fn store_err(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_check_violation() || d.is_foreign_key_violation() => bad(),
        _ => e.into(),
    }
}

/// Audit row + event, ids only. `kind` is the event (`changed` or `trashed`), `op` the audit verb.
pub(crate) async fn record(
    conn: &mut SqliteConnection,
    op: &str,
    event: &str,
    id: &str,
    rev: i64,
    origin: &str,
    project: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut d = json!({"note": id});
    if let Some(p) = project {
        d["project"] = json!(p);
    }
    let row = NewAuditEvent {
        actor: BY,
        action: format!("lore.note.{op}"),
        entity: None,
        details: d.to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(
        conn,
        &format!("lore.note.{event}"),
        &json!({"id": id, "rev": rev, "origin": origin}),
    )
    .await?;
    Ok(())
}

/// The project `ident` names, as the text id a note stores. The Projects store is the authority:
/// a text that is no existing project's id is refused (no foreign key into a Core table).
async fn project_id(conn: &mut SqliteConnection, ident: &str) -> Result<String, ApiError> {
    let unknown = || ApiError::bad_request("no such project");
    if ident.is_empty() || ident.len() > 18 || !ident.bytes().all(|c| c.is_ascii_digit()) {
        return Err(unknown());
    }
    let n: i64 = ident.parse().map_err(|_| unknown())?;
    projects::get(conn, n).await.map_err(|_| unknown())?;
    Ok(n.to_string())
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    /// `active` (default), `trashed` or `all`.
    state: Option<String>,
    kind: Option<String>,
    project: Option<String>,
}

#[utoipa::path(get, path = "/notes", operation_id = "loreListNotes", tag = "lore",
    params(("state" = Option<String>, Query, description = "`active` (default), `trashed` or `all`"),
           ("kind" = Option<String>, Query, description = "`note` or `daily`"),
           ("project" = Option<String>, Query, description = "Only notes of this project id")),
    responses((status = 200, description = "Notes, newest change first, without their text (at most 500)", body = Vec<NoteSummary>)))]
pub(crate) async fn list(
    State(app): State<App>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> ApiResult<Vec<NoteSummary>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let state = q.state.as_deref().unwrap_or("active");
    if !["active", "trashed", "all"].contains(&state)
        || q.kind
            .as_deref()
            .is_some_and(|k| !["note", "daily"].contains(&k))
    {
        return Err(ApiError::bad_request("the query is not valid"));
    }
    let rows = sqlx::query(
        "SELECT * FROM lore_notes \
         WHERE (?1 = 'all' OR (?1 = 'active' AND trashed_at IS NULL) \
                OR (?1 = 'trashed' AND trashed_at IS NOT NULL)) \
           AND (?2 IS NULL OR kind = ?2) AND (?3 IS NULL OR project = ?3) \
         ORDER BY updated_at DESC, id LIMIT ?4",
    )
    .bind(state)
    .bind(q.kind)
    .bind(q.project)
    .bind(LIST_MAX)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows.iter().map(summary).collect::<Result<_, _>>()?))
}

#[derive(Deserialize, ToSchema)]
pub struct NewNote {
    /// The Markdown document; empty when absent. At most 2 000 000 bytes.
    pub text: Option<String>,
    /// A project id; checked through the Projects store. Absent = personal.
    pub project: Option<String>,
}

#[utoipa::path(post, path = "/notes", operation_id = "loreCreateNote", tag = "lore", request_body = NewNote,
    responses((status = 200, description = "The new note at rev 1 (audited as `lore.note.created`); an unknown project is refused", body = NoteView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<NewNote>,
) -> ApiResult<NoteView> {
    let text = req.text.unwrap_or_default();
    if text.len() > TEXT_MAX {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    let project = match req.project.as_deref() {
        Some(p) => Some(project_id(&mut tx, p).await?),
        None => None,
    };
    let id = new_id();
    let parse = parsed(&text)?;
    let title = parse.title.clone();
    let who = format!("person:{}", me.device.id);
    sqlx::query(
        "INSERT INTO lore_notes (id, project, title, title_norm, text, created_by, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&project)
    .bind(&title)
    .bind(lore_model::normalize_title(&title))
    .bind(&text)
    .bind(&who)
    .bind(&who)
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    crate::save::seed(&mut tx, &id, &text, &parse).await?;
    record(
        &mut tx,
        "created",
        "changed",
        &id,
        1,
        "person",
        project.as_deref(),
    )
    .await?;
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub(crate) struct TodayQuery {
    day: Option<String>,
}

#[utoipa::path(get, path = "/today", operation_id = "loreToday", tag = "lore",
    params(("day" = String, Query, description = "The caller's local date, `YYYY-MM-DD`")),
    responses((status = 200, description = "That day's note, created empty on first use (audited as `lore.note.created`); the same note on every call. A trashed one is restored. Needs admin: it may write", body = NoteView)))]
pub(crate) async fn today(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    q: Result<Query<TodayQuery>, QueryRejection>,
) -> ApiResult<NoteView> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let day = q.day.unwrap_or_default();
    let date = parse_day(&day).ok_or_else(|| ApiError::bad_request("the day is not valid"))?;
    let mut tx = begin_write(&app.pool).await?;
    let found: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT id, trashed_at FROM lore_notes WHERE day = ?")
            .bind(&day)
            .fetch_optional(&mut *tx)
            .await?;
    let id = match found {
        Some((id, trashed)) => {
            if trashed.is_some() {
                let rev = restore_row(&mut tx, &id).await?;
                record(&mut tx, "restored", "changed", &id, rev, "person", None).await?;
            }
            id
        }
        None => {
            let id = new_id();
            let title = long_date(date);
            let who = format!("person:{}", me.device.id);
            // The UNIQUE day is the backstop; the write gate already serialises callers.
            sqlx::query(
                "INSERT INTO lore_notes (id, kind, day, title, title_norm, text, created_by, updated_by) \
                 VALUES (?, 'daily', ?, ?, ?, '', ?, ?)",
            )
            .bind(&id)
            .bind(&day)
            .bind(&title)
            .bind(lore_model::normalize_title(&title))
            .bind(&who)
            .bind(&who)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
            crate::save::seed(&mut tx, &id, "", &Default::default()).await?;
            record(&mut tx, "created", "changed", &id, 1, "person", None).await?;
            id
        }
    };
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(get, path = "/notes/{note}", operation_id = "loreGetNote", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "The note with its text, trashed ones included", body = NoteView)))]
pub(crate) async fn get(State(app): State<App>, Path(note): Path<String>) -> ApiResult<NoteView> {
    if !id_ok(&note) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(view(&mut conn, &note).await?))
}

/// Every field is optional; `project` set to `null` makes the note personal.
#[derive(Deserialize, ToSchema)]
pub struct NotePatch {
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub project: Option<Option<String>>,
    /// `true` moves the note to the trash, `false` restores it.
    pub trashed: Option<bool>,
}

/// Clears `trashed_at`; the revision moves so a watcher sees the change. Returns the new rev.
async fn restore_row(conn: &mut SqliteConnection, id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE lore_notes SET trashed_at = NULL, rev = rev + 1, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ? RETURNING rev",
    )
    .bind(id)
    .fetch_one(conn)
    .await
}

#[utoipa::path(patch, path = "/notes/{note}", operation_id = "lorePatchNote", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = NotePatch,
    responses((status = 200, description = "The changed note (audited as `lore.note.moved`, `trashed` or `restored`). The trash keeps every row until the 30-day sweep. A trashed note can only be restored; a daily note has no project", body = NoteView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(note): Path<String>,
    In(req): In<NotePatch>,
) -> ApiResult<NoteView> {
    if !id_ok(&note) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    let cur = view(&mut tx, &note).await?;
    let was_trashed = cur.note.trashed_at.is_some();
    let want_trashed = req.trashed.unwrap_or(was_trashed);
    if was_trashed && want_trashed && req.project.is_some() {
        return Err(ApiError::conflict("the note is in the trash"));
    }
    if let Some(p) = req.project {
        let new = match p.as_deref() {
            Some(p) => Some(project_id(&mut tx, p).await?),
            None => None,
        };
        if new != cur.note.project {
            let rev: i64 = sqlx::query_scalar(
                "UPDATE lore_notes SET project = ?, rev = rev + 1, \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ? RETURNING rev",
            )
            .bind(&new)
            .bind(&note)
            .fetch_one(&mut *tx)
            .await
            .map_err(store_err)?;
            record(
                &mut tx,
                "moved",
                "changed",
                &note,
                rev,
                "person",
                new.as_deref(),
            )
            .await?;
        }
    }
    if want_trashed && !was_trashed {
        let rev: i64 = sqlx::query_scalar(
            "UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), rev = rev + 1 \
             WHERE id = ? RETURNING rev",
        )
        .bind(&note)
        .fetch_one(&mut *tx)
        .await?;
        record(&mut tx, "trashed", "trashed", &note, rev, "person", None).await?;
    } else if !want_trashed && was_trashed {
        let rev = restore_row(&mut tx, &note).await?;
        record(&mut tx, "restored", "changed", &note, rev, "person", None).await?;
    }
    let out = view(&mut tx, &note).await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Deletes the notes trashed more than [`TRASH_DAYS`] days ago, with their saves, versions, links
/// and tags (cascade) and their FTS row. Returns how many. One audit row and event per note.
pub async fn sweep(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM lore_notes WHERE trashed_at IS NOT NULL \
         AND trashed_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
    )
    .bind(format!("-{TRASH_DAYS} days"))
    .fetch_all(&mut *tx)
    .await?;
    for id in &ids {
        sqlx::query(
            "DELETE FROM lore_fts WHERE rowid = (SELECT rowid FROM lore_notes WHERE id = ?)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM lore_notes WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let row = NewAuditEvent {
            actor: BY,
            action: "lore.note.purged".to_owned(),
            entity: None,
            details: json!({"note": id}).to_string(),
        };
        audit::append(&mut tx, &row).await?;
        events::append(&mut tx, "lore.note.purged", &json!({"id": id})).await?;
    }
    tx.commit().await?;
    Ok(ids.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days() {
        assert_eq!(parse_day("2026-11-17"), Some((2026, 11, 17)));
        assert_eq!(long_date((2026, 11, 17)), "Tuesday, 17 November 2026");
        assert_eq!(long_date((2024, 2, 29)), "Thursday, 29 February 2024");
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-1-01",
            "20261117",
            "2026-11-1x",
            "1899-01-01",
            "",
        ] {
            assert_eq!(parse_day(bad), None, "{bad}");
        }
    }

    #[test]
    fn ids() {
        let id = new_id();
        assert!(id_ok(&id), "{id}");
        assert!(!id_ok("ln_AAAAAAAAAAAA") && !id_ok("ln_aaaa") && !id_ok("dd_aaaaaaaaaaaa"));
    }
}
