//! Lore through Code Mode (R5-01, plan T14): what an AI session may search, read and write of the notes.
//!
//! Security model, in one place:
//! - **One scope for reads and writes.** The scope is the session's own row, read on every call
//!   (`core_agent_sessions.project_id`), never an argument: a session WITH a project reaches only that
//!   project's notes; a session WITHOUT one reaches only personal and daily notes (`project IS NULL`). Every
//!   query below carries `project IS ?` with that value, so a note of another project is the same 404 as an
//!   unknown id. No route takes a project, and no op moves a note between projects or personal.
//! - **Outside data.** Everything a note says (title, text, link context) leaves inside the fixed
//!   `ainkrad_core::untrusted` envelope; nothing a note wrote is returned as a bare field.
//! - **Writes are reversible.** Before a session's first edit of a note an `auto` version of the old text is
//!   kept (T4); nothing is ever deleted: the one removal is the trash (30 days, restorable by a person), and
//!   it is a `risky` op that waits for a person's approval. Restore, purge, import and attachment ops do not
//!   exist here. An edit that does not match changes nothing.
//! - **No side writes outside the scope.** A rename by an AI edit does not rewrite `[[links]]` in other notes
//!   (that would write into notes of other projects); a person's save still does.
//! - The routes answer only the Code Mode dispatcher's synthetic caller (`code_mode:<session>`).
//!
//! ponytail: search is the full-text ranking only; the meaning ranking needs a project filter in the shared
//! search and adds nothing the AI cannot get by asking twice. Add it when a session needs it.

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::{agents, begin_write};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::notes::{In, bad, id_ok, none, record};
use crate::save::{Head, Snap, load, relink, write_text};
use crate::search::{match_expr, snippet, words};
use crate::versions;

const SESSION: &str = "code_mode:";
const TEXT_MAX: usize = 2_000_000;
/// The most a session writes in one call (Code Mode's own argument cap is 64 KiB).
const WRITE_MAX: usize = 60_000;
const FIND_MAX: usize = 2_000;
/// A read returns this many characters of a note; `truncated` says there is more.
const READ_MAX: usize = 60_000;
const LIMIT_DEFAULT: i64 = 10;
const LIMIT_MAX: i64 = 25;
const Q_MAX: usize = 300;
const LINKS_MAX: i64 = 100;

/// What the session may reach: its project's notes, or (no project) personal and daily ones.
struct Scope {
    session: String,
    /// `core_projects.id` as text, as a note stores it; `None` = personal and daily.
    project: Option<String>,
}

impl Scope {
    /// Who a note's `created_by`/`updated_by` and a version's origin name.
    fn who(&self) -> String {
        format!("session:{}", self.session)
    }
}

async fn scope_of(app: &App, me: &Caller) -> Result<Scope, ApiError> {
    let session = me
        .session
        .strip_prefix(SESSION)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "session_only",
                "this route answers AI sessions",
            )
        })?;
    // An ended or unknown session reaches nothing.
    if !agents::get(&app.pool, session)
        .await?
        .is_some_and(|s| s.live())
    {
        return Err(none());
    }
    let project: Option<i64> =
        sqlx::query_scalar("SELECT project_id FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_one(&app.pool)
            .await?;
    Ok(Scope {
        session: session.to_owned(),
        project: project.map(|p| p.to_string()),
    })
}

/// The head of `id` when it is a live note of the scope; else the 404 of an unknown note. Call inside the
/// write transaction of a write, so the check and the write see the same row.
async fn head(conn: &mut SqliteConnection, s: &Scope, id: &str) -> Result<Head, ApiError> {
    if !id_ok(id) {
        return Err(none());
    }
    let seen: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM lore_notes WHERE id = ?1 AND project IS ?2 AND trashed_at IS NULL",
    )
    .bind(id)
    .bind(&s.project)
    .fetch_optional(&mut *conn)
    .await?;
    seen.ok_or_else(none)?;
    load(conn, id).await
}

/// The first `n` characters of `s`, and whether there was more.
fn cut(s: &str, n: usize) -> (&str, bool) {
    match s.char_indices().nth(n) {
        Some((i, _)) => (&s[..i], true),
        None => (s, false),
    }
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiHit {
    /// `ln_` and 12 base32 characters.
    pub id: String,
    /// `note` or `daily`.
    pub kind: String,
    pub updated_at: String,
    /// The note's title and the stretch that matched, inside the outside-text envelope.
    pub text: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiHits {
    pub hits: Vec<LoreAiHit>,
}

#[derive(Deserialize)]
pub(crate) struct SearchQuery {
    q: Option<String>,
    tag: Option<String>,
    limit: Option<i64>,
}

#[utoipa::path(get, path = "/ai/search", operation_id = "loreAiSearch", tag = "lore",
    params(("q" = String, Query, description = "Words (prefix match) and \"quoted phrases\"; at most 300 characters"),
           ("tag" = Option<String>, Query, description = "Only notes with this tag"),
           ("limit" = Option<i64>, Query, description = "At most this many hits (default 10, most 25)")),
    responses((status = 200, description = "Live notes of this AI session's scope (its project's, or personal and daily ones), best first; every text is wrapped as outside data", body = LoreAiHits)))]
pub(crate) async fn search(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    q: Result<Query<SearchQuery>, QueryRejection>,
) -> ApiResult<LoreAiHits> {
    let s = scope_of(&app, &me).await?;
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let text = q.q.as_deref().map(str::trim).unwrap_or_default();
    let limit = q.limit.unwrap_or(LIMIT_DEFAULT);
    let expr = match_expr(text).filter(|_| text.chars().count() <= Q_MAX);
    let (true, Some(expr)) = ((1..=LIMIT_MAX).contains(&limit), expr) else {
        return Err(ApiError::bad_request("the query is not valid"));
    };
    let tag = q
        .tag
        .as_deref()
        .map(|t| t.trim().trim_start_matches('#').to_owned());
    let rows = sqlx::query(
        "SELECT n.id, n.kind, n.title, n.text, n.updated_at \
         FROM lore_fts JOIN lore_notes n ON n.rowid = lore_fts.rowid \
         WHERE lore_fts MATCH ?1 AND n.trashed_at IS NULL AND n.project IS ?2 \
           AND (?3 IS NULL OR EXISTS (SELECT 1 FROM lore_tags t WHERE t.note = n.id AND t.tag = ?3)) \
         ORDER BY bm25(lore_fts, 4.0, 1.0), n.id LIMIT ?4",
    )
    .bind(&expr)
    .bind(&s.project)
    .bind(&tag)
    .bind(limit)
    .fetch_all(&app.pool)
    .await?;
    let ws = words(text);
    let mut hits = Vec::new();
    for r in &rows {
        let id: String = r.try_get("id")?;
        let title: String = r.try_get("title")?;
        let body: String = r.try_get("text")?;
        let kind: String = r.try_get("kind")?;
        let shown = format!("{title}\n{}", snippet(&body, &ws, 0).text);
        hits.push(LoreAiHit {
            text: wrap(&format!("note {id} ({kind})"), &shown),
            id,
            kind,
            updated_at: r.try_get("updated_at")?,
        });
    }
    Ok(Json(LoreAiHits { hits }))
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiNote {
    pub id: String,
    /// `note` or `daily`.
    pub kind: String,
    /// A daily note's local date.
    pub day: Option<String>,
    pub rev: i64,
    pub updated_at: String,
    /// The Markdown, inside the outside-text envelope; cut at 60 000 characters.
    pub text: String,
    pub truncated: bool,
}

#[utoipa::path(get, path = "/ai/notes/{note}", operation_id = "loreAiRead", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "One live note of this AI session's scope, as outside data. A note of another project, a trashed one and an unknown id are the same 404", body = LoreAiNote)))]
pub(crate) async fn read(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
) -> ApiResult<LoreAiNote> {
    let s = scope_of(&app, &me).await?;
    if !id_ok(&note) {
        return Err(none());
    }
    let r = sqlx::query(
        "SELECT id, kind, day, rev, text, updated_at FROM lore_notes \
         WHERE id = ?1 AND project IS ?2 AND trashed_at IS NULL",
    )
    .bind(&note)
    .bind(&s.project)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(none)?;
    let body: String = r.try_get("text")?;
    let kind: String = r.try_get("kind")?;
    let (shown, truncated) = cut(&body, READ_MAX);
    Ok(Json(LoreAiNote {
        text: wrap(&format!("note {note} ({kind})"), shown),
        id: note,
        kind,
        day: r.try_get("day")?,
        rev: r.try_get("rev")?,
        updated_at: r.try_get("updated_at")?,
        truncated,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiLink {
    /// The note on the other end, when it is a live note of this scope; `null` for a link that names no such
    /// note (a note of another project reads the same as no note).
    pub note: Option<String>,
    /// The link's target title (or `#Heading`) and the line it is on, inside the outside-text envelope.
    pub text: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiLinks {
    /// The `[[links]]` this note's text makes.
    pub links: Vec<LoreAiLink>,
    /// The live notes of this scope that link to this one.
    pub backlinks: Vec<LoreAiLink>,
}

#[utoipa::path(get, path = "/ai/notes/{note}/links", operation_id = "loreAiLinks", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "The links of a note of this AI session's scope and the notes of the scope that link to it (at most 100 each), as outside data", body = LoreAiLinks)))]
pub(crate) async fn links(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
) -> ApiResult<LoreAiLinks> {
    let s = scope_of(&app, &me).await?;
    let mut conn = app.pool.acquire().await?;
    head(&mut conn, &s, &note).await?;
    // The target counts only when it is in scope: T6 resolves across projects, and its id is not ours to show.
    let out = sqlx::query(
        "SELECT n.id AS other, l.target_title_norm, l.heading, l.context FROM lore_links l \
         LEFT JOIN lore_notes n ON n.id = l.target AND n.project IS ?2 AND n.trashed_at IS NULL \
         WHERE l.src = ?1 ORDER BY l.target_title_norm, l.heading LIMIT ?3",
    )
    .bind(&note)
    .bind(&s.project)
    .bind(LINKS_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let back = sqlx::query(
        "SELECT n.id AS other, l.target_title_norm, l.heading, l.context FROM lore_links l \
         JOIN lore_notes n ON n.id = l.src \
         WHERE l.target = ?1 AND n.project IS ?2 AND n.trashed_at IS NULL \
         ORDER BY n.updated_at DESC, n.id, l.heading LIMIT ?3",
    )
    .bind(&note)
    .bind(&s.project)
    .bind(LINKS_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let one = |r: &sqlx::sqlite::SqliteRow| -> Result<LoreAiLink, sqlx::Error> {
        let (title, heading, context): (String, String, String) = (
            r.try_get("target_title_norm")?,
            r.try_get("heading")?,
            r.try_get("context")?,
        );
        let at = if heading.is_empty() {
            title
        } else {
            format!("{title}#{heading}")
        };
        Ok(LoreAiLink {
            note: r.try_get("other")?,
            text: wrap(&format!("link in note {note}"), &format!("{at}\n{context}")),
        })
    };
    Ok(Json(LoreAiLinks {
        links: out.iter().map(&one).collect::<Result<_, _>>()?,
        backlinks: back.iter().map(&one).collect::<Result<_, _>>()?,
    }))
}

/// What a write answers: ids and the revision only (the AI wrote the text; it is not echoed).
#[derive(Serialize, ToSchema)]
pub struct LoreAiWrote {
    pub id: String,
    pub rev: i64,
    /// `false` when the text came out the same, so nothing was written.
    pub changed: bool,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoreAiText {
    /// Markdown; 1 to 60 000 characters.
    #[schema(max_length = 60000)]
    pub text: String,
}

fn text_ok(t: &str) -> Result<(), ApiError> {
    if t.trim().is_empty() || t.len() > WRITE_MAX {
        return Err(bad());
    }
    Ok(())
}

/// Writes `text` as the head for the session: an `auto` version of the old text first when this session has
/// not made one of this note yet (T4), then the normal write path. No rename rewrite (see the header).
async fn put(
    conn: &mut SqliteConnection,
    s: &Scope,
    h: &Head,
    text: &str,
) -> Result<LoreAiWrote, ApiError> {
    if text.len() > TEXT_MAX {
        return Err(bad());
    }
    if text == h.text {
        return Ok(LoreAiWrote {
            id: h.id.clone(),
            rev: h.rev,
            changed: false,
        });
    }
    let who = s.who();
    let kept: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM lore_versions WHERE note = ? AND origin = ? AND kind = 'auto' LIMIT 1",
    )
    .bind(&h.id)
    .bind(&who)
    .fetch_optional(&mut *conn)
    .await?;
    if kept.is_none() {
        versions::snapshot(conn, h, "auto", None, &who).await?;
    }
    let w = write_text(conn, h, text, &who, "session", Snap::Never).await?;
    Ok(LoreAiWrote {
        id: h.id.clone(),
        rev: w.rev,
        changed: true,
    })
}

#[utoipa::path(post, path = "/ai/notes", operation_id = "loreAiCreate", tag = "lore", request_body = LoreAiText,
    responses((status = 200, description = "A new note at rev 1, in this AI session's project, or personal when it has none. It cannot be put anywhere else", body = LoreAiWrote)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<LoreAiText>,
) -> ApiResult<LoreAiWrote> {
    let s = scope_of(&app, &me).await?;
    text_ok(&req.text)?;
    let mut tx = begin_write(&app.pool).await?;
    let id = crate::notes::insert(
        &mut tx,
        s.project.as_deref(),
        &req.text,
        &s.who(),
        "session",
    )
    .await?;
    tx.commit().await?;
    Ok(Json(LoreAiWrote {
        id,
        rev: 1,
        changed: true,
    }))
}

#[utoipa::path(post, path = "/ai/notes/{note}/append", operation_id = "loreAiAppend", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = LoreAiText,
    responses((status = 200, description = "The text added after the note's last line, on a new line. A version of the old text is kept before this session's first edit of the note", body = LoreAiWrote)))]
pub(crate) async fn append(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
    In(req): In<LoreAiText>,
) -> ApiResult<LoreAiWrote> {
    let s = scope_of(&app, &me).await?;
    text_ok(&req.text)?;
    let mut tx = begin_write(&app.pool).await?;
    let h = head(&mut tx, &s, &note).await?;
    let mut text = h.text.clone();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&req.text);
    let out = put(&mut tx, &s, &h, &text).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoreAiEdit {
    /// Text that occurs exactly once in the note.
    #[schema(max_length = 2000)]
    pub find: String,
    /// What takes its place; may be empty. At most 60 000 characters.
    #[schema(max_length = 60000)]
    pub replace: String,
}

#[utoipa::path(post, path = "/ai/notes/{note}/edit", operation_id = "loreAiEdit", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = LoreAiEdit,
    responses((status = 200, description = "`find` replaced by `replace`. A `find` that is not in the note exactly once is a 409 and changes nothing. A version of the old text is kept before this session's first edit of the note", body = LoreAiWrote)))]
pub(crate) async fn edit(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
    In(req): In<LoreAiEdit>,
) -> ApiResult<LoreAiWrote> {
    let s = scope_of(&app, &me).await?;
    if req.find.is_empty() || req.find.len() > FIND_MAX || req.replace.len() > WRITE_MAX {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    let h = head(&mut tx, &s, &note).await?;
    // Exactly once, overlapping matches counted: no second match after the first one's first character.
    let once = h.text.find(&req.find).is_some_and(|i| {
        let step = h.text[i..].chars().next().map_or(1, char::len_utf8);
        !h.text[i + step..].contains(&req.find)
    });
    if !once {
        return Err(ApiError::conflict("find is not in the note exactly once"));
    }
    let text = h.text.replacen(req.find.as_str(), &req.replace, 1);
    let out = put(&mut tx, &s, &h, &text).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct LoreAiTrashed {
    pub id: String,
    pub rev: i64,
}

#[utoipa::path(post, path = "/ai/notes/{note}/trash", operation_id = "loreAiTrash", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "The note is in the trash: nothing is deleted, a person restores it within 30 days. Needs a person's approval", body = LoreAiTrashed)))]
pub(crate) async fn trash(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
) -> ApiResult<LoreAiTrashed> {
    let s = scope_of(&app, &me).await?;
    let mut tx = begin_write(&app.pool).await?;
    head(&mut tx, &s, &note).await?;
    let rev: i64 = sqlx::query_scalar(
        "UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), rev = rev + 1 \
         WHERE id = ? RETURNING rev",
    )
    .bind(&note)
    .fetch_one(&mut *tx)
    .await?;
    record(
        &mut tx,
        "trashed",
        "trashed",
        &note,
        rev,
        "session",
        s.project.as_deref(),
    )
    .await?;
    relink(&mut tx, &note, None).await?;
    tx.commit().await?;
    Ok(Json(LoreAiTrashed { id: note, rev }))
}
