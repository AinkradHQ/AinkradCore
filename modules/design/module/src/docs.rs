//! Design docs: list, create, read, change, archive, and the links to projects. A doc is never
//! deleted: archiving keeps every row (updates, versions, screens, links). Every refusal is a fixed
//! sentence; nothing a caller sent is echoed back. Audit and events carry ids only, never a name.

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
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

const LIST_MAX: i64 = 500;
const KINDS: &[&str] = &["design", "system", "mockup"];

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
pub(crate) fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

fn bad() -> ApiError {
    ApiError::bad_request("the design is not valid")
}

fn new_id() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    format!(
        "dd_{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// 1 to 100 characters, no control character, no edge whitespace.
pub(crate) fn name_ok(s: &str) -> bool {
    (1..=100).contains(&s.chars().count()) && s == s.trim() && !s.chars().any(char::is_control)
}

pub(crate) fn doc_id_ok(s: &str) -> bool {
    s.len() == 19 && s.starts_with("dd_") && s[3..].bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Serialize, ToSchema)]
pub struct DocView {
    /// `dd_` and 16 hex characters.
    pub id: String,
    /// `design`, `system` or `mockup`.
    pub kind: String,
    pub name: String,
    /// `active` or `archived`.
    pub state: String,
    /// The design system a design uses (a `system` doc id).
    pub system: Option<String>,
    /// Projects it is related to (ids as text), ascending.
    pub projects: Vec<String>,
    pub ai_paused: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

pub(crate) async fn view(conn: &mut SqliteConnection, id: &str) -> Result<DocView, ApiError> {
    let r = sqlx::query("SELECT * FROM design_docs WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| ApiError::not_found("no such design"))?;
    let projects: Vec<String> = sqlx::query_scalar(
        "SELECT project FROM design_links WHERE item_kind = 'doc' AND item = ? \
         ORDER BY CAST(project AS INTEGER)",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(DocView {
        id: text("id")?,
        kind: text("kind")?,
        name: text("name")?,
        state: text("state")?,
        system: r.try_get("system")?,
        projects,
        ai_paused: r.try_get::<i64, _>("ai_paused")? == 1,
        created_by: text("created_by")?,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
    })
}

/// A table refusal is the second layer answering: a fixed sentence, never the database's text.
fn store_err(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_check_violation() || d.is_foreign_key_violation() => bad(),
        _ => e.into(),
    }
}

pub(crate) async fn record(
    conn: &mut SqliteConnection,
    op: &str,
    id: &str,
    project: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut d = json!({"doc": id});
    let mut e = json!({"op": op, "id": id});
    if let Some(p) = project {
        d["project"] = json!(p);
        e["project"] = json!(p);
    }
    let row = NewAuditEvent {
        actor: BY,
        action: format!("design.doc.{op}"),
        entity: None,
        details: d.to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "design.doc", &e).await?;
    Ok(())
}

/// The project `ident` names, as the text id a link stores. The Projects store is the authority:
/// a text that is no existing project's id is refused (no foreign key into a Core table).
pub(crate) async fn project_id(
    conn: &mut SqliteConnection,
    ident: &str,
) -> Result<String, ApiError> {
    let unknown = || ApiError::bad_request("no such project");
    if ident.is_empty() || ident.len() > 18 || !ident.bytes().all(|c| c.is_ascii_digit()) {
        return Err(unknown());
    }
    let n: i64 = ident.parse().map_err(|_| unknown())?;
    projects::get(conn, n).await.map_err(|_| unknown())?;
    Ok(n.to_string())
}

/// An active doc, or the fixed refusal (not found / archived).
pub(crate) async fn editable(conn: &mut SqliteConnection, id: &str) -> Result<(), ApiError> {
    let none = || ApiError::not_found("no such design");
    if !doc_id_ok(id) {
        return Err(none());
    }
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM design_docs WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    match state.as_deref() {
        None => Err(none()),
        Some("active") => Ok(()),
        Some(_) => Err(ApiError::conflict("the design is archived")),
    }
}

/// The system a design names must be a `system` doc, and only a design names one.
async fn check_system(
    conn: &mut SqliteConnection,
    kind: &str,
    system: Option<&str>,
) -> Result<(), ApiError> {
    let Some(s) = system else { return Ok(()) };
    if kind != "design" || !doc_id_ok(s) {
        return Err(bad());
    }
    let k: Option<String> = sqlx::query_scalar("SELECT kind FROM design_docs WHERE id = ?")
        .bind(s)
        .fetch_optional(&mut *conn)
        .await?;
    if k.as_deref() != Some("system") {
        return Err(bad());
    }
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    /// `active` (default), `archived` or `all`.
    state: Option<String>,
    kind: Option<String>,
    project: Option<String>,
}

#[utoipa::path(get, path = "/docs", operation_id = "designListDocs", tag = "design",
    params(("state" = Option<String>, Query, description = "`active` (default), `archived` or `all`"),
           ("kind" = Option<String>, Query, description = "Only this kind"),
           ("project" = Option<String>, Query, description = "Only docs linked to this project id")),
    responses((status = 200, description = "Designs by name (at most 500)", body = Vec<DocView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> ApiResult<Vec<DocView>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let state = q.state.as_deref().unwrap_or("active");
    if !["active", "archived", "all"].contains(&state)
        || q.kind.as_deref().is_some_and(|k| !KINDS.contains(&k))
    {
        return Err(ApiError::bad_request("the query is not valid"));
    }
    let mut conn = app.pool.acquire().await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM design_docs \
         WHERE (?1 = 'all' OR state = ?1) AND (?2 IS NULL OR kind = ?2) \
           AND (?3 IS NULL OR EXISTS (SELECT 1 FROM design_links l \
                WHERE l.item_kind = 'doc' AND l.item = design_docs.id AND l.project = ?3)) \
         ORDER BY name COLLATE NOCASE, id LIMIT ?4",
    )
    .bind(state)
    .bind(q.kind)
    .bind(q.project)
    .bind(LIST_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(view(&mut conn, &id).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct NewDoc {
    /// `design`, `system` or `mockup`.
    pub kind: String,
    pub name: String,
    /// The design system (a `system` doc id); designs only.
    pub system: Option<String>,
    /// A project id to relate it to; checked through the Projects store.
    pub project: Option<String>,
}

#[utoipa::path(post, path = "/docs", operation_id = "designCreateDoc", tag = "design", request_body = NewDoc,
    responses((status = 200, description = "The new design (audited as `design.doc.created`); an unknown project is refused", body = DocView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<NewDoc>,
) -> ApiResult<DocView> {
    if !KINDS.contains(&req.kind.as_str()) || !name_ok(&req.name) {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    check_system(&mut tx, &req.kind, req.system.as_deref()).await?;
    let project = match req.project.as_deref() {
        Some(p) => Some(project_id(&mut tx, p).await?),
        None => None,
    };
    let id = new_id();
    sqlx::query(
        "INSERT INTO design_docs (id, kind, name, system, created_by) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.kind)
    .bind(&req.name)
    .bind(&req.system)
    .bind(format!("person:{}", me.device.id))
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    record(&mut tx, "created", &id, None).await?;
    if let Some(p) = &project {
        sqlx::query("INSERT INTO design_links (item_kind, item, project) VALUES ('doc', ?, ?)")
            .bind(&id)
            .bind(p)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        record(&mut tx, "linked", &id, Some(p)).await?;
    }
    let out = view(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(get, path = "/docs/{doc}", operation_id = "designGetDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "The design, archived ones included", body = DocView)))]
pub(crate) async fn get(State(app): State<App>, Path(doc): Path<String>) -> ApiResult<DocView> {
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(view(&mut conn, &doc).await?))
}

/// Every field is optional; `system` set to `null` is cleared.
#[derive(Deserialize, ToSchema)]
pub struct DocPatch {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub system: Option<Option<String>>,
}

#[utoipa::path(patch, path = "/docs/{doc}", operation_id = "designPatchDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = DocPatch,
    responses((status = 200, description = "The changed design (audited as `design.doc.changed`); an archived design is refused", body = DocView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(doc): Path<String>,
    In(req): In<DocPatch>,
) -> ApiResult<DocView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let cur = view(&mut tx, &doc).await?;
    let name = req.name.unwrap_or(cur.name);
    let system = req.system.unwrap_or(cur.system);
    if !name_ok(&name) {
        return Err(bad());
    }
    check_system(&mut tx, &cur.kind, system.as_deref()).await?;
    if system.as_deref() == Some(doc.as_str()) {
        return Err(bad());
    }
    sqlx::query(
        "UPDATE design_docs SET name = ?, system = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(&name)
    .bind(&system)
    .bind(&doc)
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    record(&mut tx, "changed", &doc, None).await?;
    let out = view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// Set `ai_paused` and record it once (a repeat changes nothing). Take over / resume are human actions on the
/// design: never ops, so no AI session can resume itself (T12/T13); `designApply` (V1-04) reads the flag.
async fn set_paused(app: App, doc: String, paused: bool) -> ApiResult<DocView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let changed = sqlx::query(
        "UPDATE design_docs SET ai_paused = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE id = ? AND ai_paused != ?",
    )
    .bind(paused as i64)
    .bind(&doc)
    .bind(paused as i64)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        record(
            &mut tx,
            if paused { "taken_over" } else { "resumed" },
            &doc,
            None,
        )
        .await?;
    }
    let out = view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/docs/{doc}/take-over", operation_id = "designTakeOver", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "AI sessions are paused on this design: `designApply` answers `paused` until resume (audited as `design.doc.taken_over`); repeating changes nothing; an archived design is refused", body = DocView)))]
pub(crate) async fn take_over(
    State(app): State<App>,
    Path(doc): Path<String>,
) -> ApiResult<DocView> {
    set_paused(app, doc, true).await
}

#[utoipa::path(post, path = "/docs/{doc}/resume", operation_id = "designResume", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "AI sessions may write again (audited as `design.doc.resumed`); repeating changes nothing; an archived design is refused", body = DocView)))]
pub(crate) async fn resume(State(app): State<App>, Path(doc): Path<String>) -> ApiResult<DocView> {
    set_paused(app, doc, false).await
}

#[utoipa::path(post, path = "/docs/{doc}/archive", operation_id = "designArchiveDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "Archived, every row kept (step-up; audited as `design.doc.archived`); archiving twice changes nothing", body = DocView)))]
pub(crate) async fn archive(State(app): State<App>, Path(doc): Path<String>) -> ApiResult<DocView> {
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let mut tx = begin_write(&app.pool).await?;
    let cur = view(&mut tx, &doc).await?;
    if cur.state == "active" {
        sqlx::query(
            "UPDATE design_docs SET state = 'archived', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        )
        .bind(&doc)
        .execute(&mut *tx)
        .await?;
        record(&mut tx, "archived", &doc, None).await?;
    }
    let out = view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(put, path = "/docs/{doc}/projects/{project}", operation_id = "designLinkDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "Related to the project (audited as `design.doc.linked`); an unknown project is refused, linking twice changes nothing", body = DocView)))]
pub(crate) async fn link(
    State(app): State<App>,
    Path((doc, project)): Path<(String, String)>,
) -> ApiResult<DocView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let p = project_id(&mut tx, &project).await?;
    let added = sqlx::query(
        "INSERT OR IGNORE INTO design_links (item_kind, item, project) VALUES ('doc', ?, ?)",
    )
    .bind(&doc)
    .bind(&p)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if added > 0 {
        record(&mut tx, "linked", &doc, Some(&p)).await?;
    }
    let out = view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/docs/{doc}/projects/{project}", operation_id = "designUnlinkDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("project" = String, Path, description = "Project id")),
    responses((status = 200, description = "No longer related (audited as `design.doc.unlinked`); 404 when it was not", body = DocView)))]
pub(crate) async fn unlink(
    State(app): State<App>,
    Path((doc, project)): Path<(String, String)>,
) -> ApiResult<DocView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    // No Projects check here: a link to a project that is gone must still be removable.
    let gone = sqlx::query(
        "DELETE FROM design_links WHERE item_kind = 'doc' AND item = ? AND project = ?",
    )
    .bind(&doc)
    .bind(&project)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if gone == 0 {
        return Err(ApiError::not_found("no such link"));
    }
    record(&mut tx, "unlinked", &doc, Some(&project)).await?;
    let out = view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}
