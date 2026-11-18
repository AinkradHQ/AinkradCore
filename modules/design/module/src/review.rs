//! Comments, approvals and take-over (V1-04). The review stories (V6-02) build on these rows.
//!
//! SECURITY MODEL
//! - Every route here is a person's: device-signed, module scope. Approve, withdraw, take over and resume are NEVER
//!   Code Mode ops (T12): nothing in `api/ai-ops.allow.json` may name them.
//! - Approve freezes the document as it is at that moment into an `approval` version (a trigger keeps it unchanged and
//!   undeletable), then points the screen's row at it. Re-approving makes a new version; the old one stays.
//! - A comment body is hostile text: length-capped by the table, never echoed in audit or events (ids only), and a
//!   reader that shows it to an AI must wrap it as outside data (V7-01).
//! - Take over sets `ai_paused`; `Actor::edit` reads it under the document lock, so no AI batch slips past it.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use design_model::ids::is_node_id;
use design_model::limits::MAX_COORD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::ToSchema;

use crate::apply::{edit_err, open_actor, person};
use crate::docs::{In, doc_id_ok, editable, record};
use crate::sync::Registry;
use crate::versions::{note, rand_id, store_version};

const LIST_MAX: i64 = 1000;

fn none() -> ApiError {
    ApiError::not_found("no such design")
}

// ---- comments

#[derive(Serialize, ToSchema)]
pub struct CommentView {
    /// `dc_` and 16 hex characters.
    pub id: String,
    pub screen: String,
    pub node: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    /// The reply's parent comment.
    pub parent: Option<String>,
    pub body: String,
    pub author: String,
    pub resolved_at: Option<String>,
    pub created_at: String,
}

fn comment(r: &sqlx::sqlite::SqliteRow) -> Result<CommentView, sqlx::Error> {
    Ok(CommentView {
        id: r.try_get("id")?,
        screen: r.try_get("screen")?,
        node: r.try_get("node")?,
        x: r.try_get("x")?,
        y: r.try_get("y")?,
        parent: r.try_get("parent")?,
        body: r.try_get("body")?,
        author: r.try_get("author")?,
        resolved_at: r.try_get("resolved_at")?,
        created_at: r.try_get("created_at")?,
    })
}

#[derive(Deserialize)]
pub(crate) struct CommentQuery {
    screen: Option<String>,
    /// `open` (default), `resolved` or `all`.
    state: Option<String>,
}

#[utoipa::path(get, path = "/docs/{doc}/comments", operation_id = "designListComments", tag = "design",
    params(("doc" = String, Path, description = "Design id"),
           ("screen" = Option<String>, Query, description = "Only this screen"),
           ("state" = Option<String>, Query, description = "`open` (default), `resolved` or `all`")),
    responses((status = 200, description = "Comments oldest first (at most 1000)", body = Vec<CommentView>)))]
pub(crate) async fn comments(
    State(app): State<App>,
    Path(doc): Path<String>,
    q: Result<Query<CommentQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Vec<CommentView>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let state = q.state.as_deref().unwrap_or("open");
    if !doc_id_ok(&doc) || !["open", "resolved", "all"].contains(&state) {
        return Err(ApiError::bad_request("the query is not valid"));
    }
    let rows = sqlx::query(
        "SELECT * FROM design_comments WHERE doc = ?1 AND (?2 IS NULL OR screen = ?2) \
         AND (?3 = 'all' OR (?3 = 'open') = (resolved_at IS NULL)) ORDER BY rowid LIMIT ?4",
    )
    .bind(&doc)
    .bind(q.screen)
    .bind(state)
    .bind(LIST_MAX)
    .fetch_all(&app.pool)
    .await?;
    let out = rows.iter().map(comment).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewComment {
    /// The screen (a top-level frame id).
    pub screen: String,
    pub node: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    /// Reply to this comment (of the same design).
    pub parent: Option<String>,
    /// 1 to 4000 characters.
    pub body: String,
}

#[utoipa::path(post, path = "/docs/{doc}/comments", operation_id = "designCreateComment", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = NewComment,
    responses((status = 200, description = "The comment (audited as `design.comment.created`, ids only)", body = CommentView)))]
pub(crate) async fn add_comment(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(doc): Path<String>,
    In(req): In<NewComment>,
) -> ApiResult<CommentView> {
    let bad = || ApiError::bad_request("the comment is not valid");
    let body_ok = (1..=4000).contains(&req.body.chars().count());
    let pos_ok = [req.x, req.y]
        .iter()
        .flatten()
        .all(|v| v.is_finite() && v.abs() <= MAX_COORD)
        && req.x.is_some() == req.y.is_some();
    if !body_ok
        || !pos_ok
        || !is_node_id(&req.screen)
        || req.node.as_deref().is_some_and(|n| !is_node_id(n))
    {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    if let Some(p) = &req.parent {
        let ok: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM design_comments WHERE id = ? AND doc = ?")
                .bind(p)
                .bind(&doc)
                .fetch_optional(&mut *tx)
                .await?;
        if ok.is_none() {
            return Err(bad());
        }
    }
    let id = rand_id("dc");
    sqlx::query(
        "INSERT INTO design_comments (id, doc, screen, node, x, y, parent, body, author) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&doc)
    .bind(&req.screen)
    .bind(&req.node)
    .bind(req.x)
    .bind(req.y)
    .bind(&req.parent)
    .bind(&req.body)
    .bind(person(&me))
    .execute(&mut *tx)
    .await?;
    note(
        &mut tx,
        "design.comment",
        "created",
        json!({"doc": doc, "comment": id, "screen": req.screen}),
    )
    .await?;
    let row = sqlx::query("SELECT * FROM design_comments WHERE id = ?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    let out = comment(&row)?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Resolve {
    pub resolved: bool,
}

#[utoipa::path(put, path = "/docs/{doc}/comments/{comment}/resolved", operation_id = "designResolveComment", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("comment" = String, Path, description = "Comment id")),
    request_body = Resolve,
    responses((status = 200, description = "Resolved or reopened (audited as `design.comment.resolved` / `reopened`); the same again changes nothing", body = CommentView)))]
pub(crate) async fn resolve(
    State(app): State<App>,
    Path((doc, id)): Path<(String, String)>,
    In(req): In<Resolve>,
) -> ApiResult<CommentView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let changed = sqlx::query(
        "UPDATE design_comments SET resolved_at = CASE WHEN ?1 THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END \
         WHERE id = ?2 AND doc = ?3 AND (resolved_at IS NULL) = ?1",
    )
    .bind(req.resolved)
    .bind(&id)
    .bind(&doc)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        let op = if req.resolved { "resolved" } else { "reopened" };
        note(
            &mut tx,
            "design.comment",
            op,
            json!({"doc": doc, "comment": id}),
        )
        .await?;
    }
    let row = sqlx::query("SELECT * FROM design_comments WHERE id = ? AND doc = ?")
        .bind(&id)
        .bind(&doc)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::not_found("no such comment"))?;
    let out = comment(&row)?;
    tx.commit().await?;
    Ok(Json(out))
}

// ---- approvals

#[derive(Serialize, ToSchema)]
pub struct ApprovalView {
    pub screen: String,
    /// The frozen `approval` version.
    pub version: String,
    /// `approved`, `changed` or `withdrawn`.
    pub state: String,
    pub decided_by: String,
    pub decided_at: String,
}

fn approval(r: &sqlx::sqlite::SqliteRow) -> Result<ApprovalView, sqlx::Error> {
    Ok(ApprovalView {
        screen: r.try_get("screen")?,
        version: r.try_get("version")?,
        state: r.try_get("state")?,
        decided_by: r.try_get("decided_by")?,
        decided_at: r.try_get("decided_at")?,
    })
}

#[utoipa::path(get, path = "/docs/{doc}/approvals", operation_id = "designListApprovals", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "One row per screen that was ever approved, by screen id", body = Vec<ApprovalView>)))]
pub(crate) async fn approvals(
    State(app): State<App>,
    Path(doc): Path<String>,
) -> ApiResult<Vec<ApprovalView>> {
    if !doc_id_ok(&doc) {
        return Err(none());
    }
    let rows = sqlx::query("SELECT * FROM design_approvals WHERE doc = ? ORDER BY screen")
        .bind(&doc)
        .fetch_all(&app.pool)
        .await?;
    let out = rows.iter().map(approval).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(out))
}

#[utoipa::path(put, path = "/docs/{doc}/screens/{screen}/approval", operation_id = "designApproveScreen", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("screen" = String, Path, description = "Screen (top-level frame) id")),
    responses((status = 200, description = "The document as it is now is frozen as an `approval` version and the screen points at it (audited as `design.approval.approved`); approving again freezes a new one. A person's act, never an AI op", body = ApprovalView),
        (status = 422, description = "The screen is not a frame or page of the document")))]
pub(crate) async fn approve(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path((doc, screen)): Path<(String, String)>,
) -> ApiResult<ApprovalView> {
    let lease = open_actor(&app, &reg, &me, &doc).await?;
    let (model, state) = lease.actor.view().await.map_err(edit_err)?;
    if !is_node_id(&screen) || !model.nodes.contains_key(&screen) {
        return Err(ApiError::new(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "no_such_screen",
            "no such screen in the design",
        ));
    }
    let who = person(&me);
    let mut tx = begin_write(&app.pool).await?;
    let version = store_version(&mut tx, &doc, "approval", None, &state, &who).await?;
    sqlx::query("INSERT OR IGNORE INTO design_screens (doc, screen) VALUES (?, ?)")
        .bind(&doc)
        .bind(&screen)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO design_approvals (doc, screen, version, state, decided_by) VALUES (?1, ?2, ?3, 'approved', ?4) \
         ON CONFLICT (doc, screen) DO UPDATE SET version = ?3, state = 'approved', baseline = '{}', fidelity = NULL, \
         decided_by = ?4, decided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
    )
    .bind(&doc)
    .bind(&screen)
    .bind(&version)
    .bind(&who)
    .execute(&mut *tx)
    .await?;
    note(
        &mut tx,
        "design.approval",
        "approved",
        json!({"doc": doc, "screen": screen, "version": version}),
    )
    .await?;
    let row = sqlx::query("SELECT * FROM design_approvals WHERE doc = ? AND screen = ?")
        .bind(&doc)
        .bind(&screen)
        .fetch_one(&mut *tx)
        .await?;
    let out = approval(&row)?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/docs/{doc}/screens/{screen}/approval", operation_id = "designWithdrawApproval", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("screen" = String, Path, description = "Screen id")),
    responses((status = 200, description = "The approval is withdrawn; the frozen version is kept (audited as `design.approval.withdrawn`)", body = ApprovalView),
        (status = 404, description = "The screen is not approved")))]
pub(crate) async fn withdraw(
    State(app): State<App>,
    Path((doc, screen)): Path<(String, String)>,
) -> ApiResult<ApprovalView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let moved = sqlx::query(
        "UPDATE design_approvals SET state = 'withdrawn', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE doc = ? AND screen = ? AND state <> 'withdrawn'",
    )
    .bind(&doc)
    .bind(&screen)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if moved == 0 {
        return Err(ApiError::not_found("the screen is not approved"));
    }
    note(
        &mut tx,
        "design.approval",
        "withdrawn",
        json!({"doc": doc, "screen": screen}),
    )
    .await?;
    let row = sqlx::query("SELECT * FROM design_approvals WHERE doc = ? AND screen = ?")
        .bind(&doc)
        .bind(&screen)
        .fetch_one(&mut *tx)
        .await?;
    let out = approval(&row)?;
    tx.commit().await?;
    Ok(Json(out))
}

// ---- take over / resume

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Paused {
    /// `true` = take over (the AI's `designApply` answers `paused`); `false` = resume.
    pub paused: bool,
}

#[utoipa::path(put, path = "/docs/{doc}/ai-paused", operation_id = "designSetAiPaused", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = Paused,
    responses((status = 200, description = "Take over / resume (audited as `design.doc.changed`); a person's act, never an AI op", body = crate::docs::DocView)))]
pub(crate) async fn ai_paused(
    State(app): State<App>,
    Path(doc): Path<String>,
    In(req): In<Paused>,
) -> ApiResult<crate::docs::DocView> {
    let mut tx = begin_write(&app.pool).await?;
    editable(&mut tx, &doc).await?;
    let changed = sqlx::query(
        "UPDATE design_docs SET ai_paused = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE id = ?2 AND ai_paused <> ?1",
    )
    .bind(i64::from(req.paused))
    .bind(&doc)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed > 0 {
        record(&mut tx, "changed", &doc, None).await?;
    }
    let out = crate::docs::view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}
