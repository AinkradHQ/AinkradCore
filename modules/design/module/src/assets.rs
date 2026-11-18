//! The asset library (V4-01, T8). Security model: every upload is untrusted bytes. The Core never
//! parses a font, image or PDF; it sniffs the magic bytes against an allow-list (the client's own
//! content type is ignored), sanitises SVG to a static subset (`svg.rs`) or refuses it, caps the
//! size per asset and per library, and stores the bytes content-addressed (sha256 of what is
//! stored). Fonts and Icon Composer zips stay `pending` until the helper parses them in its sandbox.
//! Every refusal is a fixed sentence; audit and events carry ids (the sha256), never a name.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::docs::{In, project_id};
use crate::sniff::{Class, has_svg_marker, kinds, sniff};
use crate::{Design, svg};

pub(crate) const MAX_BODY: usize = 25 * 1024 * 1024;
const LIST_MAX: i64 = 500;
const SVG_MAX: usize = 2 * 1024 * 1024;
const MAX_TAGS: usize = 20;

fn bad() -> ApiError {
    ApiError::bad_request("the asset is not valid")
}

fn too_large(what: &'static str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", what)
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_type",
        "that file type is not allowed",
    )
}

pub(crate) fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn name_ok(s: &str) -> bool {
    (1..=200).contains(&s.chars().count()) && s == s.trim() && !s.chars().any(char::is_control)
}

fn tag_ok(s: &str) -> bool {
    (1..=32).contains(&s.chars().count()) && s == s.trim() && !s.chars().any(char::is_control)
}

/// Audit row and event for one library change; ids only. `family` is `asset` or `collection`.
pub(crate) async fn record(
    conn: &mut SqliteConnection,
    family: &str,
    op: &str,
    id: &str,
    project: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut d = json!({ family: id });
    let mut e = json!({"op": op, "id": id});
    if let Some(p) = project {
        d["project"] = json!(p);
        e["project"] = json!(p);
    }
    let row = NewAuditEvent {
        actor: BY,
        action: format!("design.{family}.{op}"),
        entity: None,
        details: d.to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, &format!("design.{family}"), &e).await?;
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct AssetView {
    /// sha256 of the stored bytes, lowercase hex.
    pub sha256: String,
    /// `image`, `icon`, `logo`, `icon_composer`, `font`, `pdf`, `mockup_file` or `shot`.
    pub kind: String,
    pub name: String,
    /// Decided by the Core from the bytes, never from the client.
    pub content_type: String,
    pub size: i64,
    /// `ok`, or `pending` (a font or Icon Composer zip the helper has not parsed yet) or `refused`.
    pub check_state: String,
    pub library: bool,
    pub tags: Vec<String>,
    /// Projects it is related to (ids as text), ascending.
    pub projects: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    /// Only on an upload: the same bytes were already stored, this is the existing row.
    pub duplicate: Option<bool>,
}

pub(crate) async fn view(conn: &mut SqliteConnection, sha: &str) -> Result<AssetView, ApiError> {
    let r = sqlx::query(
        "SELECT sha256, kind, name, content_type, size, check_state, library, created_by, created_at \
         FROM design_assets WHERE sha256 = ? AND kind <> 'mockup_file'",
    )
    .bind(sha)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| ApiError::not_found("no such asset"))?;
    let tags =
        sqlx::query_scalar("SELECT tag FROM design_asset_tags WHERE sha256 = ? ORDER BY tag")
            .bind(sha)
            .fetch_all(&mut *conn)
            .await?;
    let projects = sqlx::query_scalar(
        "SELECT project FROM design_links WHERE item_kind = 'asset' AND item = ? \
         ORDER BY CAST(project AS INTEGER)",
    )
    .bind(sha)
    .fetch_all(&mut *conn)
    .await?;
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(AssetView {
        sha256: text("sha256")?,
        kind: text("kind")?,
        name: text("name")?,
        content_type: text("content_type")?,
        size: r.try_get("size")?,
        check_state: text("check_state")?,
        library: r.try_get::<i64, _>("library")? == 1,
        tags,
        projects,
        created_by: text("created_by")?,
        created_at: text("created_at")?,
        duplicate: None,
    })
}

#[derive(Deserialize)]
pub(crate) struct UploadQuery {
    name: String,
    kind: Option<String>,
    project: Option<String>,
}

#[utoipa::path(post, path = "/assets", operation_id = "designUploadAsset", tag = "design",
    params(("name" = String, Query, description = "Display name, 1 to 200 characters"),
           ("kind" = Option<String>, Query, description = "`image` (default for rasters and SVG), `icon`, `logo`; others follow the file type"),
           ("project" = Option<String>, Query, description = "A project id to relate it to")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The raw file, at most 25 MB"),
    responses((status = 200, description = "The stored asset; the same bytes twice are the same row (`duplicate`). SVG is stored sanitised or refused (415); a file over the cap or a full library is 413", body = AssetView)))]
pub(crate) async fn upload(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    q: Result<Query<UploadQuery>, QueryRejection>,
    body: Bytes,
) -> ApiResult<AssetView> {
    let Query(q) = q.map_err(|_| bad())?;
    if !name_ok(&q.name) || body.is_empty() {
        return Err(bad());
    }
    let settings = ModuleSettings::of(&Design::default() as &dyn Module);
    let max = settings
        .get(&app.pool, "asset.max_bytes")
        .await
        .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
    if i64::try_from(body.len()).unwrap_or(i64::MAX) > max {
        return Err(too_large("the file is over the size limit"));
    }
    let (mime, class) = sniff(&body).ok_or_else(unsupported)?;
    // A raster, PDF, font or zip that is also an SVG (a polyglot) is refused: browsers sniff it.
    if class != Class::Svg && has_svg_marker(&body) {
        return Err(unsupported());
    }
    let data: Bytes = if class == Class::Svg {
        if body.len() > SVG_MAX {
            return Err(too_large("the file is over the size limit"));
        }
        Bytes::from(svg::sanitise(&body).map_err(|()| unsupported())?)
    } else {
        body
    };
    let kind = match q.kind.as_deref() {
        None => kinds(class)[0],
        Some(k) => *kinds(class).iter().find(|c| **c == k).ok_or_else(bad)?,
    };
    let check = if matches!(class, Class::Font | Class::Zip) {
        "pending"
    } else {
        "ok"
    };
    let sha: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let size = i64::try_from(data.len()).unwrap_or(i64::MAX);
    let mut tx = begin_write(&app.pool).await?;
    let project = match q.project.as_deref() {
        Some(p) => Some(project_id(&mut tx, p).await?),
        None => None,
    };
    // A mockup package file is never a library asset: same bytes as one is refused, not adopted.
    let existing: Option<(i64, String)> =
        sqlx::query_as("SELECT library, kind FROM design_assets WHERE sha256 = ?")
            .bind(&sha)
            .fetch_optional(&mut *tx)
            .await?;
    if existing.as_ref().is_some_and(|e| e.1 == "mockup_file") {
        return Err(ApiError::conflict("these bytes belong to a mockup package"));
    }
    let existing = existing.map(|e| e.0);
    let dup = existing.is_some();
    if let Some(lib) = existing {
        if lib == 0 {
            sqlx::query("UPDATE design_assets SET library = 1 WHERE sha256 = ?")
                .bind(&sha)
                .execute(&mut *tx)
                .await?;
        }
    } else {
        let cap = settings
            .get_in(&mut tx, "library.max_bytes")
            .await
            .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
        let held: i64 = sqlx::query_scalar("SELECT coalesce(sum(size), 0) FROM design_assets")
            .fetch_one(&mut *tx)
            .await?;
        if held.saturating_add(size) > cap {
            return Err(too_large("the library is full"));
        }
        sqlx::query(
            "INSERT INTO design_assets (sha256, kind, name, content_type, size, check_state, data, created_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&sha)
        .bind(kind)
        .bind(&q.name)
        .bind(mime)
        .bind(size)
        .bind(check)
        .bind(&data[..])
        .bind(format!("person:{}", me.device.id))
        .execute(&mut *tx)
        .await?;
        record(&mut tx, "asset", "created", &sha, None).await?;
    }
    if let Some(p) = &project {
        let added = sqlx::query(
            "INSERT OR IGNORE INTO design_links (item_kind, item, project) VALUES ('asset', ?, ?)",
        )
        .bind(&sha)
        .bind(p)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if added > 0 {
            record(&mut tx, "asset", "linked", &sha, Some(p)).await?;
        }
    }
    let mut out = view(&mut tx, &sha).await?;
    out.duplicate = Some(dup);
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    kind: Option<String>,
    tag: Option<String>,
    q: Option<String>,
    project: Option<String>,
    collection: Option<String>,
}

#[utoipa::path(get, path = "/assets", operation_id = "designListAssets", tag = "design",
    params(("kind" = Option<String>, Query, description = "Only this kind"),
           ("tag" = Option<String>, Query, description = "Only assets with this tag"),
           ("q" = Option<String>, Query, description = "Name contains this text"),
           ("project" = Option<String>, Query, description = "Only assets related to this project id"),
           ("collection" = Option<String>, Query, description = "Only members of this collection")),
    responses((status = 200, description = "Library assets, newest first (at most 500); internal assets (shots, mockup files) are not listed", body = Vec<AssetView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> ApiResult<Vec<AssetView>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    let like = q.q.as_deref().map(|s| {
        format!(
            "%{}%",
            s.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let mut conn = app.pool.acquire().await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT sha256 FROM design_assets a WHERE library = 1 AND kind <> 'mockup_file' \
           AND (?1 IS NULL OR kind = ?1) \
           AND (?2 IS NULL OR EXISTS (SELECT 1 FROM design_asset_tags t WHERE t.sha256 = a.sha256 AND t.tag = ?2)) \
           AND (?3 IS NULL OR name LIKE ?3 ESCAPE '\\') \
           AND (?4 IS NULL OR EXISTS (SELECT 1 FROM design_links l WHERE l.item_kind = 'asset' AND l.item = a.sha256 AND l.project = ?4)) \
           AND (?5 IS NULL OR EXISTS (SELECT 1 FROM design_collection_items c WHERE c.sha256 = a.sha256 AND c.collection = ?5)) \
         ORDER BY created_at DESC, sha256 LIMIT ?6",
    )
    .bind(q.kind)
    .bind(q.tag)
    .bind(like)
    .bind(q.project)
    .bind(q.collection)
    .bind(LIST_MAX)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(view(&mut conn, &id).await?);
    }
    Ok(Json(out))
}

pub(crate) fn none() -> ApiError {
    ApiError::not_found("no such asset")
}

#[utoipa::path(get, path = "/assets/{sha}", operation_id = "designGetAsset", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset")),
    responses((status = 200, description = "The asset's metadata", body = AssetView)))]
pub(crate) async fn get(State(app): State<App>, Path(sha): Path<String>) -> ApiResult<AssetView> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(view(&mut conn, &sha).await?))
}

#[utoipa::path(get, path = "/assets/{sha}/data", operation_id = "designGetAssetData", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset")),
    responses((status = 200, description = "The stored bytes with the Core-decided content type, `nosniff` and a sandboxing CSP; a font or zip the helper has not passed (`pending`) or has `refused` is 404", body = Vec<u8>, content_type = "application/octet-stream")))]
pub(crate) async fn data(
    State(app): State<App>,
    Path(sha): Path<String>,
) -> Result<Response, ApiError> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT content_type, data FROM design_assets WHERE sha256 = ? AND check_state = 'ok' AND kind <> 'mockup_file'",
    )
    .bind(&sha)
    .fetch_optional(&app.pool)
    .await?;
    let (ct, bytes) = row.ok_or_else(none)?;
    Ok((
        [
            (header::CONTENT_TYPE, ct),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; sandbox".to_owned(),
            ),
            (header::CONTENT_DISPOSITION, "attachment".to_owned()),
        ],
        bytes,
    )
        .into_response())
}

/// Every field is optional; `tags` replaces the whole set.
#[derive(Deserialize, ToSchema)]
pub struct AssetPatch {
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[utoipa::path(patch, path = "/assets/{sha}", operation_id = "designPatchAsset", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset")), request_body = AssetPatch,
    responses((status = 200, description = "The changed asset (audited as `design.asset.changed`); at most 20 tags of 1 to 32 characters", body = AssetView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(sha): Path<String>,
    In(req): In<AssetPatch>,
) -> ApiResult<AssetView> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    if req.name.as_deref().is_some_and(|n| !name_ok(n))
        || req
            .tags
            .as_ref()
            .is_some_and(|t| t.len() > MAX_TAGS || t.iter().any(|x| !tag_ok(x)))
    {
        return Err(bad());
    }
    let mut tx = begin_write(&app.pool).await?;
    view(&mut tx, &sha).await?;
    if let Some(n) = &req.name {
        sqlx::query("UPDATE design_assets SET name = ? WHERE sha256 = ?")
            .bind(n)
            .bind(&sha)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(tags) = &req.tags {
        sqlx::query("DELETE FROM design_asset_tags WHERE sha256 = ?")
            .bind(&sha)
            .execute(&mut *tx)
            .await?;
        for t in tags {
            sqlx::query("INSERT OR IGNORE INTO design_asset_tags (sha256, tag) VALUES (?, ?)")
                .bind(&sha)
                .bind(t)
                .execute(&mut *tx)
                .await?;
        }
    }
    record(&mut tx, "asset", "changed", &sha, None).await?;
    let out = view(&mut tx, &sha).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/assets/{sha}", operation_id = "designDeleteAsset", tag = "design",
    params(("sha" = String, Path, description = "sha256 of the asset")),
    responses((status = 200, description = "Deleted (step-up; audited as `design.asset.deleted`), with its tags, collection memberships and project links. 409 while a design, version, approval or mockup uses it", body = AssetView)))]
pub(crate) async fn delete(
    State(app): State<App>,
    Path(sha): Path<String>,
) -> ApiResult<AssetView> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    let out = view(&mut tx, &sha).await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM design_asset_refs WHERE sha256 = ?")
        .bind(&sha)
        .fetch_one(&mut *tx)
        .await?;
    // A brand kit naming the font keeps it too (its `fonts` list holds the sha, not a foreign key).
    let named: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM design_collections c, json_each(c.fonts) f WHERE f.value = ?",
    )
    .bind(&sha)
    .fetch_one(&mut *tx)
    .await?;
    if used > 0 || named > 0 {
        return Err(ApiError::conflict("the asset is in use"));
    }
    sqlx::query("DELETE FROM design_links WHERE item_kind = 'asset' AND item = ?")
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM design_assets WHERE sha256 = ?")
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
    record(&mut tx, "asset", "deleted", &sha, None).await?;
    tx.commit().await?;
    Ok(Json(out))
}
