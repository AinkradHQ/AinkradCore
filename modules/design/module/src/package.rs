//! HTML mockup packages (V4-02, T10). SECURITY MODEL: a package is a folder of UNTRUSTED HTML, CSS and JS
//! that its author wants to click through. The Core never renders, parses or executes any of it. It
//! (1) validates every path (no `..`, no absolute path, no NUL or control character, no backslash, no
//! hidden name, no symlink on the importing side), (2) caps the package at 200 files and 100 MiB and
//! each file at the asset cap, (3) stores the bytes through the V4-01 asset store (content-addressed,
//! library cap, magic-byte sniff for rasters, polyglot refusal, SVG allow-list sanitiser), and (4)
//! serves a file ONLY as an inert attachment (`application/octet-stream`, `Content-Disposition:
//! attachment`, `nosniff`, `Content-Security-Policy: sandbox`), never with an HTML type, so no browser
//! renders it from the Core origin. Rendering happens in the App's sandboxed WKWebView (V3-07): no
//! network, no script bridge, served from the package only. The file types are a fixed list, fonts and
//! zips are not accepted. Every refusal is a fixed sentence; audit and events carry ids only.

use std::path::Path as FsPath;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::Design;
use crate::docs::{doc_id_ok, editable, record};
use crate::sniff::{Class, has_svg_marker, sniff};
use crate::svg;

pub(crate) const MAX_FILES: i64 = 200;
pub(crate) const MAX_BYTES: i64 = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 8;

fn bad() -> ApiError {
    ApiError::bad_request("the file path is not valid")
}

fn too_large(what: &'static str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", what)
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_type",
        "that file type is not allowed in a package",
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Svg,
    Raster(&'static str),
}

/// The fixed list of package file types: extension, the type the listing reports, how it is checked.
fn kind_of(ext: &str) -> Option<(&'static str, Kind)> {
    Some(match ext {
        "html" => ("text/html", Kind::Text),
        "css" => ("text/css", Kind::Text),
        "js" => ("text/javascript", Kind::Text),
        "json" => ("application/json", Kind::Text),
        "svg" => ("image/svg+xml", Kind::Svg),
        "png" => ("image/png", Kind::Raster("image/png")),
        "jpg" | "jpeg" => ("image/jpeg", Kind::Raster("image/jpeg")),
        "webp" => ("image/webp", Kind::Raster("image/webp")),
        "gif" => ("image/gif", Kind::Raster("image/gif")),
        _ => return None,
    })
}

fn ext_of(path: &str) -> Option<String> {
    let name = path.rsplit('/').next()?;
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
}

/// A relative package path: segments of `[A-Za-z0-9._@+~-]`, none empty, none starting with a dot (so
/// no `.` or `..` and no hidden file), at most 8 deep and 200 long. A leading `/`, a drive letter,
/// a backslash, `%`, NUL and every control character fall outside the alphabet.
pub(crate) fn valid_path(p: &str) -> bool {
    let segs: Vec<&str> = p.split('/').collect();
    p.len() <= 200
        && segs.len() <= MAX_DEPTH
        && segs.iter().all(|s| {
            (1..=80).contains(&s.len())
                && !s.starts_with('.')
                && !s.ends_with('.')
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._@+~-".contains(&c))
        })
        && ext_of(p).is_some()
}

#[derive(Serialize, ToSchema)]
pub struct FileView {
    pub path: String,
    pub sha256: String,
    pub size: i64,
    /// The type the Core decided from the extension and checked against the bytes. The file is
    /// still served as an attachment; the App picks the MIME it loads it with from this.
    pub content_type: String,
}

fn file_view(path: String, sha256: String, size: i64) -> FileView {
    let content_type = ext_of(&path)
        .and_then(|e| kind_of(&e))
        .map_or("application/octet-stream", |k| k.0)
        .to_owned();
    FileView {
        path,
        sha256,
        size,
        content_type,
    }
}

/// Stores one file of a draft package. Everything a person's upload and the one-off import share.
pub(crate) async fn put_file(
    conn: &mut SqliteConnection,
    doc: &str,
    path: &str,
    body: &[u8],
    by: &str,
) -> Result<FileView, ApiError> {
    if !valid_path(path) {
        return Err(bad());
    }
    editable(conn, doc).await?;
    let (kind, manifest): (String, Option<String>) =
        sqlx::query_as("SELECT kind, manifest FROM design_docs WHERE id = ?")
            .bind(doc)
            .fetch_one(&mut *conn)
            .await?;
    if kind != "mockup" {
        return Err(ApiError::bad_request("the design is not a mockup"));
    }
    if manifest.is_some() {
        return Err(ApiError::conflict("the package is sealed"));
    }
    if body.is_empty() {
        return Err(bad());
    }
    let settings = ModuleSettings::of(&Design);
    let max = settings
        .get_in(conn, "asset.max_bytes")
        .await
        .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    if size > max {
        return Err(too_large("the file is over the size limit"));
    }
    let (mime, k) = ext_of(path)
        .and_then(|e| kind_of(&e))
        .ok_or_else(unsupported)?;
    let data: Vec<u8> = match k {
        Kind::Text => {
            if body.contains(&0) || std::str::from_utf8(body).is_err() {
                return Err(unsupported());
            }
            body.to_vec()
        }
        Kind::Svg => {
            if body.len() > 2 * 1024 * 1024 {
                return Err(too_large("the file is over the size limit"));
            }
            svg::sanitise(body).map_err(|()| unsupported())?
        }
        Kind::Raster(want) => match sniff(body) {
            Some((m, Class::Image)) if m == want && !has_svg_marker(body) => body.to_vec(),
            _ => return Err(unsupported()),
        },
    };
    let size = i64::try_from(data.len()).unwrap_or(i64::MAX);
    let sha: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let (files, held): (i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(size), 0) FROM design_mockup_files WHERE doc = ? AND path <> ?",
    )
    .bind(doc)
    .bind(path)
    .fetch_one(&mut *conn)
    .await?;
    if files + 1 > MAX_FILES {
        return Err(too_large("the package has too many files"));
    }
    if held.saturating_add(size) > MAX_BYTES {
        return Err(too_large("the package is over the size limit"));
    }
    let known: Option<i64> = sqlx::query_scalar("SELECT 1 FROM design_assets WHERE sha256 = ?")
        .bind(&sha)
        .fetch_optional(&mut *conn)
        .await?;
    if known.is_none() {
        let cap = settings
            .get_in(conn, "library.max_bytes")
            .await
            .map_err(|_| ApiError::from(sqlx::Error::PoolClosed))?;
        let total: i64 = sqlx::query_scalar("SELECT coalesce(sum(size), 0) FROM design_assets")
            .fetch_one(&mut *conn)
            .await?;
        if total.saturating_add(size) > cap {
            return Err(too_large("the library is full"));
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        sqlx::query(
            "INSERT INTO design_assets (sha256, kind, name, content_type, size, check_state, data, library, created_by) \
             VALUES (?, 'mockup_file', ?, ?, ?, 'ok', ?, 0, ?)",
        )
        .bind(&sha)
        .bind(name)
        .bind(mime)
        .bind(size)
        .bind(&data[..])
        .bind(by)
        .execute(&mut *conn)
        .await?;
    }
    let old: Option<String> =
        sqlx::query_scalar("SELECT sha256 FROM design_mockup_files WHERE doc = ? AND path = ?")
            .bind(doc)
            .bind(path)
            .fetch_optional(&mut *conn)
            .await?;
    sqlx::query("DELETE FROM design_mockup_files WHERE doc = ? AND path = ?")
        .bind(doc)
        .bind(path)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO design_mockup_files (doc, path, sha256, size) VALUES (?, ?, ?, ?)")
        .bind(doc)
        .bind(path)
        .bind(&sha)
        .bind(size)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO design_asset_refs (sha256, owner_kind, owner) VALUES (?, 'mockup', ?)",
    )
    .bind(&sha)
    .bind(doc)
    .execute(&mut *conn)
    .await?;
    if let Some(o) = old.filter(|o| *o != sha) {
        // The replaced bytes stay referenced only while another file of this package still uses them.
        sqlx::query(
            "DELETE FROM design_asset_refs WHERE sha256 = ?1 AND owner_kind = 'mockup' AND owner = ?2 \
             AND NOT EXISTS (SELECT 1 FROM design_mockup_files WHERE doc = ?2 AND sha256 = ?1)",
        )
        .bind(&o)
        .bind(doc)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(
        "UPDATE design_docs SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(doc)
    .execute(&mut *conn)
    .await?;
    Ok(file_view(path.to_owned(), sha, size))
}

/// Drafts the manifest from the package's `*.html` (root `index.html` first, then by path), stores
/// it and seals the package. `states` start empty: a reviewer adds hash params later.
async fn seal_in(conn: &mut SqliteConnection, doc: &str) -> Result<Value, ApiError> {
    editable(conn, doc).await?;
    let (kind, manifest): (String, Option<String>) =
        sqlx::query_as("SELECT kind, manifest FROM design_docs WHERE id = ?")
            .bind(doc)
            .fetch_one(&mut *conn)
            .await?;
    if kind != "mockup" {
        return Err(ApiError::bad_request("the design is not a mockup"));
    }
    if manifest.is_some() {
        return Err(ApiError::conflict("the package is sealed"));
    }
    let pages: Vec<String> = sqlx::query_scalar(
        "SELECT path FROM design_mockup_files WHERE doc = ? AND lower(path) LIKE '%.html' \
         ORDER BY (lower(path) <> 'index.html'), path",
    )
    .bind(doc)
    .fetch_all(&mut *conn)
    .await?;
    if pages.is_empty() {
        return Err(ApiError::bad_request("the package has no HTML page"));
    }
    let screens: Vec<Value> = pages
        .iter()
        .map(|p| {
            let name = p
                .strip_suffix(".html")
                .or_else(|| p.strip_suffix(".HTML"))
                .unwrap_or(p);
            json!({"name": name, "path": p, "states": []})
        })
        .collect();
    for p in &pages {
        sqlx::query("INSERT OR IGNORE INTO design_screens (doc, screen) VALUES (?, ?)")
            .bind(doc)
            .bind(p)
            .execute(&mut *conn)
            .await?;
    }
    let m = json!({"screens": screens});
    sqlx::query(
        "UPDATE design_docs SET manifest = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(m.to_string())
    .bind(doc)
    .execute(&mut *conn)
    .await?;
    record(conn, "changed", doc, None).await?;
    Ok(m)
}

#[derive(Deserialize)]
pub(crate) struct PathQuery {
    path: String,
}

fn none() -> ApiError {
    ApiError::not_found("no such file")
}

#[utoipa::path(put, path = "/docs/{doc}/package/files", operation_id = "designPutMockupFile", tag = "design",
    params(("doc" = String, Path, description = "A `mockup` design id"), ("path" = String, Query, description = "Relative path in the package")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The raw file, at most 25 MB"),
    responses((status = 200, description = "The stored file. The path must be relative (no `..`, no absolute path, NUL or control character, no hidden name), 400 otherwise; a type outside html, css, js, json, svg (sanitised), png, jpeg, webp, gif or bytes that do not match it is 415; more than 200 files or 100 MiB in the package is 413. Putting a path again replaces it; a sealed package is 409", body = FileView)))]
pub(crate) async fn put(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(doc): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
    body: Bytes,
) -> ApiResult<FileView> {
    let Query(q) = q.map_err(|_| bad())?;
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let mut tx = begin_write(&app.pool).await?;
    let out = put_file(
        &mut tx,
        &doc,
        &q.path,
        &body,
        &format!("person:{}", me.device.id),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/docs/{doc}/package/manifest", operation_id = "designSealMockup", tag = "design",
    params(("doc" = String, Path, description = "A `mockup` design id")),
    responses((status = 200, description = "Drafts the manifest from the package's HTML pages, stores it and seals the package (audited as `design.doc.changed`); a package with no HTML page is 400, a sealed one 409", body = PackageView)))]
pub(crate) async fn seal(
    State(app): State<App>,
    Path(doc): Path<String>,
) -> ApiResult<PackageView> {
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let mut tx = begin_write(&app.pool).await?;
    seal_in(&mut tx, &doc).await?;
    let out = package_view(&mut tx, &doc).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct PackageView {
    pub doc: String,
    /// True once the manifest is drafted; a sealed package takes no more files.
    pub sealed: bool,
    /// `{"screens": [{"name", "path", "states": []}]}`, null while a draft.
    pub manifest: Option<Value>,
    pub files: Vec<FileView>,
    pub bytes: i64,
}

async fn package_view(conn: &mut SqliteConnection, doc: &str) -> Result<PackageView, ApiError> {
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT kind, manifest FROM design_docs WHERE id = ?")
            .bind(doc)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((_, manifest)) = row.filter(|r| r.0 == "mockup") else {
        return Err(ApiError::not_found("no such design"));
    };
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT path, sha256, size FROM design_mockup_files WHERE doc = ? ORDER BY path",
    )
    .bind(doc)
    .fetch_all(&mut *conn)
    .await?;
    let bytes = rows.iter().map(|r| r.2).sum();
    let manifest = manifest.and_then(|m| serde_json::from_str(&m).ok());
    Ok(PackageView {
        doc: doc.to_owned(),
        sealed: manifest.is_some(),
        manifest,
        files: rows.into_iter().map(|r| file_view(r.0, r.1, r.2)).collect(),
        bytes,
    })
}

#[utoipa::path(get, path = "/docs/{doc}/package", operation_id = "designGetMockupPackage", tag = "design",
    params(("doc" = String, Path, description = "A `mockup` design id")),
    responses((status = 200, description = "The package: manifest (null while a draft) and its files", body = PackageView)))]
pub(crate) async fn get(State(app): State<App>, Path(doc): Path<String>) -> ApiResult<PackageView> {
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(package_view(&mut conn, &doc).await?))
}

#[utoipa::path(get, path = "/docs/{doc}/package/files", operation_id = "designGetMockupFile", tag = "design",
    params(("doc" = String, Path, description = "A `mockup` design id"), ("path" = String, Query, description = "Relative path in the package")),
    responses((status = 200, description = "The bytes as an inert attachment only: `application/octet-stream`, `Content-Disposition: attachment`, `nosniff` and a sandboxing CSP, whatever the file is. Never rendered from the Core origin", body = Vec<u8>, content_type = "application/octet-stream")))]
pub(crate) async fn file(
    State(app): State<App>,
    Path(doc): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(q) = q.map_err(|_| none())?;
    if !doc_id_ok(&doc) || !valid_path(&q.path) {
        return Err(none());
    }
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT a.data FROM design_mockup_files f JOIN design_assets a ON a.sha256 = f.sha256 \
         WHERE f.doc = ? AND f.path = ? AND a.check_state = 'ok'",
    )
    .bind(&doc)
    .bind(&q.path)
    .fetch_optional(&app.pool)
    .await?;
    let bytes = bytes.ok_or_else(none)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox",
            ),
            (header::CONTENT_DISPOSITION, "attachment"),
            (
                header::HeaderName::from_static("cross-origin-resource-policy"),
                "same-origin",
            ),
        ],
        bytes,
    )
        .into_response())
}

/// Files under `dir` that a package takes, `(relative path, absolute path)`. A symlink anywhere in the
/// walked tree refuses the whole folder; directories whose name starts with a `skip` word are not
/// entered; hidden files and extensions outside the fixed list are left out.
fn walk(dir: &FsPath, skip: &[String]) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    fn rec(
        root: &FsPath,
        dir: &FsPath,
        skip: &[String],
        out: &mut Vec<(String, std::path::PathBuf)>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let meta =
                std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!("{}: a symlink is not allowed", p.display()));
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                if !skip.iter().any(|s| name.starts_with(s.as_str())) {
                    rec(root, &p, skip, out)?;
                }
            } else if meta.is_file()
                && !name.starts_with('.')
                && ext_of(&name).is_some_and(|x| kind_of(&x).is_some())
            {
                let rel = p.strip_prefix(root).map_err(|e| e.to_string())?;
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| format!("{}: the path is not UTF-8", p.display()))?
                    .join("/");
                out.push((rel, p));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    rec(dir, dir, skip, &mut out)?;
    Ok(out)
}

/// The one-off import (V4-02): one folder becomes one sealed `mockup` doc named `name`, in one
/// transaction (nothing is kept if any file is refused). Runs beside the Core's database, with the
/// same checks as an upload. Returns the doc id and the number of files taken.
pub async fn import_dir(
    pool: &sqlx::SqlitePool,
    dir: &FsPath,
    name: &str,
    skip: &[String],
) -> Result<(String, usize), String> {
    let files = walk(dir, skip)?;
    let by = "person:import";
    let mut tx = begin_write(pool).await.map_err(|e| e.to_string())?;
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let doc = format!(
        "dd_{}",
        id.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );
    let err = |e: ApiError| format!("{}: {}", e.status, e.message);
    sqlx::query("INSERT INTO design_docs (id, kind, name, created_by) VALUES (?, 'mockup', ?, ?)")
        .bind(&doc)
        .bind(name)
        .bind(by)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    record(&mut tx, "created", &doc, None)
        .await
        .map_err(|e| e.to_string())?;
    for (rel, abs) in &files {
        let bytes = std::fs::read(abs).map_err(|e| format!("{}: {e}", abs.display()))?;
        put_file(&mut tx, &doc, rel, &bytes, by)
            .await
            .map_err(|e| format!("{rel}: {}", err(e)))?;
    }
    seal_in(&mut tx, &doc).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok((doc, files.len()))
}
