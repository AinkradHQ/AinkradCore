//! Lore attachments (R1-05, T8). Security model: an upload is untrusted bytes. The Core never parses an
//! image or PDF: it sniffs the magic bytes against a closed allow-list (png, jpeg, gif, webp, heic, pdf;
//! the client's content type and file name are ignored and never stored, and SVG is not allowed at all),
//! refuses a polyglot (a file with `<svg` in its first 4 KiB), caps a file at 10 MB and the store at 2 GB,
//! and stores it content-addressed by the sha256 of the stored bytes. The body ceiling and the
//! process-wide upload byte budget come from the platform gate (`Module::body_limits`), so a refusal
//! before the device is checked leaks nothing. Bytes are served only by sha, with the Core-decided type,
//! `nosniff`, `attachment` and a sandboxing CSP; the app opens them in its own viewer, never `open`.
//! A note references one as `lore-attachment:<64 hex>` in its text; there is no link table, the sweep
//! counts references from note and version text, and deletes an unreferenced one only after a grace day
//! (an upload precedes the save that mentions it). A refusal is a fixed sentence; audit carries the sha.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{SqliteConnection, SqlitePool};
use std::collections::{BTreeSet, HashSet};
use utoipa::ToSchema;

/// One file; also the route's body ceiling at the gate.
pub(crate) const MAX_FILE: usize = 10 * 1024 * 1024;
/// A little over the file cap, for the gate and the extractor: the handler gives the exact 413.
pub(crate) const BODY_MAX: usize = MAX_FILE + 4096;
/// All attachments together (a constant, T8).
const MAX_TOTAL: i64 = 2 * 1024 * 1024 * 1024;
/// An unreferenced attachment younger than this survives the sweep.
const GRACE_DAYS: i64 = 1;

#[derive(Serialize, ToSchema)]
pub struct AttachmentView {
    /// sha256 of the stored bytes, lowercase hex: write it into the note as `lore-attachment:<sha256>`.
    pub sha256: String,
    /// Decided by the Core from the bytes.
    pub content_type: String,
    pub size: i64,
    /// The same bytes were already stored; this is the existing row.
    pub duplicate: bool,
}

fn none() -> ApiError {
    ApiError::not_found("no such attachment")
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_type",
        "that file type is not allowed",
    )
}

fn too_large(what: &'static str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", what)
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// The type of `b` by its magic bytes; `None` is refused.
fn sniff(b: &[u8]) -> Option<&'static str> {
    let t = |p: &[u8]| b.starts_with(p);
    let mime = if t(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if t(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if t(b"GIF87a") || t(b"GIF89a") {
        "image/gif"
    } else if b.len() > 12 && t(b"RIFF") && &b[8..12] == b"WEBP" {
        "image/webp"
    } else if b.len() > 12
        && &b[4..8] == b"ftyp"
        && [&b"heic"[..], b"heix", b"heim", b"heis", b"mif1", b"msf1"].contains(&&b[8..12])
    {
        "image/heic"
    } else if t(b"%PDF-") {
        "application/pdf"
    } else {
        return None;
    };
    // A polyglot is refused: a browser may sniff it as SVG.
    if String::from_utf8_lossy(&b[..b.len().min(4096)]).contains("<svg") {
        return None;
    }
    Some(mime)
}

#[utoipa::path(post, path = "/attachments", operation_id = "loreUploadAttachment", tag = "lore",
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The raw file, at most 10 MB: png, jpeg, gif, webp, heic or pdf"),
    responses((status = 200, description = "The stored attachment; the same bytes twice are the same row (`duplicate`). A type outside the allow-list (SVG included, whatever the name) is 415; over 10 MB or a full store is 413", body = AttachmentView)))]
pub(crate) async fn upload(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AttachmentView> {
    if body.is_empty() {
        return Err(ApiError::bad_request("the attachment is not valid"));
    }
    if body.len() > MAX_FILE {
        return Err(too_large("the file is over the size limit"));
    }
    let mime = sniff(&body).ok_or_else(unsupported)?;
    let sha: String = Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let mut tx = begin_write(&app.pool).await?;
    let dup =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lore_attachments WHERE sha256 = ?")
            .bind(&sha)
            .fetch_one(&mut *tx)
            .await?
            > 0;
    if dup {
        // A re-upload makes the file young again, so a sweep between this and the save that names it spares it.
        sqlx::query(
            "UPDATE lore_attachments SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE sha256 = ?",
        )
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
    } else {
        let held: i64 = sqlx::query_scalar("SELECT coalesce(sum(size), 0) FROM lore_attachments")
            .fetch_one(&mut *tx)
            .await?;
        if held.saturating_add(size) > MAX_TOTAL {
            return Err(too_large("the attachment store is full"));
        }
        sqlx::query(
            "INSERT INTO lore_attachments (sha256, content_type, size, data, created_by) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&sha)
        .bind(mime)
        .bind(size)
        .bind(&body[..])
        .bind(format!("person:{}", me.device.id))
        .execute(&mut *tx)
        .await?;
        record(&mut tx, "created", &sha).await?;
    }
    tx.commit().await?;
    Ok(Json(AttachmentView {
        sha256: sha,
        content_type: mime.to_owned(),
        size,
        duplicate: dup,
    }))
}

#[utoipa::path(get, path = "/attachments/{sha}", operation_id = "loreGetAttachment", tag = "lore",
    params(("sha" = String, Path, description = "sha256 of the attachment")),
    responses((status = 200, description = "The stored bytes with the Core-decided content type, `nosniff`, `attachment` and a sandboxing CSP", body = Vec<u8>, content_type = "application/octet-stream")))]
pub(crate) async fn get(
    State(app): State<App>,
    Path(sha): Path<String>,
) -> Result<Response, ApiError> {
    if !sha_ok(&sha) {
        return Err(none());
    }
    let (ct, bytes): (String, Vec<u8>) =
        sqlx::query_as("SELECT content_type, data FROM lore_attachments WHERE sha256 = ?")
            .bind(&sha)
            .fetch_optional(&app.pool)
            .await?
            .ok_or_else(none)?;
    Ok((
        [
            (header::CONTENT_TYPE, ct),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_owned(),
            ),
            (header::CONTENT_DISPOSITION, "attachment".to_owned()),
        ],
        bytes,
    )
        .into_response())
}

async fn record(conn: &mut SqliteConnection, op: &str, sha: &str) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("lore.attachment.{op}"),
        entity: None,
        details: json!({"attachment": sha}).to_string(),
    };
    audit::append(conn, &row).await?;
    Ok(())
}

const PREFIX: &str = "lore-attachment:";

/// Every `lore-attachment:<64 lowercase hex>` in `text`, as the sha.
pub(crate) fn refs(text: &str) -> impl Iterator<Item = &str> {
    text.match_indices(PREFIX).filter_map(|(i, _)| {
        let sha = text.get(i + PREFIX.len()..i + PREFIX.len() + 64)?;
        sha_ok(sha).then_some(sha)
    })
}

/// The shas `text` names that are not stored, ascending and without repeats.
pub(crate) async fn missing(
    conn: &mut SqliteConnection,
    text: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let named: BTreeSet<&str> = refs(text).collect();
    let mut out = Vec::new();
    for sha in named {
        let have: i64 =
            sqlx::query_scalar("SELECT count(*) FROM lore_attachments WHERE sha256 = ?")
                .bind(sha)
                .fetch_one(&mut *conn)
                .await?;
        if have == 0 {
            out.push(sha.to_owned());
        }
    }
    Ok(out)
}

/// Deletes the attachments no note (trashed ones included, until they are purged) or version names in its
/// text and that are older than the grace day. Run after the notes are purged. Returns how many.
/// The texts are read once outside the write lock; the candidates are re-checked inside a short write.
pub(crate) async fn sweep(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let old: Vec<String> = sqlx::query_scalar(
        "SELECT sha256 FROM lore_attachments WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
    )
    .bind(format!("-{GRACE_DAYS} days"))
    .fetch_all(pool)
    .await?;
    if old.is_empty() {
        return Ok(0);
    }
    let mut named: HashSet<String> = HashSet::new();
    // ponytail: all texts in memory at once (notes are capped at 2 MB each); page by rowid if that ever hurts.
    let texts: Vec<String> =
        sqlx::query_scalar("SELECT text FROM lore_notes UNION ALL SELECT text FROM lore_versions")
            .fetch_all(pool)
            .await?;
    for text in &texts {
        named.extend(refs(text).map(str::to_owned));
    }
    let cands: Vec<String> = old.into_iter().filter(|s| !named.contains(s)).collect();
    let mut gone = Vec::new();
    for chunk in cands.chunks(50) {
        // A save may have named one since the read: the check is repeated per candidate under the lock.
        let mut tx = begin_write(pool).await?;
        for sha in chunk {
            let deleted: Option<String> = sqlx::query_scalar(
                "DELETE FROM lore_attachments WHERE sha256 = ?1 \
                 AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2) \
                 AND NOT EXISTS (SELECT 1 FROM lore_notes n WHERE instr(n.text, 'lore-attachment:' || ?1) > 0) \
                 AND NOT EXISTS (SELECT 1 FROM lore_versions v WHERE instr(v.text, 'lore-attachment:' || ?1) > 0) \
                 RETURNING sha256",
            )
            .bind(sha)
            .bind(format!("-{GRACE_DAYS} days"))
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(d) = deleted {
                record(&mut tx, "purged", &d).await?;
                gone.push(d);
            }
        }
        tx.commit().await?;
    }
    Ok(gone.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_allow_list_and_polyglot() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n.."), Some("image/png"));
        assert_eq!(sniff(b"%PDF-1.7"), Some("application/pdf"));
        assert_eq!(sniff(b"\0\0\0\x18ftypheic\0\0\0\0"), Some("image/heic"));
        assert_eq!(sniff(b"<svg xmlns='x'></svg>"), None);
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n<svg onload=x>"), None);
        assert_eq!(sniff(b"MZ"), None);
        let sha = "a".repeat(64);
        let t = format!(
            "![x](lore-attachment:{sha}) lore-attachment:{} lore-attachment:{}",
            "A".repeat(64),
            "b".repeat(63)
        );
        assert_eq!(refs(&t).collect::<Vec<_>>(), vec![sha.as_str()]);
    }
}
