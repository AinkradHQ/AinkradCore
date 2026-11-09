//! Project logos (API minor 18), by the company logo's rules (`org::logo`): a PNG, JPEG or WebP
//! by its first bytes, at most the company's `avatar.max_bytes`, stored content-addressed with the
//! artifacts; audited as `project.logo_set` and `project.logo_reset`.

use std::path::Path;

use crate::domain::work::{Project, ProjectId};
use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::get_project;
use crate::store::artifacts::{blob_path, sha256_hex, store_blob};
use crate::store::org::avatars::{AvatarError, Image, sniff};

async fn existing(pool: &SqlitePool, id: ProjectId) -> Result<Project, AvatarError> {
    get_project(pool, id)
        .await?
        .ok_or(AvatarError::NoProject(id))
}

/// The largest logo the project's company takes (`avatar.max_bytes`).
pub async fn logo_max_bytes(pool: &SqlitePool, id: ProjectId) -> Result<u64, AvatarError> {
    let p = existing(pool, id).await?;
    let _ = p;
    // ponytail: server-wide until the Core settings store has company/project scopes.
    Ok(crate::settings::value(pool, "avatar.max_bytes").await? as u64)
}

async fn set(
    pool: &SqlitePool,
    id: ProjectId,
    sha: Option<&str>,
    (action, details): (&str, serde_json::Value),
    by: AuditActor,
) -> Result<Project, AvatarError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_projects SET logo_sha256 = ? WHERE id = ? RETURNING company_id",
    )
    .bind(sha)
    .bind(id.0)
    .fetch_optional(&mut *tx)
    .await?;
    let company = company.ok_or(AvatarError::NoProject(id))?;
    super::append(&mut tx, company, by, action, ("project", id.0), details).await?;
    tx.commit().await?;
    existing(pool, id).await
}

/// Gives the project `bytes` as its logo, stored under `root` (the artifacts dir).
pub async fn upload_logo(
    pool: &SqlitePool,
    root: &Path,
    id: ProjectId,
    bytes: &[u8],
    by: AuditActor,
) -> Result<Project, AvatarError> {
    let (size, max) = (bytes.len() as u64, logo_max_bytes(pool, id).await?);
    if size > max {
        return Err(AvatarError::TooLarge { size, max });
    }
    let mime = sniff(bytes).ok_or(AvatarError::NotAnImage)?;
    let sha = sha256_hex(bytes);
    store_blob(root, &sha, bytes).map_err(|e| {
        tracing::error!(error = %e, "storing a logo failed");
        AvatarError::Io(e)
    })?;
    let details = json!({"mime": mime, "size": size, "sha256": sha});
    set(pool, id, Some(&sha), ("project.logo_set", details), by).await
}

/// Removes the project's logo.
pub async fn reset_logo(
    pool: &SqlitePool,
    id: ProjectId,
    by: AuditActor,
) -> Result<Project, AvatarError> {
    set(pool, id, None, ("project.logo_reset", json!({})), by).await
}

/// The project's logo (from `root`); `None` when it has none.
pub async fn logo_image(
    pool: &SqlitePool,
    root: &Path,
    id: ProjectId,
) -> Result<Option<Image>, AvatarError> {
    let Some(sha256) = existing(pool, id).await?.logo_sha256 else {
        return Ok(None);
    };
    let path = blob_path(root, &sha256);
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "reading a logo failed");
        AvatarError::Io(e.to_string())
    })?;
    let mime = sniff(&bytes).ok_or(AvatarError::NotAnImage)?;
    Ok(Some(Image {
        mime,
        sha256,
        bytes,
    }))
}
