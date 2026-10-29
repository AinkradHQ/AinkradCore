//! Company logos (API minor 17), by the agent avatar's rules (`avatars`): a PNG, JPEG or WebP
//! by its first bytes, at most the company's `avatar.max_bytes`, stored content-addressed with
//! the artifacts; audited as `company.logo_set` and `company.logo_reset`.

use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{Company, CompanyId};
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::avatars::{AvatarError, Image, sniff};
use super::get_company;
use super::service::append_org_event;
use crate::store::artifacts::{blob_path, sha256_hex, store_blob};

/// The largest logo the company takes (`avatar.max_bytes`).
pub async fn logo_max_bytes(pool: &SqlitePool, company: CompanyId) -> Result<u64, AvatarError> {
    get_company(pool, company)
        .await?
        .ok_or(AvatarError::NoCompany(company))?;
    let at = Scope::Company(company);
    Ok(crate::store::settings::value(pool, Key::AvatarMaxBytes, at).await? as u64)
}

/// Sets (`Some`) or removes the logo, audited as `action`.
async fn set(
    pool: &SqlitePool,
    company: CompanyId,
    sha: Option<&str>,
    (action, details): (&str, serde_json::Value),
    by: AuditActor,
) -> Result<Company, AvatarError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let done = sqlx::query("UPDATE companies SET logo_sha256 = ? WHERE id = ?")
        .bind(sha)
        .bind(company.0)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if !done {
        return Err(AvatarError::NoCompany(company));
    }
    append_org_event(
        &mut tx,
        company,
        by,
        action,
        ("company", company.0),
        details,
    )
    .await?;
    let c = get_company(&mut *tx, company)
        .await?
        .ok_or(AvatarError::NoCompany(company))?;
    tx.commit().await?;
    Ok(c)
}

/// Gives the company `bytes` as its logo, stored under `root` (the artifacts dir).
pub async fn upload_logo(
    pool: &SqlitePool,
    root: &Path,
    company: CompanyId,
    bytes: &[u8],
    by: AuditActor,
) -> Result<Company, AvatarError> {
    let (size, max) = (bytes.len() as u64, logo_max_bytes(pool, company).await?);
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
    set(pool, company, Some(&sha), ("company.logo_set", details), by).await
}

/// Removes the company's logo.
pub async fn reset_logo(
    pool: &SqlitePool,
    company: CompanyId,
    by: AuditActor,
) -> Result<Company, AvatarError> {
    set(pool, company, None, ("company.logo_reset", json!({})), by).await
}

/// The company's logo (from `root`); `None` when it has none.
pub async fn logo_image(
    pool: &SqlitePool,
    root: &Path,
    company: CompanyId,
) -> Result<Option<Image>, AvatarError> {
    let c = get_company(pool, company)
        .await?
        .ok_or(AvatarError::NoCompany(company))?;
    let Some(sha256) = c.profile.logo_sha256 else {
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
