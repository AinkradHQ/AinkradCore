//! Company logos (API minor 17), by the agent avatar's rules (`avatars`): audited as
//! `company.logo_reset`. NOT ported yet: `upload_logo` and `logo_image` (`company.logo_set`)
//! need the artifacts slice's blob store (S5), like the agent avatar's upload.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::SqlitePool;

use super::avatars::AvatarError;
use super::chart::append_org_event;
use super::get_company;
use crate::domain::org::{Company, CompanyId};

/// The largest logo the company takes (`avatar.max_bytes`, server-wide).
pub async fn logo_max_bytes(pool: &SqlitePool, company: CompanyId) -> Result<u64, AvatarError> {
    get_company(pool, company)
        .await?
        .ok_or(AvatarError::NoCompany(company))?;
    // ponytail: server-wide until the Core settings store has company/project scopes
    Ok(crate::settings::value(pool, "avatar.max_bytes").await? as u64)
}

/// Removes the company's logo.
pub async fn reset_logo(
    pool: &SqlitePool,
    company: CompanyId,
    by: AuditActor,
) -> Result<Company, AvatarError> {
    let mut tx = begin_write(pool).await?;
    let done = sqlx::query("UPDATE citadel_companies SET logo_sha256 = NULL WHERE id = ?")
        .bind(company.0)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if !done {
        return Err(AvatarError::NoCompany(company));
    }
    let entity = ("company", company.0);
    append_org_event(
        &mut tx,
        company,
        by,
        "company.logo_reset",
        entity,
        json!({}),
    )
    .await?;
    let c = get_company(&mut *tx, company)
        .await?
        .ok_or(AvatarError::NoCompany(company))?;
    tx.commit().await?;
    Ok(c)
}
