//! Roles (parity API B2): what a company hires for, and the defaults a new agent of the role
//! starts on. Audited (`role.created`, `role.updated`, `role.deleted`), each an event on the
//! stream.

use citadel_core::audit::AuditActor;
use citadel_core::ops::{NewRole, Role};
use citadel_core::org::CompanyId;
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

use super::service::append_org_event;

macro_rules! columns {
    () => {
        "id, company_id, name, purpose, icon, harness, model, budget_tokens, skills, instructions"
    };
}

fn role(row: SqliteRow) -> Result<Role, Error> {
    let Json(skills) = row.try_get::<Json<Vec<String>>, _>("skills")?;
    let harness: Option<String> = row.try_get("harness")?;
    Ok(Role {
        id: row.try_get("id")?,
        company_id: row.try_get("company_id")?,
        name: row.try_get("name")?,
        purpose: row.try_get("purpose")?,
        icon: row.try_get("icon")?,
        harness: harness
            .map(|h| {
                h.parse().map_err(|e| Error::ColumnDecode {
                    index: "harness".to_owned(),
                    source: Box::new(e),
                })
            })
            .transpose()?,
        model: row.try_get("model")?,
        budget_tokens: row.try_get("budget_tokens")?,
        skills,
        instructions: row.try_get("instructions")?,
    })
}

/// The company's roles, by name.
pub async fn list_roles(pool: &SqlitePool, company: CompanyId) -> Result<Vec<Role>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM roles WHERE company_id = ? ORDER BY name"
    ))
    .bind(company.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(role)
    .collect()
}

fn invalid(why: String) -> Error {
    Error::InvalidArgument(why)
}

fn details(r: &NewRole) -> serde_json::Value {
    json!({"name": r.name.trim(), "harness": r.harness.map(|h| h.as_str()), "model": r.model,
           "budget_tokens": r.budget_tokens, "skills": r.skills})
}

/// Adds a role; a name the company has is a UNIQUE constraint error.
pub async fn create_role(
    pool: &SqlitePool,
    company: CompanyId,
    r: &NewRole,
    actor: AuditActor,
) -> Result<Role, Error> {
    if let Some(why) = r.invalid() {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let made = sqlx::query(concat!(
        "INSERT INTO roles (company_id, name, purpose, icon, harness, model, budget_tokens, \
         skills, instructions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        columns!()
    ))
    .bind(company.0)
    .bind(r.name.trim())
    .bind(&r.purpose)
    .bind(&r.icon)
    .bind(r.harness.map(|h| h.as_str()))
    .bind(r.model.as_deref().map(str::trim))
    .bind(r.budget_tokens)
    .bind(Json(&r.skills))
    .bind(&r.instructions)
    .fetch_one(&mut *tx)
    .await
    .and_then(role)?;
    let by = ("role", made.id);
    append_org_event(&mut tx, company, actor, "role.created", by, details(r)).await?;
    tx.commit().await?;
    Ok(made)
}

/// Replaces the role's fields; `None` when it is gone.
pub async fn update_role(
    pool: &SqlitePool,
    id: i64,
    r: &NewRole,
    actor: AuditActor,
) -> Result<Option<Role>, Error> {
    if let Some(why) = r.invalid() {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let made = sqlx::query(concat!(
        "UPDATE roles SET name = ?, purpose = ?, icon = ?, harness = ?, model = ?, \
         budget_tokens = ?, skills = ?, instructions = ? WHERE id = ? RETURNING ",
        columns!()
    ))
    .bind(r.name.trim())
    .bind(&r.purpose)
    .bind(&r.icon)
    .bind(r.harness.map(|h| h.as_str()))
    .bind(r.model.as_deref().map(str::trim))
    .bind(r.budget_tokens)
    .bind(Json(&r.skills))
    .bind(&r.instructions)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .map(role)
    .transpose()?;
    let Some(made) = made else { return Ok(None) };
    let by = ("role", id);
    append_org_event(
        &mut tx,
        CompanyId(made.company_id),
        actor,
        "role.updated",
        by,
        details(r),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(made))
}

/// Deletes the role (agents keep their free-text role title); `false` when it is gone.
pub async fn delete_role(pool: &SqlitePool, id: i64, actor: AuditActor) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let gone = sqlx::query("DELETE FROM roles WHERE id = ? RETURNING company_id, name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(gone) = gone else { return Ok(false) };
    let company = CompanyId(gone.try_get("company_id")?);
    let name: String = gone.try_get("name")?;
    let by = ("role", id);
    append_org_event(
        &mut tx,
        company,
        actor,
        "role.deleted",
        by,
        json!({"name": name}),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}
