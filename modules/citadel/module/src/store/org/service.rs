//! The audited org writes (the first of the monolith's `store/org/service.rs`): each runs in one
//! write transaction with its audit row, so a change and its record land together or not at all.
//! The audit entity is the changed row; the company is in the details.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core_server::store::{audit, begin_write};
use serde_json::{Value, json};
use sqlx::{Error, SqliteConnection, SqlitePool};

use super::{
    create_company, create_department, create_team, delete_department, delete_team, get_company,
    get_department, get_team, update_company, update_department, update_team,
};
use crate::domain::org::{Company, CompanyId, CompanyKind, Department, DepartmentId, Team, TeamId};

async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    (kind, id): (&str, i64),
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: format!("citadel.{action}"),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &event).await.map(drop)
}

fn named(name: &str) -> Result<&str, Error> {
    match name.trim() {
        "" => Err(Error::Protocol("a name is required".to_owned())),
        name => Ok(name),
    }
}

/// Whether `e` is a violated constraint (a duplicate name, a missing parent).
pub fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

/// Adds a company and appends `company.created`.
pub async fn add_company(
    pool: &SqlitePool,
    name: &str,
    kind: CompanyKind,
    actor: AuditActor,
) -> Result<Company, Error> {
    let name = named(name)?;
    let mut tx = begin_write(pool).await?;
    let mut c = create_company(&mut *tx, name).await?;
    if kind != c.kind {
        c.kind = kind;
        update_company(&mut *tx, &c).await?;
    }
    let details = json!({"company_id": c.id.0, "name": c.name, "kind": c.kind.as_str()});
    record(
        &mut tx,
        actor,
        "company.created",
        ("company", c.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(c)
}

/// Renames / re-kinds a company and appends `company.updated`; `None` when there is none.
pub async fn change_company(
    pool: &SqlitePool,
    id: CompanyId,
    name: Option<&str>,
    kind: Option<CompanyKind>,
    actor: AuditActor,
) -> Result<Option<Company>, Error> {
    let name = name.map(named).transpose()?;
    let mut tx = begin_write(pool).await?;
    let Some(mut c) = get_company(&mut *tx, id).await? else {
        return Ok(None);
    };
    if let Some(name) = name {
        c.name = name.to_owned();
    }
    c.kind = kind.unwrap_or(c.kind);
    update_company(&mut *tx, &c).await?;
    let details = json!({"company_id": c.id.0, "name": c.name, "kind": c.kind.as_str()});
    record(
        &mut tx,
        actor,
        "company.updated",
        ("company", c.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(c))
}

/// Adds a department and appends `department.added`.
pub async fn add_department(
    pool: &SqlitePool,
    company: CompanyId,
    name: &str,
    actor: AuditActor,
) -> Result<Department, Error> {
    let name = named(name)?;
    let mut tx = begin_write(pool).await?;
    let d = create_department(&mut *tx, company, name).await?;
    let details = json!({"company_id": company.0, "name": d.name});
    record(
        &mut tx,
        actor,
        "department.added",
        ("department", d.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(d)
}

pub async fn rename_department(
    pool: &SqlitePool,
    id: DepartmentId,
    name: &str,
    actor: AuditActor,
) -> Result<Option<Department>, Error> {
    let name = named(name)?;
    let mut tx = begin_write(pool).await?;
    let Some(mut d) = get_department(&mut *tx, id).await? else {
        return Ok(None);
    };
    d.name = name.to_owned();
    update_department(&mut *tx, &d).await?;
    let details = json!({"company_id": d.company_id.0, "name": d.name});
    record(
        &mut tx,
        actor,
        "department.updated",
        ("department", d.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(d))
}

/// Deletes a department (its teams and seats with it) and appends `department.deleted`.
pub async fn remove_department(
    pool: &SqlitePool,
    id: DepartmentId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let Some(d) = get_department(&mut *tx, id).await? else {
        return Ok(false);
    };
    delete_department(&mut *tx, id).await?;
    let details = json!({"company_id": d.company_id.0, "name": d.name});
    record(
        &mut tx,
        actor,
        "department.deleted",
        ("department", id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Adds a team to a department and appends `team.added`.
pub async fn add_team(
    pool: &SqlitePool,
    department: DepartmentId,
    name: &str,
    actor: AuditActor,
) -> Result<Team, Error> {
    let name = named(name)?;
    let mut tx = begin_write(pool).await?;
    let t = create_team(&mut *tx, department, name).await?;
    let details = json!({"department_id": department.0, "name": t.name});
    record(&mut tx, actor, "team.added", ("team", t.id.0), details).await?;
    tx.commit().await?;
    Ok(t)
}

pub async fn rename_team(
    pool: &SqlitePool,
    id: TeamId,
    name: &str,
    actor: AuditActor,
) -> Result<Option<Team>, Error> {
    let name = named(name)?;
    let mut tx = begin_write(pool).await?;
    let Some(mut t) = get_team(&mut *tx, id).await? else {
        return Ok(None);
    };
    t.name = name.to_owned();
    update_team(&mut *tx, &t).await?;
    let details = json!({"department_id": t.department_id.0, "name": t.name});
    record(&mut tx, actor, "team.updated", ("team", t.id.0), details).await?;
    tx.commit().await?;
    Ok(Some(t))
}

/// Deletes a team and appends `team.deleted`.
pub async fn remove_team(pool: &SqlitePool, id: TeamId, actor: AuditActor) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let Some(t) = get_team(&mut *tx, id).await? else {
        return Ok(false);
    };
    delete_team(&mut *tx, id).await?;
    let details = json!({"department_id": t.department_id.0, "name": t.name});
    record(&mut tx, actor, "team.deleted", ("team", id.0), details).await?;
    tx.commit().await?;
    Ok(true)
}
