//! Project attachments (Y1-03, L3): one global host list; a project attaches hosts with a role.
//! A project is a Core row, so it is checked through the Projects store (`projects::get`), never
//! by a foreign key: `leyline_project_hosts.project` is the project id as text. Archiving a
//! project leaves its attachments (nothing here listens for `project.archived`). Deleting a host
//! removes its attachments (the table's cascade).

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use ainkrad_core_server::store::secrets::Error as StoreError;
use ainkrad_core_server::store::{audit, begin_write, events, projects};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::hosts::{In, find};

const ROLES: &[&str] = &["production", "staging", "development", "other"];

/// A host attached to a project.
#[derive(Serialize, ToSchema)]
pub struct ProjectHost {
    pub host_id: String,
    pub name: String,
    /// `production`, `staging`, `development` or `other`.
    pub role: String,
}

/// A project a host is attached to.
#[derive(Serialize, ToSchema)]
pub struct HostProject {
    /// The Core project's id.
    pub project: String,
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct Role {
    /// `production`, `staging`, `development` or `other`.
    pub role: String,
}

#[derive(Serialize, ToSchema)]
pub struct Detached {
    pub detached: String,
}

/// The project `p` names, through the Projects store; its id as text. A bad id and a missing
/// project are the same fixed answer.
pub(crate) async fn project(
    conn: &mut SqliteConnection,
    p: &str,
) -> Result<(String, bool), ApiError> {
    let none = || ApiError::not_found("no such project");
    let id = p
        .parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(none)?;
    match projects::get(conn, id).await {
        Ok(p) => Ok((p.id.to_string(), p.state == "archived")),
        Err(StoreError::Db(e)) => Err(e.into()),
        Err(_) => Err(none()),
    }
}

/// The projects each host is attached to (one host, or all).
pub(crate) async fn of_hosts(
    conn: &mut SqliteConnection,
    host: Option<&str>,
) -> Result<Vec<(String, HostProject)>, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT host_id, project, role FROM leyline_project_hosts \
         WHERE (?1 IS NULL OR host_id = ?1) ORDER BY project",
    )
    .bind(host)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(h, project, role)| (h, HostProject { project, role }))
        .collect())
}

async fn record(
    conn: &mut SqliteConnection,
    op: &str,
    host: &str,
    project: &str,
    role: Option<&str>,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.host.{op}"),
        entity: None,
        details: json!({"host": host, "project": project, "role": role}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(
        conn,
        "leyline.host",
        &json!({"op": op, "id": host, "project": project}),
    )
    .await?;
    Ok(())
}

#[utoipa::path(get, path = "/projects/{project}/hosts", operation_id = "leylineListProjectHosts", tag = "leyline",
    params(("project" = String, Path, description = "The Core project's id")),
    responses((status = 200, description = "The project's hosts by label; 404 for no such project", body = Vec<ProjectHost>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(p): Path<String>,
) -> ApiResult<Vec<ProjectHost>> {
    let mut conn = app.pool.acquire().await?;
    let (p, _) = project(&mut conn, &p).await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT h.id, h.name, a.role FROM leyline_project_hosts a JOIN leyline_hosts h ON h.id = a.host_id \
         WHERE a.project = ? ORDER BY h.name COLLATE NOCASE",
    )
    .bind(p)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(host_id, name, role)| ProjectHost {
                host_id,
                name,
                role,
            })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/projects/{project}/hosts/{host}", operation_id = "leylineAttachHost", tag = "leyline",
    params(("project" = String, Path, description = "The Core project's id"),
           ("host" = String, Path, description = "Host id, else its unique label")),
    request_body = Role,
    responses((status = 200, description = "Attached, or the role changed (audited as `leyline.host.attached`); 404 for no such project or host; 409 for an archived project", body = ProjectHost)))]
pub(crate) async fn attach(
    State(app): State<App>,
    Path((p, host)): Path<(String, String)>,
    In(req): In<Role>,
) -> ApiResult<ProjectHost> {
    if !ROLES.contains(&req.role.as_str()) {
        return Err(ApiError::bad_request(
            "the role is production, staging, development or other",
        ));
    }
    let mut tx = begin_write(&app.pool).await?;
    let (p, archived) = project(&mut tx, &p).await?;
    if archived {
        return Err(ApiError::conflict("the project is archived"));
    }
    let id = find(&mut tx, &host).await?;
    sqlx::query(
        "INSERT INTO leyline_project_hosts (project, host_id, role) VALUES (?, ?, ?) \
         ON CONFLICT (project, host_id) DO UPDATE SET role = excluded.role",
    )
    .bind(&p)
    .bind(&id)
    .bind(&req.role)
    .execute(&mut *tx)
    .await?;
    record(&mut tx, "attached", &id, &p, Some(&req.role)).await?;
    let name: String = sqlx::query_scalar("SELECT name FROM leyline_hosts WHERE id = ?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(ProjectHost {
        host_id: id,
        name,
        role: req.role,
    }))
}

#[utoipa::path(delete, path = "/projects/{project}/hosts/{host}", operation_id = "leylineDetachHost", tag = "leyline",
    params(("project" = String, Path, description = "The Core project's id"),
           ("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "Detached (audited as `leyline.host.detached`); 404 when it was not attached", body = Detached)))]
pub(crate) async fn detach(
    State(app): State<App>,
    Path((p, host)): Path<(String, String)>,
) -> ApiResult<Detached> {
    let mut tx = begin_write(&app.pool).await?;
    let (p, _) = project(&mut tx, &p).await?;
    let id = find(&mut tx, &host).await?;
    let n = sqlx::query("DELETE FROM leyline_project_hosts WHERE project = ? AND host_id = ?")
        .bind(&p)
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("the host is not attached"));
    }
    record(&mut tx, "detached", &id, &p, None).await?;
    tx.commit().await?;
    Ok(Json(Detached { detached: id }))
}
