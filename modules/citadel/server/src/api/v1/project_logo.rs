//! A project's logo (API minor 18), served, uploaded and removed as a company's is.

use citadel_core::work::ProjectId;
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;

use super::avatars::{image_body, serve_image};
use super::model::Project;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::work::logo;

#[utoipa::path(get, path = "/api/v1/projects/{id}/logo", operation_id = "getProjectLogo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses(
        (status = 200, description = "Its uploaded logo; 404 when it has none",
            content(("image/png"), ("image/jpeg"), ("image/webp"))),
        (status = 304, description = "Not modified: the If-None-Match ETag is current")))]
pub async fn get(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let img = logo::logo_image(&app.pool, &app.artifacts, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("project {id} has no logo")))?;
    Ok(serve_image(img, &headers))
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/logo", operation_id = "uploadProjectLogo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body(description = "The image itself: PNG, JPEG or WebP, at most the company's \
        avatar.max_bytes (the agent avatar's rules)",
        content(("image/png"), ("image/jpeg"), ("image/webp"))),
    responses(
        (status = 200, description = "The project with its logo (audited as `project.logo_set`)",
            body = Project),
        (status = 413, description = "Over avatar.max_bytes", body = super::types::ErrorBody),
        (status = 415, description = "Not a PNG, JPEG or WebP image",
            body = super::types::ErrorBody)))]
pub async fn upload(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Project> {
    let project = ProjectId(id);
    let max = logo::logo_max_bytes(&app.pool, project).await?;
    let bytes = image_body(&headers, body, max).await?;
    let p = logo::upload_logo(&app.pool, &app.artifacts, project, &bytes, BY).await?;
    Ok(Json(p.into()))
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/logo", operation_id = "resetProjectLogo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project without a logo (audited as \
        `project.logo_reset`)", body = Project)))]
pub async fn reset(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Project> {
    let p = logo::reset_logo(&app.pool, ProjectId(id), BY).await?;
    Ok(Json(p.into()))
}
