//! Agent avatar and company logo images: upload (PUT) and download (GET). An image is accepted
//! only when its first bytes say PNG, JPEG or WebP and any declared `Content-Type` agrees with
//! them; it is served with `nosniff` and a sandboxing CSP, so it can never run as a page.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{agent_out, company_out};
use crate::api::model::{Agent, Company};
use crate::api::scope::Acting;
use crate::domain::org::{AgentId, CompanyId};
use crate::store::artifacts::artifact_root;
use crate::store::org::avatars::{self, AvatarError, Image, sniff};
use crate::store::org::logo;

fn failed(e: AvatarError) -> ApiError {
    match e {
        AvatarError::NotAnImage => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "an avatar is a PNG, JPEG or WebP image",
        ),
        AvatarError::TooLarge { size, max } => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("{size} bytes is over the {max} byte limit"),
        ),
        AvatarError::NoAgent(_) | AvatarError::NoCompany(_) | AvatarError::NoProject(_) => {
            ApiError::not_found(e.to_string())
        }
        AvatarError::Io(_) => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "image_store",
            "image store unavailable",
        ),
        AvatarError::Db(e) => e.into(),
        e => ApiError::bad_request(e.to_string()),
    }
}

/// The body's type must be an image by its bytes, and the declared type, when sent, the same one.
fn checked(headers: &HeaderMap, body: &[u8]) -> Result<(), ApiError> {
    let mime = sniff(body).ok_or_else(|| failed(AvatarError::NotAnImage))?;
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    match declared {
        Some(d) if d != mime && d != "application/octet-stream" => {
            Err(failed(AvatarError::NotAnImage))
        }
        _ => Ok(()),
    }
}

fn served(image: Option<Image>) -> Result<Response, ApiError> {
    let image = image.ok_or_else(|| ApiError::not_found("no image"))?;
    let mut r = image.bytes.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(image.mime));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", image.sha256)) {
        h.insert(header::ETAG, etag);
    }
    Ok(r)
}

#[utoipa::path(put, path = "/agents/{id}/avatar", operation_id = "uploadAvatar", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, description = "The agent with its image", body = Agent),
        (status = 413, description = "Over `avatar.max_bytes`"),
        (status = 415, description = "Not a PNG, JPEG or WebP, or the declared type disagrees")))]
pub async fn upload_avatar(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Agent> {
    checked(&headers, &body)?;
    let root = artifact_root(&app.pool).await.map_err(ApiError::from)?;
    let a = avatars::upload_avatar(&app.pool, &root, AgentId(id), &body, BY)
        .await
        .map_err(failed)?;
    agent_out(&app, a).await.map(Json)
}

#[utoipa::path(get, path = "/agents/{id}/avatar", operation_id = "downloadAvatar", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The image", body = Vec<u8>)))]
pub async fn download_avatar(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let root = artifact_root(&app.pool).await.map_err(ApiError::from)?;
    served(
        avatars::avatar_image(&app.pool, &root, AgentId(id))
            .await
            .map_err(failed)?,
    )
}

#[utoipa::path(put, path = "/companies/{id}/logo", operation_id = "uploadCompanyLogo", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, description = "The company with its logo", body = Company)))]
pub async fn upload_logo(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Company> {
    checked(&headers, &body)?;
    let root = artifact_root(&app.pool).await.map_err(ApiError::from)?;
    logo::upload_logo(&app.pool, &root, CompanyId(id), &body, BY)
        .await
        .map_err(failed)?;
    company_out(&app, id).await
}

#[utoipa::path(get, path = "/companies/{id}/logo", operation_id = "downloadCompanyLogo", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The image", body = Vec<u8>)))]
pub async fn download_logo(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let root = artifact_root(&app.pool).await.map_err(ApiError::from)?;
    served(
        logo::logo_image(&app.pool, &root, CompanyId(id))
            .await
            .map_err(failed)?,
    )
}
