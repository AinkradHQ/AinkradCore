//! The Core's repo copies served to runners (P3-01; `crate::mirrors` holds the security model):
//! git smart HTTP, upload side only, behind the signed gate with the `runner` scope. The git
//! clients are the runner's (it signs each request); a push is refused here, always, because the
//! copy is read-only: the remote is where work is pushed.
//!
//! A copy is served only to a device holding a lease for that repo, while its project is active
//! (P3-02, `crate::mirrors::servable`): the one answer to anything else is 404 `no such repo`.

use axum::body::Body;
use axum::Extension;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{ApiError, Caller};
use crate::api::App;
use crate::mirrors::ServeError;

#[derive(Debug, Deserialize)]
pub struct Service {
    pub service: Option<String>,
}

fn read_only() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "read_only",
        "the Core's copy is read-only: push to the remote",
    )
}

fn failed(e: ServeError) -> ApiError {
    match e {
        ServeError::NotReady => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mirror_not_ready",
            "the Core has not fetched this repo yet",
        ),
        ServeError::Bad(why) => ApiError::bad_request(why),
        ServeError::Failed(why) => {
            tracing::warn!(why, "serving a mirror failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mirror_failed",
                "git failed",
            )
        }
    }
}

pub(super) fn mirrors(app: &App) -> Result<&crate::mirrors::Mirrors, ApiError> {
    app.mirrors.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mirrors_unavailable",
            "this Core keeps no repo copies",
        )
    })
}

fn protocol(h: &HeaderMap) -> Option<&str> {
    h.get("git-protocol").and_then(|v| v.to_str().ok())
}

fn repo_id(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such repo"))
}

/// What the repo's mirror must have been made for. A repo that is gone (removed, its id maybe
/// recycled), one of an archived project, and one this device holds no lease for are all the same
/// 404, whatever is still on disk.
async fn key(app: &App, device: &str, repo: i64) -> Result<String, ApiError> {
    crate::mirrors::servable(app, mirrors(app)?, device, repo)
        .await?
        .ok_or_else(|| ApiError::not_found("no such repo"))
}

/// `GET /api/v1/mirrors/{repo}/info/refs?service=git-upload-pack`.
pub async fn info_refs(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(repo): Path<String>,
    Query(q): Query<Service>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let repo = repo_id(&repo)?;
    match q.service.as_deref() {
        Some("git-upload-pack") => {}
        Some("git-receive-pack") => return Err(read_only()),
        _ => return Err(ApiError::bad_request("service must be git-upload-pack")),
    }
    let mirrors = mirrors(&app)?;
    let key = key(&app, &me.device.id, repo).await?;
    let body = mirrors
        .advertise(repo, &key, protocol(&headers))
        .await
        .map_err(failed)?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "application/x-git-upload-pack-advertisement",
            ),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response())
}

/// `POST /api/v1/mirrors/{repo}/git-upload-pack`: the clone or fetch itself.
pub async fn upload_pack(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(repo): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let repo = repo_id(&repo)?;
    let (parts, body) = req.into_parts();
    let gzip = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "gzip");
    let bytes = axum::body::to_bytes(body, super::gate::SIGNED_BODY)
        .await
        .map_err(|_| ApiError::bad_request("the request is too large"))?;
    let mirrors = mirrors(&app)?;
    let key = key(&app, &me.device.id, repo).await?;
    let out: Body = mirrors
        .upload_pack(repo, &key, protocol(&parts.headers), &bytes, gzip)
        .await
        .map_err(failed)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-git-upload-pack-result"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        out,
    )
        .into_response())
}

/// `POST /api/v1/mirrors/{repo}/git-receive-pack`: never.
pub async fn receive_pack() -> ApiError {
    read_only()
}
