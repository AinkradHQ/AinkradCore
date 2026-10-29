//! Agent avatars (decision #61): the client draws each agent as an animated figure from its
//! `appearance` (a figure version and a palette, `listPalettes`) and its `figure_state`; the
//! admin may change the palette, or upload an image shown instead of the figure.
//!
//! An upload is the raw image as the body: PNG, JPEG or WebP by its first bytes, whatever its
//! `Content-Type` says (which, when an image type, must agree), never SVG or HTML, at most
//! `avatar.max_bytes`. It is served with its type, inline, never sniffed, sandboxed, and with
//! its SHA-256 as the `ETag`, revalidated on every use (`If-None-Match` answers 304).

use ainkrad_core::org::{AgentId, AgentStatus};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::model::Agent;
use super::org::agent_out;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::avatars::{self as store, AvatarError, sniff};

impl From<AvatarError> for ApiError {
    fn from(e: AvatarError) -> Self {
        let why = e.to_string();
        match e {
            AvatarError::NoAgent(_) | AvatarError::NoCompany(_) | AvatarError::NoProject(_) => {
                Self::not_found(why)
            }
            AvatarError::UnknownPalette(_) | AvatarError::UnknownFigure(_) => {
                Self::bad_request(why)
            }
            AvatarError::NotAnImage => unsupported(why),
            AvatarError::TooLarge { .. } => too_large(why),
            AvatarError::Io(_) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", why),
            AvatarError::Db(e) => e.into(),
        }
    }
}

fn unsupported(why: String) -> ApiError {
    ApiError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        why,
    )
}

fn too_large(why: String) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", why)
}

/// A palette the client colours a figure with.
#[derive(Debug, Serialize, ToSchema)]
pub struct Palette {
    /// E.g. `neon-tide`.
    pub id: String,
    pub name: String,
}

#[utoipa::path(get, path = "/api/v1/avatars/palettes", operation_id = "listPalettes",
    tag = "org", responses((status = 200, description = "Every palette, in the figure design's order; the colours \
        live in the client", body = Vec<Palette>)))]
pub async fn palettes(State(app): State<App>) -> ApiResult<Vec<Palette>> {
    let all = store::list_palettes(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .map(|(id, name)| Palette { id, name })
            .collect(),
    ))
}

/// A new look: a palette, and a figure version when it changes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AppearanceChange {
    pub palette_id: String,
    pub figure_version: Option<String>,
}

#[utoipa::path(put, path = "/api/v1/agents/{id}/appearance", operation_id = "setAppearance",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = AppearanceChange,
    responses((status = 200, description = "The agent, in its new palette", body = Agent)))]
pub async fn set_appearance(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<AppearanceChange>,
) -> ApiResult<Agent> {
    let v = c.figure_version.as_deref();
    let a = store::set_appearance(&app.pool, AgentId(id), &c.palette_id, v, BY).await?;
    agent_out(&app, a).await.map(Json)
}

#[utoipa::path(get, path = "/api/v1/agents/{id}/avatar", operation_id = "getAvatar",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses(
        (status = 200, description = "Its uploaded image; 404 when it has none (draw its \
            figure)", content(("image/png"), ("image/jpeg"), ("image/webp"))),
        (status = 304, description = "Not modified: the If-None-Match ETag is current")))]
pub async fn get(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let img = store::avatar_image(&app.pool, &app.artifacts, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("agent {id} has no avatar image")))?;
    Ok(serve_image(img, &headers))
}

/// `img` served inline, never sniffed, with its SHA-256 as the `ETag`, revalidated on every
/// use: 304 when `headers` carries it in `If-None-Match`.
pub(super) fn serve_image(img: store::Image, headers: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", img.sha256);
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim() == "*" || t.trim().trim_start_matches("W/") == etag)
        });
    let mut r = match fresh {
        true => StatusCode::NOT_MODIFIED.into_response(),
        false => super::artifacts::served(img.bytes, img.mime, "inline".to_owned()),
    };
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    r
}

/// The image types an upload may declare; `application/octet-stream` leaves it to its bytes.
const DECLARED: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/octet-stream",
];

#[utoipa::path(put, path = "/api/v1/agents/{id}/avatar", operation_id = "uploadAvatar",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body(description = "The image itself: PNG, JPEG or WebP, at most avatar.max_bytes",
        content(("image/png"), ("image/jpeg"), ("image/webp"))),
    responses(
        (status = 200, description = "The agent, its image shown instead of its figure",
            body = Agent),
        (status = 413, description = "Over avatar.max_bytes", body = super::types::ErrorBody),
        (status = 415, description = "Not a PNG, JPEG or WebP image",
            body = super::types::ErrorBody)))]
pub async fn upload(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Agent> {
    let agent = AgentId(id);
    let max = store::max_bytes(&app.pool, agent).await?;
    let bytes = image_body(&headers, body, max).await?;
    let a = store::upload_avatar(&app.pool, &app.artifacts, agent, &bytes, BY).await?;
    agent_out(&app, a).await.map(Json)
}

/// An uploaded image's bytes, at most `max`: refused when its declared type is not one of
/// [`DECLARED`] or, an image type, disagrees with its first bytes.
pub(super) async fn image_body(
    headers: &HeaderMap,
    body: Body,
    max: u64,
) -> Result<axum::body::Bytes, ApiError> {
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    if let Some(t) = &declared
        && !DECLARED.contains(&t.as_str())
    {
        return Err(unsupported(format!(
            "rejected: {t} is not an image type; send PNG, JPEG or WebP"
        )));
    }
    let bytes = axum::body::to_bytes(body, max as usize)
        .await
        .map_err(|_| {
            too_large(format!(
                "rejected: over the {max}-byte image limit (avatar.max_bytes)"
            ))
        })?;
    if let Some(t) = declared.filter(|t| t.starts_with("image/"))
        && sniff(&bytes) != Some(t.as_str())
    {
        return Err(unsupported(format!(
            "rejected: the body is not the {t} it says"
        )));
    }
    Ok(bytes)
}

#[utoipa::path(delete, path = "/api/v1/agents/{id}/avatar", operation_id = "resetAvatar",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent, its figure shown again", body = Agent)))]
pub async fn reset(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = store::reset_avatar(&app.pool, AgentId(id), BY).await?;
    agent_out(&app, a).await.map(Json)
}

/// An agent's figure: which version the client draws, in which palette (`listPalettes`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Appearance {
    pub figure_version: String,
    pub palette_id: String,
}

/// What an agent's figure shows, first match wins:
///
/// | state | when |
/// |---|---|
/// | `sleepy` | the agent is paused |
/// | `rest` | it waits on its hire approval, or is terminated |
/// | `listening` | it has an open question to the admin, or an approval it asked for is pending |
/// | `working` | its run is running and has produced output |
/// | `thinking` | its run is running, no output yet |
/// | `loading` | its run is queued or claimed by a runner, not yet started |
/// | `confused` | its last run failed, timed out, lost its runner or stalled |
/// | `success` | its last run succeeded in the last five minutes |
/// | `idle` | otherwise |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FigureState {
    Rest,
    Idle,
    Listening,
    Thinking,
    Working,
    Success,
    Confused,
    Sleepy,
    Loading,
}

impl FigureState {
    pub fn of(status: AgentStatus, a: &store::Activity) -> Self {
        match status {
            AgentStatus::Paused => Self::Sleepy,
            AgentStatus::PendingApproval | AgentStatus::Terminated => Self::Rest,
            AgentStatus::Active => match a.live.as_deref() {
                _ if a.waiting => Self::Listening,
                Some("running") if a.speaking => Self::Working,
                Some("running") => Self::Thinking,
                Some(_) => Self::Loading,
                None if a.failed => Self::Confused,
                None if a.succeeded => Self::Success,
                None => Self::Idle,
            },
        }
    }
}
