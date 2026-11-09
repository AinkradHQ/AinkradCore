//! Artifacts (E15.12, pain #13, screen 13): what agents published, for the company a client
//! works in, without opening any agent's conversation. List them (by requirement, issue, agent,
//! kind), read one's provenance, preview text and images, and download any.
//!
//! Serving is defensive: a download is always an attachment (`Content-Disposition`) with its
//! stored type, never sniffed (`nosniff`) and sandboxed by CSP, so an HTML or SVG an agent
//! published never runs in the app's or a browser's origin; only text (as `text/plain`) and
//! raster images are previewed inline.

use citadel_core::gov::ArtifactId;
use citadel_core::org::{AgentId, CompanyId};
use citadel_core::work::{IssueId, RequirementId};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::scope::Acting;
use super::types::{ArtifactKind, Page, Timestamp, ts};
use super::{ApiError, ApiResult, Paging};
use crate::api::App;
use crate::store::artifacts::{self as store, Preview, blob_path, preview_of};

/// Default and most artifacts on a page.
const PAGE: u32 = 100;
/// The most text a preview shows.
const PREVIEW_BYTES: usize = 64 * 1024;

#[derive(Debug, Serialize, ToSchema)]
pub struct Artifact {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub kind: ArtifactKind,
    pub mime: String,
    pub size: i64,
    /// The content's SHA-256, hex.
    pub sha256: String,
    /// Secrets redacted from its content before it was stored (text artifacts only).
    pub redactions: i64,
    /// Stored as it is, never scanned for secrets (not text: images, PDF, zip).
    pub unscanned: bool,
    pub issue_id: Option<i64>,
    pub requirement_id: Option<i64>,
    pub run_id: Option<i64>,
    pub agent_id: Option<i64>,
    /// `text`, `image`, or `none` (download it).
    pub preview: String,
    pub created_at: Timestamp,
}

impl From<store::Artifact> for Artifact {
    fn from(a: store::Artifact) -> Self {
        let preview = match preview_of(&a.mime) {
            Preview::Text => "text",
            Preview::Image => "image",
            Preview::None => "none",
        };
        Self {
            id: a.id.0,
            company_id: a.company_id.0,
            name: a.name,
            kind: a.kind.into(),
            mime: a.mime,
            size: a.size,
            sha256: a.sha256,
            redactions: a.redactions,
            unscanned: a.unscanned,
            issue_id: a.issue_id.map(|i| i.0),
            requirement_id: a.requirement_id.map(|r| r.0),
            run_id: a.run_id.map(|r| r.0),
            agent_id: a.agent_id.map(|g| g.0),
            preview: preview.to_owned(),
            created_at: ts(&a.created_at),
        }
    }
}

/// Narrows the list.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ArtifactQuery {
    pub requirement: Option<i64>,
    pub issue: Option<i64>,
    pub agent: Option<i64>,
    pub kind: Option<ArtifactKind>,
}

#[utoipa::path(get, path = "/api/v1/artifacts", operation_id = "listArtifacts", tag = "artifacts",
    params(ArtifactQuery, Paging),
    responses((status = 200, description = "Artifacts, newest first, of the acting company (else \
        every company's); `after` continues with older ones", body = Page<Artifact>)))]
pub async fn list(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
    Query(q): Query<ArtifactQuery>,
    Query(page): Query<Paging>,
) -> ApiResult<Page<Artifact>> {
    let f = store::ArtifactFilter {
        company: acting.0,
        requirement: q.requirement.map(RequirementId),
        issue: q.issue.map(IssueId),
        agent: q.agent.map(AgentId),
        kind: q.kind.map(Into::into),
    };
    let limit = page.limit.unwrap_or(PAGE).clamp(1, PAGE);
    let all = store::list_artifacts(&app.pool, &f, page.after, limit + 1).await?;
    let items: Vec<Artifact> = all.into_iter().map(Into::into).collect();
    Ok(Json(Page::of(items, limit, |a| a.id)))
}

async fn find(app: &App, id: i64) -> Result<store::Artifact, ApiError> {
    store::get_artifact(&app.pool, ArtifactId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no artifact {id}")))
}

#[utoipa::path(get, path = "/api/v1/artifacts/{id}", operation_id = "getArtifact",
    tag = "artifacts", params(("id" = i64, Path, description = "Artifact id")),
    responses((status = 200, description = "The artifact and where it came from", body = Artifact)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Artifact> {
    find(&app, id).await.map(|a| Json(a.into()))
}

/// `bytes` served with `mime`, as `disposition`, never sniffed, sandboxed.
pub(super) fn served(bytes: Vec<u8>, mime: &str, disposition: String) -> Response {
    let mut r = bytes.into_response();
    let h = r.headers_mut();
    let value = |v: &str| {
        HeaderValue::from_str(v)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
    };
    h.insert(header::CONTENT_TYPE, value(mime));
    h.insert(header::CONTENT_DISPOSITION, value(&disposition));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let csp = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox";
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

/// `attachment; filename="…"` with the name made header-safe.
fn attachment(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() || "._- ".contains(c) => c,
            _ => '_',
        })
        .collect();
    format!("attachment; filename=\"{safe}\"")
}

async fn content(app: &App, a: &store::Artifact) -> Result<Vec<u8>, ApiError> {
    let path = blob_path(&app.artifacts, &a.sha256);
    tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "reading an artifact failed");
        ApiError::new(
            axum::http::StatusCode::GONE,
            "gone",
            "the artifact's file is gone",
        )
    })
}

#[utoipa::path(get, path = "/api/v1/artifacts/{id}/content", operation_id = "downloadArtifact",
    tag = "artifacts", params(("id" = i64, Path, description = "Artifact id")),
    responses((status = 200, description = "The file, as an attachment of its stored type",
        content_type = "*/*", body = Vec<u8>)))]
pub async fn download(State(app): State<App>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let a = find(&app, id).await?;
    let bytes = content(&app, &a).await?;
    Ok(served(bytes, &a.mime, attachment(&a.name)))
}

#[utoipa::path(get, path = "/api/v1/artifacts/{id}/preview", operation_id = "previewArtifact",
    tag = "artifacts", params(("id" = i64, Path, description = "Artifact id")),
    responses((status = 200, description = "Text (as text/plain, its first 64 KiB) or an image, \
        inline; a type with no preview is a 409: download it", content_type = "*/*",
        body = Vec<u8>)))]
pub async fn preview(State(app): State<App>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let a = find(&app, id).await?;
    match preview_of(&a.mime) {
        Preview::Text => {
            let mut bytes = content(&app, &a).await?;
            bytes.truncate(PREVIEW_BYTES);
            let text = String::from_utf8_lossy(&bytes).into_owned().into_bytes();
            Ok(served(
                text,
                "text/plain; charset=utf-8",
                "inline".to_owned(),
            ))
        }
        Preview::Image => {
            let bytes = content(&app, &a).await?;
            Ok(served(bytes, &a.mime, "inline".to_owned()))
        }
        Preview::None => Err(ApiError::conflict(format!(
            "no preview for {}; download it",
            a.mime
        ))),
    }
}

/// A company's artifact storage.
#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactUsage {
    pub used_bytes: u64,
    /// `artifact.company_quota_bytes`.
    pub quota_bytes: u64,
    /// `artifact.max_file_bytes`.
    pub max_file_bytes: u64,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/artifact-usage", operation_id = "getArtifactUsage",
    tag = "artifacts", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its artifact storage against its quota",
        body = ArtifactUsage)))]
pub async fn usage(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<ArtifactUsage> {
    crate::store::org::get_company(&app.pool, CompanyId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no company {id}")))?;
    let (used_bytes, quota_bytes, max_file_bytes) =
        store::artifact_usage(&app.pool, CompanyId(id)).await?;
    Ok(Json(ArtifactUsage {
        used_bytes,
        quota_bytes,
        max_file_bytes,
    }))
}
