//! Artifacts (E15.12, pain #13, screen 13): what agents published, for the company a client
//! works in, without opening any agent's conversation. List them (by requirement, issue, agent,
//! kind), read one's provenance, and see a company's storage against its quota.
//!
//! Not here: `downloadArtifact` and `previewArtifact` serve the stored file, which needs the
//! Core to give the module an artifacts directory (the monolith's `serve --artifacts`).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiResult, Paging};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::error::found;
use crate::api::model::governance::Artifact;
use crate::api::scope::Acting;
use crate::api::types::{ArtifactKind, Page};
use crate::domain::gov::ArtifactId;
use crate::domain::org::{AgentId, CompanyId};
use crate::domain::work::{IssueId, RequirementId};
use crate::store::artifacts as store;
use crate::store::org;

/// Default and most artifacts on a page.
const PAGE: u32 = 100;

/// Narrows the list.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ArtifactQuery {
    pub requirement: Option<i64>,
    pub issue: Option<i64>,
    pub agent: Option<i64>,
    pub kind: Option<ArtifactKind>,
}

#[utoipa::path(get, path = "/artifacts", operation_id = "listArtifacts", tag = "artifacts",
    params(ArtifactQuery, Paging),
    responses((status = 200, description = "Artifacts, newest first, of the acting company (else \
        every company's); `after` continues with older ones", body = Page<Artifact>)))]
pub async fn list(
    State(app): State<App>,
    acting: Acting,
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

#[utoipa::path(get, path = "/artifacts/{id}", operation_id = "getArtifact",
    tag = "artifacts", params(("id" = i64, Path, description = "Artifact id")),
    responses((status = 200, description = "The artifact and where it came from", body = Artifact)))]
pub async fn get(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Artifact> {
    let a = found(
        store::get_artifact(&app.pool, ArtifactId(id)).await?,
        "artifact",
    )?;
    Ok(Json(a.into()))
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

#[utoipa::path(get, path = "/companies/{id}/artifact-usage", operation_id = "getArtifactUsage",
    tag = "artifacts", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its artifact storage against its quota",
        body = ArtifactUsage)))]
pub async fn usage(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<ArtifactUsage> {
    found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let (used_bytes, quota_bytes, max_file_bytes) =
        store::artifact_usage(&app.pool, CompanyId(id)).await?;
    Ok(Json(ArtifactUsage {
        used_bytes,
        quota_bytes,
        max_file_bytes,
    }))
}
