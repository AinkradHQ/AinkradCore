//! A project's cumulative flow, and the run context its profile renders to (API minor 18).

use citadel_core::work::ProjectId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::projects::project;
use super::reads::window;
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::gov::project_knowledge;
use crate::store::work::{self, STATES};

/// A window of days.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CfdQuery {
    /// `YYYY-MM-DD` or RFC 3339; default 30 days before `until`.
    pub since: Option<String>,
    /// `day`, the only bucket.
    pub bucket: Option<String>,
}

/// One day of a cumulative flow diagram.
#[derive(Debug, Serialize, ToSchema)]
pub struct CfdDay {
    /// `YYYY-MM-DD`.
    pub day: String,
    /// Issues in each state at the day's end, every state present (zero when empty).
    pub counts: std::collections::BTreeMap<String, i64>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/cfd", operation_id = "getProjectCfd",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), CfdQuery),
    responses((status = 200, description = "The project's issues per state at the end of each \
        day from `since` to today, oldest first (API minor 18); the window is at most a year, \
        and any bucket but `day` is a 400", body = Vec<CfdDay>)))]
pub async fn cfd(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<CfdQuery>,
) -> ApiResult<Vec<CfdDay>> {
    let p = project(&app, id).await?;
    if q.bucket.as_deref().is_some_and(|b| b != "day") {
        return Err(ApiError::bad_request("the only bucket is day"));
    }
    let (since, until) = window(&app, q.since.as_deref(), None, 30, 366.0).await?;
    let days = work::cumulative_flow(&app.pool, p.id, &since[..10], &until[..10]).await?;
    Ok(Json(
        days.into_iter()
            .map(|(day, counts)| CfdDay {
                day,
                counts: STATES
                    .iter()
                    .zip(counts)
                    .map(|(s, n)| (s.as_str().to_owned(), n))
                    .collect(),
            })
            .collect(),
    ))
}

/// What a run on the project is told about it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfilePreview {
    /// The project's profile and accepted knowledge exactly as a run's instructions carry them
    /// (a run's skills come first there, and are per agent); empty when it has neither.
    pub text: String,
    pub bytes: u64,
    /// The profile's budget (`profile.budget_bytes`); the profile text is fitted to it.
    pub budget_bytes: u64,
    /// Sections the budget leaves out of the text (named at its end).
    pub dropped: Vec<String>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/profile/preview",
    operation_id = "getProfilePreview", tag = "projects",
    params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The run context text, as the server renders it for a \
        run (API minor 18)", body = ProfilePreview)))]
pub async fn preview(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<ProfilePreview> {
    let p = project(&app, id).await?;
    let (fitted, budget) = work::run_profile(&app.pool, ProjectId(p.id.0)).await?;
    let knowledge = project_knowledge(&app.pool, p.id).await?.render();
    let text: String = [fitted.text, knowledge].into_iter().flatten().collect();
    Ok(Json(ProfilePreview {
        bytes: text.len() as u64,
        text,
        budget_bytes: budget,
        dropped: fitted.dropped.iter().map(|d| (*d).to_owned()).collect(),
    }))
}
