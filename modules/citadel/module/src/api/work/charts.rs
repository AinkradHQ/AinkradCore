//! A project's cumulative flow, and the run context its profile renders to (API minor 18).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::util::project;
use crate::api::scope::Acting;
use crate::domain::work::ProjectId;
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

/// `since` and `until` normalised, with `default_days` back when `since` is absent; refused when
/// either is not a time, `since` is after `until`, or the window is longer than `max_days`.
async fn window(
    app: &App,
    since: Option<&str>,
    until: Option<&str>,
    default_days: i64,
    max_days: f64,
) -> Result<(String, String), ApiError> {
    let now = app.clock.now();
    let (since, until, days): (Option<String>, Option<String>, Option<f64>) = sqlx::query_as(
        "WITH w (u) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', coalesce(?2, ?3))), \
         v (s, u) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', coalesce(?1, u), \
             CASE WHEN ?1 IS NULL THEN '-' || ?4 || ' days' ELSE '+0 seconds' END), u FROM w) \
         SELECT s, u, julianday(u) - julianday(s) FROM v",
    )
    .bind(since)
    .bind(until)
    .bind(&now)
    .bind(default_days)
    .fetch_one(&app.pool)
    .await?;
    let (Some(since), Some(until), Some(days)) = (since, until, days) else {
        return Err(ApiError::bad_request("since and until are RFC 3339 times"));
    };
    if !(0.0..=max_days).contains(&days) {
        let why = format!("since must be before until, and at most {max_days} days before it");
        return Err(ApiError::bad_request(why));
    }
    Ok((since, until))
}

#[utoipa::path(get, path = "/projects/{id}/cfd", operation_id = "getProjectCfd",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), CfdQuery),
    responses((status = 200, description = "The project's issues per state at the end of each \
        day from `since` to today, oldest first (API minor 18); the window is at most a year, \
        and any bucket but `day` is a 400", body = Vec<CfdDay>)))]
pub async fn cfd(
    State(app): State<App>,
    _: Acting,
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

#[utoipa::path(get, path = "/projects/{id}/profile/preview",
    operation_id = "getProfilePreview", tag = "projects",
    params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The run context text, as the server renders it for a \
        run (API minor 18)", body = ProfilePreview)))]
pub async fn preview(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<ProfilePreview> {
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
