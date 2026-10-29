//! Notification preferences (API minor 18): the matrix of event by channel, quiet hours and
//! what breaks through them, per company, and a test that emits an event.

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::org::company;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::{self, NotificationsChange};

/// One cell of the matrix.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NotifyChoice {
    /// `approval_waiting`, `run_waiting_permission`, `agent_question`, `issue_stuck`,
    /// `budget_warning`, `account_limit`, `run_finished` or `requirement_done`.
    pub event: String,
    /// `push`, `signal` or `email`.
    pub channel: String,
    pub on: bool,
}

/// Quiet hours: minutes from midnight (0-1439); the window wraps past midnight when `start` is
/// after `end`.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuietHours {
    pub start: i64,
    pub end: i64,
    pub on: bool,
    /// What still gets through: `stalled` (stalled production work) or `nothing`.
    pub breakthrough: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Notifications {
    /// Every event and channel, with its choice or its default.
    pub matrix: Vec<NotifyChoice>,
    pub quiet: QuietHours,
}

impl From<org::Notifications> for Notifications {
    fn from(n: org::Notifications) -> Self {
        Self {
            matrix: n
                .matrix
                .into_iter()
                .map(|(event, channel, on)| NotifyChoice { event, channel, on })
                .collect(),
            quiet: QuietHours {
                start: n.quiet.start,
                end: n.quiet.end,
                on: n.quiet.on,
                breakthrough: n.quiet.breakthrough,
            },
        }
    }
}

/// What to change; absent fields stay.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NotificationsUpdate {
    /// Only the cells listed change.
    #[serde(default)]
    pub matrix: Vec<NotifyChoice>,
    pub quiet_start: Option<i64>,
    pub quiet_end: Option<i64>,
    pub quiet_on: Option<bool>,
    pub breakthrough: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/notifications", operation_id = "getNotifications",
    tag = "settings", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's notification preferences", body = Notifications)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Notifications> {
    let c = company(&app, id).await?;
    Ok(Json(org::notifications(&app.pool, c.id).await?.into()))
}

#[utoipa::path(put, path = "/api/v1/companies/{id}/notifications", operation_id = "setNotifications",
    tag = "settings", params(("id" = i64, Path, description = "Company id")),
    request_body = NotificationsUpdate,
    responses((status = 200, description = "The preferences as changed (audited as \
        `notifications.updated`); 400 for an unknown event, channel or breakthrough, or a time \
        outside 0-1439", body = Notifications)))]
pub async fn set(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(u): Json<NotificationsUpdate>,
) -> ApiResult<Notifications> {
    let c = company(&app, id).await?;
    let change = NotificationsChange {
        matrix: u
            .matrix
            .into_iter()
            .map(|m| (m.event, m.channel, m.on))
            .collect(),
        quiet_start: u.quiet_start,
        quiet_end: u.quiet_end,
        quiet_on: u.quiet_on,
        breakthrough: u.breakthrough,
    };
    match org::set_notifications(&app.pool, c.id, &change, BY).await {
        Ok(n) => Ok(Json(n.into())),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationTest {
    /// The audit sequence of the `notifications.test` event just emitted.
    pub seq: i64,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/notifications/test", operation_id = "testNotification",
    tag = "settings", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Emits a `notifications.test` event on the stream, \
        which a device shows as a sample", body = NotificationTest)))]
pub async fn test(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<NotificationTest> {
    let c = company(&app, id).await?;
    let seq = org::test_notification(&app.pool, c.id, BY).await?;
    Ok(Json(NotificationTest { seq }))
}
