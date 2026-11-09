//! Helpers the work handlers share: reads that answer a 404, the error mapping of the store's
//! rules, enum parsing for request bodies, and the labels of a list of issues.

use std::str::FromStr;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;

use crate::api::model::work::Issue;
use crate::domain::org::UnknownVariant;
use crate::domain::work::{self as core, IssueId, ProjectId, SprintId};
use crate::store::work::{self, IssueTransitionError, SprintError};

/// A rule the store states (`InvalidArgument`, or the Core's `Protocol`) is a 400; anything else
/// is the Core's own mapping.
pub(super) fn rule(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) | sqlx::Error::Protocol(why) => {
            ApiError::bad_request(why)
        }
        e => e.into(),
    }
}

/// `text` as a request-body enum value: a bad value is a 400 (a serde enum would say 422).
pub(super) fn parse<T: FromStr<Err = UnknownVariant>>(
    text: &str,
    field: &str,
) -> Result<T, ApiError> {
    text.parse()
        .map_err(|_| ApiError::bad_request(format!("`{field}` is not a known value: {text:?}")))
}

pub(super) async fn project(app: &App, id: i64) -> Result<core::Project, ApiError> {
    work::get_project(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))
}

pub(super) async fn sprint(app: &App, id: i64) -> Result<core::Sprint, ApiError> {
    work::get_sprint(&app.pool, SprintId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sprint {id}")))
}

pub(super) async fn issue(app: &App, id: i64) -> Result<core::Issue, ApiError> {
    work::get_issue(&app.pool, IssueId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))
}

/// `items` with their labels, in one read.
pub(super) async fn labeled(app: &App, mut items: Vec<Issue>) -> Result<Vec<Issue>, ApiError> {
    let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
    for (issue, l) in work::labels_of(&app.pool, &ids).await? {
        if let Some(i) = items.iter_mut().find(|i| i.id == issue) {
            i.labels.push(l.into());
        }
    }
    Ok(items)
}

/// `Option<Option<T>>` from JSON: absent is `None`, `null` is `Some(None)`.
pub(super) mod serde_with_none {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

pub(super) fn transition_error(e: IssueTransitionError) -> ApiError {
    match e {
        IssueTransitionError::NotFound => ApiError::not_found(e.to_string()),
        IssueTransitionError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

pub(super) fn sprint_error(e: SprintError) -> ApiError {
    match e {
        SprintError::NotFound => ApiError::not_found(e.to_string()),
        SprintError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}
