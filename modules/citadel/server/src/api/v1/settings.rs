//! Settings (E15.17, decision #52): every limit, quota and threshold, with its bounds, where
//! it may be set and its effective value at a scope. A scope in a path is `server`,
//! `company:<id>`, `project:<id>`, `runner:<id>` or `account:<id>`. A value out of bounds, at a
//! scope the setting does not allow, or not an integer is refused (400, `code`
//! `out_of_bounds`, `wrong_scope` or `not_integer`); an unknown key or scope row is a 404;
//! nothing is clamped. Every set and reset is audited, and `history` reads it back.

use citadel_core::settings::{Key, Scope};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use super::events::EventActor;
use super::types::{SettingScope, SettingUnit, Timestamp, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::settings::{self as store, Change, Effective, SetError};

/// One setting and its effective value at the scope asked about.
#[derive(Debug, Serialize, ToSchema)]
pub struct Setting {
    /// E.g. `run.stuck_after_secs`.
    pub key: String,
    pub description: String,
    pub unit: SettingUnit,
    pub default: i64,
    /// The bounds a value must be within.
    pub min: i64,
    pub max: i64,
    /// Where it may be set; the most specific with a value wins.
    pub scopes: Vec<SettingScope>,
    pub value: i64,
    /// Where `value` was set (`server`, `company:1`, …); absent: the default.
    pub source: Option<String>,
}

impl From<Effective> for Setting {
    fn from(e: Effective) -> Self {
        Self {
            key: e.spec.name.to_owned(),
            description: e.spec.description.to_owned(),
            unit: e.spec.unit.into(),
            default: e.spec.default,
            min: e.spec.min,
            max: e.spec.max,
            scopes: e.spec.scopes.iter().map(|s| (*s).into()).collect(),
            value: e.value,
            source: e.source.map(|s| s.to_string()),
        }
    }
}

/// A value to set: an integer in the setting's unit.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetSetting {
    #[schema(value_type = i64)]
    pub value: Value,
}

/// One set or reset, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct SettingChange {
    pub seq: i64,
    pub at: Timestamp,
    pub actor: EventActor,
    pub scope: String,
    /// What was set at `scope` before; absent when it inherited.
    pub old: Option<i64>,
    /// What was set; absent for a reset.
    pub new: Option<i64>,
}

impl From<Change> for SettingChange {
    fn from(c: Change) -> Self {
        Self {
            seq: c.seq.0,
            at: ts(&c.at),
            actor: actor(c.actor),
            scope: c.scope.to_string(),
            old: c.old,
            new: c.new,
        }
    }
}

fn actor(a: citadel_core::audit::AuditActor) -> EventActor {
    use citadel_core::audit::AuditActor as A;
    match a {
        A::User(u) => EventActor::User { user_id: u.0 },
        A::Agent(a) => EventActor::Agent { agent_id: a.0 },
        A::Runner(r) => EventActor::Runner { runner_id: r.0 },
        A::System => EventActor::System {},
    }
}

fn scope(text: &str) -> Result<Scope, ApiError> {
    text.parse().map_err(|_| {
        ApiError::bad_request(format!(
            "bad scope {text:?}: server, company:<id>, project:<id>, runner:<id> or account:<id>"
        ))
    })
}

fn key(text: &str) -> Result<Key, ApiError> {
    text.parse()
        .map_err(|e: citadel_core::settings::SettingError| ApiError::not_found(e.to_string()))
}

fn refused(e: SetError) -> ApiError {
    match e {
        SetError::Refused(e) => ApiError::new(StatusCode::BAD_REQUEST, e.code(), e.to_string()),
        SetError::NoScope(s) => ApiError::not_found(format!("no {s}")),
        SetError::Db(e) => e.into(),
    }
}

async fn listed(app: &App, at: Scope) -> ApiResult<Vec<Setting>> {
    let all = store::list(&app.pool, at).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/api/v1/settings", operation_id = "listServerSettings",
    tag = "settings",
    responses((status = 200, description = "Every setting with its server-wide value", body = Vec<Setting>)))]
pub async fn list_server(State(app): State<App>) -> ApiResult<Vec<Setting>> {
    listed(&app, Scope::Server).await
}

#[utoipa::path(get, path = "/api/v1/settings/{scope}", operation_id = "listSettings",
    tag = "settings",
    params(("scope" = String, Path, description = "server, company:<id>, project:<id>, runner:<id> or account:<id>")),
    responses((status = 200, description = "Every setting that may be set at this kind of scope, with its effective value there", body = Vec<Setting>)))]
pub async fn list(State(app): State<App>, Path(at): Path<String>) -> ApiResult<Vec<Setting>> {
    listed(&app, scope(&at)?).await
}

#[utoipa::path(get, path = "/api/v1/settings/{scope}/{key}", operation_id = "getSetting",
    tag = "settings",
    params(("scope" = String, Path, description = "Where to read it"),
        ("key" = String, Path, description = "The setting, e.g. run.stuck_after_secs")),
    responses((status = 200, description = "Its effective value at the scope", body = Setting)))]
pub async fn get(
    State(app): State<App>,
    Path((at, name)): Path<(String, String)>,
) -> ApiResult<Setting> {
    let e = store::effective(&app.pool, key(&name)?, scope(&at)?).await?;
    Ok(Json(e.into()))
}

#[utoipa::path(put, path = "/api/v1/settings/{scope}/{key}", operation_id = "setSetting",
    tag = "settings",
    params(("scope" = String, Path, description = "Where to set it"),
        ("key" = String, Path, description = "The setting")),
    request_body = SetSetting,
    responses((status = 200, description = "Set; its effective value there. 400 `out_of_bounds`, `wrong_scope` or `not_integer` when refused", body = Setting)))]
pub async fn set(
    State(app): State<App>,
    Path((at, name)): Path<(String, String)>,
    Json(body): Json<SetSetting>,
) -> ApiResult<Setting> {
    let (k, at) = (key(&name)?, scope(&at)?);
    let value = body.value.to_string();
    let e = store::set(&app.pool, k, at, &value, BY, &app.clock.now()).await;
    Ok(Json(e.map_err(refused)?.into()))
}

#[utoipa::path(delete, path = "/api/v1/settings/{scope}/{key}", operation_id = "resetSetting",
    tag = "settings",
    params(("scope" = String, Path, description = "Where to reset it"),
        ("key" = String, Path, description = "The setting")),
    responses((status = 200, description = "Reset: the value it inherits there now", body = Setting)))]
pub async fn reset(
    State(app): State<App>,
    Path((at, name)): Path<(String, String)>,
) -> ApiResult<Setting> {
    let (k, at) = (key(&name)?, scope(&at)?);
    let e = store::reset(&app.pool, k, at, BY, &app.clock.now()).await;
    Ok(Json(e.map_err(refused)?.into()))
}

#[utoipa::path(get, path = "/api/v1/settings/{scope}/{key}/history",
    operation_id = "settingHistory", tag = "settings",
    params(("scope" = String, Path, description = "The scope whose changes to list"),
        ("key" = String, Path, description = "The setting")),
    responses((status = 200, description = "Its sets and resets at the scope, newest first", body = Vec<SettingChange>)))]
pub async fn history(
    State(app): State<App>,
    Path((at, name)): Path<(String, String)>,
) -> ApiResult<Vec<SettingChange>> {
    let all = store::history(&app.pool, key(&name)?, Some(scope(&at)?)).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

/// A value set at a company or one of its projects, for the Limits screen.
#[derive(Debug, Serialize, ToSchema)]
pub struct SettingOverride {
    pub key: String,
    pub description: String,
    pub unit: SettingUnit,
    pub default: i64,
    /// `company:<id>` or `project:<id>`.
    pub scope: String,
    pub value: i64,
    /// Who set it last, and when.
    pub set_by: EventActor,
    pub set_at: Timestamp,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/settings/overridden",
    operation_id = "listOverriddenSettings", tag = "settings",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Every value set at the company or one of its \
        projects, by key then scope; a setting left at its default or the server's is absent", body = Vec<SettingOverride>)))]
pub async fn overridden(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<SettingOverride>> {
    let c = super::org::company(&app, id).await?;
    let all = store::company_overrides(&app.pool, c.id).await?;
    let out = all.into_iter().map(|o| SettingOverride {
        key: o.spec.name.to_owned(),
        description: o.spec.description.to_owned(),
        unit: o.spec.unit.into(),
        default: o.spec.default,
        scope: o.scope.to_string(),
        value: o.value,
        set_by: actor(o.by),
        set_at: ts(&o.at),
    });
    Ok(Json(out.collect()))
}
