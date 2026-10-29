//! Companies (E15.14, pain #12: the admin works for several companies and his own, and they must
//! never mix): list, add and change them, each the admin's own or a client's, with the pool
//! accounts its runs may use. A client works in one company at a time by sending its id in
//! `X-Citadel-Company` (`scope`); every other route then refuses another company's data.

use ainkrad_core::org::{CompanyId, CompanyProfile};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use utoipa::ToSchema;

use super::avatars::{image_body, serve_image};
use super::model::Company;
use super::quest::serde_with_none;
use super::types::CompanyKind;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::logo;
use crate::store::{gov, org};

/// `all` with the accounts assigned to each.
pub(super) async fn with_accounts(
    app: &App,
    all: Vec<ainkrad_core::org::Company>,
) -> ApiResult<Vec<Company>> {
    let accounts = gov::list_accounts(&app.pool).await?;
    let out = all.into_iter().map(|c| {
        let id = c.id;
        let mut c: Company = c.into();
        c.account_ids = accounts
            .iter()
            .filter(|a| a.companies.contains(&id.0))
            .map(|a| a.id.0)
            .collect();
        c
    });
    Ok(Json(out.collect()))
}

#[utoipa::path(get, path = "/api/v1/companies", operation_id = "listCompanies", tag = "org",
    responses((status = 200, description = "Every company, own or client, with its pool \
        accounts: the company switcher", body = Vec<Company>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Company>> {
    let all = org::list_companies(&app.pool).await?;
    with_accounts(&app, all).await
}

/// A new company. The profile fields (API minor 17) are optional; see `Company` for their
/// shapes. A field out of shape is a 400.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewCompany {
    pub name: String,
    pub kind: CompanyKind,
    pub color: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub industries: Vec<String>,
    pub website: Option<String>,
    pub timezone: Option<String>,
    pub work_start: Option<u16>,
    pub work_end: Option<u16>,
    pub work_days: Option<u8>,
}

#[utoipa::path(post, path = "/api/v1/companies", operation_id = "createCompany", tag = "org",
    request_body = NewCompany,
    responses((status = 200, description = "The new company, with no accounts yet (audited as \
        `company.created`)", body = Company)))]
pub async fn create(State(app): State<App>, Json(n): Json<NewCompany>) -> ApiResult<Company> {
    let profile = CompanyProfile {
        color: n.color,
        description: n.description,
        industries: n.industries,
        website: n.website,
        timezone: n.timezone,
        work_start: n.work_start,
        work_end: n.work_end,
        work_days: n.work_days,
        logo_sha256: None,
    };
    let c = org::add_company(&app.pool, &n.name, n.kind.into(), &profile, BY)
        .await
        .map_err(invalid)?;
    Ok(Json(c.into()))
}

/// What to change; absent fields stay, `null` clears an optional one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CompanyChange {
    pub name: Option<String>,
    pub kind: Option<CompanyKind>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub color: Option<Option<String>>,
    pub description: Option<String>,
    pub industries: Option<Vec<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub website: Option<Option<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub timezone: Option<Option<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u16>)]
    pub work_start: Option<Option<u16>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u16>)]
    pub work_end: Option<Option<u16>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u8>)]
    pub work_days: Option<Option<u8>>,
}

#[utoipa::path(put, path = "/api/v1/companies/{id}", operation_id = "updateCompany", tag = "org",
    params(("id" = i64, Path, description = "Company id")), request_body = CompanyChange,
    responses((status = 200, description = "The company as changed (audited as \
        `company.updated`, with its profile)", body = Company)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(change): Json<CompanyChange>,
) -> ApiResult<Company> {
    let mut c = super::org::company(&app, id).await?;
    if let Some(name) = change.name {
        c.name = name;
    }
    if let Some(kind) = change.kind {
        c.kind = kind.into();
    }
    let p = &mut c.profile;
    let keep = |old: &mut Option<String>, new: Option<Option<String>>| {
        if let Some(new) = new {
            *old = new;
        }
    };
    keep(&mut p.color, change.color);
    keep(&mut p.website, change.website);
    keep(&mut p.timezone, change.timezone);
    p.description = change.description.unwrap_or(p.description.clone());
    p.industries = change.industries.unwrap_or(p.industries.clone());
    p.work_start = change.work_start.unwrap_or(p.work_start);
    p.work_end = change.work_end.unwrap_or(p.work_end);
    p.work_days = change.work_days.unwrap_or(p.work_days);
    org::edit_company(&app.pool, &c, BY)
        .await
        .map_err(invalid)?;
    shown(&app, id).await
}

/// The company `id` with its accounts, as the client sees it.
async fn shown(app: &App, id: i64) -> ApiResult<Company> {
    let now = org::get_company(&app.pool, CompanyId(id))
        .await?
        .into_iter()
        .collect();
    let mut out = with_accounts(app, now).await?.0;
    out.pop()
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no company {id}")))
}

fn invalid(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        e => e.into(),
    }
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/logo", operation_id = "getCompanyLogo",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses(
        (status = 200, description = "Its uploaded logo; 404 when it has none",
            content(("image/png"), ("image/jpeg"), ("image/webp"))),
        (status = 304, description = "Not modified: the If-None-Match ETag is current")))]
pub async fn get_logo(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let img = logo::logo_image(&app.pool, &app.artifacts, CompanyId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("company {id} has no logo")))?;
    Ok(serve_image(img, &headers))
}

#[utoipa::path(put, path = "/api/v1/companies/{id}/logo", operation_id = "uploadCompanyLogo",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body(description = "The image itself: PNG, JPEG or WebP, at most the company's \
        avatar.max_bytes (the agent avatar's rules)",
        content(("image/png"), ("image/jpeg"), ("image/webp"))),
    responses(
        (status = 200, description = "The company with its logo (audited as \
            `company.logo_set`)", body = Company),
        (status = 413, description = "Over avatar.max_bytes", body = super::types::ErrorBody),
        (status = 415, description = "Not a PNG, JPEG or WebP image",
            body = super::types::ErrorBody)))]
pub async fn upload_logo(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Company> {
    let company = CompanyId(id);
    let max = logo::logo_max_bytes(&app.pool, company).await?;
    let bytes = image_body(&headers, body, max).await?;
    logo::upload_logo(&app.pool, &app.artifacts, company, &bytes, BY).await?;
    shown(&app, id).await
}

#[utoipa::path(delete, path = "/api/v1/companies/{id}/logo", operation_id = "resetCompanyLogo",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company without a logo (audited as \
        `company.logo_reset`)", body = Company)))]
pub async fn reset_logo(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Company> {
    logo::reset_logo(&app.pool, CompanyId(id), BY).await?;
    shown(&app, id).await
}
