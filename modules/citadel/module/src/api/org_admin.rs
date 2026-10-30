//! The rest of the org: agent edit, the hire gate, avatars and logos, escalation chains,
//! fallbacks and tiers, roles, structure (seats, reporting lines), the Engineering template and
//! the org chart.
//!
//! Slice S3 of the port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). This file is the
//! slice's seam with the rest of the module: it exports its routes, its per-route scopes, its
//! destructive routes, its company-owner rows and its OpenAPI document, and `api.rs`, `scopes.rs`,
//! `scope.rs` and `spec.rs` aggregate them. Handlers live in submodules next to this file.
//!
//! Not ported (needs a later slice): `wakeAgent`, `terminateAgent` and `getAgentStats` (the run
//! engine, S7), `getTaskCosts` (runs, S7), the avatar and logo image upload and download (the
//! artifacts blob store, S5), account pins on chains (accounts, S9), `listStuck` and
//! `submitRequest` (work, S4/S7).

use std::collections::HashMap;
use std::str::FromStr;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::Json;
use axum::Router;
use axum::routing::{delete, get, patch, post, put};
use utoipa::OpenApi;

use super::error::found;
use super::model::org_admin::FigureState;
use super::model::{Agent, Company};
use crate::domain::org::{self, CompanyId};
use crate::store::org::avatars;
use crate::store::org::chart::OrgError;

pub mod agents;
pub mod presets;
pub mod routing;
pub mod staffing;
pub mod structure;

/// A request-body enum value, or a 400 naming the field.
pub(crate) fn parse<T: FromStr>(what: &str, v: &str) -> Result<T, ApiError> {
    v.parse()
        .map_err(|_| ApiError::bad_request(format!("{what} {v:?} is not a known value")))
}

/// A refused org change: a missing or foreign company, agent or team is a 404, a bad value a
/// 400, a taken name or seat or a broken rule a 409.
pub(crate) fn org_refused(e: OrgError) -> ApiError {
    match e {
        OrgError::NotFound | OrgError::OtherCompany => ApiError::not_found(e.to_string()),
        OrgError::Db(e) => failed(e),
        e => ApiError::conflict(e.to_string()),
    }
}

/// A failed write: `InvalidArgument` is a 400, a UNIQUE violation a 409.
pub(crate) fn failed(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) | sqlx::Error::Protocol(why) => {
            ApiError::bad_request(why)
        }
        sqlx::Error::Database(d) if d.message().contains("UNIQUE") => {
            ApiError::conflict("that name or seat is taken already")
        }
        e => e.into(),
    }
}

pub(crate) async fn company(app: &App, id: i64) -> Result<org::Company, ApiError> {
    found(
        crate::store::org::get_company(&app.pool, CompanyId(id)).await?,
        "company",
    )
}

/// `a` as the client sees it, with its figure's state and chain preset.
pub(crate) async fn agent_out(app: &App, a: org::Agent) -> Result<Agent, ApiError> {
    let doing = avatars::activity(&app.pool, None, Some(a.id)).await?;
    let activity = doing.get(&a.id).cloned().unwrap_or_default();
    let preset: Option<i64> =
        sqlx::query_scalar("SELECT chain_preset_id FROM citadel_agents WHERE id = ?")
            .bind(a.id.0)
            .fetch_one(&app.pool)
            .await?;
    let figure = FigureState::of(a.status, &activity);
    let mut out = Agent::from(a);
    out.figure_state = Some(figure);
    out.chain_preset_id = preset;
    Ok(out)
}

/// The company's agents as the client sees them, each with its figure's state.
pub(crate) async fn agent_out_all(app: &App, c: CompanyId) -> Result<Vec<Agent>, ApiError> {
    let agents = crate::store::org::list_agents(&app.pool, c).await?;
    let doing = avatars::activity(&app.pool, Some(c), None).await?;
    let presets: HashMap<i64, i64> = sqlx::query_as(
        "SELECT id, chain_preset_id FROM citadel_agents \
         WHERE company_id = ? AND chain_preset_id IS NOT NULL",
    )
    .bind(c.0)
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .collect();
    Ok(agents
        .into_iter()
        .map(|a| {
            let activity = doing.get(&a.id).cloned().unwrap_or_default();
            let figure = FigureState::of(a.status, &activity);
            let preset = presets.get(&a.id.0).copied();
            let mut out = Agent::from(a);
            out.figure_state = Some(figure);
            out.chain_preset_id = preset;
            out
        })
        .collect())
}

/// The company `id` as the client sees it.
pub(crate) async fn company_out(app: &App, id: i64) -> ApiResult<Company> {
    Ok(Json(company(app, id).await?.into()))
}

/// The slice's routes, relative to `/modules/citadel/v1`.
pub fn routes() -> Router<App> {
    Router::new()
        .route("/agents/{id}", patch(agents::update_agent))
        .route("/companies/{id}/agents", post(staffing::propose_agent))
        .route(
            "/companies/{id}/templates/{template}",
            post(staffing::apply_template),
        )
        .route("/avatars/palettes", get(agents::palettes))
        .route("/agents/{id}/appearance", put(agents::set_appearance))
        .route("/agents/{id}/avatar", delete(agents::reset_avatar))
        .route(
            "/agents/{id}/fallbacks",
            get(agents::list_fallbacks).put(agents::set_fallbacks),
        )
        .route(
            "/agents/{id}/tiers",
            get(routing::list_tiers).put(routing::set_tiers),
        )
        .route("/agents/{id}/chain", put(presets::set_chain))
        .route(
            "/projects/{id}/tier-rules",
            get(routing::get_rules).put(routing::set_rules),
        )
        .route(
            "/companies/{id}/chain-presets",
            get(presets::list_presets).post(presets::create_preset),
        )
        .route(
            "/chain-presets/{id}",
            put(presets::update_preset).delete(presets::delete_preset),
        )
        .route(
            "/companies/{id}/roles",
            get(presets::list_roles).post(presets::create_role),
        )
        .route(
            "/roles/{id}",
            put(presets::update_role).delete(presets::delete_role),
        )
        .route("/companies/{id}/org", get(structure::org_chart))
        .route("/departments/{id}", patch(structure::patch_department))
        .route("/teams/{id}", patch(structure::patch_team))
        .route("/companies/{id}/logo", delete(structure::reset_logo))
        .route(
            "/teams/{id}/members/{agent_id}",
            put(structure::seat).delete(structure::unseat),
        )
}

/// `(method, template, scope)` of the slice's routes below `admin` (`api::scopes`).
pub const SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/companies/{id}/org", "read"),
    ("GET", "/avatars/palettes", "read"),
    ("GET", "/agents/{id}/fallbacks", "read"),
    ("GET", "/agents/{id}/tiers", "read"),
    ("GET", "/projects/{id}/tier-rules", "read"),
    ("GET", "/companies/{id}/chain-presets", "read"),
    ("GET", "/companies/{id}/roles", "read"),
];

/// GET templates that deliberately stay `admin` (`api::scopes::ADMIN_READS`): none.
pub const ADMIN_READS: &[&str] = &[];

/// `(method, template)` of the slice's routes that need a live step-up (`Module::destructive`):
/// deleting a chain preset or a role.
pub const DESTRUCTIVE: &[(&str, &str)] =
    &[("DELETE", "/chain-presets/{id}"), ("DELETE", "/roles/{id}")];

/// `(path segment, SQL)` rows for `scope::OWNERS`: the company that owns what `segment/{id}` names.
/// `/teams/{id}/members/{agent_id}` names an agent under `members`.
pub const OWNERS: &[(&str, &str)] = &[(
    "members",
    "SELECT company_id FROM citadel_agents WHERE id = ?",
)];

/// The slice's `#[utoipa::path]` routes and schemas (operation ids unprefixed: `spec` adds
/// `citadel`; schema names must not clash with the Core's or another slice's).
#[derive(OpenApi)]
#[openapi(
    paths(
        agents::update_agent,
        agents::palettes,
        agents::set_appearance,
        agents::reset_avatar,
        agents::list_fallbacks,
        agents::set_fallbacks,
        staffing::propose_agent,
        staffing::apply_template,
        routing::list_tiers,
        routing::set_tiers,
        routing::get_rules,
        routing::set_rules,
        presets::set_chain,
        presets::list_presets,
        presets::create_preset,
        presets::update_preset,
        presets::delete_preset,
        presets::list_roles,
        presets::create_role,
        presets::update_role,
        presets::delete_role,
        structure::org_chart,
        structure::patch_department,
        structure::patch_team,
        structure::seat,
        structure::unseat,
        structure::reset_logo,
    ),
    components(schemas(
        super::model::org_admin::FigureState,
        super::model::org_admin::NewDepartment,
        super::model::org_admin::OrgRemoved,
    ))
)]
pub struct Doc;
