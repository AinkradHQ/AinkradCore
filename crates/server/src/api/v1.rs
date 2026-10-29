//! The client API (E10): everything under `/api/v1`, for the Ainkrad app. Every request
//! passes, in order:
//!
//! 1. The shared gate (`super::refusal`): `Host` must be the server's name (403), no
//!    `Origin` (403). Unlike the runner and MCP routes, a query string is allowed, but only
//!    the paging and filter names in [`QUERY`]; anything else, a `?token=` above all, is a
//!    400, so a key never ends up in a URL.
//! 2. The failure bucket of the client's address (`limit`): too many failed authentications
//!    and every request from that address is a 429 until it refills.
//! 3. A live device key as `Authorization: Bearer` (401 otherwise, counted as a failure).
//! 4. The device's request bucket (429).
//!
//! Single admin (#18): whichever device calls, it acts as the admin user, and every write is
//! audited as that user through the same store calls the CLI and the agents use.
//!
//! The contract (E10.1) is `api/openapi.json` at the repo root, generated from the
//! `#[utoipa::path]` annotations here by `spec` (`make contract`); `make test` fails when it
//! is stale. Its versioning rule is in `types`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::DeviceKeyId;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::UserId;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use serde::Deserialize;
use utoipa::IntoParams;

use super::limit::Limiter;
use super::{App, bearer, refusal};
use crate::store::gov::authorize_device_key;

mod account_usage;
mod accounts;
mod agent_stats;
mod agents;
mod artifacts;
mod audit;
mod avatars;
mod chains;
mod companies;
mod controls;
mod devices;
mod disk;
pub mod events;
mod fallbacks;
mod gov;
mod hire;
mod hub;
mod issues;
mod library;
mod me;
mod model;
mod money;
mod notifications;
mod org;
mod pairing;
mod probe;
mod profile;
mod project_charts;
mod project_logo;
mod projects;
mod quest;
mod reads;
mod repos;
mod requirements;
mod roles;
mod routing;
mod runners;
mod runs;
pub mod scope;
mod settings;
pub mod spec;
mod structure;
mod stuck;
mod trace;
pub use trace::{ApiError, ApiResult};
pub mod types;

/// The one admin user every device acts as (#18).
pub const ADMIN: UserId = UserId(1);
pub const BY: AuditActor = AuditActor::User(ADMIN);

/// Query parameter names any `/api/v1` route may take; nothing else is let through.
pub const QUERY: &[&str] = &[
    "after",
    "limit",
    "pending",
    "since",
    "requirement",
    "issue",
    "agent",
    "kind",
    "live",
    "state",
    "bucket",
    "until",
    "harness",
    "model",
    "before",
    "target",
    "actor",
];

/// A page of a list: the cursor to continue after (its meaning is per route) and how many.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Paging {
    pub after: Option<i64>,
    pub limit: Option<u32>,
}

/// The device a request authenticated as, for the handlers.
#[derive(Debug, Clone, Copy)]
pub struct Device(pub DeviceKeyId);

/// The address a request came from, past any trusted proxy (`limit::client_ip`).
#[derive(Debug, Clone)]
pub struct Client(pub String);

/// The client API's rate limits.
pub struct Limits {
    /// Failed authentications, by client address.
    pub failures: Limiter,
    /// Requests, by device key.
    pub requests: Limiter,
}

impl Limits {
    /// Buckets of `burst` refilled at `per_min`: failures, then requests.
    fn of([fail_burst, fail_per_min, burst, per_min]: [i64; 4]) -> Self {
        Self {
            failures: Limiter::new(fail_burst as u32, fail_per_min as f64 / 60.0),
            requests: Limiter::new(burst as u32, per_min as f64 / 60.0),
        }
    }

    const KEYS: [Key; 4] = [
        Key::ApiAuthFailureBurst,
        Key::ApiAuthFailuresPerMin,
        Key::ApiRequestBurst,
        Key::ApiRequestsPerMin,
    ];

    /// The limits from the `api.*` settings (E15.17), read once at start.
    pub async fn from_settings(pool: &sqlx::SqlitePool) -> Result<Self, sqlx::Error> {
        let mut v = [0; 4];
        for (v, key) in v.iter_mut().zip(Self::KEYS) {
            *v = crate::store::settings::value(pool, key, Scope::Server).await?;
        }
        Ok(Self::of(v))
    }
}

impl Default for Limits {
    /// The settings' defaults: ten wrong keys, then one more every six seconds; 120 requests
    /// at once, then 20 a second.
    fn default() -> Self {
        Self::of(Self::KEYS.map(Key::default))
    }
}

fn too_many(wait: std::time::Duration) -> Response {
    let mut response = ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests; retry later",
    )
    .into_response();
    let secs = wait.as_secs().max(1).to_string();
    if let Ok(v) = HeaderValue::from_str(&secs) {
        response.headers_mut().insert(header::RETRY_AFTER, v);
    }
    response
}

/// Whether every query parameter name is one of [`QUERY`].
fn query_ok(query: &str) -> bool {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .all(|pair| QUERY.contains(&pair.split('=').next().unwrap_or(pair)))
}

/// The one route that needs no device key (`pairing`).
pub fn pairing_router(app: App) -> Router {
    pairing::public_router(app)
}

pub fn router(app: App) -> Router {
    Router::new()
        .route(
            "/api/v1/accounts",
            get(accounts::list).post(accounts::create),
        )
        .route(
            "/api/v1/accounts/{id}/companies/{company_id}",
            put(accounts::assign).delete(accounts::unassign),
        )
        .route("/api/v1/accounts/{id}", delete(accounts::delete))
        .route("/api/v1/accounts/{id}/status", post(accounts::set_status))
        .route("/api/v1/accounts/{id}/plan", put(accounts::set_plan))
        .route(
            "/api/v1/accounts/{id}/limits",
            post(account_usage::set_limit),
        )
        .route(
            "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
            delete(account_usage::clear_limit),
        )
        .route("/api/v1/accounts/usage", get(account_usage::usage))
        .route(
            "/api/v1/companies/{id}/account-usage",
            get(account_usage::company_usage),
        )
        .route("/api/v1/devices", get(devices::list).post(devices::create))
        .route("/api/v1/devices/{id}", delete(devices::revoke))
        .route(
            "/api/v1/push-token",
            put(devices::set_push).delete(devices::clear_push),
        )
        .route("/api/v1/events", get(events::replay))
        .route("/api/v1/events/ws", get(events::ws))
        .route("/api/v1/events/latest", get(events::latest))
        .route("/api/v1/audit", get(audit::list))
        .route("/api/v1/me", get(me::me))
        .route(
            "/api/v1/companies",
            get(companies::list).post(companies::create),
        )
        .route("/api/v1/companies/{id}", put(companies::update))
        .route(
            "/api/v1/companies/{id}/logo",
            get(companies::get_logo)
                .put(companies::upload_logo)
                .delete(companies::reset_logo),
        )
        .route("/api/v1/companies/{id}/org", get(org::org_chart))
        .route(
            "/api/v1/companies/{id}/agents",
            get(org::list_agents).post(hire::propose_agent),
        )
        .route("/api/v1/companies/{id}/requests", post(org::submit_request))
        .route(
            "/api/v1/companies/{id}/projects",
            get(projects::list_projects).post(projects::create_project),
        )
        .route("/api/v1/companies/{id}/approvals", get(gov::list_approvals))
        .route("/api/v1/companies/{id}/costs", get(gov::company_costs))
        .route(
            "/api/v1/companies/{id}/costs/tasks",
            get(routing::task_costs),
        )
        .route(
            "/api/v1/agents/{id}",
            get(org::get_agent).patch(agents::update),
        )
        .route(
            "/api/v1/companies/{id}/departments",
            post(structure::create_department),
        )
        .route(
            "/api/v1/departments/{id}",
            patch(structure::update_department).delete(structure::delete_department),
        )
        .route(
            "/api/v1/departments/{id}/teams",
            post(structure::create_team),
        )
        .route(
            "/api/v1/teams/{id}",
            patch(structure::update_team).delete(structure::delete_team),
        )
        .route(
            "/api/v1/teams/{id}/members/{agent_id}",
            put(structure::seat).delete(structure::unseat),
        )
        .route("/api/v1/agents/{id}/wake", post(agents::wake))
        .route("/api/v1/agents/{id}/terminate", post(agents::terminate))
        .route("/api/v1/agents/{id}/runs", get(runs::list_agent_runs))
        .route("/api/v1/agents/{id}/skills", get(reads::agent_skills))
        .route("/api/v1/companies/{id}/runs", get(reads::company_runs))
        .route(
            "/api/v1/companies/{id}/questions",
            get(reads::open_questions),
        )
        .route("/api/v1/companies/{id}/spend", get(reads::spend_series))
        .route(
            "/api/v1/companies/{id}/costs/breakdown",
            get(reads::spend_breakdown),
        )
        .route("/api/v1/issues/{id}/diff", get(reads::issue_diff))
        .route("/api/v1/issues/{id}/prs", get(reads::issue_prs))
        .route("/api/v1/agents/{id}/pause", post(controls::pause_agent))
        .route("/api/v1/agents/{id}/resume", post(controls::resume_agent))
        .route(
            "/api/v1/companies/{id}/pause",
            post(controls::pause_company),
        )
        .route(
            "/api/v1/companies/{id}/resume",
            post(controls::resume_company),
        )
        .route("/api/v1/runs/{id}/stop", post(controls::stop_run))
        .route("/api/v1/runs/{id}/messages", post(controls::message_run))
        .route("/api/v1/runners/{id}/wake", post(controls::wake_runner))
        .route("/api/v1/issues/{id}/nudge", post(controls::nudge_issue))
        .route(
            "/api/v1/issues/{id}/backlog",
            post(controls::move_to_backlog),
        )
        .route(
            "/api/v1/prices",
            get(money::list_prices).post(money::set_price),
        )
        .route(
            "/api/v1/companies/{id}/budgets",
            put(money::set_budget).post(money::create_budget),
        )
        .route(
            "/api/v1/companies/{id}/chain-presets",
            get(chains::list).post(chains::create),
        )
        .route(
            "/api/v1/chain-presets/{id}",
            put(chains::update).delete(chains::delete),
        )
        .route("/api/v1/agents/{id}/chain", put(chains::set_chain))
        .route(
            "/api/v1/companies/{id}/notifications",
            get(notifications::get).put(notifications::set),
        )
        .route(
            "/api/v1/companies/{id}/notifications/test",
            post(notifications::test),
        )
        .route("/api/v1/agents/{id}/stats", get(agent_stats::get))
        .route(
            "/api/v1/companies/{id}/roles",
            get(roles::list).post(roles::create),
        )
        .route(
            "/api/v1/roles/{id}",
            put(roles::update).delete(roles::delete),
        )
        .route(
            "/api/v1/companies/{id}/costs/unpriced",
            get(money::list_unpriced),
        )
        .route(
            "/api/v1/issues/{id}/reassign",
            post(controls::reassign_issue),
        )
        .route(
            "/api/v1/approvals/{id}/allow-for-issue",
            post(controls::allow_for_issue),
        )
        .route(
            "/api/v1/agents/{id}/appearance",
            put(avatars::set_appearance),
        )
        .route(
            "/api/v1/agents/{id}/avatar",
            get(avatars::get)
                .put(avatars::upload)
                .delete(avatars::reset),
        )
        .route("/api/v1/avatars/palettes", get(avatars::palettes))
        .route(
            "/api/v1/agents/{id}/fallbacks",
            get(fallbacks::list).put(fallbacks::set),
        )
        .route(
            "/api/v1/agents/{id}/tiers",
            get(routing::list_tiers).put(routing::set_tiers),
        )
        .route(
            "/api/v1/runners",
            get(runners::list).post(runners::register),
        )
        .route("/api/v1/runners/{id}", delete(runners::remove))
        .route("/api/v1/runners/{id}/probe", post(runners::probe))
        .route(
            "/api/v1/runners/{id}/drain",
            post(runners::drain_runner).delete(runners::undrain_runner),
        )
        .route("/api/v1/runners/{id}/logs", get(runners::logs))
        .route(
            "/api/v1/runners/{id}/power-nap",
            put(runners::set_power_nap),
        )
        .route("/api/v1/runners/{id}/disk", get(disk::get_disk))
        .route("/api/v1/settings", get(settings::list_server))
        .route("/api/v1/settings/{scope}", get(settings::list))
        .route(
            "/api/v1/settings/{scope}/{key}",
            get(settings::get)
                .put(settings::set)
                .delete(settings::reset),
        )
        .route(
            "/api/v1/settings/{scope}/{key}/history",
            get(settings::history),
        )
        .route("/api/v1/stuck", get(org::list_stuck))
        .route("/api/v1/runs/{id}", get(runs::get_run))
        .route("/api/v1/runs/{id}/transcript", get(runs::transcript))
        .route("/api/v1/approvals/{id}/decision", post(gov::decide))
        .route(
            "/api/v1/projects/{id}",
            get(projects::get_project).put(quest::update_project),
        )
        .route(
            "/api/v1/projects/{id}/issues",
            get(projects::list_issues).post(issues::create_issue),
        )
        .route("/api/v1/projects/{id}/backlog", get(projects::backlog))
        .route(
            "/api/v1/projects/{id}/repos",
            get(repos::list).post(repos::add),
        )
        .route(
            "/api/v1/projects/{id}/logo",
            get(project_logo::get)
                .put(project_logo::upload)
                .delete(project_logo::reset),
        )
        .route("/api/v1/projects/{id}/repos/probe", post(repos::probe))
        .route("/api/v1/projects/{id}/repo-order", put(repos::order))
        .route(
            "/api/v1/repos/{id}",
            put(repos::update).delete(repos::remove),
        )
        .route("/api/v1/repos/{id}/primary", post(repos::primary))
        .route(
            "/api/v1/issues/{id}/repos",
            get(repos::get_issue_repos).put(repos::set_issue_repos),
        )
        .route(
            "/api/v1/projects/{id}/profile",
            get(profile::get).put(profile::update),
        )
        .route("/api/v1/projects/{id}/timing", get(runs::timing))
        .route("/api/v1/projects/{id}/cfd", get(project_charts::cfd))
        .route(
            "/api/v1/projects/{id}/profile/preview",
            get(project_charts::preview),
        )
        .route(
            "/api/v1/projects/{id}/tier-rules",
            get(routing::get_rules).put(routing::set_rules),
        )
        .route(
            "/api/v1/projects/{id}/epics",
            get(projects::list_epics).post(projects::create_epic),
        )
        .route("/api/v1/epics/{id}", patch(projects::update_epic))
        .route(
            "/api/v1/projects/{id}/sprints",
            get(projects::list_sprints).post(projects::plan_sprint),
        )
        .route("/api/v1/projects/{id}/velocity", get(projects::velocity))
        .route(
            "/api/v1/projects/{id}/wip",
            get(projects::wip_limits).post(projects::set_wip_limit),
        )
        .route("/api/v1/sprints/{id}", delete(projects::delete_sprint))
        .route("/api/v1/sprints/{id}/close", post(projects::close_sprint))
        .route("/api/v1/sprints/{id}/report", get(projects::sprint_report))
        .route("/api/v1/sprints/{id}/costs", get(gov::sprint_costs))
        .route("/api/v1/artifacts", get(artifacts::list))
        .route("/api/v1/artifacts/{id}", get(artifacts::get))
        .route("/api/v1/artifacts/{id}/content", get(artifacts::download))
        .route("/api/v1/artifacts/{id}/preview", get(artifacts::preview))
        .route(
            "/api/v1/companies/{id}/artifact-usage",
            get(artifacts::usage),
        )
        .route("/api/v1/requirements", get(requirements::list))
        .route(
            "/api/v1/requirements/{id}",
            get(requirements::get).put(requirements::rename),
        )
        .route("/api/v1/requirements/{id}/tree", get(requirements::tree))
        .route(
            "/api/v1/requirements/{id}/thread",
            get(hub::get).post(hub::post),
        )
        .route(
            "/api/v1/issues/{id}",
            get(issues::get_issue).patch(issues::update_issue),
        )
        .route("/api/v1/issues/{id}/activity", get(issues::activity))
        .route("/api/v1/issues/{id}/transition", post(issues::transition))
        .route("/api/v1/issues/{id}/blockers", get(issues::list_blockers))
        .route(
            "/api/v1/issues/{id}/blockers/{blocker_id}",
            put(issues::link_blocker).delete(issues::unlink_blocker),
        )
        .route("/api/v1/issues/{id}/move", post(issues::move_issue))
        .route("/api/v1/issues/{id}/estimate", post(issues::estimate))
        .route("/api/v1/issues/{id}/epic", post(issues::set_epic))
        .route("/api/v1/issues/{id}/sprint", post(issues::set_sprint))
        .route(
            "/api/v1/issues/{id}/comments",
            get(issues::list_comments).post(issues::post_comment),
        )
        .merge(hire::routes())
        .merge(pairing::routes())
        .merge(stuck::routes())
        .merge(quest::routes())
        .merge(library::routes())
        // Modules sit inside the same gate: they never authenticate for themselves.
        .merge(crate::module::mount(&app.modules))
        // Inner: the company a request works in (E15.14), checked once it is authenticated.
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            scope::company_scope,
        ))
        // Refused writes, authenticated, cross-company refusals included (`trace`).
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            trace::audit_refusals,
        ))
        .route_layer(middleware::from_fn_with_state(app.clone(), client_gate))
        .with_state(app)
}

async fn client_gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    if let Some((status, why)) = refusal(&app, req.uri(), req.headers(), query_ok) {
        tracing::warn!(%status, why, "client request refused");
        return ApiError::new(status, "refused", why).into_response();
    }
    let client = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(
            || "local".to_owned(),
            |c| {
                let xff = req.headers().get_all("x-forwarded-for").iter();
                let xff = xff.filter_map(|v| v.to_str().ok());
                super::limit::client_ip(c.0.ip(), xff, &app.trusted_proxies).to_string()
            },
        );
    let limits = Arc::clone(&app.limits);
    let now = Instant::now();
    if let Err(wait) = limits.failures.check(&client, now) {
        return too_many(wait);
    }
    let failed = |why: &'static str| {
        tracing::warn!(client, why, "device key refused");
        // The bucket was not empty a moment ago; a race only lets one more through.
        limits.failures.take(&client, now).ok();
        ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", why).into_response()
    };
    let Some(key) = bearer(req.headers()).map(str::to_owned) else {
        return failed("missing device key");
    };
    req.headers_mut().remove(header::AUTHORIZATION);
    let device = match authorize_device_key(&app.pool, &key, &app.clock.now()).await {
        Ok(Some(device)) => device,
        Ok(None) => return failed("invalid or revoked device key"),
        Err(e) => return ApiError::from(e).into_response(),
    };
    if let Err(wait) = limits.requests.take(&device.id.0.to_string(), now) {
        return too_many(wait);
    }
    req.extensions_mut().insert(Device(device.id));
    req.extensions_mut().insert(Client(client));
    next.run(req).await
}

#[cfg(test)]
mod tests;
