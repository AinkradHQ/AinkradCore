//! Governance: approvals, budgets and their guard, prices, skills, knowledge, artifacts.
//!
//! Slice S5 of the port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). This file is the
//! slice's seam with the rest of the module: it exports its routes, its per-route scopes, its
//! destructive routes, its company-owner rows and its OpenAPI document, and `api.rs`, `scopes.rs`,
//! `scope.rs` and `spec.rs` aggregate them. Handlers live in submodules next to this file.
//!
//! Left out of the monolith's `api/v1/{gov,money,library,artifacts}` until their blockers land:
//! the cost reports (`getCompanyCosts`, `getSprintCosts`, `listUnpriced`: run table, S7), the
//! artifact file serving (`downloadArtifact`, `previewArtifact`: the Core gives the module no
//! artifacts directory) and the project permission policy routes (`getProjectPolicy`,
//! `setProjectPolicy`: the project's, S4).

use ainkrad_core_server::api::App;
use axum::Router;
use axum::routing::{get, post, put};
use utoipa::OpenApi;

mod approvals;
mod artifacts;
mod library;
mod money;

use super::model::governance as model;

/// The slice's routes, relative to `/modules/citadel/v1`.
pub fn routes() -> Router<App> {
    Router::new()
        .route("/companies/{id}/approvals", get(approvals::list_approvals))
        .route("/approvals/{id}/decide", post(approvals::decide))
        .route(
            "/approvals/{id}/decide-forge",
            post(approvals::decide_forge),
        )
        .route("/approvals/{id}/raise", post(approvals::raise))
        .route("/prices", get(money::list_prices).post(money::set_price))
        .route("/prices/history", get(money::price_history))
        .route("/companies/{id}/costs", get(money::company_costs))
        .route("/companies/{id}/ledger", get(money::company_ledger))
        .route(
            "/companies/{id}/budgets",
            put(money::set_budget).post(money::create_budget),
        )
        .route("/budgets/{id}", axum::routing::delete(money::delete_budget))
        .route(
            "/companies/{id}/skills",
            get(library::list_skills).post(library::publish_skill),
        )
        .route("/projects/{id}/knowledge", get(library::list_knowledge))
        .route("/knowledge/{id}/accept", post(library::accept))
        .route("/knowledge/{id}/reject", post(library::reject))
        .route("/knowledge/{id}/retire", post(library::retire))
        .route("/knowledge/{id}/supersede", post(library::supersede))
        .route("/artifacts", get(artifacts::list))
        .route("/artifacts/{id}", get(artifacts::get))
        .route("/companies/{id}/artifact-usage", get(artifacts::usage))
        .route("/companies/{id}/artifacts", post(artifacts::upload))
        .route("/artifacts/{id}/content", get(artifacts::download))
}

/// `(method, template, scope)` of the slice's routes below `admin` (`api::scopes`): every GET a
/// phone may see (no file content: serving is not here), and the approval decision.
pub const SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/companies/{id}/approvals", "read"),
    ("POST", "/approvals/{id}/decide", "approve"),
    ("POST", "/approvals/{id}/decide-forge", "approve"),
    ("POST", "/approvals/{id}/raise", "approve"),
    ("GET", "/prices", "read"),
    ("GET", "/prices/history", "read"),
    ("GET", "/companies/{id}/costs", "read"),
    ("GET", "/companies/{id}/ledger", "read"),
    ("GET", "/companies/{id}/skills", "read"),
    ("GET", "/projects/{id}/knowledge", "read"),
    ("GET", "/artifacts", "read"),
    ("GET", "/artifacts/{id}", "read"),
    ("GET", "/companies/{id}/artifact-usage", "read"),
];

/// GET templates that deliberately stay `admin` (`api::scopes::ADMIN_READS`): an artifact's bytes
/// (non-text types are never scanned for secrets).
pub const ADMIN_READS: &[&str] = &["/artifacts/{id}/content"];

/// `(method, template)` of the slice's routes that need a live step-up (`Module::destructive`):
/// deleting a budget, and setting one in place (it may raise a cap, which widens spend).
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/budgets/{id}"),
    ("PUT", "/companies/{id}/budgets"),
    // Approving a budget overrun with a raise widens spend, so it is its own step-up route.
    ("POST", "/approvals/{id}/raise"),
    // A PR merge or a workflow-file push has real effects: its own step-up route.
    ("POST", "/approvals/{id}/decide-forge"),
    // Accepting a knowledge entry may apply a profile proposal.
    ("POST", "/knowledge/{id}/accept"),
    ("POST", "/companies/{id}/artifacts"),
];

/// `(path segment, SQL)` rows for `scope::OWNERS`: the company that owns what `segment/{id}` names
/// (`approvals`, `artifacts` and `knowledge` are in `scope::OWNERS` already).
pub const OWNERS: &[(&str, &str)] = &[("budgets", crate::store::gov::BUDGET_COMPANY)];

/// The slice's `#[utoipa::path]` routes and schemas (operation ids unprefixed: `spec` adds
/// `citadel`; schema names must not clash with the Core's or another slice's).
#[derive(OpenApi)]
#[openapi(
    paths(
        approvals::list_approvals,
        approvals::decide,
        approvals::raise,
        approvals::decide_forge,
        money::list_prices,
        money::set_price,
        money::price_history,
        money::company_costs,
        money::company_ledger,
        money::set_budget,
        money::create_budget,
        money::delete_budget,
        library::list_skills,
        library::publish_skill,
        library::list_knowledge,
        library::accept,
        library::reject,
        library::retire,
        library::supersede,
        artifacts::list,
        artifacts::get,
        artifacts::usage,
        artifacts::upload,
        artifacts::download,
    ),
    components(schemas(
        model::Approval,
        model::BudgetScope,
        model::BudgetStanding,
        model::Price,
        model::PriceVersion,
        model::CompanySkill,
        model::Knowledge,
        model::Artifact,
        approvals::Decision,
        approvals::Raise,
        money::NewPrice,
        money::BudgetBody,
        library::NewSkillVersion,
        library::KnowledgeDecision,
        library::Retirement,
        library::Supersession,
        artifacts::ArtifactUsage,
        money::CostReport,
        money::LedgerEntry,
    ))
)]
pub struct Doc;
