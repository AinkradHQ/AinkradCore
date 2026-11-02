//! Seeding a live server (KAN-275): the CLI hook (`admin::seed_command`) refuses a running
//! server, so the same seed arrives here. `admin` scope (deny by default, never a phone read) and
//! a step-up route; the body is the seed's own type, which carries names and kinds only and
//! refuses any other field, so no credential can ride in it. One transaction, idempotent, and one
//! `citadel.seed.applied` audit row holding counts, the size, the SHA-256 and the device.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use axum::extract::State;
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::Serialize;
use sha2::Digest;
use utoipa::{OpenApi, ToSchema};

use super::scope::Acting;
use crate::admin::{self, Seed};

pub fn routes() -> Router<App> {
    Router::new().route("/admin/seed", post(apply_seed))
}

/// Adds companies (and may change nothing else): a bulk write by an operator, so a step-up.
pub const DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/admin/seed")];

#[derive(Debug, Serialize, ToSchema)]
pub struct SeedApplied {
    /// Companies added.
    pub added: usize,
    /// Companies named in the seed that exist under another kind (left as they are).
    pub kind_mismatch: usize,
}

#[utoipa::path(post, path = "/admin/seed", operation_id = "applySeed", tag = "admin",
    request_body = Seed,
    responses(
        (status = 200, description = "The seed, applied in one transaction (audited as \
            `citadel.seed.applied`); applying it again adds nothing", body = SeedApplied),
        (status = 400, description = "An unknown field, a bad kind or name, or too many companies")))]
pub async fn apply_seed(
    State(app): State<App>,
    acting: Acting,
    Extension(me): Extension<Caller>,
    body: Result<Json<Seed>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<SeedApplied> {
    // A seed is not per company: a request pinned to one company is a mistake.
    if acting.0.is_some() {
        return Err(ApiError::bad_request("a seed is not scoped to a company"));
    }
    // The rejection text can quote the body (a smuggled field's value): say only that it is bad.
    let Json(seed) = body.map_err(|_| ApiError::bad_request("invalid Citadel seed"))?;
    admin::check(&seed).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let canonical = serde_json::to_vec(&seed).unwrap_or_default();
    let applied = admin::apply_audited(
        &app.pool,
        seed,
        BY,
        serde_json::json!({"via": "api", "by_device": me.device.id,
            "bytes": canonical.len(), "sha256": hex(&sha2::Sha256::digest(&canonical))}),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "applying a seed failed");
        ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the seed could not be applied",
        )
    })?;
    Ok(Json(SeedApplied {
        added: applied.added,
        kind_mismatch: applied.kind_mismatch,
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(OpenApi)]
#[openapi(
    paths(apply_seed),
    components(schemas(Seed, admin::CompanySeed, SeedApplied))
)]
pub struct Doc;
