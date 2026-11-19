//! Exporting every secret to its owner (E2-6, D-4). `POST /secrets/export` is `admin` and a danger
//! route (a fresh step-up, like a lease), audited (`secret.exported`, the count only), rate limited
//! per device; no value is in a log, an event or an audit row, and no `Debug` type holds one. Not
//! in an export: provider-account keys (`acct.*`), a module's own secrets (`brain.*`, `leyline.*`)
//! and file secrets. Showing one value is E1's `POST /secrets/{id}/reveal` (`secrets::reveal`).

use std::sync::OnceLock;
use std::time::Instant;

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::secrets::sealer;
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::api::limit::Limiter;
use crate::store::secrets as store;

/// Exports a device may take at once, then per minute: stricter than a reveal, it is every value.
const BURST: u32 = 2;
const PER_MIN: f64 = 2.0;

/// One secret of an export. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct ExportedSecret {
    pub name: String,
    pub kind: Option<String>,
    pub group: Option<String>,
    pub file_name: Option<String>,
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
}

/// Every secret the Secrets screen lists, with its value. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct SecretsExport {
    pub count: i64,
    pub items: Vec<ExportedSecret>,
}

fn limiter() -> &'static Limiter {
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(BURST, PER_MIN / 60.0))
}

fn allow(device: &str) -> Result<(), ApiError> {
    limiter().take(device, Instant::now()).map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many secrets shown; wait a minute",
        )
    })
}

#[utoipa::path(post, path = "/api/v1/secrets/export", operation_id = "exportSecrets",
    tag = "secrets",
    responses((status = 200, description = "Every secret the Secrets screen lists with its \
        value, for a file the owner saves (audited once as `secret.exported` with the count; \
        needs a step-up). Provider-account keys, a module's own secrets and file secrets are not in it. 409 `secrets_disabled`; 429 \
        `rate_limited`; 503 `secrets_unavailable`", body = SecretsExport)))]
pub async fn export(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<SecretsExport> {
    allow(&me.device.id)?;
    let all = store::export_all(&app.pool, sealer(&app)?, &me.device.id, BY).await?;
    Ok(Json(SecretsExport {
        count: all.len() as i64,
        items: all
            .into_iter()
            .map(|e| ExportedSecret {
                name: e.name,
                kind: Some(e.kind),
                group: e.group,
                file_name: e.file_name,
                value: e.value,
            })
            .collect(),
    }))
}
