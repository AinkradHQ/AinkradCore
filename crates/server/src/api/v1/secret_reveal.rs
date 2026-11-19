//! Showing and exporting secrets to their owner (E2-6, D-4). `POST /secrets/{id}/reveal` and
//! `POST /secrets/export` are `admin` and destructive (a live step-up, like a lease), audited
//! (`secret.revealed`, `secret.exported`), rate limited per device; the value is in no log, no event and no audit row, and no `Debug`
//! type holds it. A provider-account key (`acct.*`) is never shown: it is the Accounts screen's.

use std::sync::OnceLock;
use std::time::Instant;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::secrets::sealer;
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::api::limit::Limiter;
use crate::store::secrets as store;

/// How long the app keeps a shown value on screen, in seconds (the mockup's 15 s timer).
pub const HIDE_AFTER_SECS: i64 = 15;

/// Reveals a device may take at once, then per minute. An export counts as one.
const BURST: u32 = 5;
const PER_MIN: f64 = 5.0;

/// A shown value. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct RevealedSecret {
    pub name: String,
    pub version: i64,
    /// `text`, `multiline`, `file` (the value is base64) or `env_bundle`.
    pub kind: Option<String>,
    pub file_name: Option<String>,
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// The client hides the value, and wipes it from memory, after this many seconds.
    pub hide_after_secs: i64,
}

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

#[utoipa::path(post, path = "/api/v1/secrets/{id}/reveal", operation_id = "revealSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    responses((status = 200, description = "The value, once, for the owner's screen (audited as \
        `secret.revealed`; needs a step-up). 404 for no such secret; 400 for a provider-account \
        key; 409 `secrets_disabled`; 429 `rate_limited` (5 a minute per device); 503 \
        `secrets_unavailable`", body = RevealedSecret)))]
pub async fn reveal(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
) -> ApiResult<RevealedSecret> {
    if !store::valid_name(&n) {
        return Err(ApiError::not_found("no such secret"));
    }
    allow(&me.device.id)?;
    let r = store::reveal(&app.pool, sealer(&app)?, &n, &me.device.id, BY).await?;
    Ok(Json(RevealedSecret {
        name: r.name,
        version: r.version,
        kind: Some(r.kind),
        file_name: r.file_name,
        value: r.value,
        hide_after_secs: HIDE_AFTER_SECS,
    }))
}

#[utoipa::path(post, path = "/api/v1/secrets/export", operation_id = "exportSecrets",
    tag = "secrets",
    responses((status = 200, description = "Every secret the Secrets screen lists with its \
        value, for a file the owner saves (audited once as `secret.exported` with the count; \
        needs a step-up). Provider-account keys are not in it. 409 `secrets_disabled`; 429 \
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
