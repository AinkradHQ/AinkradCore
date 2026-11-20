//! The secrets broker v0 (E2-07, `store::secrets`): store, list, rotate and delete secrets
//! (scope `admin`; every write needs a step-up), grant a runner a lease (`admin`, step-up) and the
//! runner's redemption (scope `runner`, the lease's own runner only). A value reaches a person
//! only through `secret_export` (a fresh step-up) and `reveal` (E1); this file's routes return none.
//!
//! Bodies are parsed here, not by axum's `Json`: a serde error can quote the input, and the
//! input may be the value. A malformed body gets one fixed message.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::iso_of_unix;
use crate::store::secrets::{self as store, Error, Meta, NewValue};

/// A secret, never its value.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretInfo {
    /// `[a-z][a-z0-9_.-]{0,63}`.
    pub name: String,
    /// The device that stored it, `d_…`.
    pub owner: String,
    /// The runner devices it may be leased to (its scope); empty: none.
    pub runners: Vec<String>,
    /// How a runner hands it to a session: `env`, `file` or `askpass`.
    pub delivery: String,
    /// 1 when stored, one more per rotation.
    pub version: i64,
    /// The value's length in bytes.
    pub size: i64,
    /// The master key it is sealed under.
    pub key_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// `text`, `multiline`, `file` or `env_bundle`. `size` is a file's decoded length.
    pub kind: Option<String>,
    /// One line: what it is for.
    pub description: Option<String>,
    /// A `file` secret's name on the runner, and its octal mode (`0600`).
    pub file_name: Option<String>,
    pub file_mode: Option<String>,
    /// The group it belongs to (`/api/v1/secret-groups`); none for no group.
    pub group: Option<String>,
    /// The runners a lease may go to: its own, else its group's.
    pub effective_runners: Option<Vec<String>>,
    /// When a runner last redeemed it; none before the first redemption.
    pub last_used_at: Option<Timestamp>,
    /// How many redemptions.
    pub use_count: Option<i64>,
}

impl From<Meta> for SecretInfo {
    fn from(m: Meta) -> Self {
        Self {
            name: m.name,
            owner: m.owner,
            runners: m.runners,
            delivery: m.delivery,
            version: m.version,
            size: m.size,
            key_id: m.key_id,
            created_at: ts(&m.created_at),
            updated_at: ts(&m.updated_at),
            kind: Some(m.kind),
            description: Some(m.description),
            file_name: m.file_name,
            file_mode: m.file_mode.map(|m| format!("{m:04o}")),
            group: m.group,
            effective_runners: Some(m.effective_runners),
            last_used_at: super::types::opt_ts(m.last_used_at.as_deref()),
            use_count: Some(m.use_count),
        }
    }
}

/// A new secret. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewSecret {
    pub name: String,
    /// UTF-8 text, at most `secrets.max_bytes`; for kind `file` the file's bytes in standard
    /// base64 (at most 1 MiB decoded); written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Runner device ids it may be leased to; default none (a group's runners then apply).
    pub runners: Option<Vec<String>>,
    /// `env` (the default), `file` or `askpass`.
    pub delivery: Option<String>,
    /// `text` (the default), `multiline`, `file` or `env_bundle` (`NAME=value` lines).
    pub kind: Option<String>,
    /// One line, at most 200 characters.
    pub description: Option<String>,
    /// Required for kind `file`: `[A-Za-z0-9._-]{1,64}`.
    pub file_name: Option<String>,
    /// Kind `file`: an octal mode the owner can read, `0400` to `0777`; default `0600`.
    pub file_mode: Option<String>,
    /// The name of a group made with `createSecretGroup`; one level.
    pub group: Option<String>,
}

/// A rotation: the new value, and optionally a new scope or delivery. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct RotateSecret {
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    pub runners: Option<Vec<String>>,
    pub delivery: Option<String>,
    /// Omitted keeps the kind; the other fields are those of `createSecret`, omitted keeps them.
    pub kind: Option<String>,
    pub description: Option<String>,
    pub file_name: Option<String>,
    pub file_mode: Option<String>,
    /// An empty string leaves the group.
    pub group: Option<String>,
}

/// A lease to grant.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewLease {
    /// The runner's device id, `d_…`; it must be in the secret's scope.
    pub runner: String,
    /// Its lifetime; default and most `secrets.lease_secs`.
    pub ttl_secs: Option<i64>,
}

/// A granted lease: hand `lease` to the runner, which redeems it once before `expires_at`.
/// No `Debug` (review L4): a log line must never print a live lease.
#[derive(Serialize, ToSchema)]
pub struct LeaseGrant {
    /// `l_…`; only its runner can redeem it.
    pub lease: String,
    pub expires_at: Timestamp,
}

/// A lease to redeem. No `Debug` (review L4).
#[derive(Deserialize, ToSchema)]
pub struct RedeemLease {
    pub lease: String,
}

/// A redeemed secret, for the runner only. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct LeasedSecret {
    pub name: String,
    pub version: i64,
    pub delivery: String,
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Drop it by then, or at the session's end.
    pub expires_at: Timestamp,
    /// `text`, `multiline`, `file` (the value is base64: decode it, write it as `file_name`
    /// with `file_mode`) or `env_bundle` (the value is `NAME=value` lines).
    pub kind: Option<String>,
    pub file_name: Option<String>,
    pub file_mode: Option<String>,
}

pub(super) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

/// An octal mode, `600` or `0600`.
pub(super) fn mode(m: Option<&str>) -> Result<Option<i64>, ApiError> {
    m.map(|m| {
        i64::from_str_radix(m, 8)
            .ok()
            .filter(|_| (3..=4).contains(&m.len()))
            .ok_or_else(|| ApiError::bad_request("file_mode is an octal mode such as 0600"))
    })
    .transpose()
}

pub(super) fn sealer(app: &App) -> Result<&SecretBox, ApiError> {
    app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Db(e) => e.into(),
            Error::Refused { code, message } => {
                let status = match code {
                    "not_found" => StatusCode::NOT_FOUND,
                    "lease_expired" => StatusCode::GONE,
                    "secrets_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
                    "secrets_disabled"
                    | "real_secret_refused"
                    | "conflict"
                    | "limit_reached"
                    | "subscription_pool_alone"
                    | "no_runner"
                    | "login_required"
                    | "login_state" => StatusCode::CONFLICT,
                    _ => StatusCode::BAD_REQUEST,
                };
                ApiError::new(status, code, message)
            }
        }
    }
}

fn name(name: &str) -> Result<&str, ApiError> {
    match store::valid_name(name) {
        true => Ok(name),
        false => Err(ApiError::not_found("no such secret")),
    }
}

/// The general routes never write or delete a provider-account key: an account's key, its
/// masked tail and its audit trail move together, through the accounts API only.
fn not_account(name: &str) -> Result<&str, ApiError> {
    match name.starts_with(store::ACCOUNT_PREFIX) {
        true => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "provider-account keys are managed through the accounts API",
        )),
        false => Ok(name),
    }
}

/// A module's own secrets (its master key and the like: `brain.*`, `leyline.*`) are not rotated,
/// deleted, leased or revealed through the general routes; the module opens them itself.
fn not_module(name: &str) -> Result<&str, ApiError> {
    match name.split_once('.').map(|(m, _)| m) {
        Some("brain" | "leyline") => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "a module's own secret is not managed here",
        )),
        _ => Ok(name),
    }
}

/// Project secrets (`/projects/{id}/secrets`) are not written, moved or deleted here: the project
/// routes check that no spec still uses one. `secret` is the existing secret, `group` the group a
/// request asks for.
async fn not_project(app: &App, secret: Option<&str>, group: Option<&str>) -> Result<(), ApiError> {
    let named = group.is_some_and(|g| g.starts_with(crate::store::project_secrets::GROUP_PREFIX));
    let member = match secret {
        Some(n) => {
            let mut conn = app.pool.acquire().await?;
            crate::store::project_secrets::is_member(&mut conn, n).await?
        }
        None => false,
    };
    match named || member {
        true => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "project secrets are managed through the project's secrets",
        )),
        false => Ok(()),
    }
}

/// A new global secret may not be named `<project-slug>.*`: that is the project's namespace, and
/// a look-alike outside its group must not exist.
async fn not_project_slug(app: &App, name: &str) -> Result<(), ApiError> {
    let Some((slug, _)) = name.split_once('.') else {
        return Ok(());
    };
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_projects WHERE slug = ?")
        .bind(slug)
        .fetch_one(&app.pool)
        .await?;
    match taken {
        0 => Ok(()),
        _ => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "that name belongs to a project; add it under the project's secrets",
        )),
    }
}

#[utoipa::path(get, path = "/api/v1/secrets", operation_id = "listSecrets", tag = "secrets",
    responses((status = 200, description = "Every secret, by name, without its value", body = Vec<SecretInfo>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<SecretInfo>> {
    let all = store::list(&app.pool).await?;
    // An account's key (`acct.*`) is the Accounts screen's: it is never a row here. (`store::list`
    // stays whole: the secret groups read it.)
    Ok(Json(
        all.into_iter()
            .filter(|m| !m.name.starts_with(store::ACCOUNT_PREFIX))
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/secrets", operation_id = "createSecret", tag = "secrets",
    request_body = NewSecret,
    responses((status = 200, description = "Stored, sealed (audited as `secret.created`). 409 \
        `secrets_disabled` (gate G-SEC, `secrets.mode` 0), `real_secret_refused` (mode 1 and a \
        value shaped like a real credential), `conflict` or `limit_reached`; 400 `too_large`; \
        503 `secrets_unavailable` (no master key)", body = SecretInfo)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<SecretInfo> {
    let b: NewSecret = parse(&body)?;
    not_account(&b.name)?;
    not_module(&b.name)?;
    not_project(&app, None, b.group.as_deref()).await?;
    not_project_slug(&app, &b.name).await?;
    let new = NewValue {
        value: &b.value,
        runners: b.runners.as_deref(),
        delivery: b.delivery.as_deref(),
        kind: b.kind.as_deref(),
        description: b.description.as_deref(),
        file_name: b.file_name.as_deref(),
        file_mode: mode(b.file_mode.as_deref())?,
        group: b.group.as_deref(),
    };
    let m = store::create(
        &app.pool,
        sealer(&app)?,
        &b.name,
        &new,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(m.into()))
}

#[utoipa::path(put, path = "/api/v1/secrets/{id}", operation_id = "rotateSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    request_body = RotateSecret,
    responses((status = 200, description = "A new version (audited as `secret.rotated`); the \
        refusals of `createSecret`", body = SecretInfo)))]
pub async fn rotate(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> ApiResult<SecretInfo> {
    let n = not_module(not_account(name(&n)?)?)?;
    let b: RotateSecret = parse(&body)?;
    // Widening which runners may lease a secret needs the app unlock, not just its scope.
    if b.runners.is_some() {
        super::stepup::require_unlock(&app, &me, &headers)?;
    }
    // Putting an existing secret in a group widens who may lease it: danger (E1 review M6).
    if b.group.as_deref().is_some_and(|g| !g.is_empty()) {
        super::stepup::require_elevated(&app, &me)?;
    }
    not_project(&app, Some(n), b.group.as_deref()).await?;
    let new = NewValue {
        value: &b.value,
        runners: b.runners.as_deref(),
        delivery: b.delivery.as_deref(),
        kind: b.kind.as_deref(),
        description: b.description.as_deref(),
        file_name: b.file_name.as_deref(),
        file_mode: mode(b.file_mode.as_deref())?,
        group: b.group.as_deref(),
    };
    let m = store::rotate(
        &app.pool,
        sealer(&app)?,
        n,
        &new,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(m.into()))
}

/// What a delete answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretDeleted {
    pub deleted: bool,
}

#[utoipa::path(delete, path = "/api/v1/secrets/{id}", operation_id = "deleteSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    responses((status = 200, description = "Deleted with its leases (audited as \
        `secret.deleted`); works whatever `secrets.mode` is", body = SecretDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
) -> ApiResult<SecretDeleted> {
    let n = not_module(not_account(name(&n)?)?)?;
    not_project(&app, Some(n), None).await?;
    store::delete(&app.pool, n, &me.device.id, BY).await?;
    Ok(Json(SecretDeleted { deleted: true }))
}

#[utoipa::path(post, path = "/api/v1/secrets/{id}/leases", operation_id = "leaseSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    request_body = NewLease,
    responses((status = 200, description = "A lease for one runner in the secret's scope, one \
        redemption, `ttl_secs` at most (audited as `secret.leased`). 409 `secrets_disabled` or \
        `limit_reached`; 400 when the runner is not in scope", body = LeaseGrant)))]
pub async fn lease(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    body: Bytes,
) -> ApiResult<LeaseGrant> {
    let n = not_module(name(&n)?)?;
    not_project(&app, Some(n), None).await?;
    let b: NewLease = parse(&body)?;
    let (lease, expires_at) = store::lease(
        &app.pool,
        n,
        &b.runner,
        b.ttl_secs,
        &me.device.id,
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await?;
    Ok(Json(LeaseGrant {
        lease,
        expires_at: ts(&iso_of_unix(expires_at)),
    }))
}

/// A secret's value, shown to the person who asked. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct RevealedSecret {
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
}

#[utoipa::path(post, path = "/api/v1/secrets/{id}/reveal", operation_id = "revealSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    responses((status = 200, description = "The plain value, for the app's Reveal (a fresh \
        step-up, audited as `secret.revealed`). 404 no such secret, 409 `secrets_disabled` or \
        `secrets_unavailable`, 400 for a provider account's key", body = RevealedSecret)))]
pub async fn reveal(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
) -> ApiResult<RevealedSecret> {
    let n = not_module(name(&n)?)?;
    not_project(&app, Some(n), None).await?;
    if let Err(wait) = app
        .auth
        .reveal_limit
        .take(&me.device.id, std::time::Instant::now())
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("too many reveals; wait {} s", wait.as_secs() + 1),
        ));
    }
    let value = store::reveal(&app.pool, sealer(&app)?, n, &me.device.id, BY).await?;
    Ok(Json(RevealedSecret { value }))
}

#[utoipa::path(post, path = "/api/v1/secret-leases/redeem", operation_id = "redeemSecretLease",
    tag = "secrets",
    request_body = RedeemLease,
    responses((status = 200, description = "The lease's runner (and only it) gets the value, \
        once (audited as `secret.redeemed`). 404 for a lease that is not this runner's or no \
        longer in scope, 410 `lease_expired` when spent or expired, 409 `secrets_disabled`",
        body = LeasedSecret)))]
pub async fn redeem(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<LeasedSecret> {
    let b: RedeemLease = parse(&body)?;
    if me.device.kind != "runner" {
        return Err(ApiError::not_found("no such lease"));
    }
    // A credential a module minted for this runner's session (`Module::credentials`): held in
    // memory, single use, outside the broker's tables but not its mode (`secrets.mode 0` stops
    // it like every other credential path).
    store::require_enabled(&app.pool).await?;
    if let Some(e) = app
        .agents
        .take_ephemeral(&b.lease, &me.device.id, app.clock.unix())
    {
        let hash = crate::auth::crypto::sha256(b.lease.as_bytes());
        let lease: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
        let event = ainkrad_core::audit::NewAuditEvent {
            actor: BY,
            action: "secret.redeemed".to_owned(),
            entity: None,
            details: serde_json::json!({"name": e.var, "runner": me.device.id, "lease": lease,
                                        "delivery": "env", "by_device": me.device.id})
            .to_string(),
        };
        crate::store::audit::append_one(&app.pool, &event).await?;
        return Ok(Json(LeasedSecret {
            name: e.var,
            version: 1,
            delivery: "env".to_owned(),
            value: e.value,
            expires_at: ts(&iso_of_unix(e.expires)),
            kind: None,
            file_name: None,
            file_mode: None,
        }));
    }
    let r = store::redeem(
        &app.pool,
        sealer(&app)?,
        &b.lease,
        &me.device.id,
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await?;
    Ok(Json(LeasedSecret {
        name: r.name,
        version: r.version,
        delivery: r.delivery,
        value: r.value,
        expires_at: ts(&iso_of_unix(r.expires_at)),
        kind: Some(r.kind),
        file_name: r.file_name,
        file_mode: r.file_mode.map(|m| format!("{m:04o}")),
    }))
}
