//! Subscription sign-in routes (KAN-441 L1; plan `2026-11-05-claude-subscription-sign-in`). All
//! `admin`; starting one is a step-up (it begins a sign-in on a runner and ends in a stored
//! credential). A login is state only: no route, event or audit row carries the token or the
//! approval code, and the code's body type has no `Debug` and parses its own errors.

use super::*;
use crate::agents::login;
use crate::store::logins::Login;

/// Starts a sign-in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewLogin {
    /// A subscription provider: `claude-sub`.
    pub provider: String,
    /// The new account's label.
    pub label: String,
    /// A runner device id; absent, the best ready runner that has the provider's harness.
    #[serde(default)]
    pub runner: Option<String>,
}

/// The approval code the user pasted. No `Debug`: it is a one-time secret.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginCode {
    /// 8 to 512 of letters, digits and `-_.~#:+/=`; passed to the runner and dropped.
    #[schema(value_type = String)]
    pub code: Zeroizing<String>,
}

/// Where a sign-in has got to. Never a token or a code.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountLogin {
    pub id: String,
    pub provider: String,
    pub label: String,
    /// The runner doing the sign-in.
    pub runner: String,
    /// `starting`, `open_url` (open `url`, then send the code), `waiting_code` (the code is with
    /// the runner), `storing`, `done` (see `account_id`), `failed` (see `reason`) or `cancelled`.
    pub state: String,
    /// The sign-in URL, from `open_url` on.
    pub url: Option<String>,
    /// The new account, once `done`.
    pub account_id: Option<i64>,
    /// Why it `failed` or was `cancelled`; provider text passes the redactor.
    pub reason: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Ten minutes after it began; a sign-in open past it fails.
    pub expires_at: Timestamp,
}

impl From<Login> for AccountLogin {
    fn from(l: Login) -> Self {
        Self {
            id: l.id,
            provider: l.provider,
            label: l.label,
            runner: l.runner,
            state: l.state,
            url: l.url,
            account_id: l.account_id,
            reason: l.reason,
            created_at: ts(&l.created_at),
            updated_at: ts(&l.updated_at),
            expires_at: ts(&l.expires_at),
        }
    }
}

#[utoipa::path(post, path = "/api/v1/accounts/logins", operation_id = "startAccountLogin",
    tag = "accounts", request_body = NewLogin,
    responses((status = 200, description = "A sign-in began on a runner (audited as \
        `account.login_started`, event `account.login.started`); poll it for the URL. 409 \
        `no_runner` (none is ready with the harness and sign-in support), `conflict` (the label \
        is taken or open), `secrets_disabled` or `real_secret_refused` (a gate the stored token \
        would meet is closed), `limit_reached`; 400 for a provider with no browser sign-in or a \
        bad label; 503 `secrets_unavailable`. A step-up", body = AccountLogin)))]
pub async fn start_login(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AccountLogin> {
    let b: NewLogin = parse(&body)?;
    let l = login::start(&app, &me, &b.provider, &b.label, b.runner.as_deref())
        .await
        .map_err(err)?;
    Ok(Json(l.into()))
}

#[utoipa::path(get, path = "/api/v1/accounts/logins/{id}", operation_id = "getAccountLogin",
    tag = "accounts", params(("id" = String, Path, description = "The sign-in's id")),
    responses((status = 200, description = "Its state: never a token or a code. Only the device \
        that started it sees it; 404 otherwise", body = AccountLogin)))]
pub async fn get_login(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountLogin> {
    Ok(Json(login::get(&app, &me, &id).await.map_err(err)?.into()))
}

#[utoipa::path(post, path = "/api/v1/accounts/logins/{id}/code",
    operation_id = "sendAccountLoginCode", tag = "accounts",
    params(("id" = String, Path, description = "The sign-in's id")), request_body = LoginCode,
    responses((status = 200, description = "The code went to the runner (once, never stored or \
        logged); the sign-in is `waiting_code` until the account is stored. 409 `login_state` \
        unless the sign-in is `open_url`; 400 for a code of the wrong shape (never echoed). No \
        step-up beyond the one that started it", body = AccountLogin)))]
pub async fn send_login_code(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AccountLogin> {
    let b: LoginCode = parse(&body)?;
    let l = login::code(&app, &me, &id, b.code).await.map_err(err)?;
    Ok(Json(l.into()))
}

#[utoipa::path(delete, path = "/api/v1/accounts/logins/{id}", operation_id = "cancelAccountLogin",
    tag = "accounts", params(("id" = String, Path, description = "The sign-in's id")),
    responses((status = 200, description = "Cancelled (audited as `account.login_cancelled`, \
        event `account.login.failed` with the reason `cancelled`) and the runner told to drop \
        it; one that already ended is returned as it is", body = AccountLogin)))]
pub async fn cancel_login(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountLogin> {
    Ok(Json(
        login::cancel(&app, &me, &id).await.map_err(err)?.into(),
    ))
}
