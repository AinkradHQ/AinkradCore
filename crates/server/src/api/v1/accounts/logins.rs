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
    /// A subscription provider: `claude-sub` (a pasted approval code), or the runner-bound
    /// `codex-sub` (a device code; the login stays on that runner and no token comes back).
    pub provider: String,
    /// The new account's label.
    pub label: String,
    /// The new account's free-text name (as `createAccount` takes it); default none.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Deprecated (API 103): the Core places a sign-in itself, on its own runner first. Still
    /// honoured when sent. A ChatGPT or OpenCode login then moves into the Core's vault; an
    /// Antigravity one stays on the runner it ran on.
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

/// One line the user typed into a guided sign-in. No `Debug`: it may be a pasted code.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginInputBody {
    /// Up to 512 printable characters, sent to the runner with Enter and dropped.
    #[schema(value_type = String)]
    pub text: Zeroizing<String>,
}

/// What a guided sign-in shows now. Text only, redacted; nothing here is a credential.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginScreenView {
    /// The last lines the sign-in's CLI printed.
    pub lines: Vec<String>,
    /// The sign-in page, once it printed one (https on the provider's own hosts).
    pub url: Option<String>,
    /// The device code, once it printed one.
    pub code: Option<String>,
    /// What the person does now (API 105), read from this screen: `starting` (the CLI is still
    /// getting there, or going back after a failed attempt; a menu it knows is answered for them), `open_url` (open `url` and sign
    /// in), `enter_code` (the CLI waits for a pasted code; `url`, when shown, is the page that gives
    /// it) or `finishing` (the CLI says it is signed in). `lines` are for a "Show details" view.
    #[schema(required = false)]
    pub stage: Option<String>,
    /// Why the last attempt on this screen failed, in plain words (the CLI then goes back and a new
    /// page follows: use the code from that one).
    #[schema(required = false)]
    pub message: Option<String>,
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
    /// The one-time device code to type on that page (`codex-sub`), from `open_url` on. Not a
    /// credential. Absent for a sign-in with no device code. A runner-bound sign-in takes no
    /// `/code`: it goes `open_url` then `storing` then `done` by itself once the user finishes.
    pub code: Option<String>,
    /// The new account, once `done`.
    pub account_id: Option<i64>,
    /// Why it `failed` or was `cancelled`; provider text passes the redactor.
    pub reason: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Ten minutes after it began; a sign-in open past it fails.
    pub expires_at: Timestamp,
    /// What the person does now (API 105): `starting`, `open_url` (open `url` and sign in),
    /// `enter_code` (paste the code the page gives: `claude-sub`), `finishing` (the code is in or
    /// the account is being stored), `done` or `failed` (also a cancelled one; see `message`). A
    /// guided sign-in (`agy-sub`, `opencode-sub`) is `starting` here until it showed a page:
    /// `getAccountLoginScreen` reads its live stage.
    #[schema(required = false)]
    pub stage: Option<String>,
    /// Why it failed, in plain words, when `stage` is `failed`.
    #[schema(required = false)]
    pub message: Option<String>,
}

impl From<Login> for AccountLogin {
    fn from(l: Login) -> Self {
        let (stage, message) = login::stage(&l);
        Self {
            id: l.id,
            provider: l.provider,
            label: l.label,
            runner: l.runner,
            state: l.state,
            url: l.url,
            code: l.code,
            account_id: l.account_id,
            reason: l.reason,
            created_at: ts(&l.created_at),
            updated_at: ts(&l.updated_at),
            expires_at: ts(&l.expires_at),
            stage: Some(stage.to_owned()),
            message,
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
    let l = login::start(
        &app,
        &me,
        &b.provider,
        &b.label,
        b.display_name.as_deref(),
        b.runner.as_deref(),
    )
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

#[utoipa::path(post, path = "/api/v1/accounts/logins/{id}/input",
    operation_id = "sendAccountLoginInput", tag = "accounts",
    params(("id" = String, Path, description = "The sign-in's id")), request_body = LoginInputBody,
    responses((status = 200, description = "One line went to the guided sign-in's terminal on its \
        runner (once, never stored or logged). Only for a provider whose sign-in is guided \
        (`opencode-sub`); 409 `login_state` unless the sign-in is `open_url`; 400 for a line that is \
        not printable text; 409 `runner_failed`. No step-up beyond the one that started it", body = AccountLogin)))]
pub async fn send_login_input(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AccountLogin> {
    let b: LoginInputBody = parse(&body)?;
    let l = login::input(&app, &me, &id, b.text).await.map_err(err)?;
    Ok(Json(l.into()))
}

#[utoipa::path(get, path = "/api/v1/accounts/logins/{id}/screen",
    operation_id = "getAccountLoginScreen", tag = "accounts",
    params(("id" = String, Path, description = "The sign-in's id")),
    responses((status = 200, description = "The redacted screen of a guided sign-in, read from its \
        runner now. Only the device that started it; 409 `login_state` unless `open_url`", body = LoginScreenView)))]
pub async fn get_login_screen(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<LoginScreenView> {
    let s = login::screen(&app, &me, &id).await.map_err(err)?;
    let (stage, message) = login::screen_stage(&s);
    Ok(Json(LoginScreenView {
        stage: Some(stage.to_owned()),
        message,
        lines: s.lines,
        url: s.url,
        code: s.code,
    }))
}

#[utoipa::path(post, path = "/api/v1/accounts/{id}/move-to-core", operation_id = "moveAccountToCore",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "The login of a ChatGPT or OpenCode plan that signed in \
        on one runner is now in the Core's vault (API 103): sealed, lent to whichever runner runs a \
        session, its runner-bound record gone and its home on the runner wiped once that runner \
        confirms (audited `account.moved_to_core`, `secret.rotated`). Nothing changes on any \
        refusal. 409 `not_portable` (Antigravity: its login is in the OS keyring), `runner_offline`, \
        `runner_too_old`, `runner_failed`, `real_secret_refused`; 400 for an account that is not \
        runner-bound; 503 `secrets_unavailable`", body = ProviderAccount)))]
pub async fn move_to_core(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProviderAccount> {
    let id = num(&id, "account")?;
    crate::agents::lend::move_to_core(&app, id, &me.device.id, BY)
        .await
        .map_err(err)?;
    get(State(app), Extension(me), Path(id.to_string())).await
}

/// A login the harness of a session refreshed, sent back by the session's runner.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReturnedCredential {
    /// Each credential file the harness changed (`auth.json`, …) and its JSON text. A secret: no
    /// `Debug`, never logged or echoed.
    #[schema(value_type = std::collections::BTreeMap<String, String>)]
    pub files: ainkrad_proto::v2::Bundle,
}

#[utoipa::path(post, path = "/api/v1/runner/sessions/{id}/credential",
    operation_id = "runnerSessionCredential", tag = "accounts",
    params(("id" = String, Path, description = "The session's id")), request_body = ReturnedCredential,
    responses((status = 204, description = "The Core-held login the session was lent, refreshed by its \
        harness, is resealed in the vault (API 103; audited `secret.rotated`). Only the runner \
        running the session (`runner` scope), only for the plan account it holds, only the \
        harness's own credential files and only the same account's (identity claims, else key set). \
        Unchanged files are a no-op"),
        (status = 400, description = "Not the harness's files, not JSON, or another account's login"),
        (status = 404, description = "No such session on this runner")))]
pub async fn runner_credential(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<axum::http::StatusCode, ApiError> {
    if me.device.kind != "runner" {
        return Err(ApiError::not_found("no such session on this runner"));
    }
    let b: ReturnedCredential = parse(&body)?;
    crate::agents::lend::take_back(&app, &me.device.id, &id, &b.files)
        .await
        .map_err(err)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
