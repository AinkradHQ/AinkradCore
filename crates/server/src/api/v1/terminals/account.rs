//! `POST /runner/terminals/{id}/account` (0.10.5): the runner's `claude` shim asks for the account
//! of the person who opened terminal `id` (`agents::terminal`). Only the runner that hosts the
//! terminal may ask, only while it runs, and only for a terminal its opener may still open: a
//! device still usable that holds `terminal`.

use super::*;
use crate::agents::terminal::{self as term, Pick};

/// What a terminal's tool asks for.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RunnerTerminalAccount {
    /// The tool typed in the terminal: `claude` only for now.
    pub tool: String,
}

/// A Claude plan leased to the terminal's runner as env, for the one process the shim starts.
#[derive(Serialize, ToSchema)]
pub struct TerminalAccountLease {
    /// The account's id.
    pub account: i64,
    /// The account's name: its display name, else its label.
    pub name: String,
    /// `l_…`, redeemable once by this runner (`POST /secret-leases/redeem`) until `expires_at`.
    pub lease: String,
    /// The variable the token goes in: `CLAUDE_CODE_OAUTH_TOKEN`.
    pub var: String,
    pub expires_at: Timestamp,
}

// No `Debug` that prints a lease.
impl std::fmt::Debug for TerminalAccountLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalAccountLease")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

#[utoipa::path(post, path = "/api/v1/runner/terminals/{id}/account",
    operation_id = "runnerTerminalAccount", tag = "terminals",
    params(("id" = String, Path, description = "The terminal's id")),
    request_body = RunnerTerminalAccount,
    responses(
        (status = 200, description = "The first Claude plan of the opener's AI order that can take \
            work, leased as env to the calling runner (audited `secret.leased`). Only the runner \
            hosting the running terminal may call it (`runner` scope)", body = TerminalAccountLease),
        (status = 400, description = "A tool other than `claude`"),
        (status = 404, description = "`no_account` (the message is the line to show), or no such \
            running terminal on this runner")))]
pub async fn runner_account(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(req): Json<RunnerTerminalAccount>,
) -> Response {
    match answer(&app, &me, &id, &req).await {
        Ok(l) => Json(l).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn answer(
    app: &App,
    me: &Caller,
    id: &str,
    req: &RunnerTerminalAccount,
) -> Result<TerminalAccountLease, ApiError> {
    if req.tool != term::TOOL {
        return Err(ApiError::bad_request(
            "a terminal is given an account for claude only",
        ));
    }
    let gone = || ApiError::not_found("no such terminal");
    let (runner, status, opener): (String, String, Option<String>) =
        sqlx::query_as("SELECT runner, status, opened_by FROM core_terminals WHERE id = ?")
            .bind(id)
            .fetch_optional(&app.pool)
            .await?
            .ok_or_else(gone)?;
    if me.device.kind != "runner" || runner != me.device.id || status != "running" {
        return Err(gone());
    }
    let opener = opener.ok_or_else(gone)?;
    let may = gov::get_device(&app.pool, &opener)
        .await?
        .is_some_and(|d| d.usable() && d.scopes.iter().any(|s| s == "terminal"));
    if !may {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "forbidden_scope",
            "the device that opened this terminal may no longer open terminals",
        ));
    }
    match term::lease(app, id, &runner, &opener).await? {
        Pick::Leased {
            account,
            lease,
            expires,
        } => Ok(TerminalAccountLease {
            account: account.id,
            name: account
                .display_name
                .clone()
                .unwrap_or(account.label.clone()),
            lease,
            var: ainkrad_proto::v2::SUBSCRIPTION_VAR.to_owned(),
            expires_at: ts(&iso_of_unix(expires)),
        }),
        Pick::None(why) => Err(ApiError::new(
            axum::http::StatusCode::NOT_FOUND,
            "no_account",
            why,
        )),
    }
}
