//! `claude` typed in a Core terminal (0.10.5): the runner's `claude` shim asks for the person's
//! account, and the first Claude plan in their AI order that can take work now is leased to the
//! terminal's runner as env, exactly as an AI session's subscription token is
//! (`subscription::mint_to`: the same lease, the same second look). The runner redeems it, and the
//! shim starts `claude` with `CLAUDE_CODE_OAUTH_TOKEN` in that one process's environment.
//!
//! - **Only a plan, for now.** An API-key account is served only by the gateway, which is wired to an
//!   AI session's sandbox and ledger; a runner-bound login (Codex, OpenCode) lives in the runner's
//!   hidden state, which a shell never reaches. Both are skipped, and named when nothing else is left.
//! - **The AI order, and the account's own state.** Disabled, cooling, limited or unhealthy accounts
//!   are skipped, in order; nothing is held, so a terminal takes no slot of the account's cap and no
//!   budget room from AI sessions.
//! - Each lease is recorded (`core_terminal_account_uses`) and listed with the account's sessions.

use ainkrad_proto::v2::{SUBSCRIPTION_HARNESS, SUBSCRIPTION_PROVIDERS};

use super::*;
use crate::store::{accounts, chains, secrets};

/// What the Core answers a terminal's `claude`.
pub enum Pick {
    /// `lease` (env, `CLAUDE_CODE_OAUTH_TOKEN`) redeemable once by the runner until `expires`.
    Leased {
        account: Box<accounts::Account>,
        lease: String,
        expires: i64,
    },
    /// Nothing usable: the one line the shim prints.
    None(&'static str),
}

/// The only tool a terminal is given an account for.
pub const TOOL: &str = SUBSCRIPTION_HARNESS;

/// Leases the first usable Claude plan of `opener`'s AI order to `runner`, for terminal `terminal`.
pub async fn lease(app: &App, terminal: &str, runner: &str, opener: &str) -> Result<Pick, Refusal> {
    let user = chains::user_of(&app.pool, opener).await?;
    let order = chains::order::get(&app.pool, user).await?;
    let mut api_key = false;
    for item in order.items.iter().filter(|i| i.harness == TOOL) {
        if !SUBSCRIPTION_PROVIDERS.contains(&item.provider.as_str()) {
            api_key = true;
            continue;
        }
        crate::store::health::recover(&app.pool, item.account, &app.clock.now()).await?;
        let a = match accounts::get(&app.pool, item.account).await {
            Ok(a) => a,
            Err(secrets::Error::Db(e)) => return Err(e.into()),
            Err(_) => continue,
        };
        if !crate::store::health::startable(&a.state, a.state_reason.as_deref(), false) {
            continue;
        }
        let delivery: Option<String> =
            sqlx::query_scalar("SELECT delivery FROM core_secrets WHERE name = ?")
                .bind(&a.secret_name)
                .fetch_optional(&app.pool)
                .await?;
        if delivery.as_deref() != Some("env") {
            continue;
        }
        match subscription::mint_to(app, &a.secret_name, runner, opener, false).await {
            Ok((lease, expires)) => {
                let now = app.clock.now();
                sqlx::query(
                    "INSERT INTO core_terminal_account_uses (terminal, account_id, tool, runner, \
                     created_at) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(terminal)
                .bind(a.id)
                .bind(TOOL)
                .bind(runner)
                .bind(&now)
                .execute(&app.pool)
                .await?;
                sqlx::query("UPDATE core_accounts SET last_used_at = ? WHERE id = ?")
                    .bind(&now)
                    .bind(a.id)
                    .execute(&app.pool)
                    .await?;
                return Ok(Pick::Leased {
                    account: Box::new(a),
                    lease,
                    expires,
                });
            }
            Err(Refusal::Db(e)) => return Err(e.into()),
            // Not in the runner's scope, the lease cap, gone meanwhile: the next one is tried.
            Err(_) => {}
        }
    }
    Ok(Pick::None(if api_key {
        "Your AI order has only Anthropic API keys for Claude, and a terminal signs in with a \
         Claude plan: add one in Accounts"
    } else {
        "No Claude plan in your AI order can take work now: add one in Accounts"
    }))
}
