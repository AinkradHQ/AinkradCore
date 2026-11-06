//! A subscription account in a session (KAN-434, KAN-441 L5; gateway design §10 Q4): its token is a
//! leased ENV variable, the opposite of an API-key account (gateway only, never env). The shape
//! rule (claude only, `CLAUDE_CODE_OAUTH_TOKEN` only, env only, one account, no gateway grant) is
//! `ainkrad_proto::v2::subscription_problem`, applied at create, at launch and again by the runner.
//! What is here: the lease (after the account is checked live) and the module refusal.
//!
//! - **Never pooled.** A session names its subscription account itself, and nothing picks or fails
//!   over between accounts: a restart or resume leases the same secret again, and a subscription is
//!   alone in its pool.
//! - **Money.** No gateway serves it (`gateway_account_id` stays NULL), so no hold, no ledger row,
//!   no stop and no top-up exist for it; nothing writes a dollar cost for a plan that bills none.

use ainkrad_proto::v2::{SUBSCRIPTION_HARNESS, is_subscription_secret};

use super::*;
use crate::store::{accounts, providers, secrets};

fn refuse(why: impl Into<String>) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::InvalidArgs, why))
}

fn lift(e: secrets::Error) -> Refusal {
    match e {
        secrets::Error::Refused { message, .. } => refuse(message),
        secrets::Error::Db(e) => Refusal::Db(e),
    }
}

/// Whether `s` is a subscription account's secret.
pub(super) fn is_subscription(s: &store::SessionSecret) -> bool {
    is_subscription_secret(&s.name)
}

/// Why a session owned by a module may not name a subscription account: the ledger would record
/// the module's run from the harness's own meter at list price (a plan bills none), and its
/// agent, company and issue budgets would count dollars nobody paid. Refused, as an API-key
/// account is (`gateway::module_refusal`).
pub(super) fn module_refusal(secrets: &[store::SessionSecret]) -> Option<&'static str> {
    secrets.iter().any(is_subscription).then_some(
        "a module's session may not use a subscription account: its budgets would count a cost \
         the plan does not bill",
    )
}

/// Leases `secret` (a subscription account's token) to `s`'s runner for one start, as env. The
/// account is read live: deleted, disabled or any state but active is refused, and so is a
/// harness other than claude or a secret not delivered as env.
pub(super) async fn lease(
    app: &App,
    s: &Session,
    secret: &store::SessionSecret,
) -> Result<(String, i64), Refusal> {
    let Some((provider, id)) = crate::store::gateway::account_secret(&secret.name) else {
        return Err(refuse("the session's account does not exist"));
    };
    let account = match accounts::get(&app.pool, id).await {
        Err(secrets::Error::Refused {
            code: "not_found", ..
        }) => return Err(refuse("the subscription account no longer exists")),
        found => found.map_err(lift)?,
    };
    if account.secret_name != secret.name || account.provider != provider {
        return Err(refuse(
            "the session's account is not the one its secret names",
        ));
    }
    if account.state != "active" {
        return Err(refuse(format!(
            "the subscription account is {}, not active",
            account.state
        )));
    }
    let def = providers::get(&app.pool, provider).await.map_err(lift)?;
    if s.harness != SUBSCRIPTION_HARNESS || def.harness != s.harness {
        return Err(refuse(
            "a subscription account's token goes only to the claude harness",
        ));
    }
    let delivery: Option<String> =
        sqlx::query_scalar("SELECT delivery FROM core_secrets WHERE name = ?")
            .bind(&secret.name)
            .fetch_optional(&app.pool)
            .await?;
    if delivery.as_deref() != Some("env") {
        return Err(refuse(
            "a subscription account's token is an environment variable, never a file",
        ));
    }
    secrets::lease_to(
        &app.pool,
        &secret.name,
        &s.runner,
        None,
        &s.created_by,
        AuditActor::System,
        &app.clock.now(),
        app.clock.unix(),
        Some("env"),
    )
    .await
    .map_err(lift)
}
