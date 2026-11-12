//! A subscription account in a session (KAN-434, KAN-441 L5; gateway design §10 Q4): its token is a
//! leased ENV variable, the opposite of an API-key account (gateway only, never env). The shape
//! rule (claude only, `CLAUDE_CODE_OAUTH_TOKEN` only, env only, one account, no gateway grant) is
//! `ainkrad_proto::v2::subscription_problem`, applied at create, at launch and again by the runner.
//! What is here: the lease (after the account is checked live) and the module refusal.
//!
//! - **Never pooled.** A session names its subscription account itself, and nothing picks or fails
//!   over between accounts: a restart or resume leases the same secret again, and a subscription is
//!   alone in its pool.
//! - **Money.** No gateway serves it (`gateway_account_id` stays NULL), so no hold, stop or top-up
//!   exists for it. Its ledger rows are the harness meter's (`store::usage_meter`): tokens, unpriced.

use ainkrad_proto::v2::{
    AGENT_DRIVER, CAP_SUBSCRIPTION_ENV, SUBSCRIPTION_HARNESS, is_subscription_secret,
};

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
    crate::store::health::recover(&app.pool, id, &app.clock.now()).await?;
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
    if !crate::store::health::startable(
        &account.state,
        account.state_reason.as_deref(),
        s.state == "interrupted",
    ) {
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
    mint(app, s, secret).await
}

/// The lease itself, then a second look at the account. A disable or delete that commits before
/// this lease is written has revoked every lease it knew of and cannot see this one, so the state
/// is read again after it and the lease is revoked here if the account is no longer active. One
/// that commits after revokes it itself (`accounts::set_state`).
async fn mint(
    app: &App,
    s: &Session,
    secret: &store::SessionSecret,
) -> Result<(String, i64), Refusal> {
    let got = secrets::lease_to(
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
    .map_err(lift)?;
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT state, state_reason FROM core_accounts WHERE secret_name = ?")
            .bind(&secret.name)
            .fetch_optional(&app.pool)
            .await?;
    let resumed = s.state == "interrupted";
    if !row
        .as_ref()
        .is_some_and(|(st, why)| crate::store::health::startable(st, why.as_deref(), resumed))
    {
        // A disabled or deleted account has no lease left. A cooldown or health state only refuses
        // this start: another session's unredeemed lease is its own, and only ours is dropped.
        if row.as_ref().is_none_or(|(st, _)| st == "disabled") {
            crate::store::account_keys::revoke_leases(&app.pool, &secret.name).await?;
            return Err(refuse(
                "the subscription account was disabled or deleted while the session started",
            ));
        }
        crate::store::account_keys::revoke_unused_lease(&app.pool, &got.0).await?;
        return Err(refuse(
            "the subscription account became unavailable while the session started",
        ));
    }
    Ok(got)
}

/// [`mint`] without the first, live check of the account: the interleaving a test cannot otherwise
/// reach (the account goes away after that check, before the lease is written).
#[cfg(feature = "test-support")]
pub async fn mint_for_tests(
    app: &App,
    s: &Session,
    secret: &store::SessionSecret,
) -> Result<(String, i64), Refusal> {
    mint(app, s, secret).await
}

/// Whether `runner` lists the `subscription-env` command beside its agent driver's ops: it applies
/// the subscription rules before it redeems a lease. An older runner does not, and is never sent
/// the token.
pub(super) fn lists_cap(runner: &RunnerState) -> bool {
    runner
        .drivers
        .iter()
        .filter(|d| d.name == AGENT_DRIVER)
        .any(|d| d.commands.iter().any(|c| c == CAP_SUBSCRIPTION_ENV))
}

/// [`account_refusal`] plus, for a session holding a subscription's token, the capability above.
pub(super) fn account_refusal(
    runner: &RunnerState,
    secrets: &[store::SessionSecret],
) -> Option<String> {
    super::account_refusal(runner).or_else(|| {
        (secrets.iter().any(is_subscription) && !lists_cap(runner)).then(|| {
            "a session holding a subscription account's token needs a runner that checks it \
             before redeeming (the subscription-env command): update the runner"
                .to_owned()
        })
    })
}

/// Sets account `id`'s state, and when a subscription account leaves `active` also kills the live
/// sessions holding its token (the lease is revoked; a running harness still has the value). This
/// does NOT revoke the token at Anthropic: the user does that.
pub async fn set_state(
    app: &App,
    id: i64,
    state: &str,
    reason: Option<&str>,
    until: Option<&str>,
    by_device: &str,
    actor: AuditActor,
) -> Result<accounts::Account, secrets::Error> {
    let now = app.clock.now();
    let a =
        accounts::set_state(&app.pool, id, state, reason, until, by_device, actor, &now).await?;
    if state != "active" && crate::store::account_keys::subscription_provider(&a.provider) {
        stop_live(
            app,
            &a.secret_name,
            &format!("the subscription account is {state}"),
        )
        .await;
    }
    Ok(a)
}

/// Deletes account `id`, and kills the live sessions holding a subscription account's token.
pub async fn delete(
    app: &App,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), secrets::Error> {
    let a = accounts::get(&app.pool, id).await?;
    accounts::delete(&app.pool, id, by_device, actor).await?;
    if crate::store::account_keys::subscription_provider(&a.provider) {
        stop_live(app, &a.secret_name, "the subscription account was deleted").await;
    }
    Ok(())
}

/// Kills every live session whose secrets name `secret_name`, audited `agent.killed` with `why`. A
/// session the runner cannot be asked about (away, no elevation) is logged and left to end at its
/// next start, which refuses the account.
async fn stop_live(app: &App, secret_name: &str, why: &str) {
    let live = match store::live(&app.pool).await {
        Ok(l) => l,
        Err(e) => return tracing::warn!(error = %e, "listing the sessions to stop"),
    };
    for s in live
        .iter()
        .filter(|s| s.secrets.iter().any(|x| x.name == secret_name))
    {
        let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
        let stop = Command::AgentStop(ainkrad_proto::v2::AgentStop {
            session: s.id.clone(),
            kill: true,
        });
        match ask(app, &s.runner, stop, app.agents.config.answer, proof).await {
            Ok(ev) => {
                let at = app.clock.now();
                if let Err(e) = store::apply(&app.pool, &s.id, &ev, &at).await {
                    tracing::warn!(session = s.id, error = %e, "storing a killed session's answer");
                }
                let details = json!({"reason": why});
                let act = store::action(
                    &app.pool,
                    s,
                    AuditActor::System,
                    "agent.killed",
                    None,
                    details,
                    "core",
                );
                if let Err(e) = act.await {
                    tracing::warn!(session = s.id, error = %e, "auditing a killed session");
                }
            }
            Err(e) => tracing::warn!(
                session = s.id,
                why = e.message,
                "stopping a session of a gone account"
            ),
        }
    }
}
