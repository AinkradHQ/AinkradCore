//! The session-shaped doors into [`on_signal`](super::on_signal): the account is found from the
//! session's own row, never from the signal.

use ainkrad_proto::v2::{GatewayReport, PlanLimit, UpstreamStatus};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

use super::super::agents::SessionSecret;
use super::super::{account_keys::subscription_provider, gateway::account_secret};
use super::{CLASSES, Signal, on_signal};

/// The Core's own gateway report on a session of `account` (`r.status` is the gateway's, not the
/// harness's): records the session's last upstream class and acts on it. Once per report: the
/// caller records only reports past the cursor.
pub async fn on_report(
    conn: &mut SqliteConnection,
    account: i64,
    session: &str,
    r: &GatewayReport,
    now: &str,
) -> Result<(), sqlx::Error> {
    let class = match r.status {
        UpstreamStatus::Ok => "ok",
        UpstreamStatus::RateLimited => "rate_limited",
        UpstreamStatus::Quota => "quota",
        UpstreamStatus::AuthFailed => "auth_failed",
        UpstreamStatus::ServerError => "server_error",
        UpstreamStatus::Unreachable => "unreachable",
        UpstreamStatus::RefusedAddress => "refused_address",
        UpstreamStatus::TlsFailed => "tls_failed",
        UpstreamStatus::Unknown => return Ok(()),
    };
    sqlx::query("UPDATE core_agent_sessions SET upstream_class = ? WHERE id = ?")
        .bind(class)
        .bind(session)
        .execute(&mut *conn)
        .await?;
    let signal = Signal::Gateway {
        status: r.status,
        retry_after: r.retry_after,
        reset_at: r.reset_at.as_deref(),
    };
    on_signal(conn, account, session, signal, now).await
}

/// The subscription account a harness signal of `session` is about: the one its own row names, and
/// none for a session a gateway serves (its health comes from the gateway's reports), a module's
/// session, or a session whose secret names no such account.
async fn harness_account(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT gateway_account_id, owner_module, secrets FROM core_agent_sessions WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    if r.try_get::<Option<i64>, _>("gateway_account_id")?.is_some()
        || r.try_get::<Option<String>, _>("owner_module")?.is_some()
    {
        return Ok(None);
    }
    let secrets: Vec<SessionSecret> =
        serde_json::from_str(&r.try_get::<String, _>("secrets")?).unwrap_or_default();
    let Some((name, id)) = secrets.iter().find_map(|s| {
        account_secret(&s.name)
            .filter(|(p, _)| subscription_provider(p))
            .map(|(_, id)| (&s.name, id))
    }) else {
        return Ok(None);
    };
    let held: bool = sqlx::query_scalar(
        "SELECT count(*) > 0 FROM core_accounts WHERE id = ? AND secret_name = ?",
    )
    .bind(id)
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    Ok(held.then_some(id))
}

/// A session ended with `outcome` (the runner's, so harness-influenced): a subscription session's
/// success starts its account's counts again, and a failure whose fingerprint is a class counts.
/// Called once per session, inside the transaction that ends it.
pub async fn on_end(
    conn: &mut SqliteConnection,
    session: &str,
    outcome: &Value,
    now: &str,
) -> Result<(), sqlx::Error> {
    let signal = match outcome["kind"].as_str() {
        Some("succeeded") => Signal::Success,
        Some("failed") => match outcome["fingerprint"].as_str() {
            Some(class) if CLASSES.contains(&class) => Signal::HarnessEnd { class },
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    if let Some(account) = harness_account(conn, session).await? {
        on_signal(conn, account, session, signal, now).await?;
    }
    Ok(())
}

/// A subscription session's plan-limit snapshot (`AgentEvents.plan_limit`), if it sent one.
pub async fn on_plan_limit(
    conn: &mut SqliteConnection,
    session: &str,
    plan: Option<&PlanLimit>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let Some(plan) = plan else { return Ok(()) };
    if let Some(account) = harness_account(conn, session).await? {
        on_signal(conn, account, session, Signal::HarnessPlan { plan }, now).await?;
    }
    Ok(())
}
