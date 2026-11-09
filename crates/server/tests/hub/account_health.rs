//! Account health through the hub (KAN-438 S3): an upstream 429 in a gateway report, answered by a
//! runner played by hand, cools the account exactly once; the session that reported it runs on;
//! and a new session on the cooled account is refused at start, not at its first request.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::{accounts, secrets};
use ainkrad_proto::v2::*;

use super::gateway::{W, command, events, started, until, up, usage, world};
use super::subscription::{make, sub, up as sub_up};

fn rate_limited(seq: u64) -> GatewayReport {
    GatewayReport {
        kind: GatewayReportKind::Upstream,
        status: UpstreamStatus::RateLimited,
        model: None,
        retry_after: Some(120),
        ..usage(seq, 0, 0)
    }
}

#[tokio::test]
async fn a_gateway_429_cools_the_account_once_and_a_new_session_on_it_is_refused() {
    let mut w = world("health-429", None).await;
    started(&mut w, u64::MAX).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    // The report, and its resend with the next read: one change of state.
    let ev = events(&w.session, AgentState::Running, vec![rate_limited(1)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 1));
    let first = accounts::get(&w.core.app.pool, w.account.id).await.unwrap();
    // The resend of report 1 carries a much longer ask: if the cursor did not drop it, the open
    // window would be extended to it.
    let again = GatewayReport {
        retry_after: Some(3600),
        ..rate_limited(1)
    };
    let ev = events(&w.session, AgentState::Running, vec![again]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // The next read is only sent once that answer is stored.
    let (_stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 1));
    let a = accounts::get(&w.core.app.pool, w.account.id).await.unwrap();
    assert_eq!(
        (a.state.as_str(), a.state_reason.as_deref()),
        ("cooling", Some("rate_limited"))
    );
    assert_eq!(a.state_until, first.state_until, "a resend changes nothing");
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'account.state_set'")
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    let class: Option<String> =
        sqlx::query_scalar("SELECT upstream_class FROM core_agent_sessions WHERE id = ?")
            .bind(&w.session)
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(class.as_deref(), Some("rate_limited"));
    // The reporting session runs on (a cooldown does not kill it).
    let s = ainkrad_core_server::store::agents::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert!(s.live());
    // A fresh session on the same account is refused at its start.
    let second = super::gateway::start(&w.core, &w.runner, &w.account).await;
    until("the refusal", &w.core, &second, |s| !s.live()).await;
    let s = ainkrad_core_server::store::agents::get(&w.core.app.pool, &second)
        .await
        .unwrap()
        .unwrap();
    assert!(
        s.outcome.unwrap().to_string().contains("cooling"),
        "the outcome says why"
    );
}

#[tokio::test]
async fn a_start_succeeds_once_the_window_has_ended_through_lazy_recovery() {
    let (core, fake, runner, account) = up("health-recover", true, None).await;
    // A cooldown whose end has passed, and one still ahead.
    let set = |until: &'static str| {
        sqlx::query(
            "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', \
             state_until = ? WHERE id = ?",
        )
        .bind(until)
        .bind(account.id)
    };
    set("2999-01-01T00:00:00.000Z")
        .execute(&core.app.pool)
        .await
        .unwrap();
    let blocked = super::gateway::start(&core, &runner, &account).await;
    until("the refusal", &core, &blocked, |s| !s.live()).await;
    set("2000-01-01T00:00:00.000Z")
        .execute(&core.app.pool)
        .await
        .unwrap();
    let session = super::gateway::start(&core, &runner, &account).await;
    let mut w = W {
        core,
        fake,
        runner,
        account,
        session,
    };
    started(&mut w, u64::MAX).await;
    until("the start", &w.core, &w.session, |s| s.state == "running").await;
    let a = accounts::get(&w.core.app.pool, w.account.id).await.unwrap();
    assert_eq!(a.state, "active");
    let recovered: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'account.state_set' \
         AND details LIKE '%\"recovered\"%'",
    )
    .fetch_one(&w.core.app.pool)
    .await
    .unwrap();
    assert_eq!(recovered, 1, "recovery is audited");
}

#[tokio::test]
async fn a_start_refused_on_a_cooling_account_leaves_another_sessions_lease() {
    let w = sub_up("health-lease").await;
    let (pool, id) = (&w.core.app.pool, w.account.id);
    let (now, unix) = (w.core.app.clock.now(), w.core.app.clock.unix());
    let sealer = w.core.app.secrets.as_deref().unwrap();
    // Another session's lease, not redeemed yet.
    let (other, _) = secrets::lease(
        pool,
        &w.account.secret_name,
        &w.runner,
        None,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', \
         state_until = '2999-01-01T00:00:00.000Z' WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let minted =
        service::subscription::mint_for_tests(&w.core.app, &row, &sub(&w.account)[0]).await;
    assert!(
        minted.is_err(),
        "a fresh start is refused on a cooling account"
    );
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(live, 1, "only the refused start's own lease was dropped");
    let got = secrets::redeem(
        pool,
        sealer,
        &other,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await;
    assert!(got.is_ok(), "the other session's lease still redeems");
}
