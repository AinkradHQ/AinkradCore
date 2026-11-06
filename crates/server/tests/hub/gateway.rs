//! The auth gateway wired into the Core (KAN-435 G5), end to end through the hub with a runner played
//! by hand (`Fake`): the grant a start carries (and no env secret), the reports it answers with
//! recorded in the ledger and acknowledged on the next read, a budget that runs out sending
//! `agent.limit` 0 and then `agent.stop`, and an upstream `auth_failed` that disables an account
//! only when a one-shot `gateway.test` says the provider refuses the key too. The ops reach a runner
//! that lists the `gateway` capability, as the real driver does (it never lists them by name).

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::hub::HubConfig;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_core_server::store::budgets::{self, NewBudget};
use ainkrad_core_server::store::{accounts, prices};
use ainkrad_proto::runner::{Isolation, Outcome};
use ainkrad_proto::v2::*;
use serde_json::json;

use super::{Core, Fake, agents, quick, random32};

const KEY: &str = "throwaway-account-value-one-5a91c3";

pub(super) struct W {
    pub(super) core: Core,
    pub(super) fake: Fake,
    pub(super) runner: String,
    pub(super) account: accounts::Account,
    pub(super) session: String,
}

fn driver(gateway: bool) -> DriverInfo {
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    // What a real runner lists: the capabilities, never `agent.limit` or `gateway.test` by name.
    commands.push("egress-filter".to_owned());
    if gateway {
        commands.push(CAP_GATEWAY.to_owned());
    }
    DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 2,
        streams: Some(32),
        ..DriverInfo::default()
    }
}

/// A Core with a Linux runner (a sandbox, `gateway` listed or not), an account with a price, and
/// an account budget of `budget` tokens when given.
pub(super) async fn up(
    name: &str,
    gateway: bool,
    budget: Option<i64>,
) -> (Core, Fake, String, accounts::Account) {
    let hub = HubConfig {
        heartbeat: Duration::from_secs(30),
        ..quick()
    };
    let core = Core::start_agents(name, hub, agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    fake.os = Some("linux".to_owned());
    fake.isolation = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    let auth = fake.hello(&dev, vec![driver(gateway)], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    agents::throwaway_mode(&core).await;
    agents::make_admin(&core, &dev.id).await;
    let now = core.app.clock.now();
    let runners = [dev.id.clone()];
    let new = accounts::NewAccount {
        provider: "anthropic",
        label: "main",
        value: KEY,
        runners: &runners,
        cap: None,
    };
    let sealer = core.app.secrets.as_deref().unwrap();
    let account = accounts::create(
        &core.app.pool,
        sealer,
        &new,
        &dev.id,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    prices::set(
        &core.app.pool,
        "anthropic",
        "claude-x",
        [3_000_000, 15_000_000, 300_000],
        "2026-11-01T00:00:00Z",
        &dev.id,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    if let Some(tokens) = budget {
        let subject = account.id.to_string();
        let b = NewBudget {
            kind: "account",
            subject: &subject,
            company: None,
            period: "total",
            token_cap: tokens,
            usd_cap_micros: None,
            warn_at_percent: None,
            hard_stop: true,
        };
        budgets::set(&core.app.pool, &b, &dev.id, AuditActor::System, &now)
            .await
            .unwrap();
    }
    (core, fake, dev.id, account)
}

pub(super) fn policy() -> serde_json::Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

pub(super) fn key_secret(account: &accounts::Account) -> [SessionSecret; 1] {
    [SessionSecret {
        name: account.secret_name.clone(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    }]
}

/// A session on the account, started in the background (the Core waits for the runner's answer).
pub(super) async fn start(core: &Core, runner: &str, account: &accounts::Account) -> String {
    let policy = policy();
    let secrets = key_secret(account);
    let new = NewSession {
        runner,
        harness: "claude",
        model: Some("claude-x"),
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: runner,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (core.app.clone(), s.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    s.id
}

pub(super) fn events(session: &str, state: AgentState, gateway: Vec<GatewayReport>) -> AgentEvents {
    AgentEvents {
        session: session.to_owned(),
        state,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway,
        plan_limit: None,
    }
}

pub(super) fn usage(seq: u64, input: u64, output: u64) -> GatewayReport {
    GatewayReport {
        gw_seq: seq,
        epoch: 0,
        kind: GatewayReportKind::Usage,
        model: Some("claude-x".to_owned()),
        input,
        output,
        cache_read: 0,
        cache_write: 0,
        status: UpstreamStatus::Ok,
        approximate: false,
        reported_usd_micros: None,
        retry_after: None,
        reset_at: None,
    }
}

/// The next command the Core sends, and its stream.
pub(super) async fn command(fake: &mut Fake) -> (u64, Command) {
    loop {
        let f = fake.next().await;
        if let Some(Body::Command(c)) = f.body().unwrap() {
            return (f.stream_id, c);
        }
    }
}

pub(super) async fn count(core: &Core, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&core.app.pool)
        .await
        .unwrap()
}

pub(super) async fn until(
    what: &str,
    core: &Core,
    session: &str,
    f: impl Fn(&sessions::Session) -> bool,
) {
    for _ in 0..250 {
        let s = sessions::get(&core.app.pool, session)
            .await
            .unwrap()
            .unwrap();
        if f(&s) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Answers the start with a running session, after checking what the grant says.
pub(super) async fn started(w: &mut W, ceiling_tokens: u64) {
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentStart(start) = cmd else {
        panic!("expected agent.start, got {cmd:?}")
    };
    assert!(start.secrets.is_empty(), "the key is never an env secret");
    let g = start.gateway.as_ref().expect("a gateway grant");
    assert_eq!(
        (g.account, g.provider.as_str()),
        (w.account.id, "anthropic")
    );
    assert_eq!(g.upstream.host, "api.anthropic.com");
    assert_eq!(g.upstream.base_path, "");
    assert_eq!(g.upstream.wire, Wire::AnthropicMessages);
    assert_eq!(g.upstream.auth, GatewayAuth::XApiKey);
    assert_eq!(g.models, ["claude-x"]);
    assert_eq!(
        (
            g.prices[0].input,
            g.prices[0].output,
            g.prices[0].cache_read
        ),
        (3_000_000, 15_000_000, 300_000)
    );
    assert_eq!(g.ceiling.tokens, ceiling_tokens);
    assert_eq!(
        g.ceiling.usd_micros,
        u64::MAX,
        "no dollar budget: no dollar limit"
    );
    assert_eq!(g.rate.concurrent, 2);
    assert!(g.lease.starts_with("l_"));
    // The lease was audited as a read by the gateway.
    let leased = count(
        &w.core,
        "SELECT count(*) FROM audit_events WHERE action = 'secret.leased' \
         AND details LIKE '%\"to\":\"gateway\"%'",
    )
    .await;
    assert_eq!(leased, 1);
    let ev = events(&w.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentStart(ev)))
        .await;
}

pub(super) async fn world(name: &str, budget: Option<i64>) -> W {
    let (core, fake, runner, account) = up(name, true, budget).await;
    let session = start(&core, &runner, &account).await;
    W {
        core,
        fake,
        runner,
        account,
        session,
    }
}

#[tokio::test]
async fn reports_are_recorded_and_acknowledged_and_a_budget_that_runs_out_stops_the_session() {
    let mut w = world("gw-stop", Some(700_000)).await;
    started(&mut w, 700_000).await;

    // First read: nothing acknowledged yet. Two reports come back.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read")
    };
    assert_eq!(read.gw_after, 0);
    let ev = events(
        &w.session,
        AgentState::Running,
        vec![usage(1, 100_000, 20_000), usage(2, 50_000, 0)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;

    // The next read acknowledges both (they are in the ledger by then), and carries a resend of 2
    // and the report that uses the rest of the budget.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read, got {cmd:?}")
    };
    assert_eq!(read.gw_after, 2);
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_cost_events").await,
        2
    );
    let ev = events(
        &w.session,
        AgentState::Running,
        vec![usage(2, 50_000, 0), usage(3, 600_000, 0)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;

    // The budget has nothing left: the gateway is told to refuse everything, then the session is
    // cancelled, in that order.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentLimit(limit) = cmd else {
        panic!("expected agent.limit, got {cmd:?}")
    };
    assert_eq!(limit.session, w.session);
    assert_eq!((limit.ceiling.tokens, limit.ceiling.usd_micros), (0, 0));
    let ev = events(&w.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentLimit(ev)))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentStop(stop) = cmd else {
        panic!("expected agent.stop, got {cmd:?}")
    };
    assert_eq!(
        (stop.session.as_str(), stop.kill),
        (w.session.as_str(), false)
    );
    let mut ended = events(&w.session, AgentState::Ended, vec![]);
    ended.outcome = Some(Outcome::Cancelled {
        reason: "the budget ran out".to_owned(),
    });
    w.fake
        .send(stream, Body::Result(Reply::AgentStop(ended.clone())))
        .await;

    // The rest of the session: the read that sees it end, acknowledging all three reports.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read, got {cmd:?}")
    };
    assert_eq!(read.gw_after, 3);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended)))
        .await;
    until("the session to end", &w.core, &w.session, |s| !s.live()).await;

    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_cost_events").await,
        3
    );
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'budget.exhausted'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'agent.cancelled'"
        )
        .await,
        1
    );
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_budget_holds").await,
        0
    );
    let account = accounts::get(&w.core.app.pool, w.account.id).await.unwrap();
    assert_eq!(
        account.state, "active",
        "a budget stop is not an account fault"
    );
}

#[tokio::test]
async fn the_ack_is_not_sent_for_reports_the_ledger_did_not_take() {
    let mut w = world("gw-ack", None).await;
    started(&mut w, u64::MAX).await;
    sqlx::query(
        "CREATE TRIGGER ledger_down BEFORE INSERT ON core_cost_events \
         BEGIN SELECT RAISE(ABORT, 'ledger down'); END",
    )
    .execute(&w.core.app.pool)
    .await
    .unwrap();
    let reports = vec![usage(1, 1_000, 0), usage(2, 2_000, 0)];
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 0));
    let ev = events(&w.session, AgentState::Running, reports.clone());
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // The ledger write failed: the next read still acknowledges nothing, so the runner keeps them.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 0));
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_cost_events").await,
        0
    );
    // The ledger is back; the runner resends, and only then is it acknowledged.
    sqlx::query("DROP TRIGGER ledger_down")
        .execute(&w.core.app.pool)
        .await
        .unwrap();
    let ev = events(&w.session, AgentState::Running, reports);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (_, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 2));
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_cost_events").await,
        2
    );
}

#[tokio::test]
async fn a_runner_without_the_gateway_is_refused_and_never_sees_a_grant() {
    let (core, _fake, runner, account) = up("gw-no-cap", false, None).await;
    // At create: the placement says so.
    let secrets = key_secret(&account);
    let refused = service::admit_holding(&core.app, &runner, "claude", &policy(), &secrets).await;
    let Err(service::Refusal::Runner(e)) = refused else {
        panic!("placed")
    };
    assert!(e.message.contains("offers the gateway"), "{}", e.message);
    // A stored session is refused at launch too, and nothing is sent or leased.
    let id = start(&core, &runner, &account).await;
    until("the session to fail", &core, &id, |s| !s.live()).await;
    let row = sessions::get(&core.app.pool, &id).await.unwrap().unwrap();
    assert!(
        row.outcome
            .unwrap()
            .to_string()
            .contains("offers the gateway")
    );
    assert_eq!(
        count(&core, "SELECT count(*) FROM core_secret_leases").await,
        0
    );
}

#[tokio::test]
async fn a_ceiling_that_cannot_admit_one_turn_fails_the_start_with_the_reason() {
    let (core, _fake, runner, account) = up("gw-small", true, Some(100_000)).await;
    let id = start(&core, &runner, &account).await;
    until("the session to fail", &core, &id, |s| !s.live()).await;
    let row = sessions::get(&core.app.pool, &id).await.unwrap().unwrap();
    let why = row.outcome.unwrap().to_string();
    assert!(why.contains("100000") && why.contains("328000"), "{why}");
    assert_eq!(
        count(&core, "SELECT count(*) FROM core_secret_leases").await,
        0
    );
    assert_eq!(
        count(&core, "SELECT count(*) FROM core_budget_holds").await,
        0
    );
}
