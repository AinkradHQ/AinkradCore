//! A subscription account's token in a session (KAN-434, KAN-441 L5) through the hub with a runner
//! played by hand: leased as ENV to the claude harness of this runner only, audited, never in any
//! row or log, never through the gateway, refused for the wrong harness, variable or shape, for a
//! module's session, and after the account is disabled or deleted. Fake tokens only.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use ainkrad_core_server::agents::{self as service, Invalid, placement_refusal, validate_new};
use ainkrad_core_server::hub::RunnerState;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_core_server::store::secrets;
use ainkrad_core_server::store::{accounts, pools, settings};
use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::*;
use serde_json::{Value, json};

use super::gateway::{command, count, events, policy, usage};
use super::login::{TOKEN, everything, refusal};
use super::{Core, Fake, agents, quick, random32};

const VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";

struct S {
    core: Core,
    fake: Fake,
    runner: String,
    account: accounts::Account,
}

async fn up(name: &str) -> S {
    let core = Core::start_agents(name, quick(), agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    fake.os = Some("linux".to_owned());
    fake.isolation = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    commands.push("egress-filter".to_owned());
    let driver = DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 4,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let auth = fake.hello(&dev, vec![driver], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    agents::throwaway_mode(&core).await;
    agents::make_admin(&core, &dev.id).await;
    let now = core.app.clock.now();
    let gate = settings::set(
        &core.app.pool,
        SettingKey::SecretsProviderAccounts,
        Scope::Server,
        "1",
        AuditActor::System,
        &now,
    );
    gate.await.unwrap();
    let runners = [dev.id.clone()];
    let new = accounts::NewAccount {
        provider: "claude-sub",
        label: "claude-me",
        value: TOKEN,
        runners: &runners,
        cap: None,
    };
    let sealer = core.app.secrets.as_deref().unwrap();
    let account = accounts::create_by(
        &core.app.pool,
        sealer,
        &new,
        "subscription",
        &dev.id,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    S {
        core,
        fake,
        runner: dev.id,
        account,
    }
}

fn sub(a: &accounts::Account) -> [SessionSecret; 1] {
    [SessionSecret {
        name: a.secret_name.clone(),
        var: VAR.to_owned(),
    }]
}

fn sandboxed() -> Value {
    policy()
}

/// A stored session (not started) of `harness` holding `secrets`, owned by `owner`.
async fn make(
    s: &S,
    harness: &str,
    secrets: &[SessionSecret],
    owner: Option<&str>,
) -> sessions::Session {
    let policy = sandboxed();
    let new = NewSession {
        runner: &s.runner,
        harness,
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets,
        created_by: &s.runner,
    };
    let row = sessions::create_owned(
        &s.core.app.pool,
        &new,
        owner,
        AuditActor::System,
        &s.core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&s.core.app, &row.id);
    row
}

/// Starts `row` and returns why it was refused.
async fn refused_start(s: &S, row: &sessions::Session) -> String {
    match service::start(&s.core.app, row).await {
        Err(e) => service::describe(&e),
        Ok(()) => panic!("the start was accepted"),
    }
}

#[tokio::test]
async fn the_token_is_leased_as_env_to_this_runner_only_and_audited() {
    let mut w = up("sub-lease").await;
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let (app, started) = (w.core.app.clone(), row.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &started).await;
    });
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentStart(start) = cmd else {
        panic!("expected agent.start, got {cmd:?}")
    };
    assert_eq!(start.harness, "claude");
    assert!(
        start.gateway.is_none(),
        "a subscription is never served by the gateway"
    );
    assert_eq!(start.secrets.len(), 1);
    assert_eq!(start.secrets[0].var, VAR);
    let lease = start.secrets[0].lease.clone();
    assert!(lease.starts_with("l_"));
    // Audited as a read into the environment, naming the account and the method, never a value.
    let leased: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'secret.leased'")
            .fetch_all(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(leased.len(), 1, "{leased:?}");
    for want in [
        "\"to\":\"env\"".to_owned(),
        "\"method\":\"subscription\"".to_owned(),
        format!("\"account\":{}", w.account.id),
        format!("\"runner\":\"{}\"", w.runner),
    ] {
        assert!(
            leased[0].contains(&want),
            "{want} missing from {}",
            leased[0]
        );
    }
    // The lease is single-use and this runner's: another runner is told it never existed.
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let (now, unix) = (w.core.app.clock.now(), w.core.app.clock.unix());
    let other = secrets::redeem(
        &w.core.app.pool,
        sealer,
        &lease,
        "d_somebodyelse",
        AuditActor::System,
        &now,
        unix,
    )
    .await;
    assert_eq!(refusal(other).0, "not_found");
    let got = secrets::redeem(
        &w.core.app.pool,
        sealer,
        &lease,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await
    .unwrap();
    assert_eq!((got.delivery.as_str(), got.value.as_str()), ("env", TOKEN));
    let again = secrets::redeem(
        &w.core.app.pool,
        sealer,
        &lease,
        &w.runner,
        AuditActor::System,
        &now,
        unix,
    )
    .await;
    assert_eq!(refusal(again).0, "lease_expired");

    // The session runs; no gateway account, no hold, no ledger row.
    let ev = events(&row.id, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentStart(ev)))
        .await;
    let live = sessions::get(&w.core.app.pool, &row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.gateway_account_id, None);

    // A gateway report for it (a runner that sent one anyway) is ignored: never recorded, never
    // acknowledged. The ledger stays empty: a plan bills no dollars.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)), "{cmd:?}");
    let ev = events(
        &row.id,
        AgentState::Running,
        vec![usage(1, 100_000, 20_000)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (_, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read, got {cmd:?}")
    };
    assert_eq!(read.gw_after, 0);
    for table in ["core_cost_events", "core_cost_subjects"] {
        let n = count(&w.core, &format!("SELECT count(*) FROM {table}")).await;
        assert_eq!(n, 0, "{table}");
    }
    // The token is in no row, event, audit entry or log line.
    let all = everything(&w.core).await;
    assert!(!all.contains(TOKEN) && !all.contains("0123456789abcdefghijklmnop"));
}

fn checked(harness: &str, secrets: &[SessionSecret], policy: &Value) -> Result<(), Invalid> {
    let new = NewSession {
        runner: "d_00000000000000000000000000",
        harness,
        model: None,
        prompt: None,
        workspace: None,
        policy,
        secrets,
        created_by: "d_00000000000000000000000001",
    };
    validate_new(&new, true)
}

fn named(name: &str, var: &str) -> SessionSecret {
    SessionSecret {
        name: name.to_owned(),
        var: var.to_owned(),
    }
}

#[test]
fn a_subscription_session_is_refused_for_every_wrong_shape_at_create() {
    let ok = [named("acct.claude-sub.7", VAR)];
    assert!(checked("claude", &ok, &sandboxed()).is_ok());
    // Only the claude harness.
    for h in ["codex", "agy", "opencode", "fake"] {
        let Err(Invalid::Bad(why)) = checked(h, &ok, &sandboxed()) else {
            panic!("{h} must be refused")
        };
        assert!(why.contains("claude"), "{h}: {why}");
    }
    // Only the one variable.
    for var in ["ANTHROPIC_API_KEY", "HTTPS_PROXY", "MY_TOKEN"] {
        let s = [named("acct.claude-sub.7", var)];
        assert!(checked("claude", &s, &sandboxed()).is_err(), "{var}");
    }
    // Never two subscriptions, never beside an API-key account (the gateway's), never a malformed name.
    let two = [
        named("acct.claude-sub.7", VAR),
        named("acct.claude-sub.8", VAR),
    ];
    assert!(checked("claude", &two, &sandboxed()).is_err());
    let api = [
        named("acct.claude-sub.7", VAR),
        named("acct.anthropic.3", "ANTHROPIC_API_KEY"),
    ];
    assert!(checked("claude", &api, &sandboxed()).is_err());
    assert!(
        checked(
            "claude",
            &[named("acct.claude-sub.main", VAR)],
            &sandboxed()
        )
        .is_err()
    );
    // A sibling that redirects traffic could steer the token.
    let steer = [
        named("acct.claude-sub.7", VAR),
        named("git.token", "ANTHROPIC_BASE_URL"),
    ];
    assert!(checked("claude", &steer, &sandboxed()).is_err());
    // An isolated sandbox is required, whoever creates it.
    assert!(checked("claude", &ok, &json!({"mode": "ask"})).is_err());
    // The reverse: an API-key account is still never an env secret.
    let key = [named("acct.anthropic.3", "ANTHROPIC_API_KEY")];
    assert!(
        checked("claude", &key, &sandboxed()).is_ok(),
        "a gateway account is judged as before"
    );
}

fn runner(os: &str, filter: bool) -> RunnerState {
    RunnerState {
        online: true,
        degraded: false,
        last_seen: 0,
        version: String::new(),
        drivers: vec![DriverInfo {
            name: AGENT_DRIVER.to_owned(),
            commands: if filter {
                vec!["agent.start".to_owned(), "egress-filter".to_owned()]
            } else {
                vec!["agent.start".to_owned()]
            },
            capacity: 1,
            ..Default::default()
        }],
        capacity: 1,
        load: 0,
        host_load: None,
        isolation: Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable)),
        arch: None,
        os: Some(os.to_owned()),
    }
}

#[test]
fn a_subscription_session_is_placed_only_on_a_linux_runner_with_a_proven_egress_filter() {
    let s = [named("acct.claude-sub.7", VAR)];
    for (os, filter) in [("macos", true), ("linux", false)] {
        assert!(
            placement_refusal(&runner(os, filter), &s, &sandboxed()).is_some(),
            "{os} {filter}"
        );
    }
    assert!(placement_refusal(&runner("linux", true), &s, &json!({"mode": "ask"})).is_some());
    assert_eq!(
        placement_refusal(&runner("linux", true), &s, &sandboxed()),
        None
    );
}

#[tokio::test]
async fn a_stored_session_is_refused_at_launch_for_the_wrong_harness_and_for_a_module() {
    let w = up("sub-launch").await;
    // A stored row the create checks never saw (a codex session naming the token).
    let row = make(&w, "codex", &sub(&w.account), None).await;
    let why = refused_start(&w, &row).await;
    assert!(why.contains("claude"), "{why}");
    // A module's session is refused: its budgets would count a cost the plan does not bill.
    let row = make(&w, "claude", &sub(&w.account), Some("citadel")).await;
    let why = refused_start(&w, &row).await;
    assert!(
        why.contains("module") && why.contains("subscription"),
        "{why}"
    );
    assert_eq!(agents::state_of(&w.core, &row.id).await.state, "ended");
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'secret.leased'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn a_disabled_or_deleted_account_is_not_leased_and_an_earlier_lease_is_revoked() {
    let w = up("sub-gone").await;
    let (pool, id) = (&w.core.app.pool, w.account.id);
    let (now, unix) = (w.core.app.clock.now(), w.core.app.clock.unix());
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let mint = || {
        secrets::lease(
            pool,
            &w.account.secret_name,
            &w.runner,
            None,
            &w.runner,
            AuditActor::System,
            &now,
            unix,
        )
    };
    let (runner, now_ref) = (&w.runner, &now);
    let redeem = |l: String| async move {
        secrets::redeem(pool, sealer, &l, runner, AuditActor::System, now_ref, unix).await
    };

    // Disabled: no start, and a lease minted before is dead.
    let (before, _) = mint().await.unwrap();
    let off = accounts::set_state(
        pool,
        id,
        "disabled",
        Some("test"),
        None,
        &w.runner,
        AuditActor::System,
        &now,
    );
    off.await.unwrap();
    assert_eq!(refusal(redeem(before).await).0, "not_found");
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let why = refused_start(&w, &row).await;
    assert!(
        why.contains("disabled") && why.contains("not active"),
        "{why}"
    );
    let on = accounts::set_state(
        pool,
        id,
        "active",
        None,
        None,
        &w.runner,
        AuditActor::System,
        &now,
    );
    on.await.unwrap();

    // Deleted: a lease minted before is revoked with the key, and no start leases it again.
    let (before, _) = mint().await.unwrap();
    accounts::delete(pool, id, &w.runner, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(refusal(redeem(before).await).0, "not_found");
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let why = refused_start(&w, &row).await;
    assert!(why.contains("no longer exists"), "{why}");
    assert_eq!(agents::state_of(&w.core, &row.id).await.state, "ended");
    let all = everything(&w.core).await;
    assert!(!all.contains(TOKEN));
    // The only leases ever minted here were the two this test made by hand.
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'secret.leased'"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn nothing_binds_or_picks_a_subscription_account_for_an_agent() {
    let w = up("sub-nopool").await;
    let (pool, now) = (&w.core.app.pool, w.core.app.clock.now());
    let p = pools::create(
        pool,
        "claude-subs",
        "claude-sub",
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    pools::add_member(
        pool,
        p.id,
        w.account.id,
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    // An agent is never bound to a subscription pool: it names its account in the session itself.
    let bound = pools::bind(pool, "agent-1", p.id, &w.runner, AuditActor::System, &now).await;
    assert_eq!(refusal(bound).0, "bad_request");
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        pools::resolve(&mut conn, Some("agent-1"), "claude-sub")
            .await
            .unwrap(),
        None
    );
}
