//! `POST /accounts/{id}/test` and a user-provider grant through the hub (KAN-435 G7), with a runner
//! played by hand: the runner chosen is the one in the key's scope and the lease is for it alone, the
//! one-shot `gateway.test` carries the frozen host and the declared path, the result is recorded and
//! audited, a test that fails is recorded and its lease does not stay live, and a session on a
//! user-defined provider's account reaches the runner with a grant and no env secret.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use ainkrad_core_server::agents as service;
use ainkrad_core_server::agents::gateway::test::{self as acct_test, Failed};
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_core_server::store::providers::{Definition, Model};
use ainkrad_core_server::store::{accounts, gov, prices, providers, settings};
use ainkrad_proto::v2::*;

use super::gateway::{command, policy, up};
use super::{Core, Fake};

const OR: &str = "sk-or-v1-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";

async fn caller(core: &Core, device: &str) -> Caller {
    let device = gov::get_device(&core.app.pool, device)
        .await
        .unwrap()
        .expect("the runner device");
    Caller {
        device,
        session: String::new(),
    }
}

fn tested(result: UpstreamStatus) -> Body {
    Body::Result(Reply::GatewayTest(GatewayTested {
        result,
        latency_ms: 7,
    }))
}

/// Runs a test in the background and hands back the `gateway.test` the runner receives.
async fn ask(
    core: &Core,
    fake: &mut Fake,
    who: &Caller,
    account: i64,
) -> (
    tokio::task::JoinHandle<Result<acct_test::Tested, Failed>>,
    u64,
    GatewayTest,
) {
    let (app, who) = (core.app.clone(), who.clone());
    let task = tokio::spawn(async move { acct_test::run(&app, &who, account).await });
    let (stream, cmd) = command(fake).await;
    let Command::GatewayTest(t) = cmd else {
        panic!("{cmd:?}")
    };
    (task, stream, t)
}

async fn user_provider(core: &Core, runner: &str) -> accounts::Account {
    let now = core.app.clock.now();
    settings::set(
        &core.app.pool,
        SettingKey::SecretsProviderAccounts,
        Scope::Server,
        "1",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let def = Definition {
        id: "openrouter".to_owned(),
        name: "OpenRouter".to_owned(),
        harness: "codex".to_owned(),
        auth_var: "OPENAI_API_KEY".to_owned(),
        base_url: "https://openrouter.ai/api/v1".to_owned(),
        usage_parser: "openai".to_owned(),
        delivery: vec!["gateway".to_owned()],
        login_methods: vec!["paste".to_owned()],
        models: Vec::<Model>::new(),
        priced_at: None,
        wire: String::new(),
        key_prefix: Some("sk-or-v1-".to_owned()),
        test_path: Some("/key".to_owned()),
        builtin: false,
        version: 0,
    };
    providers::create(&core.app.pool, &def, runner, AuditActor::System, &now)
        .await
        .unwrap();
    let runners = [runner.to_owned()];
    let new = accounts::NewAccount {
        provider: "openrouter",
        label: "or-main",
        value: OR,
        runners: &runners,
        cap: None,
    };
    let sealer = core.app.secrets.as_deref().unwrap();
    let account = accounts::create(
        &core.app.pool,
        sealer,
        &new,
        runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    prices::set(
        &core.app.pool,
        "openrouter",
        "vendor/m",
        [1_000_000, 2_000_000, 100_000],
        "2026-11-01T00:00:00Z",
        runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    account
}

#[tokio::test]
async fn a_test_goes_to_the_runner_in_the_keys_scope_and_is_recorded_and_audited() {
    let (core, mut fake, runner, account) = up("gt-ok", true, None).await;
    let who = caller(&core, &runner).await;
    let (task, stream, t) = ask(&core, &mut fake, &who, account.id).await;
    // The request is the account's own: its provider and frozen host, the wire's model list (a
    // built-in's is authenticated), no key shape of a user definition.
    assert_eq!(t.provider, "anthropic");
    assert_eq!(t.upstream.host, "api.anthropic.com");
    assert!(t.user_key.is_none() && t.test_path.is_none());
    assert!(t.lease.starts_with("l_"));
    fake.send(stream, tested(UpstreamStatus::Ok)).await;
    let Ok(done) = task.await.unwrap() else {
        panic!("the test failed")
    };
    assert_eq!((done.result.as_str(), done.latency_ms), ("ok", 7));
    assert_eq!(done.runner, runner);
    // Recorded on the account.
    let a = accounts::get(&core.app.pool, account.id).await.unwrap();
    assert_eq!(a.last_test_result.as_deref(), Some("ok"));
    assert!(a.last_test_at.is_some());
    // The lease is for that runner alone, and was audited as a read for the gateway.
    let leased_to: Vec<String> = sqlx::query_scalar("SELECT runner FROM core_secret_leases")
        .fetch_all(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(leased_to, std::slice::from_ref(&runner));
    let leased: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'secret.leased'")
            .fetch_all(&core.app.pool)
            .await
            .unwrap();
    assert!(
        leased
            .iter()
            .any(|d| d.contains("\"to\":\"gateway\"") && d.contains(&runner)),
        "{leased:?}"
    );
    let audited: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'account.tested'")
            .fetch_all(&core.app.pool)
            .await
            .unwrap();
    assert_eq!(audited.len(), 1);
    assert!(audited[0].contains("\"result\":\"ok\"") && audited[0].contains(&runner));
    assert!(!audited[0].contains("throwaway"), "{}", audited[0]);
    // A second test within the minute is refused.
    assert!(matches!(
        acct_test::run(&core.app, &who, account.id).await,
        Err(Failed::Soon(_))
    ));
}

#[tokio::test]
async fn a_test_the_runner_fails_is_recorded_limited_and_leaves_no_live_lease() {
    let (core, mut fake, runner, account) = up("gt-fail", true, None).await;
    let who = caller(&core, &runner).await;
    let (task, stream, _t) = ask(&core, &mut fake, &who, account.id).await;
    let boom = StreamError::new(ErrorCode::Internal, "the dialer broke");
    fake.send(stream, Body::Error(boom)).await;
    assert!(matches!(task.await.unwrap(), Err(Failed::Runner(_))));
    let a = accounts::get(&core.app.pool, account.id).await.unwrap();
    assert_eq!(a.last_test_result.as_deref(), Some("failed"));
    // The lease nobody redeemed is gone, and the failure counts for the rate limit.
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(live, 0);
    assert!(matches!(
        acct_test::run(&core.app, &who, account.id).await,
        Err(Failed::Soon(_))
    ));
}

#[tokio::test]
async fn a_user_providers_test_and_grant_carry_its_frozen_host_prefix_and_path() {
    let (core, mut fake, runner, _anthropic) = up("gt-user", true, None).await;
    let account = user_provider(&core, &runner).await;
    let who = caller(&core, &runner).await;
    // The test: the declared authenticated path, and the key shape and host the runner checks.
    let (task, stream, t) = ask(&core, &mut fake, &who, account.id).await;
    assert_eq!(
        (t.provider.as_str(), t.upstream.host.as_str()),
        ("openrouter", "openrouter.ai")
    );
    assert_eq!(t.upstream.base_path, "/api/v1");
    assert_eq!(t.upstream.wire, Wire::OpenaiResponses);
    assert_eq!(t.test_path.as_deref(), Some("/key"));
    let key = t.user_key.expect("a user provider carries its key shape");
    assert_eq!(
        (key.prefix.as_str(), key.host.as_str()),
        ("sk-or-v1-", "openrouter.ai")
    );
    fake.send(stream, tested(UpstreamStatus::AuthFailed)).await;
    let Ok(done) = task.await.unwrap() else {
        panic!("the test failed")
    };
    // A refused key is reported, and the account is left as it was (one test never disables it).
    assert_eq!(done.result, "auth_failed");
    assert_eq!(
        accounts::get(&core.app.pool, account.id)
            .await
            .unwrap()
            .state,
        "active"
    );

    // A session on the account: a grant reaches the runner, and the key is no env secret.
    let policy = policy();
    let secrets = [SessionSecret {
        name: account.secret_name.clone(),
        var: "OPENAI_API_KEY".to_owned(),
    }];
    let new = NewSession {
        runner: &runner,
        harness: "codex",
        model: Some("vendor/m"),
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &runner,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(s.gateway_account_id, Some(account.id));
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (core.app.clone(), s.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    let start = loop {
        let (_, cmd) = command(&mut fake).await;
        if let Command::AgentStart(start) = cmd {
            break start;
        }
    };
    assert!(
        start.secrets.is_empty(),
        "the key was leased as an env secret"
    );
    let grant = start.gateway.expect("a gateway grant");
    assert_eq!(grant.provider, "openrouter");
    assert_eq!(grant.upstream.host, "openrouter.ai");
    assert_eq!(grant.models, ["vendor/m"]);
    let key = grant
        .user_key
        .expect("a user provider's grant carries its key shape");
    assert_eq!(
        (key.prefix.as_str(), key.host.as_str()),
        ("sk-or-v1-", "openrouter.ai")
    );
    assert!(grant.lease.starts_with("l_"));
}
