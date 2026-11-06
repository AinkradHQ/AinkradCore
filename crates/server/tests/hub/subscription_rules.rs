//! A subscription account's token in a session (KAN-434, KAN-441 L5): the rules at create, the
//! placement (Linux, a proven egress filter, the `subscription-env` command), and the pool.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents::{Invalid, placement_refusal, validate_new};
use ainkrad_core_server::hub::RunnerState;
use ainkrad_core_server::store::agents::{NewSession, SessionSecret};
use ainkrad_core_server::store::pools;
use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::*;
use serde_json::{Value, json};

use super::login::refusal;
use super::subscription::{VAR, sandboxed, up};

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

/// Why the create refuses `secrets` (the refusal's own text), panicking if it does not.
fn bad(harness: &str, secrets: &[SessionSecret], policy: &Value) -> &'static str {
    match checked(harness, secrets, policy) {
        Err(Invalid::Bad(why)) => why,
        other => panic!("{harness} {secrets:?} must be refused, got {other:?}"),
    }
}

#[test]
fn a_subscription_session_is_refused_for_every_wrong_shape_at_create() {
    let ok = [named("acct.claude-sub.7", VAR)];
    assert!(checked("claude", &ok, &sandboxed()).is_ok());
    for h in ["codex", "agy", "opencode", "fake"] {
        assert!(bad(h, &ok, &sandboxed()).contains("claude harness"), "{h}");
    }
    for var in ["ANTHROPIC_API_KEY", "HTTPS_PROXY", "MY_TOKEN"] {
        let s = [named("acct.claude-sub.7", var)];
        assert!(
            bad("claude", &s, &sandboxed()).contains("CLAUDE_CODE_OAUTH_TOKEN"),
            "{var}"
        );
    }
    let two = [
        named("acct.claude-sub.7", VAR),
        named("acct.claude-sub.8", VAR),
    ];
    assert!(bad("claude", &two, &sandboxed()).contains("at most one"));
    let api = [
        named("acct.claude-sub.7", VAR),
        named("acct.anthropic.3", "ANTHROPIC_API_KEY"),
    ];
    assert!(bad("claude", &api, &sandboxed()).contains("no other provider account"));
    // A malformed name is an account name that is not the model's own: never an env secret.
    let main = [named("acct.claude-sub.main", VAR)];
    assert!(bad("claude", &main, &sandboxed()).contains("acct.<provider>.<id>"));
    // A sibling that redirects traffic could steer the token.
    let steer = [
        named("acct.claude-sub.7", VAR),
        named("git.token", "ANTHROPIC_BASE_URL"),
    ];
    assert!(bad("claude", &steer, &sandboxed()).contains("redirect"));
    // An isolated sandbox is required, whoever creates it.
    assert!(bad("claude", &ok, &json!({"mode": "ask"})).contains("sandboxed"));
    // An ordinary secret may not take a harness authentication variable, so it cannot carry a
    // credential past the rules above (a pre-existing gap the shared rule now closes).
    for (h, var) in [
        ("claude", VAR),
        ("claude", "ANTHROPIC_API_KEY"),
        ("codex", "OPENAI_API_KEY"),
    ] {
        let s = [named("git.token", var)];
        assert!(
            bad(h, &s, &sandboxed()).contains("provider-account secret"),
            "{h} {var}"
        );
    }
    // An API-key account is judged as before (the gateway's).
    let key = [named("acct.anthropic.3", "ANTHROPIC_API_KEY")];
    assert!(checked("claude", &key, &sandboxed()).is_ok());
}

fn runner(os: &str, filter: bool, cap: bool) -> RunnerState {
    let mut commands = vec!["agent.start".to_owned()];
    if filter {
        commands.push("egress-filter".to_owned());
    }
    if cap {
        commands.push(CAP_SUBSCRIPTION_ENV.to_owned());
    }
    RunnerState {
        online: true,
        degraded: false,
        last_seen: 0,
        version: String::new(),
        drivers: vec![DriverInfo {
            name: AGENT_DRIVER.to_owned(),
            commands,
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
fn a_subscription_session_is_placed_only_where_the_runner_checks_the_token_before_redeeming() {
    let s = [named("acct.claude-sub.7", VAR)];
    for (os, filter) in [("macos", true), ("linux", false)] {
        let r = runner(os, filter, true);
        assert!(
            placement_refusal(&r, &s, &sandboxed()).is_some(),
            "{os} {filter}"
        );
    }
    assert!(placement_refusal(&runner("linux", true, true), &s, &json!({"mode": "ask"})).is_some());
    // An older runner does not list `subscription-env`: refused before any lease, whatever else holds.
    let why = placement_refusal(&runner("linux", true, false), &s, &sandboxed()).unwrap();
    assert!(why.contains("subscription-env"), "{why}");
    assert_eq!(
        placement_refusal(&runner("linux", true, true), &s, &sandboxed()),
        None
    );
    // The command is asked for of a subscription session only: an API-key account's session is
    // placed as before on a runner without it.
    let key = [named("acct.anthropic.3", "ANTHROPIC_API_KEY")];
    let gw = runner("linux", true, false);
    assert!(
        placement_refusal(&gw, &key, &sandboxed()).is_none_or(|w| !w.contains("subscription-env"))
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
    let (code, why) = refusal(bound);
    assert_eq!(code, "bad_request");
    assert!(why.contains("never bound"), "{why}");
    // The refused bind left nothing behind.
    assert!(pools::list_bindings(pool).await.unwrap().is_empty());
}
