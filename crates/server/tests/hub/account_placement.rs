//! Forced filtered placement for a session holding a provider-account secret (KAN-433): the
//! policy must ask for a sandbox, and the runner must be Linux with a proven egress filter.

use ainkrad_core_server::agents::{
    Invalid, account_refusal, placement_refusal, placement_refusal_with, validate_new,
};
use ainkrad_core_server::hub::RunnerState;
use ainkrad_core_server::store::agents::{NewSession, SessionSecret};
use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::{AGENT_DRIVER, DriverInfo, IsolationCaps, Kvm};
use serde_json::{Value, json};

fn secret(name: &str) -> SessionSecret {
    SessionSecret {
        name: name.into(),
        var: "ANTHROPIC_API_KEY".into(),
    }
}

fn runner(os: Option<&str>, filter: bool) -> RunnerState {
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
        os: os.map(str::to_owned),
    }
}

fn sandboxed() -> Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

fn checked(secrets: &[SessionSecret], policy: &Value) -> Result<(), Invalid> {
    let new = NewSession {
        runner: "d_00000000000000000000000000",
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy,
        secrets,
        created_by: "d_00000000000000000000000001",
    };
    validate_new(&new, true)
}

#[test]
fn an_account_session_must_ask_for_a_sandbox_whoever_creates_it() {
    let key = [secret("acct.anthropic.7")];
    for policy in [
        json!({"mode": "ask"}),
        json!({"mode": "ask", "min_isolation": "none"}),
    ] {
        let Err(Invalid::Bad(why)) = checked(&key, &policy) else {
            panic!("{policy} must be refused")
        };
        assert!(why.contains("provider-account"), "{why}");
    }
    // A malformed acct. name counts as an account too: fail closed.
    assert!(checked(&[secret("acct.nobody.x")], &json!({"mode": "ask"})).is_err());
    assert!(checked(&[secret("acct.")], &json!({"mode": "ask"})).is_err());
    // Asking for the sandbox passes, and so does a stronger tier.
    assert!(checked(&key, &sandboxed()).is_ok());
    assert!(checked(&key, &json!({"mode": "ask", "min_isolation": "microvm"})).is_ok());
    // Control: other secrets and no secrets keep needing nothing.
    let other = SessionSecret {
        name: "git.token".into(),
        var: "GH_TOKEN".into(),
    };
    assert!(checked(&[other], &json!({"mode": "ask"})).is_ok());
    assert!(checked(&[], &json!({"mode": "ask"})).is_ok());
}

#[test]
fn an_account_session_is_placed_only_on_a_linux_runner_with_a_proven_filter() {
    let key = [secret("acct.openai.main")];
    // macOS, with the filter: refused (Seatbelt is not an egress filter we rely on).
    let why = placement_refusal(&runner(Some("macos"), true), &key, &sandboxed()).unwrap();
    assert!(why.contains("Linux") && why.contains("macos"), "{why}");
    // A runner that never said its OS: refused.
    let why = placement_refusal(&runner(None, true), &key, &sandboxed()).unwrap();
    assert!(why.contains("unreported"), "{why}");
    // Linux without the filter: refused.
    let why = placement_refusal(&runner(Some("linux"), false), &key, &sandboxed()).unwrap();
    assert!(why.contains("egress filter"), "{why}");
    assert!(account_refusal(&runner(Some("linux"), false)).is_some());
    // A stored session whose policy asks for no sandbox is refused at launch too.
    let why =
        placement_refusal(&runner(Some("linux"), true), &key, &json!({"mode": "ask"})).unwrap();
    assert!(why.contains("sandboxed"), "{why}");
    // An unreadable policy is refused, never read as "no requirement".
    assert!(placement_refusal(&runner(Some("linux"), true), &key, &json!({"x": 1})).is_some());
    // Control: Linux with the filter and the sandbox is placed.
    assert_eq!(
        placement_refusal(&runner(Some("linux"), true), &key, &sandboxed()),
        None
    );
    // Control: a session with no account secret is not held to any of it.
    for secrets in [&[][..], &[secret("git.token")][..]] {
        assert_eq!(
            placement_refusal(
                &runner(Some("macos"), false),
                secrets,
                &json!({"mode": "ask"})
            ),
            None
        );
    }
}

/// A runner of `os` whose agent driver lists the `gateway` command, or not.
fn gw_runner(os: Option<&str>, gateway: bool) -> RunnerState {
    let mut r = runner(os, false);
    if gateway {
        r.drivers[0].commands.push("gateway".to_owned());
    }
    r
}

#[test]
fn a_gateway_session_is_placed_only_on_a_linux_runner_that_offers_the_gateway() {
    let gw = |r: &RunnerState, p: &Value| placement_refusal_with(r, &[], p, true);
    // An old runner (no `gateway`): refused.
    let why = gw(&gw_runner(Some("linux"), false), &sandboxed()).unwrap();
    assert!(why.contains("offers the gateway"), "{why}");
    // macOS and an unreported OS: refused even with the capability (decision 6).
    let why = gw(&gw_runner(Some("macos"), true), &sandboxed()).unwrap();
    assert!(why.contains("Linux") && why.contains("macos"), "{why}");
    assert!(
        gw(&gw_runner(None, true), &sandboxed())
            .unwrap()
            .contains("unreported")
    );
    // No sandbox asked for, or an unreadable policy: refused.
    let ok = gw_runner(Some("linux"), true);
    assert!(
        gw(&ok, &json!({"mode": "ask"}))
            .unwrap()
            .contains("sandboxed")
    );
    assert!(gw(&ok, &json!({"x": 1})).is_some());
    // Control: Linux + capability + sandbox is placed, with no egress filter needed.
    assert_eq!(gw(&ok, &sandboxed()), None);
    // Control: a session that does not need the gateway ignores the capability.
    assert_eq!(
        placement_refusal(
            &gw_runner(Some("macos"), false),
            &[],
            &json!({"mode": "ask"})
        ),
        None
    );
    assert_eq!(
        placement_refusal_with(
            &gw_runner(Some("macos"), false),
            &[],
            &json!({"mode": "ask"}),
            false
        ),
        None
    );
}

#[test]
fn a_gateway_session_that_asks_for_egress_needs_the_proven_filter() {
    let policy = json!({"mode": "ask", "min_isolation": "process", "egress": {"allow": ["10.0.0.0/8"], "deny": []}});
    let gw = |r: &RunnerState| placement_refusal_with(r, &[], &policy, true);
    // Gateway but no filter: refused. With the filter too: placed.
    let why = gw(&gw_runner(Some("linux"), true)).unwrap();
    assert!(why.contains("egress filter"), "{why}");
    let mut both = gw_runner(Some("linux"), true);
    both.drivers[0].commands.push("egress-filter".to_owned());
    assert_eq!(gw(&both), None);
}

#[test]
fn an_api_key_account_session_is_placed_through_the_gateway_and_not_the_env_filter() {
    // The account model's own name (`acct.<provider>.<id>`) is an API key a gateway serves.
    let key = [secret("acct.anthropic.7")];
    // A runner without the gateway is refused, though it has the egress filter an env key needs.
    let why = placement_refusal(&runner(Some("linux"), true), &key, &sandboxed()).unwrap();
    assert!(why.contains("offers the gateway"), "{why}");
    // macOS and an unreported OS are refused even with the capability (decision 6).
    let why = placement_refusal(&gw_runner(Some("macos"), true), &key, &sandboxed()).unwrap();
    assert!(why.contains("Linux") && why.contains("macos"), "{why}");
    assert!(placement_refusal(&gw_runner(None, true), &key, &sandboxed()).is_some());
    // Unsandboxed, or an unreadable policy: refused.
    let ok = gw_runner(Some("linux"), true);
    let why = placement_refusal(&ok, &key, &json!({"mode": "ask"})).unwrap();
    assert!(why.contains("sandboxed"), "{why}");
    assert!(placement_refusal(&ok, &key, &json!({"x": 1})).is_some());
    // Placed with the gateway and the sandbox: no egress filter is demanded of it.
    assert_eq!(placement_refusal(&ok, &key, &sandboxed()), None);
    // An account secret of any other label stays on the env rules: it needs the filter.
    let env = [secret("acct.anthropic.main")];
    let why = placement_refusal(&ok, &env, &sandboxed()).unwrap();
    assert!(why.contains("egress filter"), "{why}");
}

#[test]
fn a_session_names_at_most_one_api_key_account() {
    assert!(checked(&[secret("acct.anthropic.7")], &sandboxed()).is_ok());
    let two = [secret("acct.anthropic.7"), secret("acct.anthropic.8")];
    let Err(Invalid::Bad(why)) = checked(&two, &sandboxed()) else {
        panic!("two accounts must be refused")
    };
    assert!(why.contains("at most one"), "{why}");
    // An API-key account still needs the sandbox, as any account does.
    assert!(checked(&[secret("acct.anthropic.7")], &json!({"mode": "ask"})).is_err());
}
