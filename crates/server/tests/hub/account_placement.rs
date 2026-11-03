//! Forced filtered placement for a session holding a provider-account secret (KAN-433): the
//! policy must ask for a sandbox, and the runner must be Linux with a proven egress filter.

use ainkrad_core_server::agents::{Invalid, account_refusal, placement_refusal, validate_new};
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
    let key = [secret("acct.anthropic.main")];
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
    assert!(checked(&[secret("git.token")], &json!({"mode": "ask"})).is_ok());
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
