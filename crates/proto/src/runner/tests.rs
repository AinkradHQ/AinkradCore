//! Wire shapes of the runner protocol.

use serde_json::json;

use super::*;

#[test]
fn messages_are_tagged_json() {
    let ended = RunnerMessage::RunEnded {
        run: 7,
        outcome: Outcome::Failed {
            reason: "build broke".to_owned(),
            fingerprint: None,
        },
    };
    let wire = serde_json::to_value(&ended).unwrap();
    assert_eq!(
        wire,
        json!({"type": "run_ended", "run": 7,
               "outcome": {"kind": "failed", "reason": "build broke", "fingerprint": null}})
    );
    assert_eq!(
        serde_json::from_value::<RunnerMessage>(wire).unwrap(),
        ended
    );
    // A 1.0 `ready` has no workspaces.
    let ready: RunnerMessage = serde_json::from_str(r#"{"type":"ready"}"#).unwrap();
    assert_eq!(ready, RunnerMessage::Ready { workspaces: vec![] });
    assert!(serde_json::from_str::<RunnerMessage>(r#"{"type":"sudo"}"#).is_err());
}

#[test]
fn a_token_is_plain_on_the_wire_and_redacted_in_debug() {
    let msg = ServerMessage::Token {
        run: 1,
        token: RunToken::new("cit_run_secret".to_owned()),
    };
    let wire = serde_json::to_string(&msg).unwrap();
    assert_eq!(wire, r#"{"type":"token","run":1,"token":"cit_run_secret"}"#);
    assert!(!format!("{msg:?}").contains("secret"));
    let back: ServerMessage = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn workspaces_never_carry_credentials_or_options() {
    let ws = |repo: &str, branch: &str| Workspace {
        repo: repo.to_owned(),
        base: "main".to_owned(),
        branch: branch.to_owned(),
        push: false,
        name: String::new(),
        also: vec![],
        expected_head: None,
    };
    for ok in [
        "https://github.com/AinkradHQ/AinkradCitadel.git",
        "git@github.com:AinkradHQ/AinkradCitadel.git",
        "ssh://git@github.com/AinkradHQ/AinkradCitadel.git",
    ] {
        assert_eq!(ws(ok, "citadel/CIT-12").problem(), None, "{ok}");
    }
    for bad in [
        "/srv/git/citadel.git",
        "relative/repo",
        "http://example.com/r",
        "git://example.com/r",
        "https://example.com/r?token=secret",
        "ssh://u:pw@example.com/r",
        "file:///srv/git/citadel.git",
        "ext::sh -c touch /tmp/pwned",
        "https://x-access-token:ghp_secret@github.com/a/b.git",
        "HTTPS://ghp_secret@github.com/a/b.git",
        "--upload-pack=touch /tmp/pwned",
        "",
    ] {
        assert!(ws(bad, "citadel/CIT-12").problem().is_some(), "{bad}");
    }
    for bad in ["-b", "citadel/../x", "/abs", "a b", ""] {
        assert!(ws("/srv/r.git", bad).problem().is_some(), "{bad}");
    }
}

/// An `Assign` without a policy (an older server) asks; the policy round-trips.
#[test]
fn the_default_policy_asks() {
    let assign = r#"{"type":"assign","run":1,"agent":2,"issue":null,"harness":"claude",
                     "model":"","context_ref":""}"#;
    let ServerMessage::Assign { policy, .. } = serde_json::from_str(assign).unwrap() else {
        panic!("not an assign");
    };
    assert_eq!(policy, Policy::default());
    assert_eq!(policy.mode, PermissionMode::Ask);
    assert!(!policy.sandboxed && policy.allow.is_empty());
    let wire = json!({"mode": "accept_edits", "allow": ["Bash:cargo test"], "sandboxed": true});
    let p: Policy = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(p.mode, PermissionMode::AcceptEdits);
    assert_eq!(serde_json::to_value(&p).unwrap(), wire);
    for mode in ["ask", "accept_edits", "sandboxed"] {
        assert_eq!(mode.parse::<PermissionMode>().unwrap().as_str(), mode);
    }
    assert!("full_auto".parse::<PermissionMode>().is_err());
}

#[test]
fn parses_the_major_version() {
    assert_eq!(protocol_major(PROTOCOL_VERSION), Some(1));
    assert_eq!(protocol_major("2.13"), Some(2));
    assert_eq!(protocol_major("1"), None);
    assert_eq!(protocol_major("x.0"), None);
    assert_eq!(protocol_major("1.x"), None);
}

/// An account reference stays under its root: no absolute path, no `..`, no odd bytes; an
/// `Assign` without one (an older server) has none.
#[test]
fn account_refs_stay_relative() {
    for ok in ["claude-a", "accounts/claude-a", "c.token", "a_b/c-d.txt"] {
        assert!(relative_path_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "/etc/passwd",
        "../x",
        "a/../b",
        "a//b",
        "./a",
        "a b",
        "a\\b",
        "~/x",
    ] {
        assert!(!relative_path_ok(bad), "{bad}");
    }
    let assign = r#"{"type":"assign","run":1,"agent":2,"issue":null,"harness":"claude",
                     "model":"","context_ref":""}"#;
    let ServerMessage::Assign { account, .. } = serde_json::from_str(assign).unwrap() else {
        panic!("not an assign");
    };
    assert_eq!(account, None);
}

/// An `Assign` from a server older than 1.27 carries `token_cap` alone; a split one round-trips
/// with its `token_cap` (the least of the three) beside it, and an exact cap of none is left out.
#[test]
fn the_run_caps_split_round_trips_beside_the_least() {
    let old = r#"{"type":"assign","run":1,"agent":2,"issue":null,"harness":"claude",
                  "model":"","context_ref":"","token_cap":500}"#;
    let ServerMessage::Assign {
        token_cap,
        token_caps,
        ..
    } = serde_json::from_str(old).unwrap()
    else {
        panic!("not an assign");
    };
    assert_eq!((token_cap, token_caps), (Some(500), None));
    let caps = TokenCaps {
        exact: None,
        run: 3_000_000,
        cache_weight_divisor: 10,
    };
    assert_eq!(caps.least(), 3_000_000);
    let wire = serde_json::to_value(caps).unwrap();
    assert_eq!(wire, json!({"run": 3_000_000, "cache_weight_divisor": 10}));
    assert_eq!(serde_json::from_value::<TokenCaps>(wire).unwrap(), caps);
    let exact = TokenCaps {
        exact: Some(40),
        ..caps
    };
    assert_eq!(exact.least(), 40);
    assert_eq!(
        TokenCaps {
            exact: Some(0),
            ..caps
        }
        .least(),
        0
    );
}
