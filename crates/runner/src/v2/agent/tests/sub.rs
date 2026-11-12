//! KAN-434 / KAN-441 L5: the runner applies the subscription rules itself, whatever the Core sent.
//! A subscription's token runs only the claude harness, in `CLAUDE_CODE_OAUTH_TOKEN`, as env, alone,
//! sandboxed on a runner with a proven egress filter; and it is masked in everything the session
//! writes. Throwaway values only: no real token, no real claude.

use super::*;
use ainkrad_proto::v2::PlanCheck;

const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";
const VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// A sandbox as a proven Linux runner offers: the process tier and the egress filter, or not.
struct Proven(bool);

impl Sandbox for Proven {
    fn name(&self) -> &'static str {
        "proven"
    }
    fn tier(&self) -> Isolation {
        Isolation::Process
    }
    fn prepare(&self, _: &AgentStart, _: &mut Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
    fn capabilities(&self) -> &'static [&'static str] {
        if self.0 { &["egress-filter"] } else { &[] }
    }
}

fn redeem() -> Redeem {
    counted(Arc::default())
}

/// A redeemer that counts how many leases it was asked to redeem.
fn counted(calls: Arc<std::sync::atomic::AtomicUsize>) -> Redeem {
    Arc::new(move |lease: String| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let (name, delivery) = match lease.as_str() {
                "l_sub" => ("acct.claude-sub.7", "env"),
                "l_file" => ("acct.claude-sub.7", "file"),
                "l_sub2" => ("acct.claude-sub.8", "env"),
                "l_key" => ("acct.anthropic.3", "env"),
                _ => return Err("no such lease".to_owned()),
            };
            Ok(secrets::Leased {
                name: name.to_owned(),
                delivery: delivery.to_owned(),
                value: Zeroizing::new(if name.contains("claude-sub") {
                    TOKEN.to_owned()
                } else {
                    "throwaway-api-key-value-31f9".to_owned()
                }),
                form: Default::default(),
            })
        })
    })
}

fn grant(lease: &str, var: &str) -> SecretGrant {
    SecretGrant {
        lease: lease.to_owned(),
        var: var.to_owned(),
    }
}

#[tokio::test]
async fn the_runner_runs_a_subscription_token_only_where_every_rule_holds() {
    // (harness, grants, sandboxed policy, egress filter proven, runs, reason fragment)
    type Case<'a> = (&'a str, Vec<SecretGrant>, bool, bool, bool, &'a str);
    let cases: Vec<Case> = vec![
        ("claude", vec![grant("l_sub", VAR)], true, true, true, ""),
        (
            "codex",
            vec![grant("l_sub", VAR)],
            true,
            true,
            false,
            "claude harness",
        ),
        (
            "agy",
            vec![grant("l_sub", VAR)],
            true,
            true,
            false,
            "claude harness",
        ),
        (
            "opencode",
            vec![grant("l_sub", VAR)],
            true,
            true,
            false,
            "claude harness",
        ),
        (
            "claude",
            vec![grant("l_sub", "ANTHROPIC_API_KEY")],
            true,
            true,
            false,
            "CLAUDE_CODE_OAUTH_TOKEN",
        ),
        (
            "claude",
            vec![grant("l_sub", "HTTPS_PROXY")],
            true,
            true,
            false,
            "CLAUDE_CODE_OAUTH_TOKEN",
        ),
        (
            "claude",
            vec![grant("l_file", VAR)],
            true,
            true,
            false,
            "never a file",
        ),
        (
            "claude",
            vec![grant("l_sub", VAR), grant("l_sub2", VAR)],
            true,
            true,
            false,
            "at most one",
        ),
        (
            "claude",
            vec![grant("l_sub", VAR), grant("l_key", "ANTHROPIC_API_KEY")],
            true,
            true,
            false,
            "no other provider account",
        ),
        (
            "claude",
            vec![grant("l_sub", VAR)],
            false,
            true,
            false,
            "sandboxed",
        ),
        (
            "claude",
            vec![grant("l_sub", VAR)],
            true,
            false,
            false,
            "egress filter",
        ),
    ];
    for (n, (harness, grants, sandboxed, filter, runs, why)) in cases.into_iter().enumerate() {
        let (_root, config) = dirs(&format!("sub-{n}"));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::default());
        let d = Arc::new(
            AgentDriver::new(
                config,
                script("echo \"tok=${CLAUDE_CODE_OAUTH_TOKEN:-none}\""),
            )
            .unwrap()
            .with_redeem(counted(calls.clone()))
            .with_sandbox(Arc::new(Proven(filter))),
        );
        let mut req = start("as_sub", harness);
        req.secrets = grants;
        if sandboxed {
            req.policy.min_isolation = Some(Isolation::Process);
        }
        // A refusal the runner can make from the request alone comes before any lease is redeemed:
        // the single-use lease stays valid and the token never reaches the runner.
        let started = d.start(req);
        if let Err(e) = &started {
            assert!(!runs && e.message.contains(why), "case {n}: {}", e.message);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "case {n}: redeemed"
            );
            continue;
        }
        let (entries, ev) = drain(&d, "as_sub").await;
        let text = serde_json::to_string(&entries).unwrap();
        let line = |t: &str| text.contains(&format!(r#""text":"{t}""#));
        assert!(
            !text.contains(TOKEN),
            "case {n}: the token reached the transcript: {text}"
        );
        assert!(!format!("{:?}", ev.outcome).contains(TOKEN), "case {n}");
        match runs {
            // The harness saw a value (masked in what it printed), never none.
            true => assert!(
                text.contains("tok=") && !line("tok=none"),
                "case {n}: {text}"
            ),
            false => {
                assert!(!text.contains("tok="), "case {n}: the harness ran: {text}");
                assert!(
                    matches!(&ev.outcome, Some(Outcome::Failed { reason, .. }) if reason.contains(why)),
                    "case {n}: {:?}",
                    ev.outcome
                );
            }
        }
    }
}

#[tokio::test]
async fn the_token_is_masked_in_output_and_in_the_failure_reason_for_the_whole_session() {
    let (_root, config) = dirs("sub-mask");
    // The harness prints the token twice and fails with it as its last line.
    let d = Arc::new(
        AgentDriver::new(
            config,
            script(
                "echo \"a=$CLAUDE_CODE_OAUTH_TOKEN\"; echo \"$CLAUDE_CODE_OAUTH_TOKEN\"; exit 1",
            ),
        )
        .unwrap()
        .with_redeem(redeem())
        .with_sandbox(Arc::new(Proven(true))),
    );
    let mut req = start("as_mask", "claude");
    req.secrets = vec![grant("l_sub", VAR)];
    req.policy.min_isolation = Some(Isolation::Process);
    d.start(req).unwrap();
    let (entries, ev) = drain(&d, "as_mask").await;
    let all = format!(
        "{}{:?}",
        serde_json::to_string(&entries).unwrap(),
        ev.outcome
    );
    assert!(!all.contains(TOKEN), "{all}");
    assert!(all.contains("[redacted"), "{all}");
}

/// N36: `plan.check` runs an ordinary sandboxed session on the leased token and forgets it.
#[tokio::test]
async fn a_plan_check_runs_the_token_in_a_session_it_then_forgets() {
    let (_root, config) = dirs("plan-check");
    let d = Arc::new(
        AgentDriver::new(
            config,
            script("echo \"tok=${CLAUDE_CODE_OAUTH_TOKEN:-none}\""),
        )
        .unwrap()
        .with_redeem(redeem())
        .with_sandbox(Arc::new(Proven(true))),
    );
    let got = d
        .plan_check(PlanCheck {
            lease: "l_sub".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(got.result, "ok");
    assert!(d.states().is_empty(), "the check's session is forgotten");
    // A harness that fails is `failed`, and is forgotten as well.
    let bad = Arc::new(
        AgentDriver::new(dirs("plan-check-bad").1, script("echo no; exit 1"))
            .unwrap()
            .with_redeem(redeem())
            .with_sandbox(Arc::new(Proven(true))),
    );
    let got = bad
        .plan_check(PlanCheck {
            lease: "l_sub".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(got.result, "failed");
    assert!(bad.states().is_empty());
}

#[tokio::test]
async fn a_plan_check_needs_the_sandbox_and_a_proven_egress_filter() {
    let (_root, config) = dirs("plan-check-no");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::default());
    let d = Arc::new(
        AgentDriver::new(config, script("true"))
            .unwrap()
            .with_redeem(counted(calls.clone()))
            .with_sandbox(Arc::new(Proven(false))),
    );
    let got = d
        .plan_check(PlanCheck {
            lease: "l_sub".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(got.result, "egress_not_proven");
    let plain = Arc::new(AgentDriver::new(dirs("plan-check-no2").1, script("true")).unwrap());
    let got = plain
        .plan_check(PlanCheck {
            lease: "l_sub".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(got.result, "egress_not_proven");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the token was never redeemed"
    );
}
