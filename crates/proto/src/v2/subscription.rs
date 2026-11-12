//! A subscription account's token in a session (KAN-434, KAN-441 L5; design `2026-11-02-ai-provider-
//! accounts` §5, gateway design §4.3 and §10 Q4). The one rule the Core's broker and the runner
//! both apply, so they cannot drift.
//!
//! An API-key account is served by the gateway and never put in a session's environment. A
//! subscription's token (`sk-ant-oat01-…`, signed in by a login) is the opposite: it authenticates
//! to hosts the gateway does not serve, so it is a leased ENV variable, and only that:
//!
//! - the claude harness only, under `CLAUDE_CODE_OAUTH_TOKEN` only;
//! - delivered as an environment variable, never a file or askpass helper;
//! - never beside a gateway grant or any other provider-account secret;
//! - at most one subscription account per session (a subscription is never pooled).

use super::ACCOUNT_PREFIX;

/// The only variable a subscription's token is delivered under.
pub const SUBSCRIPTION_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN";
/// The only harness that takes a subscription's token.
pub const SUBSCRIPTION_HARNESS: &str = "claude";
/// The command an agent driver lists when its runner applies the subscription rules before it
/// redeems a lease (KAN-434). The Core places a subscription session only on a runner that lists
/// it, so an older runner never redeems the token.
pub const CAP_SUBSCRIPTION_ENV: &str = "subscription-env";
/// The built-in subscription providers (`acct.<provider>.<id>`). The Core's tests keep this equal
/// to the built-in definitions that sign in by browser code.
pub const SUBSCRIPTION_PROVIDERS: [&str; 1] = ["claude-sub"];

/// Whether `name` is a subscription account's secret. By provider alone, so a malformed
/// `acct.claude-sub.x` counts too: fail closed.
pub fn is_subscription_secret(name: &str) -> bool {
    name.strip_prefix(ACCOUNT_PREFIX)
        .and_then(|rest| rest.split('.').next())
        .is_some_and(|p| SUBSCRIPTION_PROVIDERS.contains(&p))
}

/// Why a session of `harness` may not hold `grants` (each a secret's name, the variable it is
/// delivered under, and, once redeemed, how it is delivered: `None` where that is not known yet)
/// when one of them is a subscription's token. `None` for a session with no such secret.
pub fn subscription_problem<'a>(
    harness: &str,
    has_gateway: bool,
    grants: impl IntoIterator<Item = (&'a str, &'a str, Option<&'a str>)> + Clone,
) -> Option<&'static str> {
    let subs: Vec<_> = grants
        .clone()
        .into_iter()
        .filter(|(n, _, _)| is_subscription_secret(n))
        .collect();
    let count = subs.len();
    if count == 0 {
        return None;
    }
    if harness != SUBSCRIPTION_HARNESS {
        return Some("a subscription account's token goes only to the claude harness");
    }
    if count > 1 {
        return Some("a session names at most one subscription account: they are never pooled");
    }
    if has_gateway {
        return Some("a subscription account is never served by the gateway: no gateway grant");
    }
    if grants
        .clone()
        .into_iter()
        .any(|(n, _, _)| n.starts_with(ACCOUNT_PREFIX) && !is_subscription_secret(n))
    {
        return Some("a session holding a subscription account may hold no other provider account");
    }
    for (_, var, delivery) in subs {
        if var != SUBSCRIPTION_VAR {
            return Some(
                "a subscription account's token is delivered only as CLAUDE_CODE_OAUTH_TOKEN",
            );
        }
        if delivery.is_some_and(|d| d != "env") {
            return Some("a subscription account's token is an environment variable, never a file");
        }
    }
    None
}

/// The op that checks a subscription plan with one tiny `claude -p` run (N36).
pub const OP_PLAN_CHECK: &str = "plan.check";
/// The capability a runner lists when it answers [`OP_PLAN_CHECK`].
pub const CAP_PLAN_CHECK: &str = "plan-check";

/// Core to runner: redeem `lease` (a subscription token, env), run `claude -p` with a one-word
/// prompt in the sandbox, and answer what happened.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct PlanCheck {
    pub lease: String,
}

// No `Debug` that prints a lease (secrets review L4).
impl std::fmt::Debug for PlanCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanCheck").finish_non_exhaustive()
    }
}

/// Runner to Core: how the check ended. Never the CLI's text.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct PlanChecked {
    /// `ok`, or why not: `token_expired`, `limit_reached`, `egress_not_proven`,
    /// `sandbox_unavailable`, `runner_busy`, `unreachable`, `timeout` or `failed`.
    pub result: String,
    pub latency_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "acct.claude-sub.7";
    const KEY: &str = "acct.anthropic.3";
    const V: &str = SUBSCRIPTION_VAR;

    fn problem(h: &str, gw: bool, g: &[(&str, &str, Option<&str>)]) -> Option<&'static str> {
        subscription_problem(h, gw, g.iter().copied())
    }

    #[test]
    fn only_the_claude_harness_in_the_fixed_variable_as_env_alone() {
        assert_eq!(problem("claude", false, &[(SUB, V, Some("env"))]), None);
        assert_eq!(problem("claude", false, &[(SUB, V, None)]), None);
        for h in ["codex", "agy", "opencode", "fake"] {
            assert!(problem(h, false, &[(SUB, V, None)]).is_some(), "{h}");
        }
        assert!(problem("claude", false, &[(SUB, "ANTHROPIC_API_KEY", None)]).is_some());
        for d in ["file", "askpass", "gateway"] {
            assert!(
                problem("claude", false, &[(SUB, V, Some(d))]).is_some(),
                "{d}"
            );
        }
    }

    #[test]
    fn never_with_a_gateway_a_second_account_or_a_second_subscription() {
        assert!(problem("claude", true, &[(SUB, V, None)]).is_some());
        assert!(
            problem(
                "claude",
                false,
                &[(SUB, V, None), (KEY, "ANTHROPIC_API_KEY", None)]
            )
            .is_some()
        );
        assert!(
            problem(
                "claude",
                false,
                &[(SUB, V, None), ("acct.claude-sub.8", V, None)]
            )
            .is_some()
        );
        // A malformed name counts as a subscription's: fail closed.
        assert!(problem("codex", false, &[("acct.claude-sub.x", V, None)]).is_some());
        // Other secrets are not this rule's business; no subscription, no opinion.
        assert_eq!(problem("claude", false, &[("git.token", "GH", None)]), None);
        assert_eq!(
            problem("codex", true, &[(KEY, "OPENAI_API_KEY", None)]),
            None
        );
        assert_eq!(
            problem(
                "claude",
                false,
                &[(SUB, V, None), ("git.token", "GH", Some("askpass"))]
            ),
            None
        );
    }
}
