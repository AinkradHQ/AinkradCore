//! The runner's own check of a subscription account's token (KAN-434, KAN-441 L5), applied whatever
//! the Core sent: the shared shape rule (`ainkrad_proto::v2::subscription_problem`: claude only,
//! `CLAUDE_CODE_OAUTH_TOKEN` only, env only, one account, no gateway grant, no other provider
//! account) and, because the token sits in the harness's environment, the sandbox and the proven
//! egress filter it needs.

use super::{AgentStart, Sandbox};

/// Why `req` may not hold the redeemed secrets `granted` (each a name and the variable it was granted
/// under) delivered as `modes`, when one is a subscription's token. `None` for any other session.
pub(super) fn problem(
    req: &AgentStart,
    sandbox: &dyn Sandbox,
    granted: &[(String, String)],
    modes: &[String],
) -> Option<&'static str> {
    let grants = granted
        .iter()
        .zip(modes)
        .map(|((n, v), m)| (n.as_str(), v.as_str(), Some(m.as_str())));
    if let Some(why) =
        ainkrad_proto::v2::subscription_problem(&req.harness, req.gateway.is_some(), grants)
    {
        return Some(why);
    }
    let holds = granted
        .iter()
        .any(|(n, _)| ainkrad_proto::v2::is_subscription_secret(n));
    if holds && req.policy.required_tier().is_none() {
        return Some(
            "a session holding a subscription account's token must run sandboxed: set \
             min_isolation to process or stronger",
        );
    }
    (holds && !sandbox.capabilities().contains(&"egress-filter")).then_some(
        "a session holding a subscription account's token needs a runner with a proven egress filter",
    )
}
