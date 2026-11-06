//! The runner's own check of a subscription account's token (KAN-434, KAN-441 L5), applied whatever
//! the Core sent, in two steps:
//!
//! - [`early`], before any lease is redeemed (a lease is single use and its value is in the runner's
//!   memory once redeemed): the token's variable is in the grants, so the harness must be claude, no
//!   gateway grant may be present, and the session must run sandboxed on a runner with a proven
//!   egress filter. Only the variable is known then, not the secret's name.
//! - [`problem`], once the secrets are redeemed: the shared shape rule
//!   (`ainkrad_proto::v2::subscription_problem`: claude only, `CLAUDE_CODE_OAUTH_TOKEN` only, env
//!   only, one account, no gateway grant, no other provider account) on their names and delivery.

use ainkrad_proto::v2::{SUBSCRIPTION_HARNESS, SUBSCRIPTION_VAR, SecretGrant};

use super::{AgentStart, Sandbox};

const SANDBOX: &str = "a session holding a subscription account's token must run sandboxed: ask \
                       for the process isolation tier or stronger";
const FILTER: &str =
    "a session holding a subscription account's token needs a runner with a proven egress filter";

/// Why `req` may not redeem its leases, when one is granted under the token's variable.
pub(super) fn early(req: &AgentStart, sandbox: &dyn Sandbox) -> Result<(), &'static str> {
    if !req
        .secrets
        .iter()
        .any(|g: &SecretGrant| g.var == SUBSCRIPTION_VAR)
    {
        return Ok(());
    }
    if req.harness != SUBSCRIPTION_HARNESS {
        return Err("a subscription account's token goes only to the claude harness");
    }
    if req.gateway.is_some() {
        return Err("a subscription account is never served by the gateway: no gateway grant");
    }
    if req.policy.required_tier().is_none() {
        return Err(SANDBOX);
    }
    match sandbox.capabilities().contains(&"egress-filter") {
        true => Ok(()),
        false => Err(FILTER),
    }
}

/// Why `req` may not hold the redeemed secrets `granted` (each a name and the variable it was granted
/// under) delivered as `modes`. `Ok` for a session with no subscription token.
pub(super) fn problem(
    req: &AgentStart,
    sandbox: &dyn Sandbox,
    granted: &[(String, String)],
    modes: &[String],
) -> Result<(), String> {
    let grants = granted
        .iter()
        .zip(modes)
        .map(|((n, v), m)| (n.as_str(), v.as_str(), Some(m.as_str())));
    if let Some(why) =
        ainkrad_proto::v2::subscription_problem(&req.harness, req.gateway.is_some(), grants)
    {
        return Err(why.to_owned());
    }
    // A token under another variable was refused above; a token redeemed under the right one was
    // judged by `early`. This covers the name being a subscription's under a variable `early`
    // could not see (the shared rule refuses that variable, so this is a backstop).
    if granted
        .iter()
        .any(|(n, _)| ainkrad_proto::v2::is_subscription_secret(n))
    {
        if req.policy.required_tier().is_none() {
            return Err(SANDBOX.to_owned());
        }
        if !sandbox.capabilities().contains(&"egress-filter") {
            return Err(FILTER.to_owned());
        }
    }
    Ok(())
}
