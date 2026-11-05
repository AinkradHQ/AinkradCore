//! How the gateway reaches a provider (KAN-435 G7): the wire it speaks, and, for a user-defined
//! provider, the key shape and frozen host the runner checks a key against before dialing
//! (`key_host_problem`, the rule the broker applied at store). One answer for a session's grant and
//! for an account test, so they cannot disagree.

use ainkrad_proto::v2::{UserKeyDef, Wire};

use super::{Refusal, refuse};
use crate::store::provider_rules::host_of;
use crate::store::providers::Definition;

/// What the grant or the test carries about the provider.
pub(super) struct Route {
    pub wire: Wire,
    /// Set for a user-defined provider.
    pub user_key: Option<UserKeyDef>,
}

fn wire_named(name: &str) -> Option<Wire> {
    match name {
        "anthropic-messages" => Some(Wire::AnthropicMessages),
        "openai-responses" => Some(Wire::OpenaiResponses),
        "gemini-generate" => Some(Wire::GeminiGenerate),
        _ => None,
    }
}

/// The route of an account of `def` whose frozen base URL is `base_url`. A provider that is not
/// delivered through the gateway, has no wire, or (a user definition) declares no key shape has none.
pub(super) fn of(def: &Definition, base_url: &str) -> Result<Route, Refusal> {
    if !def.delivery.iter().any(|m| m == "gateway") {
        return Err(refuse("the provider is not delivered through the gateway"));
    }
    let wire = wire_named(&def.wire).ok_or_else(|| refuse("the provider has no wire"))?;
    let user_key = match (def.builtin, &def.key_prefix) {
        (true, _) => None,
        (false, Some(prefix)) => Some(UserKeyDef {
            prefix: prefix.clone(),
            host: host_of(base_url).to_owned(),
        }),
        (false, None) => return Err(refuse("the provider declares no key_prefix")),
    };
    Ok(Route { wire, user_key })
}

fn builtin(provider: &str) -> bool {
    crate::store::secrets::ACCOUNT_PROVIDERS
        .iter()
        .any(|(k, _)| *k == provider)
}

/// Why a session of `harness` may not hold `secrets`, if it may not (the broker's rule at create,
/// the launch's for a stored row):
///
/// - **The env rule** (`account_var_problem`: a provider-account secret only in its harness's own
///   variable, nothing that redirects traffic). An API-key account of a user-defined provider is
///   served by the gateway and delivers no variable, so it is not judged by a variable list that
///   knows three providers; the launch checks its definition's harness against the session's.
/// - **Never in `secrets`** (design §4.3, §10 Q4): a name under `acct.` that is not the account
///   model's own `acct.<provider>.<id>` would be leased into the sandbox as an environment variable,
///   with the key in it. It is refused, whatever the label.
pub(in crate::agents) fn secrets_problem(
    harness: &str,
    secrets: &[crate::store::agents::SessionSecret],
) -> Option<&'static str> {
    let served_by_gateway =
        |name: &str| crate::store::gateway::account_secret(name).is_some_and(|(p, _)| !builtin(p));
    ainkrad_proto::v2::account_var_problem(
        harness,
        secrets
            .iter()
            .filter(|s| !served_by_gateway(&s.name))
            .map(|s| (s.name.as_str(), s.var.as_str())),
    )
    .or_else(|| {
        secrets
            .iter()
            .any(|s| {
                s.name.starts_with(crate::store::secrets::ACCOUNT_PREFIX)
                    && crate::store::gateway::account_secret(&s.name).is_none()
            })
            .then_some(
                "a provider-account secret is an API-key account served by the gateway, never an \
                 environment variable: name it acct.<provider>.<id> (the account's own name)",
            )
    })
}
