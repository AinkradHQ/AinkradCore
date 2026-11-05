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
    /// The definition's authenticated test path (user definitions only).
    pub test_path: Option<String>,
    /// Whether a test of this provider says anything about the key: a built-in's model list is
    /// authenticated, a user definition's is only if it declares a `test_path`. Otherwise a test
    /// is `inconclusive`, never `ok`, and never clears an auth failure.
    pub can_test: bool,
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
    let test_path = def.test_path.clone().filter(|_| !def.builtin);
    let can_test = def.builtin || test_path.is_some();
    Ok(Route {
        wire,
        user_key,
        test_path,
        can_test,
    })
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
        // Whatever provider the gateway serves, no sibling secret may steer traffic (the env rule
        // above judges only the secrets it knows a provider for).
        let gateway = secrets
            .iter()
            .any(|s| crate::store::gateway::account_secret(&s.name).is_some());
        (gateway && secrets.iter().any(|s| ainkrad_proto::v2::redirects_traffic(&s.var))).then_some(
            "a session holding a provider-account secret may not set a proxy, base URL, endpoint or \
             certificate variable: it could redirect the key",
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::providers::{Model, built_in};

    fn user(prefix: Option<&str>) -> Definition {
        Definition {
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
            wire: "openai-responses".to_owned(),
            key_prefix: prefix.map(str::to_owned),
            test_path: None,
            builtin: false,
            version: 1,
        }
    }

    #[test]
    fn a_built_in_carries_no_key_shape_and_a_user_definition_its_prefix_and_frozen_host() {
        for d in built_in() {
            // A subscription's token is a leased env variable (§5): the gateway never serves it.
            if d.id == "claude-sub" {
                assert!(of(&d, &d.base_url).is_err());
                continue;
            }
            let r = of(&d, &d.base_url).expect("built-ins have a route");
            assert!(r.user_key.is_none(), "{}", d.id);
            assert_eq!(r.wire, wire_named(&d.wire).unwrap());
        }
        let r = of(&user(Some("sk-or-v1-")), "https://openrouter.ai/api/v1").unwrap();
        assert_eq!(r.wire, Wire::OpenaiResponses);
        let k = r.user_key.unwrap();
        // The host is the account's frozen one, not the definition's current URL.
        let frozen = of(&user(Some("sk-or-v1-")), "https://old.example.com:443/v1").unwrap();
        assert_eq!(
            (k.prefix.as_str(), k.host.as_str()),
            ("sk-or-v1-", "openrouter.ai")
        );
        assert_eq!(frozen.user_key.unwrap().host, "old.example.com");
    }

    #[test]
    fn a_definition_without_a_prefix_a_wire_or_the_gateway_has_no_route() {
        assert!(of(&user(None), "https://openrouter.ai/api/v1").is_err());
        let mut env = user(Some("sk-or-v1-"));
        env.delivery = vec!["env".to_owned()];
        assert!(of(&env, "https://openrouter.ai/api/v1").is_err());
        let mut none = user(Some("sk-or-v1-"));
        none.wire = String::new();
        assert!(of(&none, "https://openrouter.ai/api/v1").is_err());
    }

    #[test]
    fn a_session_may_not_hold_an_api_key_account_as_an_env_secret() {
        use crate::store::agents::SessionSecret;
        let s = |name: &str| SessionSecret {
            name: name.to_owned(),
            var: "OPENAI_API_KEY".to_owned(),
        };
        // The account model's own names, of a built-in and of a user definition.
        assert_eq!(secrets_problem("codex", &[s("acct.openai.7")]), None);
        assert_eq!(secrets_problem("codex", &[s("acct.openrouter.7")]), None);
        // Any other label would be leased into the sandbox as a variable.
        for name in [
            "acct.openai.main",
            "acct.openrouter.main",
            "acct.openai.07",
            "acct.x",
        ] {
            assert!(secrets_problem("codex", &[s(name)]).is_some(), "{name}");
        }
        assert_eq!(secrets_problem("codex", &[s("git.token")]), None);
        // A sibling secret may not steer traffic beside a user provider's account either.
        for var in ["OPENAI_BASE_URL", "HTTPS_PROXY", "SSL_CERT_FILE"] {
            let both = [
                s("acct.openrouter.7"),
                SessionSecret {
                    name: "git.token".to_owned(),
                    var: var.to_owned(),
                },
            ];
            let why = secrets_problem("codex", &both).expect(var);
            assert!(why.contains("redirect"), "{var}: {why}");
            // The same secret without an account is the old rule.
            assert_eq!(secrets_problem("codex", &both[1..]), None, "{var}");
        }
    }
}
