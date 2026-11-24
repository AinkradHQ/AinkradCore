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

/// The runner-bound subscription providers (E7-4, E7-5, E7-5b) and the harness each runs. Their
/// credential (Codex `auth.json`, OpenCode `auth.json`, Antigravity's keyring entry) rotates or is
/// not portable, so it stays in the account's home on one runner: the Core stores a non-secret
/// marker and the runner's id, never a token. They are deliberately not in
/// [`SUBSCRIPTION_PROVIDERS`]: the claude token rules above stay as they are.
pub const BOUND_PROVIDERS: [(&str, &str); 3] = [
    ("codex-sub", "codex"),
    ("opencode-sub", "opencode"),
    ("agy-sub", "agy"),
];
/// The command an agent driver lists when its runner starts a session in an account's own home
/// (`AgentStart::home`). The Core places a runner-bound session only on a runner that lists it.
pub const CAP_BOUND_HOME: &str = "bound-home";
/// Where a bound account's home is, under the runner's config root.
pub const BOUND_HOME_DIR: &str = "bound";

/// The command an agent driver lists when its runner takes a Core-held plan's login for one
/// session (`AgentStart::home_lease`, 2026-11-23). The Core lends one only to a runner that lists it.
pub const CAP_LENT_HOME: &str = "lent-home";

/// The runner-bound providers whose login is files the Core can keep and lend (Codex, OpenCode).
/// Antigravity's lives in the OS keyring: it stays on the runner that signed in.
pub const LENDABLE: [&str; 2] = ["codex-sub", "opencode-sub"];

/// Whether `provider`'s login can be held by the Core and lent per session.
pub fn lendable(provider: &str) -> bool {
    LENDABLE.contains(&provider)
}

/// The credential file(s) of `harness`, relative to its config dir: Codex's and OpenCode's own
/// `auth.json`. agy keeps its login in the OS keyring; `.gemini/oauth_creds.json` is what a
/// file-backed agy login writes (unverified per CLI version), copied per session on its runner only.
pub fn credential_files(harness: &str) -> &'static [&'static str] {
    match harness {
        "codex" => &["auth.json"],
        "opencode" => &["data/opencode/auth.json"],
        "agy" => &[".gemini/oauth_creds.json"],
        _ => &[],
    }
}

/// The most one credential file may be. Real ones are a few KB.
pub const MAX_CREDENTIAL: usize = 256 * 1024;

/// A lent login: each credential file's path (one of [`credential_files`]) and its JSON text.
pub type Bundle = std::collections::BTreeMap<String, String>;

/// `text` as `harness`'s bundle: at least one file, each a known path whose content is JSON of
/// at most [`MAX_CREDENTIAL`] bytes. Anything else is `Err` with a reason that holds no value.
pub fn parse_bundle(harness: &str, text: &str) -> Result<Bundle, &'static str> {
    let b: Bundle =
        serde_json::from_str(text).map_err(|_| "the login is not a credential bundle")?;
    bundle_problem(harness, &b).map_or(Ok(b), Err)
}

/// Why `b` is not a bundle of `harness`'s, if it is not.
pub fn bundle_problem(harness: &str, b: &Bundle) -> Option<&'static str> {
    let known = credential_files(harness);
    if b.is_empty() {
        return Some("the login holds no credential file");
    }
    for (path, text) in b {
        if !known.contains(&path.as_str()) {
            return Some("the login names a file that is not the harness's credential");
        }
        if text.len() > MAX_CREDENTIAL || serde_json::from_str::<serde_json::Value>(text).is_err() {
            return Some("a credential file is not small JSON");
        }
    }
    None
}

/// The identity a credential carries, as sorted `(claim, value)` pairs: Codex's `tokens.account_id`
/// and the `sub`, `email` and `chatgpt_account_id` claims of its `id_token` (a JWT whose payload is
/// decoded, NOT verified: a rotation is compared with the stored one, never trusted on its own).
fn identity(v: &serde_json::Value) -> Vec<(String, String)> {
    use base64::Engine;
    let mut out = Vec::new();
    let tokens = v.get("tokens").unwrap_or(v);
    if let Some(a) = tokens.get("account_id").and_then(|x| x.as_str()) {
        out.push(("account_id".to_owned(), a.to_owned()));
    }
    let payload = tokens
        .get("id_token")
        .and_then(|t| t.as_str())
        .and_then(|t| t.split('.').nth(1))
        .and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    if let Some(c) = payload {
        for k in ["sub", "email"] {
            if let Some(x) = c.get(k).and_then(|x| x.as_str()) {
                out.push((k.to_owned(), x.to_owned()));
            }
        }
        let auth = c.get("https://api.openai.com/auth");
        if let Some(x) = auth
            .and_then(|a| a.get("chatgpt_account_id"))
            .and_then(|x| x.as_str())
        {
            out.push(("chatgpt_account_id".to_owned(), x.to_owned()));
        }
    }
    out.sort();
    out
}

/// Whether the rotated credential `new` is the stored `old`'s own account: the same identity claims
/// when the stored one carries any (a rotated token keeps them), else the same top-level key set
/// (names only, never values). Unparseable either way: not the same. The runner and the Core both
/// apply it to a credential coming back from a session.
pub fn same_account(old: &[u8], new: &[u8]) -> bool {
    let (Ok(o), Ok(n)) = (
        serde_json::from_slice::<serde_json::Value>(old),
        serde_json::from_slice::<serde_json::Value>(new),
    ) else {
        return false;
    };
    let id = identity(&o);
    if !id.is_empty() {
        return id == identity(&n);
    }
    let keys = |v: &serde_json::Value| -> Option<Vec<String>> {
        let mut k: Vec<_> = v.as_object()?.keys().cloned().collect();
        k.sort();
        Some(k)
    };
    keys(&o).is_some() && keys(&o) == keys(&n)
}

/// Whether a login a session sends back may replace the Core-held one of `harness` (accounts on the
/// Core, security review item 5). The agent can write those files, and their claims are unsigned,
/// so a looser rule would let it swap in another account. Codex: the stored login must carry its
/// stable `tokens.account_id` (from the sign-in, stored by the Core), and the new one the very same
/// identity (that id and the `id_token`'s claims). Anything else, and every OpenCode login (no stable
/// identity at all), is refused: the vault keeps its copy; a new sign-in beats a swapped account.
pub fn same_lent_account(harness: &str, old: &[u8], new: &[u8]) -> bool {
    if harness != "codex" {
        return false;
    }
    let (Ok(o), Ok(n)) = (
        serde_json::from_slice::<serde_json::Value>(old),
        serde_json::from_slice::<serde_json::Value>(new),
    ) else {
        return false;
    };
    let id = identity(&o);
    let anchored = id.iter().any(|(k, v)| k == "account_id" && !v.is_empty());
    anchored && id == identity(&n)
}

/// The harness a bound provider runs, or `None` for any other provider.
pub fn bound_harness(provider: &str) -> Option<&'static str> {
    BOUND_PROVIDERS
        .iter()
        .find(|(p, _)| *p == provider)
        .map(|(_, h)| *h)
}

fn provider_of(name: &str) -> Option<&str> {
    name.strip_prefix(ACCOUNT_PREFIX)?.split('.').next()
}

/// Whether `name` is a runner-bound account's secret (`acct.codex-sub.<id>`). By provider alone,
/// so a malformed name counts too: fail closed.
pub fn is_bound_secret(name: &str) -> bool {
    name.strip_prefix(ACCOUNT_PREFIX)
        .and_then(|rest| rest.split('.').next())
        .is_some_and(|p| bound_harness(p).is_some())
}

/// A home key: what names an account's dir under [`BOUND_HOME_DIR`]. Plain, so it cannot escape.
pub fn bound_key_ok(key: &str) -> bool {
    (1..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Why a session of `harness` may not hold `names` (secret names) when one is a runner-bound
/// account: its harness only, one such account, no gateway grant and no other provider account.
pub fn bound_problem<'a>(
    harness: &str,
    has_gateway: bool,
    names: impl IntoIterator<Item = &'a str> + Clone,
) -> Option<&'static str> {
    let bound: Vec<&str> = names
        .clone()
        .into_iter()
        .filter(|n| is_bound_secret(n))
        .collect();
    if bound.is_empty() {
        return None;
    }
    if bound
        .iter()
        .any(|n| provider_of(n).and_then(bound_harness) != Some(harness))
    {
        return Some("a runner-bound account goes only to its own provider's harness");
    }
    if bound.len() > 1 {
        return Some("a session names at most one runner-bound account");
    }
    if has_gateway {
        return Some("a runner-bound account is never served by the gateway: no gateway grant");
    }
    if names
        .into_iter()
        .any(|n| n.starts_with(ACCOUNT_PREFIX) && !is_bound_secret(n))
    {
        return Some("a session holding a runner-bound account may hold no other provider account");
    }
    None
}

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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct PlanChecked {
    /// `ok`, or why not: `token_expired`, `limit_reached`, `egress_not_proven`,
    /// `sandbox_unavailable`, `runner_busy`, `unreachable`, `timeout` or `failed`.
    pub result: String,
    pub latency_ms: u64,
    /// The plan windows Claude reported on the check's answer (its `rate_limit_event`), stored on
    /// the account like a session's. Absent from an older runner or when Claude said none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_limit: Option<super::PlanLimit>,
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
    fn a_bundle_is_the_harness_s_own_credential_files_as_json_only() {
        assert!(lendable("codex-sub") && lendable("opencode-sub") && !lendable("agy-sub"));
        assert!(parse_bundle("codex", r#"{"auth.json":"{\"t\":\"x\"}"}"#).is_ok());
        for bad in [
            "{}",
            "not json",
            r#"{"auth.json":"not json"}"#,
            r#"{"../auth.json":"{}"}"#,
            r#"{"config.toml":"{}"}"#,
        ] {
            assert!(parse_bundle("codex", bad).is_err(), "{bad}");
        }
        assert!(parse_bundle("opencode", r#"{"auth.json":"{}"}"#).is_err());
        assert!(parse_bundle("opencode", r#"{"data/opencode/auth.json":"{}"}"#).is_ok());
        assert!(same_account(br#"{"a":1}"#, br#"{"a":2}"#));
        // A lent login comes back only for Codex, anchored on the stored account id.
        let old = br#"{"tokens":{"account_id":"acct-dummy-1","refresh_token":"r1"}}"#;
        let new = br#"{"tokens":{"account_id":"acct-dummy-1","refresh_token":"r2"}}"#;
        let other = br#"{"tokens":{"account_id":"acct-dummy-2","refresh_token":"r2"}}"#;
        assert!(same_lent_account("codex", old, new));
        assert!(!same_lent_account("codex", old, other));
        assert!(!same_lent_account(
            "codex",
            br#"{"tokens":{"r":"1"}}"#,
            br#"{"tokens":{"r":"2"}}"#
        ));
        assert!(!same_lent_account("opencode", br#"{"a":1}"#, br#"{"a":2}"#));
        assert!(!same_account(br#"{"a":1}"#, br#"{"b":2}"#));
    }

    #[test]
    fn a_bound_account_goes_to_its_own_harness_alone() {
        let b = "acct.codex-sub.4";
        assert_eq!(bound_problem("codex", false, [b]), None);
        assert!(bound_problem("claude", false, [b]).is_some());
        assert!(bound_problem("opencode", false, [b]).is_some());
        assert!(bound_problem("codex", true, [b]).is_some());
        assert!(bound_problem("codex", false, [b, "acct.codex-sub.5"]).is_some());
        assert!(bound_problem("codex", false, [b, "acct.openai.3"]).is_some());
        assert_eq!(bound_problem("codex", false, ["acct.openai.3"]), None);
        assert_eq!(bound_harness("agy-sub"), Some("agy"));
        // It is not a claude token: the claude rules do not see it.
        assert!(!is_subscription_secret(b));
        assert!(is_bound_secret("acct.agy-sub.x"));
        assert!(bound_key_ok("lg_1-a") && !bound_key_ok("../x") && !bound_key_ok(""));
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
