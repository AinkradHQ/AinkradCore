//! The auth gateway's wire types (KAN-435 G1): the grant that lets a runner hold an API key for a
//! session without the harness ever seeing it, the rule that binds a key to the host it may be sent
//! to, and the ops around it. Types and rules only: nothing here dials, stores or meters.
//!
//! - `agent.limit` moves a live session's spend ceiling (0 refuses everything from then on).
//! - `gateway.test` is the one-shot request behind `POST /accounts/{id}/test`.
//! - A runner that can serve a grant lists [`CAP_GATEWAY`] among its agent driver's commands; the
//!   Core places a session with a grant only on such a runner and sends it these ops only there.

use serde::{Deserialize, Serialize};

pub const OP_AGENT_LIMIT: &str = "agent.limit";
pub const OP_GATEWAY_TEST: &str = "gateway.test";

/// The command an agent driver lists when its runner can run the gateway (as `egress-filter`).
pub const CAP_GATEWAY: &str = "gateway";

/// The upstream API dialects the gateway speaks: a closed set, so the route table is code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Wire {
    AnthropicMessages,
    OpenaiResponses,
    GeminiGenerate,
}

/// The header the gateway puts the key in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GatewayAuth {
    /// `x-api-key: <key>`
    XApiKey,
    /// `Authorization: Bearer <key>`
    Bearer,
    /// `x-goog-api-key: <key>`
    XGoogApiKey,
}

impl Wire {
    /// How this wire authenticates.
    pub fn auth(self) -> GatewayAuth {
        match self {
            Self::AnthropicMessages => GatewayAuth::XApiKey,
            Self::OpenaiResponses => GatewayAuth::Bearer,
            Self::GeminiGenerate => GatewayAuth::XGoogApiKey,
        }
    }
}

/// Where the gateway dials: from the account row's frozen `base_url`, never from the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Upstream {
    /// The host name, no scheme, port or trailing dot (443 only).
    pub host: String,
    /// The path the wire's routes hang under (`""`, or `/v1` for the OpenAI wire).
    #[serde(default)]
    pub base_path: String,
    pub wire: Wire,
    pub auth: GatewayAuth,
}

/// What a session may spend through the gateway; `agent.limit` changes it while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Ceiling {
    pub tokens: u64,
    pub usd_micros: u64,
}

/// How fast a session may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Rate {
    pub per_minute: u32,
    pub concurrent: u32,
}

/// A user-defined provider's key shape and frozen host: what the runner needs to run
/// [`key_host_problem`] as the broker did. Absent for a built-in provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UserKeyDef {
    /// The definition's declared `key_prefix`.
    pub prefix: String,
    /// The definition's frozen host.
    pub host: String,
}

impl UserKeyDef {
    /// This definition as the rule takes it, under the grant's `provider`.
    pub fn of<'a>(&'a self, provider: &'a str) -> UserKeyHost<'a> {
        UserKeyHost {
            provider,
            prefix: &self.prefix,
            host: &self.host,
        }
    }
}

/// The list price of one model, in micro-dollars per million tokens, for the gateway's
/// per-request reservation (decision: the Core's price book, carried in the grant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelPrice {
    pub model: String,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

/// Core to runner, in `AgentStart`: the key of one account, served to the harness by the runner's
/// gateway. `lease` is redeemed into the gateway's memory, never the env or a file. No `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GatewayGrant {
    /// `l_…`, single use, this runner only.
    pub lease: String,
    /// The account id, for the runner's logs; the ledger takes it from the Core's own row.
    pub account: i64,
    /// The account's provider id (`anthropic`, or a user definition's id): the runner runs
    /// [`key_host_problem`] with it before dialing. Absent reads as empty, which no key passes.
    #[serde(default)]
    pub provider: String,
    /// The user definition's key shape and host, for a user-defined provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_key: Option<UserKeyDef>,
    pub upstream: Upstream,
    /// The model ids the session may name.
    pub models: Vec<String>,
    /// The list price of each model in `models`, for the per-request reservation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prices: Vec<ModelPrice>,
    pub ceiling: Ceiling,
    pub rate: Rate,
}

/// Core to runner: set the ceiling of a live gateway session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentLimit {
    pub session: String,
    /// All zero: refuse every request and abort open streams.
    pub ceiling: Ceiling,
}

/// Core to runner: redeem `lease`, run the dial checks, make one free request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GatewayTest {
    pub lease: String,
    /// As in [`GatewayGrant`].
    #[serde(default)]
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_key: Option<UserKeyDef>,
    pub upstream: Upstream,
}

/// The outcome class of an upstream request or test: a status class only, never provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStatus {
    Ok,
    RateLimited,
    Quota,
    AuthFailed,
    ServerError,
    Unreachable,
    RefusedAddress,
    TlsFailed,
    /// A class from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

/// Runner to Core: the status class and latency of a [`GatewayTest`]; never a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GatewayTested {
    pub result: UpstreamStatus,
    pub latency_ms: u64,
}

// No `Debug` on anything carrying a lease (secrets review L4).
impl std::fmt::Debug for GatewayGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayGrant")
            .field("account", &self.account)
            .field("host", &self.upstream.host)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GatewayTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayTest")
            .field("host", &self.upstream.host)
            .finish_non_exhaustive()
    }
}

/// Key classes by shape, most specific first, each with the one provider and host it belongs to.
/// The OpenAI bare `sk-` catch-all is not here: it is the last resort in [`key_host_problem`].
const KEY_CLASSES: [(&str, &str, &str); 5] = [
    ("sk-ant-", "anthropic", "api.anthropic.com"),
    ("AIza", "google", "generativelanguage.googleapis.com"),
    ("sk-proj-", "openai", "api.openai.com"),
    ("sk-svcacct-", "openai", "api.openai.com"),
    ("sk-admin-", "openai", "api.openai.com"),
];

/// A user definition's key shape: the provider, its declared `key_prefix` and its frozen host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserKeyHost<'a> {
    pub provider: &'a str,
    pub prefix: &'a str,
    pub host: &'a str,
}

/// Why a key `value` of `provider` may not be sent to `host`, or `None` when it may. One rule for
/// the broker (at store) and the runner (before dialing). The key's own shape decides the host, so
/// a built-in-shaped key can never go to a user's host; `user` lists the user definitions'
/// declared prefixes (the longest match wins). A shape no rule knows is refused.
pub fn key_host_problem(
    value: &str,
    provider: &str,
    host: &str,
    user: &[UserKeyHost],
) -> Option<&'static str> {
    let (want_provider, want_host) = match KEY_CLASSES.iter().find(|c| value.starts_with(c.0)) {
        Some(c) => (c.1, c.2),
        None => match user
            .iter()
            .filter(|u| value.starts_with(u.prefix))
            .max_by_key(|u| u.prefix.len())
        {
            Some(u) => (u.provider, u.host),
            None if value.starts_with("sk-") => ("openai", "api.openai.com"),
            None => return Some("the key has a shape no provider rule knows"),
        },
    };
    if provider != want_provider {
        return Some("the key belongs to another provider");
    }
    // Exact, case-insensitive on the name only: a trailing dot or a suffix is another host.
    (!host.eq_ignore_ascii_case(want_host)).then_some("the key may not be sent to that host")
}

/// Why `prefix` may not be a user definition's `key_prefix`: shorter than 6 bytes, not printable
/// ASCII, or equal to, a prefix of, or starting with a built-in key shape (it would be read as
/// that shape, or shadow it).
pub fn key_prefix_problem(prefix: &str) -> Option<&'static str> {
    if prefix.len() < 6 || !prefix.bytes().all(|b| b.is_ascii_graphic()) {
        return Some("a key prefix is at least 6 printable ASCII characters");
    }
    let builtin = KEY_CLASSES
        .iter()
        .any(|c| prefix.starts_with(c.0) || c.0.starts_with(prefix));
    builtin.then_some("a key prefix may not equal, shadow or extend a built-in key shape")
}

#[cfg(test)]
mod tests;
