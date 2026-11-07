//! Request and response bodies of the account, pool, binding and provider routes.

use super::*;

/// An account as a `read` device sees it: its key's last four characters, never the key, the
/// broker secret's name or the runners it may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderAccount {
    pub id: i64,
    /// `anthropic`, `openai`, `google` or a user definition's id.
    pub provider: String,
    pub label: String,
    /// The key's last four characters; empty for a key too short to show any.
    pub masked_tail: String,
    /// The provider's base URL when the account was stored.
    pub base_url: String,
    /// `active`, `cooling`, `limited`, `unhealthy` or `disabled`.
    pub state: String,
    pub state_reason: Option<String>,
    pub state_until: Option<Timestamp>,
    /// Sessions that may hold the account at once; 0 is no cap.
    pub cap: i64,
    /// What one session may spend through this account; absent when only the budgets limit it.
    pub session_limits: Option<SessionLimits>,
    /// The last one-shot test of the key; absent when it was never tested.
    pub last_test: Option<LastTest>,
    pub last_used_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Sessions that hold a slot of its cap now (`starting`, `running`, `interrupted`). Only the
    /// reads (`listAccounts`, `getAccount`) say it.
    pub live: Option<i64>,
    /// What the scheduler keeps of its health. Only the reads say it; `state`, `state_reason`
    /// and `state_until` (a cooldown's end) are above.
    pub health: Option<AccountHealth>,
}

/// An account's health counters, as the scheduler keeps them.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountHealth {
    /// Upstream errors counted in the current ten-minute window; three put it out for ten minutes.
    pub fail_streak: i64,
    /// A subscription's failed sessions in a row; the third keeps it out of new runs
    /// (`state_reason` `auth_suspected`) until an admin answers.
    pub auth_streak: i64,
    /// The last time a request or a session on it went well.
    pub last_success_at: Option<Timestamp>,
    /// The last status class its gateway reported on any of its sessions.
    pub upstream_class: Option<String>,
    /// A subscription's latest plan-limit snapshot, as its harness last said it (harness output:
    /// it can only cool the account, never disable it).
    pub plan_limit: Option<AccountPlanLimit>,
}

/// A subscription's plan-limit snapshot.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountPlanLimit {
    /// When the Core stored it.
    pub at: Timestamp,
    /// The harness's own word: `allowed`, `allowed_warning`, `rejected`.
    pub status: String,
    pub windows: Vec<AccountPlanWindow>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountPlanWindow {
    /// e.g. `five_hour`, `seven_day`.
    pub name: String,
    /// A fraction of the window's limit, past 1 at the limit.
    pub utilization: f64,
    pub resets_at: Option<Timestamp>,
}

impl AccountPlanLimit {
    fn of(snapshot: &serde_json::Value) -> Option<Self> {
        let at = snapshot["at"].as_i64()?;
        let plan = &snapshot["plan"];
        let when = |s: i64| ts(&crate::scheduler::iso_of_unix(s));
        Some(Self {
            at: when(at),
            status: plan["status"].as_str()?.to_owned(),
            windows: plan["windows"]
                .as_array()
                .map(|w| {
                    w.iter()
                        .filter_map(|w| {
                            Some(AccountPlanWindow {
                                name: w["name"].as_str()?.to_owned(),
                                utilization: w["utilization"].as_f64()?,
                                resets_at: w["resets_at"].as_i64().map(when),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

impl ProviderAccount {
    /// With its load and health, from [`crate::store::health::statuses`]; an account with no row
    /// there (just made) has none.
    pub(super) fn with_status(mut self, st: Option<&crate::store::health::Status>) -> Self {
        if let Some(st) = st {
            self.live = Some(st.live);
            self.health = Some(AccountHealth {
                fail_streak: st.fail_streak,
                auth_streak: st.auth_streak,
                last_success_at: opt_ts(st.last_success_at.as_deref()),
                upstream_class: st.upstream_class.clone(),
                plan_limit: st.plan_limit.as_ref().and_then(AccountPlanLimit::of),
            });
        }
        self
    }
}

impl From<acc::Account> for ProviderAccount {
    fn from(a: acc::Account) -> Self {
        Self {
            id: a.id,
            provider: a.provider,
            label: a.label,
            masked_tail: a.masked_tail,
            base_url: a.base_url,
            state: a.state,
            state_reason: a.state_reason,
            state_until: opt_ts(a.state_until.as_deref()),
            cap: a.cap,
            session_limits: (a.session_max_tokens.is_some() || a.session_max_usd_micros.is_some())
                .then_some(SessionLimits {
                    max_tokens: a.session_max_tokens,
                    max_usd_micros: a.session_max_usd_micros,
                }),
            last_test: a
                .last_test_at
                .as_deref()
                .zip(a.last_test_result)
                .map(|(at, result)| LastTest { result, at: ts(at) }),
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            created_at: ts(&a.created_at),
            updated_at: ts(&a.updated_at),
            live: None,
            health: None,
        }
    }
}

/// What an `admin` write answers: the account and the runners its key may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountDetail {
    pub account: ProviderAccount,
    /// Runner device ids, explicit (never a wildcard).
    pub runners: Vec<String>,
}

impl From<acc::Account> for AccountDetail {
    fn from(a: acc::Account) -> Self {
        let runners = a.runners.clone();
        Self {
            account: a.into(),
            runners,
        }
    }
}

/// A new account. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewProviderAccount {
    pub provider: String,
    pub label: String,
    /// The API key; written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Runner device ids it may be leased to; default none.
    pub runners: Option<Vec<String>>,
    /// Default 4; 0 is no cap.
    pub cap: Option<i64>,
}

/// A replacement key, and optionally a new runner scope. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct ReplaceKey {
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    pub runners: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetState {
    /// `active`, `cooling`, `limited`, `unhealthy` or `disabled`.
    pub state: String,
    // `reason` is kept in the audit row; the account's own `state_reason` then reads `manual`.
    pub reason: Option<String>,
    // `until` is stored with the state, but a state an admin sets stays until an admin changes it:
    // only a cooldown the Core itself set (rate_limited, quota, upstream_errors) ends by itself.
    pub until: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCap {
    pub cap: i64,
}

/// What one session may spend through an account. A dimension left out is not limited by the
/// account (only by the budgets).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SessionLimits {
    /// Input, output and cache tokens; at least 328000 (one turn needs that much room).
    pub max_tokens: Option<i64>,
    /// Millionths of a dollar.
    pub max_usd_micros: Option<i64>,
}

/// The last one-shot test of an account's key.
#[derive(Debug, Serialize, ToSchema)]
pub struct LastTest {
    /// The status class the provider answered: `ok`, `rate_limited`, `quota`, `auth_failed`,
    /// `server_error`, `unreachable`, `refused_address`, `tls_failed`, `inconclusive` (see
    /// [`AccountTested`]) or `failed` (the runner did not answer). Never provider text.
    pub result: String,
    pub at: Timestamp,
}

/// What `POST /accounts/{id}/test` answers: a status class and a latency, never a response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountTested {
    /// As [`LastTest::result`], or `inconclusive`: the provider's model list needs no key and its
    /// definition declares no `test_path`, so nothing was sent and nothing is known of the key.
    pub result: String,
    pub latency_ms: u64,
    /// The runner device that made the request (empty when `result` is `inconclusive`).
    pub runner: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountsDeleted {
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ModelPrice {
    pub id: String,
    /// List price per million input tokens, in millionths of a dollar.
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
}

/// A provider definition: a built-in, or user data validated before it is stored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Provider {
    pub id: String,
    pub name: String,
    /// `claude`, `codex` or `agy`.
    pub harness: String,
    /// The API dialect the gateway speaks to this provider: `anthropic-messages` (claude),
    /// `openai-responses` (codex) or `gemini-generate` (agy). Optional on write: it is its
    /// harness's own, and any other is refused.
    #[serde(default)]
    pub wire: Option<String>,
    /// The shape this provider's keys start with (6 to 16 characters, never a built-in's, such
    /// as `sk-or-v1-`). A definition that sets it holds keys, and then only through the gateway
    /// (`delivery` is `["gateway"]`): the broker binds each key to the account's host by it.
    #[serde(default)]
    pub key_prefix: Option<String>,
    /// The authenticated path (under the base URL, such as `/key`) of the one-shot account test,
    /// for a provider whose model list needs no key (OpenRouter's is public: a revoked key would
    /// read as `ok`). A user definition without one cannot be tested: the answer is
    /// `inconclusive`. Built-ins use their wire's own model list.
    #[serde(default)]
    pub test_path: Option<String>,
    /// The harness's own authentication variable.
    pub auth_var: String,
    /// `https://`, a public DNS name.
    pub base_url: String,
    pub usage_parser: String,
    /// `env` and/or `gateway`.
    pub delivery: Vec<String>,
    /// `paste`.
    pub login_methods: Vec<String>,
    /// Model ids exactly as the provider names them: the gateway compares a request's model with
    /// the ids it was granted, as they are, and resolves no alias (`-latest`). `:online` is refused.
    pub models: Vec<ModelPrice>,
    /// When the models' list prices were read.
    pub priced_at: Option<String>,
    /// Read-only: built-ins cannot be edited.
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub version: i64,
}

impl From<Definition> for Provider {
    fn from(d: Definition) -> Self {
        Self {
            id: d.id,
            name: d.name,
            harness: d.harness,
            wire: Some(d.wire),
            key_prefix: d.key_prefix,
            test_path: d.test_path,
            auth_var: d.auth_var,
            base_url: d.base_url,
            usage_parser: d.usage_parser,
            delivery: d.delivery,
            login_methods: d.login_methods,
            models: d
                .models
                .into_iter()
                .map(|m| ModelPrice {
                    id: m.id,
                    input_per_mtok_micro: m.input_per_mtok_micro,
                    output_per_mtok_micro: m.output_per_mtok_micro,
                })
                .collect(),
            priced_at: d.priced_at,
            builtin: d.builtin,
            version: d.version,
        }
    }
}

impl From<Provider> for Definition {
    fn from(p: Provider) -> Self {
        Self {
            id: p.id,
            name: p.name,
            harness: p.harness,
            wire: p.wire.unwrap_or_default(),
            key_prefix: p.key_prefix,
            test_path: p.test_path,
            auth_var: p.auth_var,
            base_url: p.base_url,
            usage_parser: p.usage_parser,
            delivery: p.delivery,
            login_methods: p.login_methods,
            models: p
                .models
                .into_iter()
                .map(|m| Model {
                    id: m.id,
                    input_per_mtok_micro: m.input_per_mtok_micro,
                    output_per_mtok_micro: m.output_per_mtok_micro,
                })
                .collect(),
            priced_at: p.priced_at,
            builtin: false,
            version: 0,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Pool {
    pub id: i64,
    pub name: String,
    pub provider: String,
    /// The provider's default pool serves an agent bound to none.
    pub is_default: bool,
    /// ProviderAccount ids, in fallback order.
    pub members: Vec<i64>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<pl::Pool> for Pool {
    fn from(p: pl::Pool) -> Self {
        Self {
            id: p.id,
            name: p.name,
            provider: p.provider,
            is_default: p.is_default,
            members: p.members,
            created_at: ts(&p.created_at),
            updated_at: ts(&p.updated_at),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPool {
    pub name: String,
    /// `anthropic`, `openai` or `google`.
    pub provider: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Binding {
    pub agent: String,
    pub provider: String,
    pub pool_id: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewBinding {
    /// An agent id: 1 to 64 of `[A-Za-z0-9._:-]`.
    pub agent: String,
    pub pool_id: i64,
}
