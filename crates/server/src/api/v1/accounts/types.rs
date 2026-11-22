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
    /// The free-text name a person gave it (`Work Claude`); absent: show the provider's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub display_name: Option<String>,
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
    /// The last test or check in detail: when, whether it answered `ok`, the runner that ran it, how
    /// long it took to answer and, when it was not `ok`, the result word. Absent when never checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub last_check: Option<LastCheck>,
    pub last_used_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Sessions that hold a slot of its cap now (`starting`, `running`, `interrupted`). Only the
    /// reads (`listAccounts`, `getAccount`) say it.
    pub live: Option<i64>,
    /// What the scheduler keeps of its health. Only the reads say it; `state`, `state_reason`
    /// and `state_until` (a cooldown's end) are above.
    pub health: Option<AccountHealth>,
    /// What the account cost this calendar month (UTC), in millionths of a US dollar, from the
    /// cost ledger. Only the reads say it, and only to an `admin` device.
    pub month_spend_usd_micros: Option<i64>,
    /// The account's monthly dollar budget cap, when one is set; absent when it has none.
    pub month_limit_usd_micros: Option<i64>,
    /// The row's usage meter: how much of its plan or budget is used and whether it can take work
    /// now. Only the reads say it, and only to an `admin` device.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub usage: Option<AccountMeter>,
    /// The runner device a runner-bound subscription (Codex, OpenCode, Antigravity) signed in on:
    /// its sessions run only there. Absent for any other account. An `admin` device only; a device
    /// id is not a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub runner: Option<String>,
    /// Whether a model the person switched off for this account is refused in its sessions: true for
    /// an API-key account (its gateway grants only the models left on), false for a subscription or
    /// runner-bound login, where the harness talks to its provider itself and the Core only skips the
    /// account when a session asks for a switched-off model at its start. The app shows the
    /// limit as advice when it is false.
    #[schema(required = false)]
    pub models_enforced: bool,
    /// A plain-language limit of removing this account, e.g. an Antigravity login that stays in the
    /// runner's keyring. Absent when removal clears everything.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub wipe_note: Option<String>,
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
    /// With this month's spend and limit, from [`super::month_spend`]; `None` (not an admin) adds
    /// nothing.
    pub(super) fn with_spend(
        mut self,
        m: Option<&std::collections::HashMap<i64, (i64, Option<i64>)>>,
    ) -> Self {
        if let Some(m) = m {
            let (spent, limit) = m.get(&self.id).copied().unwrap_or((0, None));
            self.month_spend_usd_micros = Some(spent);
            self.month_limit_usd_micros = limit;
        }
        self
    }

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
        let models_enforced = !crate::store::account_keys::subscription_provider(&a.provider);
        let agy_sub = a.provider == "agy-sub";
        Self {
            id: a.id,
            provider: a.provider,
            label: a.label,
            display_name: a.display_name,
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
            last_check: a.last_test_at.as_deref().zip(a.last_test_result.as_deref()).map(|(at, result)| LastCheck {
                at: ts(at),
                ok: result == "ok",
                runner_id: a.last_test_runner.clone(),
                runner_name: a.last_test_runner_name.clone(),
                answer_ms: a.last_test_ms.filter(|ms| *ms > 0),
                detail: (result != "ok").then(|| result.to_owned()),
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
            month_spend_usd_micros: None,
            month_limit_usd_micros: None,
            usage: None,
            runner: None,
            models_enforced,
            wipe_note: agy_sub.then(|| {
                "Removing this account cannot clear its login from the runner's keyring. Sign out in Antigravity on that runner.".to_owned()
            }),
        }
    }
}

/// What an `admin` write answers: the account and the runners its key may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountDetail {
    pub account: ProviderAccount,
    /// Runner device ids, explicit (never a wildcard).
    pub runners: Vec<String>,
    /// The pool the account joined (set by `createAccount`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<i64>,
    /// The chain that holds the pool (set by `createAccount`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<i64>,
}

impl From<acc::Account> for AccountDetail {
    fn from(a: acc::Account) -> Self {
        let runners = a.runners.clone();
        Self {
            account: a.into(),
            runners,
            pool: None,
            chain: None,
        }
    }
}

/// A new account. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewProviderAccount {
    pub provider: String,
    pub label: String,
    /// A free-text name, trimmed, at most 64 characters, no control characters; default none.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The API key; written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Runner device ids it may be leased to; default none.
    pub runners: Option<Vec<String>>,
    /// Default 4; 0 is no cap.
    pub cap: Option<i64>,
    /// An existing pool of the provider to join; default: the provider's default pool (made if missing).
    pub pool: Option<i64>,
    /// An existing chain to put the pool in; default: the user's default chain (made if missing).
    pub chain: Option<i64>,
    /// 0-based seat of the pool in the chain; default: last.
    pub position: Option<u32>,
    /// The monthly dollar limit in micro-dollars; default 20000000 ($20); 0 is no limit.
    pub monthly_limit_usd_micros: Option<i64>,
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

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetName {
    /// Trimmed, at most 64 characters, no control characters; `null` or blank clears it.
    pub display_name: Option<String>,
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

/// The last test or check of an account (`testAccount`, `checkAccount`) in detail.
#[derive(Debug, Serialize, ToSchema)]
pub struct LastCheck {
    pub at: Timestamp,
    /// It answered `ok`.
    pub ok: bool,
    /// The runner device that ran it, and its name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub runner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub runner_name: Option<String>,
    /// How long it took to answer, in milliseconds; absent when it did not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub answer_ms: Option<i64>,
    /// The result word when it was not `ok` (`token_expired`, `auth_failed`, `failed`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub detail: Option<String>,
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
    /// A preset: how many model ids the provider listed (E7-3); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub models: Option<u32>,
}

/// What `POST /accounts/{id}/check` answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountChecked {
    /// `ok`, or why not. A Claude plan: `token_expired`, `limit_reached`, `no_runner` (none that
    /// may hold the token is online), `runner_outdated`, `runner_busy`, `runner_failed`,
    /// `egress_not_proven`, `sandbox_unavailable`, `unreachable`, `timeout` or `failed`. An
    /// API-key account: the key test's class (`ok`, `auth_failed`, ...) or `no_runner`.
    pub result: String,
    pub latency_ms: Option<u64>,
    /// The runner device that made the check; absent when none was asked.
    pub runner: Option<String>,
    /// A preset: how many model ids the provider listed (E7-3); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub models: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountsDeleted {
    pub deleted: bool,
    /// Only for `deleteAccount`: when its Undo window ends (RFC 3339, UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub undo_until: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountRestored {
    pub restored: bool,
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
    /// A preset provider (OpenRouter, Groq, ...): shipped in code, read-only, the user only
    /// pastes a key. Its keys are bound to the account and its frozen host, not to a prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub preset: Option<bool>,
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
            preset: Some(d.preset).filter(|p| *p),
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
            preset: false,
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
