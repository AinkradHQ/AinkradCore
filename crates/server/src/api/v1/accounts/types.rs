//! Request and response bodies of the account, pool, binding and provider routes.

use super::*;

/// An account as a `read` device sees it: its key's last four characters, never the key, the
/// broker secret's name or the runners it may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderAccount {
    pub id: i64,
    /// `anthropic`, `openai` or `google`.
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
    pub last_used_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
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
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            created_at: ts(&a.created_at),
            updated_at: ts(&a.updated_at),
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
    pub reason: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCap {
    pub cap: i64,
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
    /// The harness's own authentication variable.
    pub auth_var: String,
    /// `https://`, a public DNS name.
    pub base_url: String,
    pub usage_parser: String,
    /// `env` and/or `gateway`.
    pub delivery: Vec<String>,
    /// `paste`.
    pub login_methods: Vec<String>,
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
