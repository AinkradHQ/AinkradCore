//! Configurable limits (E15.17, decision #52): every quota, limit and threshold is a setting
//! with a default, bounds and the scopes it may be set at. A value set at a more specific
//! scope wins: project → company → server, runner → server, account → server. Nothing here
//! reads storage; the store looks the rows up and `resolve` picks one.
//!
//! Every value is an integer in the setting's `unit`. Out-of-bounds or wrong-scope values are
//! refused (`SettingError`), never clamped.

use std::fmt;
use std::str::FromStr;

use crate::exec::{
    AGENT_BREAKER_TRIPS, AGENT_BREAKER_WINDOW_SECS, LEASE_GRACE_SECS, LEASE_TTL_SECS,
    LOOP_BREAKER_THRESHOLD, MAX_RETRY_BACKOFF_SECS, MAX_WAKE_ATTEMPTS, RunnerId, STALL_AFTER_SECS,
    STUCK_AFTER_SECS,
};
/// The default of `run.tool_output_bytes`, as the runner protocol's (1.18).
const TOOL_OUTPUT_BYTES: i64 = 2048;

use crate::gov::{AccountId, ApprovalKind, KNOWLEDGE_BUDGET_BYTES, SKILL_BUDGET_BYTES};
use crate::org::{CompanyId, UnknownVariant, text_enum};
use crate::work::ProjectId;

text_enum!(ScopeKind {
    Server => "server",
    Company => "company",
    Project => "project",
    Runner => "runner",
    Account => "account",
});

/// Where a value is set, or read for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Server,
    Company(CompanyId),
    Project(ProjectId),
    Runner(RunnerId),
    Account(AccountId),
}

impl Scope {
    pub fn kind(self) -> ScopeKind {
        match self {
            Self::Server => ScopeKind::Server,
            Self::Company(_) => ScopeKind::Company,
            Self::Project(_) => ScopeKind::Project,
            Self::Runner(_) => ScopeKind::Runner,
            Self::Account(_) => ScopeKind::Account,
        }
    }

    /// The row id it is stored under; 0 for the server.
    pub fn id(self) -> i64 {
        match self {
            Self::Server => 0,
            Self::Company(c) => c.0,
            Self::Project(p) => p.0,
            Self::Runner(r) => r.0,
            Self::Account(a) => a.0,
        }
    }

    /// The inverse of (`kind`, `id`).
    pub fn of(kind: ScopeKind, id: i64) -> Self {
        match kind {
            ScopeKind::Server => Self::Server,
            ScopeKind::Company => Self::Company(CompanyId(id)),
            ScopeKind::Project => Self::Project(ProjectId(id)),
            ScopeKind::Runner => Self::Runner(RunnerId(id)),
            ScopeKind::Account => Self::Account(AccountId(id)),
        }
    }
}

/// `server`, `company:1`, `project:3`, `runner:2`, `account:4`.
impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server => f.write_str("server"),
            s => write!(f, "{}:{}", s.kind().as_str(), s.id()),
        }
    }
}

impl FromStr for Scope {
    type Err = UnknownVariant;

    fn from_str(s: &str) -> Result<Self, UnknownVariant> {
        let bad = || UnknownVariant(s.to_owned());
        if s == "server" {
            return Ok(Self::Server);
        }
        let (kind, id) = s.split_once(':').ok_or_else(bad)?;
        let kind: ScopeKind = kind.parse().map_err(|_| bad())?;
        let id: i64 = id.parse().map_err(|_| bad())?;
        (kind != ScopeKind::Server && id > 0)
            .then(|| Self::of(kind, id))
            .ok_or_else(bad)
    }
}

text_enum!(Unit {
    Seconds => "seconds",
    Milliseconds => "milliseconds",
    Percent => "percent",
    Count => "count",
    Tokens => "tokens",
    Bytes => "bytes",
    PerMinute => "per_minute",
    Version => "version",
});

/// One tunable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub key: Key,
    pub name: &'static str,
    pub unit: Unit,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    /// Where it may be set; always the server first.
    pub scopes: &'static [ScopeKind],
    pub description: &'static str,
}

use ScopeKind::{Account as A, Company as C, Project as P, Runner as R, Server as S};

const SCP: &[ScopeKind] = &[S, C, P];
const SC: &[ScopeKind] = &[S, C];
const SCA: &[ScopeKind] = &[S, C, A];
const SR: &[ScopeKind] = &[S, R];
const SA: &[ScopeKind] = &[S, A];
const SO: &[ScopeKind] = &[S];

/// A day and a year, in seconds.
const DAY: i64 = 86_400;
const YEAR: i64 = 365 * DAY;
/// The largest version setting: 999999.999999.999999.
const MAX_VERSION: i64 = 999_999_999_999_999_999;

macro_rules! registry {
    ($($key:ident $name:literal $unit:ident $default:expr, $min:expr, $max:expr, $scopes:ident,
       $doc:literal;)*) => {
        /// Every tunable, by name in code. `Key::spec` is its row in [`REGISTRY`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Key { $($key),* }

        /// Every tunable, in `Key` order.
        pub const REGISTRY: &[Spec] = &[$(Spec {
            key: Key::$key,
            name: $name,
            unit: Unit::$unit,
            default: $default,
            min: $min,
            max: $max,
            scopes: $scopes,
            description: $doc,
        }),*];
    };
}

// The registry itself, kept in its own file as it grows.
mod registry;
pub use registry::*;

impl Key {
    /// The `harness.<name>.max_version` setting of `harness`.
    pub fn max_version(harness: &str) -> Option<Self> {
        Some(match harness {
            "claude" => Self::ClaudeMaxVersion,
            "codex" => Self::CodexMaxVersion,
            "opencode" => Self::OpencodeMaxVersion,
            "agy" => Self::AgyMaxVersion,
            _ => return None,
        })
    }

    pub fn spec(self) -> &'static Spec {
        &REGISTRY[self as usize]
    }

    pub fn name(self) -> &'static str {
        self.spec().name
    }

    pub fn default(self) -> i64 {
        self.spec().default
    }

    /// The deadline setting of approvals of `kind`.
    pub fn approval_deadline(kind: ApprovalKind) -> Self {
        match kind {
            ApprovalKind::SprintCommit => Self::DeadlineSprintCommit,
            ApprovalKind::PrMerge => Self::DeadlinePrMerge,
            ApprovalKind::BudgetOverrun => Self::DeadlineBudgetOverrun,
            ApprovalKind::HireAgent => Self::DeadlineHireAgent,
            ApprovalKind::PermissionEscalation => Self::DeadlinePermissionEscalation,
            ApprovalKind::PlanApproval => Self::DeadlinePlanApproval,
            ApprovalKind::WorkflowPush => Self::DeadlineWorkflowPush,
        }
    }
}

impl FromStr for Key {
    type Err = SettingError;

    fn from_str(s: &str) -> Result<Self, SettingError> {
        REGISTRY
            .iter()
            .find(|spec| spec.name == s)
            .map(|spec| spec.key)
            .ok_or_else(|| SettingError::UnknownKey(s.to_owned()))
    }
}

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingError {
    UnknownKey(String),
    /// The setting cannot be set at this kind of scope.
    WrongScope {
        key: &'static str,
        scope: ScopeKind,
        allowed: &'static [ScopeKind],
    },
    OutOfBounds {
        key: &'static str,
        value: i64,
        min: i64,
        max: i64,
    },
    /// Not a JSON integer.
    NotInteger {
        key: &'static str,
        value: String,
    },
}

impl SettingError {
    /// A stable code for clients.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownKey(_) => "unknown_setting",
            Self::WrongScope { .. } => "wrong_scope",
            Self::OutOfBounds { .. } => "out_of_bounds",
            Self::NotInteger { .. } => "not_integer",
        }
    }
}

impl fmt::Display for SettingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(k) => write!(f, "no setting {k:?}"),
            Self::WrongScope {
                key,
                scope,
                allowed,
            } => {
                let allowed: Vec<&str> = allowed.iter().map(|s| s.as_str()).collect();
                write!(
                    f,
                    "{key} cannot be set per {}; it is set per {}",
                    scope.as_str(),
                    allowed.join(", ")
                )
            }
            Self::OutOfBounds {
                key,
                value,
                min,
                max,
            } => write!(f, "{key} must be {min}..={max}; {value} is out of bounds"),
            Self::NotInteger { key, value } => write!(f, "{key} takes an integer, not {value}"),
        }
    }
}

impl std::error::Error for SettingError {}

impl Spec {
    /// `value` (JSON text) as this setting's value at a scope of `scope` kind, or why not.
    pub fn check(&self, scope: ScopeKind, value: &str) -> Result<i64, SettingError> {
        if !self.scopes.contains(&scope) {
            return Err(SettingError::WrongScope {
                key: self.name,
                scope,
                allowed: self.scopes,
            });
        }
        let not_integer = || SettingError::NotInteger {
            key: self.name,
            value: value.to_owned(),
        };
        let value: i64 = value.trim().parse().map_err(|_| not_integer())?;
        if !(self.min..=self.max).contains(&value) {
            return Err(SettingError::OutOfBounds {
                key: self.name,
                value,
                min: self.min,
                max: self.max,
            });
        }
        Ok(value)
    }
}

/// The scopes a read `at` consults, most specific first. A project's company comes from the
/// store (`company`); without it the project falls back to the server.
pub fn chain(at: Scope, company: Option<CompanyId>) -> Vec<Scope> {
    let mut chain = vec![at];
    if let Some(c) = company.filter(|_| matches!(at, Scope::Project(_))) {
        chain.push(Scope::Company(c));
    }
    if at != Scope::Server {
        chain.push(Scope::Server);
    }
    chain
}

/// The effective value of `key` along `chain`, from the stored rows (any scopes), and the
/// scope it came from (`None`: the default). Rows at scopes the key does not allow, or with a
/// value no longer in bounds, are passed over.
pub fn resolve(key: Key, chain: &[Scope], rows: &[(Scope, i64)]) -> (i64, Option<Scope>) {
    let spec = key.spec();
    chain
        .iter()
        .filter(|s| spec.scopes.contains(&s.kind()))
        .find_map(|s| {
            rows.iter()
                .find(|(at, v)| at == s && (spec.min..=spec.max).contains(v))
                .map(|(at, v)| (*v, Some(*at)))
        })
        .unwrap_or((spec.default, None))
}

#[cfg(test)]
mod tests;
