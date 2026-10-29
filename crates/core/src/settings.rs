//! Configurable limits (E15.17, decision #52): every quota, limit and threshold is a setting
//! with a default, bounds and the scopes it may be set at. A value set at a more specific
//! scope wins; the platform has one scope, the server, and the chain grows with the scopes
//! modules bring (E1-09.1). Nothing here reads storage; the store looks the rows up and
//! `resolve` picks one.
//!
//! Every value is an integer in the setting's `unit`. Out-of-bounds or wrong-scope values are
//! refused (`SettingError`), never clamped.

use std::fmt;
use std::str::FromStr;

use crate::ids::{UnknownVariant, text_enum};

text_enum!(ScopeKind {
    Server => "server",
});

/// Where a value is set, or read for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Server,
}

impl Scope {
    pub fn kind(self) -> ScopeKind {
        match self {
            Self::Server => ScopeKind::Server,
        }
    }

    /// The row id it is stored under; 0 for the server.
    pub fn id(self) -> i64 {
        match self {
            Self::Server => 0,
        }
    }

    /// The inverse of (`kind`, `id`); `None` for an id the kind does not have.
    pub fn of(kind: ScopeKind, id: i64) -> Option<Self> {
        match kind {
            ScopeKind::Server => (id == 0).then_some(Self::Server),
        }
    }
}

/// `server`.
impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind().as_str())
    }
}

impl FromStr for Scope {
    type Err = UnknownVariant;

    fn from_str(s: &str) -> Result<Self, UnknownVariant> {
        match s {
            "server" => Ok(Self::Server),
            _ => Err(UnknownVariant(s.to_owned())),
        }
    }
}

text_enum!(Unit {
    Seconds => "seconds",
    Milliseconds => "milliseconds",
    Percent => "percent",
    Count => "count",
    Bytes => "bytes",
    PerMinute => "per_minute",
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

/// Set at the server only.
const SO: &[ScopeKind] = &[ScopeKind::Server];

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
    pub fn spec(self) -> &'static Spec {
        &REGISTRY[self as usize]
    }

    pub fn name(self) -> &'static str {
        self.spec().name
    }

    pub fn default(self) -> i64 {
        self.spec().default
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
