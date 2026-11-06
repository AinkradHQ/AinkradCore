//! A kind adapter: one small descriptor (data the UI and the store read) and one function that
//! proves a credential works (design §3). Capabilities and the operations each one allows are
//! data, so a new kind needs no new screen and no new store code.
//!
//! `Registry::builtin()` is empty until C2 (GitHub) and C3 (Jira) register theirs.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde::Serialize;

use super::material::Material;

/// The auth methods a connection may use (`core_connections.auth_method`).
pub const AUTH_METHODS: [&str; 3] = ["oauth", "app_install", "token"];

/// One way to sign in, with the text the UI draws its step from.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct AuthMethodSpec {
    /// One of [`AUTH_METHODS`].
    pub id: &'static str,
    pub title: &'static str,
    pub help: &'static str,
    pub steps: &'static [&'static str],
    /// Shown under "Advanced" (token paste), not as the first choice.
    pub advanced: bool,
}

/// A named permission. `write` ones are never in a grant unless it names them.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Capability {
    pub name: &'static str,
    pub title: &'static str,
    pub write: bool,
    /// The tool operations it allows (`github.get_issue`); one operation belongs to one capability.
    pub operations: &'static [&'static str],
}

/// A key of the resource limit a grant may carry (GitHub: `repos`, `orgs`; Jira: `projects`).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LimitKey {
    pub key: &'static str,
    pub title: &'static str,
    pub help: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Descriptor {
    pub kind: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    /// In order of preference, easiest first.
    pub auth_methods: &'static [AuthMethodSpec],
    pub capabilities: &'static [Capability],
    /// The only upstream hosts a call for this kind may reach.
    pub hosts: &'static [&'static str],
    pub limits: &'static [LimitKey],
    /// The redactor shape names (`github_pat`, `github_token`) of the tokens this kind's own
    /// credentials look like. Data only in C1; C2 reads it (with `secrets.connections`) to admit
    /// exactly one such token as a connection credential.
    pub token_shapes: &'static [&'static str],
    /// Operations that enforce the resource limit themselves (a Jira search, a project list):
    /// they may be asked with no resource under a limited grant, and the adapter is handed the
    /// effective limits (`Resolved::limits`). Every other operation under a limited grant needs
    /// a resource. Each must be one of the capabilities' operations.
    pub self_limited: &'static [&'static str],
}

fn ident(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn host(s: &str) -> bool {
    s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl Descriptor {
    pub fn capability(&self, name: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.name == name)
    }

    pub fn auth_method(&self, id: &str) -> Option<&AuthMethodSpec> {
        self.auth_methods.iter().find(|m| m.id == id)
    }

    pub fn limit_key(&self, key: &str) -> Option<&LimitKey> {
        self.limits.iter().find(|l| l.key == key)
    }

    /// The capability that allows `operation`.
    pub fn capability_of(&self, operation: &str) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|c| c.operations.contains(&operation))
    }

    /// The read-only capabilities: what a grant gets when it names none.
    pub fn read_only(&self) -> Vec<String> {
        let reads = self.capabilities.iter().filter(|c| !c.write);
        reads.map(|c| c.name.to_owned()).collect()
    }

    pub fn is_self_limited(&self, operation: &str) -> bool {
        self.self_limited.contains(&operation)
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
    }

    /// Why this descriptor is malformed, if it is.
    pub fn problem(&self) -> Option<String> {
        let kind = self.kind;
        if !ident(kind, 32) || self.title.is_empty() {
            return Some(format!(
                "{kind:?}: a kind is [a-z][a-z0-9_]{{0,31}} with a title"
            ));
        }
        if self.auth_methods.is_empty() || self.capabilities.is_empty() || self.hosts.is_empty() {
            return Some(format!(
                "{kind}: needs an auth method, a capability and a host"
            ));
        }
        let mut seen = Vec::new();
        for m in self.auth_methods {
            if !AUTH_METHODS.contains(&m.id) || seen.contains(&m.id) {
                return Some(format!(
                    "{kind}: auth method {:?} is unknown or twice",
                    m.id
                ));
            }
            seen.push(m.id);
        }
        let mut ops: Vec<&str> = Vec::new();
        for (i, c) in self.capabilities.iter().enumerate() {
            if !ident(c.name, 40) || self.capabilities[..i].iter().any(|o| o.name == c.name) {
                return Some(format!(
                    "{kind}: capability {:?} is malformed or twice",
                    c.name
                ));
            }
            for op in c.operations {
                let own = op.strip_prefix(kind).and_then(|r| r.strip_prefix('.'));
                if own.is_none_or(|o| !ident(&o.replace('.', "_"), 63)) || ops.contains(op) {
                    return Some(format!("{kind}: operation {op:?} is malformed or twice"));
                }
                ops.push(op);
            }
        }
        if let Some(h) = self.hosts.iter().find(|h| !host(h)) {
            return Some(format!(
                "{kind}: host {h:?} is not a bare lowercase host name"
            ));
        }
        if let Some(o) = self
            .self_limited
            .iter()
            .find(|o| self.capability_of(o).is_none())
        {
            return Some(format!(
                "{kind}: self-limited operation {o:?} is not an operation"
            ));
        }
        if let Some(t) = self.token_shapes.iter().find(|t| !ident(t, 40)) {
            return Some(format!("{kind}: token shape {t:?} is malformed"));
        }
        for (i, l) in self.limits.iter().enumerate() {
            if !ident(l.key, 32) || self.limits[..i].iter().any(|o| o.key == l.key) {
                return Some(format!(
                    "{kind}: limit key {:?} is malformed or twice",
                    l.key
                ));
            }
        }
        None
    }
}

/// Who a credential belongs to, as the service says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// A GitHub login, a Jira site URL.
    pub subject: String,
}

/// How a credential test ended. Deliberately no text: nothing an upstream said is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestError {
    /// The service refused the credential (a confirmed auth failure).
    Rejected,
    /// No answer, or an answer that says nothing about the credential (network, 5xx, rate limit).
    Inconclusive,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected => "the service refused the credential",
            Self::Inconclusive => "the test was inconclusive",
        })
    }
}

impl std::error::Error for TestError {}

pub trait KindAdapter: Send + Sync {
    fn descriptor(&self) -> &Descriptor;

    /// Proves `material` works and reads back whose it is. Returns a boxed future so adapters
    /// can be held as `dyn`; it must hold no database transaction.
    fn test<'a>(&'a self, material: &'a Material) -> BoxFuture<'a, Result<Identity, TestError>>;
}

/// The adapters this Core knows, by kind.
#[derive(Default, Clone)]
pub struct Registry {
    adapters: BTreeMap<&'static str, Arc<dyn KindAdapter>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The shipped kinds: none yet (C2 adds `github`, C3 `jira`).
    pub fn builtin() -> Self {
        Self::new()
    }

    /// Adds an adapter; refuses a malformed descriptor or a kind already registered.
    pub fn register(&mut self, adapter: Arc<dyn KindAdapter>) -> Result<(), String> {
        let d = adapter.descriptor();
        if let Some(why) = d.problem() {
            return Err(why);
        }
        if self.adapters.contains_key(d.kind) {
            return Err(format!("{}: kind already registered", d.kind));
        }
        self.adapters.insert(d.kind, adapter);
        Ok(())
    }

    pub fn get(&self, kind: &str) -> Option<&Arc<dyn KindAdapter>> {
        self.adapters.get(kind)
    }

    /// Every descriptor, by kind: what the UI draws its setup screens from.
    pub fn descriptors(&self) -> Vec<&Descriptor> {
        self.adapters.values().map(|a| a.descriptor()).collect()
    }
}
