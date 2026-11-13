//! The operation catalogue for Code Mode (plan `2026-11-13-ainkrad-code-mode-mcp-plan`, E1): the
//! opt-in allow-list (`api/ai-ops.allow.json`), the catalogue built from the live OpenAPI
//! document ([`build`]), a typed definition per operation ([`render`]) and the search a session
//! asks for ([`search`], served by [`serve`]). `call` (E2) runs the read-only ones for a session.

mod args;
mod build;
mod call;
mod render;
mod search;
mod serve;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

pub use build::build;
pub use call::{CALL, CallState, call_call, call_tool};
pub use render::render;
pub use search::search;
pub use serve::{Principal, SEARCH, search_call, search_tool, session_principal, session_scopes};

/// What an operation may do to the world; decides the approval it needs (E6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Read,
    /// Reversible, inside the Core.
    Write,
    /// Destructive, or reaches outside the Core.
    Risky,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Risky => "risky",
        }
    }
}

/// One row of `api/ai-ops.allow.json`. `risk` may be left out for a GET (it is `read`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowed {
    pub op: String,
    pub risk: Option<Risk>,
    pub summary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    ops: Vec<Allowed>,
}

/// The committed allow-list.
///
/// # Errors
///
/// When the file does not read (a build-time test keeps it from shipping that way).
pub fn allow_list() -> Result<Vec<Allowed>, serde_json::Error> {
    let f: AllowFile = serde_json::from_str(include_str!("../../../../api/ai-ops.allow.json"))?;
    Ok(f.ops)
}

/// A parameter of an operation (`in` is `path` or `query`).
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub schema: Value,
}

/// One allow-listed operation, with every `$ref` resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Op {
    /// The `operationId`.
    pub id: String,
    /// `agent_sessions` for `/api/v1/agent-sessions/..`; the module id for a module's route.
    pub group: String,
    pub method: String,
    /// The path as in the contract (a module's with its `/modules/<id>/v1` prefix).
    pub path: String,
    pub params: Vec<Param>,
    pub body: Option<Value>,
    pub response: Option<Value>,
    /// The scope the gate needs (`x-ainkrad-scope`).
    pub scope: String,
    pub risk: Risk,
    pub summary: String,
}

/// The allow-listed operations, by id, and what the build had to say about them.
#[derive(Debug, Default)]
pub struct Catalogue {
    pub ops: BTreeMap<String, Op>,
    pub warnings: Vec<String>,
}

impl Catalogue {
    /// The catalogue of the live contract of `modules` and the committed allow-list. A broken
    /// allow-list is logged and gives an empty catalogue, never a failed Core.
    pub fn live(modules: &[std::sync::Arc<dyn crate::module::Module>]) -> Self {
        let spec = crate::api::v1::spec::json_for(modules);
        let (Ok(spec), Ok(allow)) = (serde_json::from_str::<Value>(&spec), allow_list()) else {
            tracing::error!("the operation catalogue could not be read");
            return Self::default();
        };
        let c = build(&spec, &allow);
        for w in &c.warnings {
            tracing::warn!("operation catalogue: {w}");
        }
        c
    }
}

/// Problems with `allow` against `spec`: an op the contract does not have, a non-GET without a
/// risk, a GET marked `write`/`risky`, a non-GET marked `read`, a repeat. Empty means reviewed.
pub fn check(spec: &Value, allow: &[Allowed]) -> Vec<String> {
    let mut methods: BTreeMap<&str, &str> = BTreeMap::new();
    for item in spec["paths"].as_object().into_iter().flatten() {
        for (m, op) in item.1.as_object().into_iter().flatten() {
            if let Some(id) = op["operationId"].as_str() {
                methods.insert(id, m);
            }
        }
    }
    let mut bad = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for a in allow {
        if !seen.insert(a.op.as_str()) {
            bad.push(format!("{}: listed twice", a.op));
        }
        let Some(m) = methods.get(a.op.as_str()) else {
            bad.push(format!("{}: not in the contract", a.op));
            continue;
        };
        match (m.eq_ignore_ascii_case("get"), a.risk) {
            (false, None) => bad.push(format!("{}: a {m} needs a risk", a.op)),
            (false, Some(Risk::Read)) => bad.push(format!("{}: a {m} is not read", a.op)),
            (true, Some(Risk::Write | Risk::Risky)) => {
                bad.push(format!("{}: a GET is read, not write", a.op));
            }
            _ => {}
        }
    }
    bad
}
