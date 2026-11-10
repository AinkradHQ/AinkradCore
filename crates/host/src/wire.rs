//! Wire format, version 1: one request line (at most 4 KiB, UTF-8), one response line (at most
//! 512 KiB). Every object refuses unknown fields. An action is a Rust enum variant with typed
//! params; no action takes a path, a unit name, a command, a URL or free text.

use serde::Deserialize;
use serde_json::{Value, json};

pub const MAX_REQUEST: usize = 4096;
pub const MAX_RESPONSE: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    BadRequest,
    UnknownAction,
    ForbiddenPeer,
    RateLimited,
    Busy,
    NotInstalled,
    StateUnavailable,
    Failed,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::BadRequest => "bad_request",
            Code::UnknownAction => "unknown_action",
            Code::ForbiddenPeer => "forbidden_peer",
            Code::RateLimited => "rate_limited",
            Code::Busy => "busy",
            Code::NotInstalled => "not_installed",
            Code::StateUnavailable => "state_unavailable",
            Code::Failed => "failed",
        }
    }

    /// A constant per code: the message never echoes input.
    pub fn message(self) -> &'static str {
        match self {
            Code::BadRequest => "the request was refused",
            Code::UnknownAction => "unknown action",
            Code::ForbiddenPeer => "this peer is not allowed",
            Code::RateLimited => "rate limit reached",
            Code::Busy => "the helper is busy",
            Code::NotInstalled => "not installed on this host",
            Code::StateUnavailable => "the helper state is unavailable",
            Code::Failed => "the action failed",
        }
    }
}

/// Class A actions are the ones slice 1 runs: the worst a misuse does is restart a service or
/// read redacted logs. Class B changes what runs as root or what data exists (it needs a device
/// grant the Core cannot forge, a later slice); every class B name is refused here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    A,
    B,
}

/// Every action name the helper knows, by class. Slice 1 implements the four class A names
/// below `Action`; a class B name only exists here to be refused (as `unknown_action`).
pub const REGISTRY: &[(&str, Class)] = &[
    ("status", Class::A),
    ("logs", Class::A),
    ("restart_core", Class::A),
    ("restart_runner", Class::A),
    ("runner_policy", Class::B),
    ("install_tool", Class::B),
    ("update", Class::B),
    ("restore", Class::B),
    ("uninstall", Class::B),
    ("host_config", Class::B),
    ("add_owner", Class::B),
    ("remove_owner", Class::B),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unit {
    Core,
    Runner,
    Backup,
    Helper,
}

impl Unit {
    /// The fixed systemd unit behind a journal-backed unit; `Helper` pages over `actions.log`.
    pub fn systemd(self) -> Option<&'static str> {
        match self {
            Unit::Core => Some("ainkrad-core.service"),
            Unit::Runner => Some("ainkrad-runner.service"),
            Unit::Backup => Some("ainkrad-backup.service"),
            Unit::Helper => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logs {
    pub unit: Unit,
    pub lines: usize,
    pub before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Status,
    Logs(Logs),
    RestartCore,
    RestartRunner,
}

impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Action::Status => "status",
            Action::Logs(_) => "logs",
            Action::RestartCore => "restart_core",
            Action::RestartRunner => "restart_runner",
        }
    }

    /// Mutating actions take the lock, the limits, the dedupe and the log; reads do none of it.
    pub fn mutating(&self) -> bool {
        matches!(self, Action::RestartCore | Action::RestartRunner)
    }
}

/// What the Core says it is acting for. The helper cannot check it in slice 1; it is recorded
/// as `claimed_by_core`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    pub device: String,
    pub audit_seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActor {
    device: String,
    audit_seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u32,
    id: String,
    action: String,
    #[serde(default)]
    params: Option<Value>,
    actor: RawActor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogsParams {
    unit: Unit,
    lines: Option<i64>,
    before: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub action: Action,
    pub actor: Actor,
}

/// A refused request: the code, and the little that is safe to log (validated values only).
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    pub id: Option<String>,
    /// A registry name (never input text); `None` when the action was not recognised.
    pub action: Option<&'static str>,
    pub class_b: bool,
    pub actor: Option<Actor>,
}

impl Refusal {
    fn new(code: Code) -> Self {
        Self {
            code,
            id: None,
            action: None,
            class_b: false,
            actor: None,
        }
    }
}

/// 26 characters of Crockford base32 (no I, L, O, U); the first is at most `7` (128 bits).
pub fn valid_id(id: &str) -> bool {
    id.len() == 26
        && id.bytes().enumerate().all(|(i, b)| match b {
            b'0'..=b'7' => true,
            b'8' | b'9' => i > 0,
            b'A'..=b'Z' => i > 0 && !matches!(b, b'I' | b'L' | b'O' | b'U'),
            _ => false,
        })
}

fn valid_device(d: &str) -> bool {
    d.strip_prefix("d_").is_some_and(|rest| {
        (1..=64).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// A journal cursor: `^[A-Za-z0-9=;_]{1,256}$`. It can never start with `-`.
pub fn valid_cursor(c: &str) -> bool {
    (1..=256).contains(&c.len())
        && !c.starts_with('-')
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b'_'))
}

/// Parses one request line (without its newline).
pub fn parse(line: &[u8]) -> Result<Request, Refusal> {
    let Ok(text) = std::str::from_utf8(line) else {
        return Err(Refusal::new(Code::BadRequest));
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Err(Refusal::new(Code::BadRequest));
    };
    let mut refusal = Refusal::new(Code::BadRequest);
    refusal.id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| valid_id(id))
        .map(str::to_owned);
    let Ok(env) = serde_json::from_value::<Envelope>(value) else {
        return Err(refusal);
    };
    if env.v != 1 || !valid_id(&env.id) || !valid_device(&env.actor.device) {
        return Err(refusal);
    }
    let actor = Actor {
        device: env.actor.device,
        audit_seq: env.actor.audit_seq,
    };
    refusal.actor = Some(actor.clone());
    let Some((name, class)) = REGISTRY.iter().find(|(n, _)| *n == env.action) else {
        refusal.code = Code::UnknownAction;
        return Err(refusal);
    };
    refusal.action = Some(name);
    if *class == Class::B {
        refusal.code = Code::UnknownAction;
        refusal.class_b = true;
        return Err(refusal);
    }
    let params = env.params.unwrap_or(Value::Null);
    let no_params = match &params {
        Value::Null => true,
        Value::Object(m) => m.is_empty(),
        _ => false,
    };
    let action = match *name {
        "status" if no_params => Action::Status,
        "restart_core" if no_params => Action::RestartCore,
        "restart_runner" if no_params => Action::RestartRunner,
        "logs" => {
            let Ok(p) = serde_json::from_value::<LogsParams>(params) else {
                return Err(refusal);
            };
            let lines = p.lines.unwrap_or(200);
            if !(1..=500).contains(&lines) || p.before.as_deref().is_some_and(|c| !valid_cursor(c))
            {
                return Err(refusal);
            }
            Action::Logs(Logs {
                unit: p.unit,
                lines: lines as usize,
                before: p.before,
            })
        }
        _ => return Err(refusal),
    };
    Ok(Request {
        id: env.id,
        action,
        actor,
    })
}

pub fn ok(id: &str, result: Value) -> Vec<u8> {
    line(&json!({"v": 1, "id": id, "ok": true, "result": result}))
}

pub fn err(id: Option<&str>, code: Code, retry_after: Option<u64>) -> Vec<u8> {
    let mut v =
        json!({"v": 1, "id": id, "ok": false, "code": code.as_str(), "message": code.message()});
    if let Some(s) = retry_after {
        v["retry_after"] = json!(s);
    }
    line(&v)
}

fn line(v: &Value) -> Vec<u8> {
    let mut out = v.to_string().into_bytes();
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests;
