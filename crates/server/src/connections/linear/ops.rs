//! The typed operations: each is a fixed GraphQL document ([`super::docs`]), the capability that
//! allows it (the descriptor) and the team it touches (the resource). Variables are rebuilt here
//! from validated parts; nothing a caller sends is forwarded raw. A limited connection (a grant
//! with `teams`) is enforced on the REQUEST (the team key, the identifier's prefix, the `team`
//! filter the adapter puts on a search) and again on the ANSWER ([`super::answer`]), because an
//! identifier's prefix is the team it WAS in: an issue can be moved.
//!
//! Arguments are objects with a fixed set of names; any other name is refused, which is what keeps
//! a caller from smuggling a `teamId`, a `parentId` or a raw `filter` in.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::answer::outside;
use super::cred::{issue_identifier, team_key, uuid};

/// The teams a use may reach: any, or only these (validated) keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit(Option<Vec<String>>);

impl Limit {
    pub fn any() -> Self {
        Self(None)
    }

    /// Only `keys`; a value that is not a team key is dropped, so a malformed entry can only
    /// shrink what is allowed.
    pub fn only(keys: &[String]) -> Self {
        Self(Some(keys.iter().filter(|k| team_key(k)).cloned().collect()))
    }

    /// The limit of the EFFECTIVE limits `connections::resolve` returns: its `teams` values; no
    /// `teams` key is any. There is no wildcard: `*` is a literal there, so it is not a team key
    /// and is dropped like any other malformed entry.
    pub fn from_grant(limits: &BTreeMap<String, Vec<String>>) -> Self {
        limits
            .get("teams")
            .map_or_else(Self::any, |v| Self::only(v))
    }

    pub(super) fn permits(&self, team: &str) -> bool {
        self.0.as_ref().is_none_or(|k| k.iter().any(|p| p == team))
    }

    pub(super) fn limited(&self) -> bool {
        self.0.is_some()
    }

    /// The permitted keys, when limited.
    pub(super) fn keys(&self) -> Option<&[String]> {
        self.0.as_deref()
    }
}

/// What to do for one operation, built from validated arguments.
#[derive(Debug, Clone)]
pub enum Plan {
    GetIssue {
        ident: String,
        team: String,
    },
    Search {
        /// The team asked for, if any (the resource).
        team: Option<String>,
        /// The full variables: `first`, `after`, `filter`, `orderBy`.
        vars: Value,
    },
    Create {
        team: String,
        /// `title`, `description`, `priority`: no team, no parent.
        input: Map<String, Value>,
    },
    Update {
        ident: String,
        team: String,
        input: Map<String, Value>,
        /// The workflow state to move to (a UUID), checked to belong to the issue's team.
        state: Option<String>,
    },
    Comment {
        ident: String,
        team: String,
        body: String,
    },
    Teams {
        /// The `TeamFilter` variable: the limit's keys when limited.
        filter: Value,
    },
    States {
        team: String,
    },
    Projects {
        team: Option<String>,
        filter: Value,
        first: u64,
    },
}

impl Plan {
    /// The team it touches: the `resource` for `connections::resolve` (limit key `teams`).
    pub fn resource(&self) -> Option<&str> {
        match self {
            Self::GetIssue { team, .. }
            | Self::Create { team, .. }
            | Self::Update { team, .. }
            | Self::Comment { team, .. }
            | Self::States { team } => Some(team),
            Self::Search { team, .. } | Self::Projects { team, .. } => team.as_deref(),
            Self::Teams { .. } => None,
        }
    }
}

/// The team an operation touches, for `resolve`'s resource: an identifier's prefix, the `team` of
/// a create, a state list, or an optional one of a search or a project list; none for `list_teams`.
/// `Err` is a plain refusal.
pub fn resource_of(op: &str, args: &Value) -> Result<Option<String>, String> {
    plan(op, args, &Limit::any()).map(|p| p.resource().map(str::to_owned))
}

static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);

fn obj<'a>(op: &str, args: &'a Value, names: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let m = match args {
        Value::Null => &*EMPTY,
        v => v
            .as_object()
            .ok_or_else(|| format!("{op}: the arguments are an object"))?,
    };
    if let Some(k) = m.keys().find(|k| !names.contains(&k.as_str())) {
        let shown: String = k.chars().take(40).collect();
        return Err(format!("{op}: no argument named {shown:?}"));
    }
    Ok(m)
}

fn text<'a>(m: &'a Map<String, Value>, k: &str, max: usize) -> Result<Option<&'a str>, String> {
    match m.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s))
            if !s.is_empty() && s.chars().count() <= max && !s.contains('\0') =>
        {
            Ok(Some(s))
        }
        Some(_) => Err(format!("{k} is text of 1 to {max} characters")),
    }
}

fn need<'a>(m: &'a Map<String, Value>, k: &str, max: usize) -> Result<&'a str, String> {
    text(m, k, max)?.ok_or_else(|| format!("{k} is required"))
}

fn uint(m: &Map<String, Value>, k: &str, default: u64, max: u64) -> Result<u64, String> {
    match m.get(k) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=max).contains(n))
            .ok_or_else(|| format!("{k} is a number from 1 to {max}")),
    }
}

fn priority(m: &Map<String, Value>) -> Result<Option<u64>, String> {
    match m.get("priority") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .filter(|n| *n <= 4)
            .map(Some)
            .ok_or_else(|| "priority is 0 (none) to 4 (low)".to_owned()),
    }
}

/// A team key argument, validated and checked against the limit.
fn team_arg<'a>(
    m: &'a Map<String, Value>,
    k: &str,
    limit: &Limit,
) -> Result<Option<&'a str>, String> {
    let Some(t) = text(m, k, 7)? else {
        return Ok(None);
    };
    if !team_key(t) {
        return Err(format!("{k} is a team key like ENG"));
    }
    if !limit.permits(t) {
        return Err(outside());
    }
    Ok(Some(t))
}

/// An issue IDENTIFIER (`ENG-12`; a UUID is refused, so the team is always known) and its team,
/// checked against the limit.
fn ident<'a>(m: &'a Map<String, Value>, limit: &Limit) -> Result<(&'a str, &'a str), String> {
    let id = need(m, "id", 32)?;
    let team = issue_identifier(id).ok_or("id is an issue identifier like ENG-12 (not a UUID)")?;
    if !limit.permits(team) {
        return Err(outside());
    }
    Ok((id, team))
}

fn page_cursor(m: &Map<String, Value>) -> Result<Option<&str>, String> {
    let c = text(m, "after", 200)?;
    match c {
        Some(c) if !c.bytes().all(|b| b.is_ascii_graphic()) => {
            Err("after is the cursor a previous page gave".to_owned())
        }
        other => Ok(other),
    }
}

const STATE_TYPES: [&str; 6] = [
    "triage",
    "backlog",
    "unstarted",
    "started",
    "completed",
    "canceled",
];

/// The `IssueFilter` of a search, rebuilt from validated arguments and ANDed part by part: the
/// team constraint is its own part, so nothing a caller wrote can sit inside or beside it as an
/// `or`.
fn search_filter(
    m: &Map<String, Value>,
    team: Option<&str>,
    limit: &Limit,
) -> Result<Value, String> {
    let mut parts: Vec<Value> = Vec::new();
    match (team, limit.keys()) {
        (Some(t), _) => parts.push(json!({"team": {"key": {"eq": t}}})),
        (None, Some([])) => return Err("this connection may reach no team".into()),
        (None, Some(keys)) => parts.push(json!({"team": {"key": {"in": keys}}})),
        (None, None) => {}
    }
    if let Some(t) = text(m, "text", 200)? {
        parts.push(json!({"or": [{"title": {"containsIgnoreCase": t}},
            {"description": {"containsIgnoreCase": t}}]}));
    }
    if let Some(s) = text(m, "state", 80)? {
        parts.push(json!({"state": {"name": {"eqIgnoreCase": s}}}));
    }
    if let Some(t) = text(m, "state_type", 20)? {
        if !STATE_TYPES.contains(&t) {
            return Err(format!("state_type is one of: {}", STATE_TYPES.join(", ")));
        }
        parts.push(json!({"state": {"type": {"eq": t}}}));
    }
    match text(m, "assignee", 8)? {
        None => {}
        Some("me") => parts.push(json!({"assignee": {"isMe": {"eq": true}}})),
        Some(_) => return Err("assignee is \"me\"".into()),
    }
    if let Some(p) = priority(m)? {
        parts.push(json!({"priority": {"eq": p}}));
    }
    if let Some(l) = text(m, "label", 80)? {
        parts.push(json!({"labels": {"name": {"eqIgnoreCase": l}}}));
    }
    Ok(if parts.is_empty() {
        Value::Null
    } else {
        json!({"and": parts})
    })
}

/// The `TeamFilter` of a team list: the limit's keys (or the one asked for) when there is any.
fn team_filter(team: Option<&str>, limit: &Limit) -> Result<Value, String> {
    match (team, limit.keys()) {
        (Some(t), _) => Ok(json!({"key": {"eq": t}})),
        (None, Some([])) => Err("this connection may reach no team".into()),
        (None, Some(keys)) => Ok(json!({"key": {"in": keys}})),
        (None, None) => Ok(Value::Null),
    }
}

/// Builds the plan for `op`, or says why not. `limit` is the team limit of the grant that let the
/// call through.
pub fn plan(op: &str, args: &Value, limit: &Limit) -> Result<Plan, String> {
    match op {
        "linear.get_issue" => {
            let (id, team) = ident(obj(op, args, &["id"])?, limit)?;
            Ok(Plan::GetIssue {
                ident: id.to_owned(),
                team: team.to_owned(),
            })
        }
        "linear.add_comment" => {
            let m = obj(op, args, &["id", "body"])?;
            let (id, team) = ident(m, limit)?;
            Ok(Plan::Comment {
                ident: id.to_owned(),
                team: team.to_owned(),
                body: need(m, "body", 30_000)?.to_owned(),
            })
        }
        "linear.update_issue" => {
            let names = ["id", "title", "description", "priority", "state_id"];
            let m = obj(op, args, &names)?;
            let (id, team) = ident(m, limit)?;
            let mut input = Map::new();
            if let Some(t) = text(m, "title", 255)? {
                input.insert("title".into(), json!(t));
            }
            if let Some(d) = text(m, "description", 30_000)? {
                input.insert("description".into(), json!(d));
            }
            if let Some(p) = priority(m)? {
                input.insert("priority".into(), json!(p));
            }
            let state = match text(m, "state_id", 36)? {
                Some(s) if uuid(s) => Some(s.to_owned()),
                Some(_) => return Err("state_id is the id list_workflow_states gave".into()),
                None => None,
            };
            if input.is_empty() && state.is_none() {
                return Err("update_issue needs title, description, priority or state_id".into());
            }
            Ok(Plan::Update {
                ident: id.to_owned(),
                team: team.to_owned(),
                input,
                state,
            })
        }
        "linear.create_issue" => {
            let names = ["team", "title", "description", "priority"];
            let m = obj(op, args, &names)?;
            let team = team_arg(m, "team", limit)?.ok_or("team is required")?;
            let mut input = Map::new();
            input.insert("title".into(), json!(need(m, "title", 255)?));
            if let Some(d) = text(m, "description", 30_000)? {
                input.insert("description".into(), json!(d));
            }
            if let Some(p) = priority(m)? {
                input.insert("priority".into(), json!(p));
            }
            Ok(Plan::Create {
                team: team.to_owned(),
                input,
            })
        }
        "linear.list_workflow_states" => {
            let m = obj(op, args, &["team"])?;
            let team = team_arg(m, "team", limit)?.ok_or("team is required")?;
            Ok(Plan::States {
                team: team.to_owned(),
            })
        }
        "linear.list_teams" => {
            obj(op, args, &[])?;
            Ok(Plan::Teams {
                filter: team_filter(None, limit)?,
            })
        }
        "linear.list_projects" => {
            let m = obj(op, args, &["team", "first"])?;
            let team = team_arg(m, "team", limit)?;
            Ok(Plan::Projects {
                team: team.map(str::to_owned),
                filter: team_filter(team, limit)?,
                first: uint(m, "first", 25, 50)?,
            })
        }
        "linear.search_issues" => {
            let names = [
                "team",
                "text",
                "state",
                "state_type",
                "assignee",
                "priority",
                "label",
                "order_by",
                "first",
                "after",
            ];
            let m = obj(op, args, &names)?;
            let team = team_arg(m, "team", limit)?;
            let order = match text(m, "order_by", 10)? {
                None => Value::Null,
                Some("updated") => json!("updatedAt"),
                Some("created") => json!("createdAt"),
                Some(_) => return Err("order_by is updated or created".into()),
            };
            let vars = json!({"first": uint(m, "first", 25, 50)?, "after": page_cursor(m)?,
                "filter": search_filter(m, team, limit)?, "orderBy": order});
            Ok(Plan::Search {
                team: team.map(str::to_owned),
                vars,
            })
        }
        _ => Err(format!("{op}: no such operation")),
    }
}
