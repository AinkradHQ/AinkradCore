//! The typed operations: each is a method, a URL template, the capability that allows it (the
//! descriptor) and the project it touches (the resource). Everything that reaches a URL or a JQL
//! is rebuilt here from validated parts; nothing is forwarded raw. A limited connection (a grant
//! with `projects`) is enforced on the REQUEST (the project key, the key prefix, the `project in
//! (...)` the adapter adds to a search) and again on the ANSWER (the project of every issue
//! returned), because a key can be an issue that moved to another project.
//!
//! Arguments are objects with a fixed set of names; any other name is refused, which is what
//! keeps a caller from smuggling a `project`, a `parent` or a raw `fields` object in.

use std::collections::BTreeMap;

use reqwest::Method;
use serde_json::{Map, Value, json};

use super::cred::{issue_key, project_key};
use super::jql::{field_name_ok, order_by, quote_all, scan_jql};

/// The projects a use may reach: any, or only these (validated) keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit(Option<Vec<String>>);

impl Limit {
    pub fn any() -> Self {
        Self(None)
    }

    /// Only `keys`; a value that is not a project key is dropped, so a malformed entry can only
    /// shrink what is allowed.
    pub fn only(keys: &[String]) -> Self {
        Self(Some(
            keys.iter().filter(|k| project_key(k)).cloned().collect(),
        ))
    }

    /// The limit of a grant: its `projects` values; no `projects` key (or a `*` in it) is any.
    pub fn from_grant(limits: &BTreeMap<String, Vec<String>>) -> Self {
        match limits.get("projects") {
            None => Self::any(),
            Some(v) if v.iter().any(|k| k == "*") => Self::any(),
            Some(v) => Self::only(v),
        }
    }

    fn permits(&self, project: &str) -> bool {
        self.0
            .as_ref()
            .is_none_or(|k| k.iter().any(|p| p == project))
    }

    fn limited(&self) -> bool {
        self.0.is_some()
    }
}

/// A call to make, relative to the API base (`.../rest/api/3`).
#[derive(Debug, Clone)]
pub struct Req {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
}

/// What must be checked around the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Nothing more (the request itself was bounded).
    Open,
    /// A read of one issue: its answer's project is checked.
    Read,
    /// A call on one issue (a change, or a read of its transitions): its project is read first (`GET ?fields=project`) and checked.
    Preread,
    /// A search: every issue's project is checked, and the whole answer is refused on one miss.
    Search,
    /// The project list is cut to the limit.
    Projects,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub req: Req,
    /// The project it touches: the `resource` for `connections::resolve` (limit key `projects`).
    pub resource: Option<String>,
    pub guard: Guard,
    /// The issue key, for the pre-read.
    pub key: Option<String>,
}

/// The project an operation touches, for `resolve`'s resource: an issue key's prefix, the
/// `project` of a create or a search, none for `list_projects`. `Err` is a plain refusal.
pub fn resource_of(op: &str, args: &Value) -> Result<Option<String>, String> {
    plan(op, args, &Limit::any()).map(|p| p.resource)
}

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

static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);

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
            .filter(|n| *n <= max && (*n >= 1 || k == "start_at"))
            .ok_or_else(|| format!("{k} is a number up to {max}")),
    }
}

fn issue(m: &Map<String, Value>) -> Result<(&str, &str), String> {
    let key = need(m, "key", 32)?;
    let project = issue_key(key).ok_or("key is an issue key like ABC-12 (not a numeric id)")?;
    Ok((key, project))
}

/// The `fields` to read: the caller's, or the default, and always `project`.
fn fields(m: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = match m.get("fields") {
        None | Some(Value::Null) => [
            "summary",
            "status",
            "assignee",
            "reporter",
            "priority",
            "issuetype",
            "labels",
            "created",
            "updated",
            "description",
        ]
        .map(str::to_owned)
        .to_vec(),
        Some(Value::Array(a)) if a.len() <= 30 => a
            .iter()
            .map(|v| match v.as_str() {
                Some(s) if field_name_ok(s) => Ok(s.to_owned()),
                _ => Err("fields are names like summary or customfield_10010".to_owned()),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("fields is a list of at most 30 names".to_owned()),
    };
    if !out.iter().any(|f| f == "project") {
        out.push("project".to_owned());
    }
    Ok(out)
}

fn adf(t: &str) -> Value {
    let paragraphs: Vec<Value> = t
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| json!({"type": "paragraph", "content": [{"type": "text", "text": l}]}))
        .collect();
    json!({"type": "doc", "version": 1, "content": paragraphs})
}

fn labels(m: &Map<String, Value>) -> Result<Option<Vec<String>>, String> {
    match m.get("labels") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.len() <= 20 => a
            .iter()
            .map(|v| match v.as_str() {
                Some(s)
                    if (1..=255).contains(&s.len())
                        && !s.chars().any(|c| c.is_whitespace() || c.is_control()) =>
                {
                    Ok(s.to_owned())
                }
                _ => Err("a label is 1 to 255 characters with no spaces".to_owned()),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err("labels is a list of at most 20".to_owned()),
    }
}

fn outside(project: &str) -> String {
    format!("the project {project} is outside what this connection may reach")
}

/// Builds the call for `op`, or says why not. `limit` is the project limit of the grant that
/// let the call through.
pub fn plan(op: &str, args: &Value, limit: &Limit) -> Result<Plan, String> {
    let get = |path: String, guard, resource: Option<&str>, key: Option<&str>| Plan {
        req: Req {
            method: Method::GET,
            path,
            body: None,
        },
        resource: resource.map(str::to_owned),
        guard,
        key: key.map(str::to_owned),
    };
    let on_issue = |m: &Map<String, Value>| -> Result<(String, String), String> {
        let (key, project) = issue(m)?;
        if !limit.permits(project) {
            return Err(outside(project));
        }
        Ok((key.to_owned(), project.to_owned()))
    };
    let send = |method, path: String, body: Value, project: &str, key: &str| Plan {
        req: Req {
            method,
            path,
            body: Some(body),
        },
        resource: Some(project.to_owned()),
        guard: if limit.limited() {
            Guard::Preread
        } else {
            Guard::Open
        },
        key: Some(key.to_owned()),
    };
    match op {
        "jira.get_issue" => {
            let m = obj(op, args, &["key", "fields"])?;
            let (key, project) = on_issue(m)?;
            let q = fields(m)?.join(",");
            Ok(get(
                format!("/issue/{key}?fields={q}"),
                Guard::Read,
                Some(project.as_str()),
                Some(key.as_str()),
            ))
        }
        "jira.list_transitions" => {
            let (key, project) = on_issue(obj(op, args, &["key"])?)?;
            let guard = if limit.limited() {
                Guard::Preread
            } else {
                Guard::Open
            };
            Ok(get(
                format!("/issue/{key}/transitions"),
                guard,
                Some(project.as_str()),
                Some(key.as_str()),
            ))
        }
        "jira.transition_issue" => {
            let m = obj(op, args, &["key", "transition_id"])?;
            let (key, project) = on_issue(m)?;
            let id = need(m, "transition_id", 10)?;
            if !id.bytes().all(|b| b.is_ascii_digit()) {
                return Err("transition_id is the number list_transitions gave".into());
            }
            let body = json!({"transition": {"id": id}});
            Ok(send(
                Method::POST,
                format!("/issue/{key}/transitions"),
                body,
                project.as_str(),
                key.as_str(),
            ))
        }
        "jira.add_comment" => {
            let m = obj(op, args, &["key", "body"])?;
            let (key, project) = on_issue(m)?;
            let body = json!({"body": adf(need(m, "body", 30_000)?)});
            Ok(send(
                Method::POST,
                format!("/issue/{key}/comment"),
                body,
                project.as_str(),
                key.as_str(),
            ))
        }
        "jira.update_issue" => {
            let m = obj(op, args, &["key", "summary", "description", "labels"])?;
            let (key, project) = on_issue(m)?;
            let mut f = Map::new();
            if let Some(s) = text(m, "summary", 255)? {
                f.insert("summary".into(), json!(s));
            }
            if let Some(d) = text(m, "description", 30_000)? {
                f.insert("description".into(), adf(d));
            }
            if let Some(l) = labels(m)? {
                f.insert("labels".into(), json!(l));
            }
            if f.is_empty() {
                return Err("update_issue needs summary, description or labels".into());
            }
            let body = json!({"fields": f});
            Ok(send(
                Method::PUT,
                format!("/issue/{key}"),
                body,
                project.as_str(),
                key.as_str(),
            ))
        }
        "jira.create_issue" => {
            let names = ["project", "summary", "issue_type", "description", "labels"];
            let m = obj(op, args, &names)?;
            let project = need(m, "project", 10)?;
            if !project_key(project) {
                return Err("project is a project key like ABC".into());
            }
            if !limit.permits(project) {
                return Err(outside(project));
            }
            let mut f = Map::new();
            f.insert("project".into(), json!({"key": project}));
            f.insert("summary".into(), json!(need(m, "summary", 255)?));
            f.insert(
                "issuetype".into(),
                json!({"name": need(m, "issue_type", 60)?}),
            );
            if let Some(d) = text(m, "description", 30_000)? {
                f.insert("description".into(), adf(d));
            }
            if let Some(l) = labels(m)? {
                f.insert("labels".into(), json!(l));
            }
            let req = Req {
                method: Method::POST,
                path: "/issue".into(),
                body: Some(json!({"fields": f})),
            };
            Ok(Plan {
                req,
                resource: Some(project.to_owned()),
                guard: Guard::Open,
                key: None,
            })
        }
        "jira.list_projects" => {
            let m = obj(op, args, &["start_at", "max_results"])?;
            let (start, max) = (
                uint(m, "start_at", 0, 1_000_000)?,
                uint(m, "max_results", 50, 50)?,
            );
            let mut path = format!("/project/search?startAt={start}&maxResults={max}");
            for k in limit.0.iter().flatten().take(50) {
                path.push_str("&keys=");
                path.push_str(k);
            }
            Ok(get(path, Guard::Projects, None, None))
        }
        "jira.search_issues" => {
            let names = [
                "jql",
                "project",
                "fields",
                "order_by",
                "max_results",
                "next_page_token",
            ];
            let m = obj(op, args, &names)?;
            let project = text(m, "project", 10)?;
            let constraint = match (project, &limit.0) {
                (Some(p), _) => {
                    if !project_key(p) {
                        return Err("project is a project key like ABC".into());
                    }
                    if !limit.permits(p) {
                        return Err(outside(p));
                    }
                    Some(format!("project = \"{p}\""))
                }
                (None, Some(keys)) if keys.is_empty() => {
                    return Err("this connection may reach no project".into());
                }
                (None, Some(keys)) => Some(format!("project in ({})", quote_all(keys))),
                (None, None) => None,
            };
            let user = text(m, "jql", 4000)?.unwrap_or("").trim();
            let mut q = match (&constraint, user.is_empty()) {
                (Some(c), true) => c.clone(),
                (Some(c), false) => {
                    scan_jql(user)?;
                    format!("{c} AND ({user})")
                }
                (None, _) => user.to_owned(),
            };
            let order = order_by(m)?;
            if !order.is_empty() {
                q.push_str(&format!(" ORDER BY {}", order.join(", ")));
            }
            let mut body = json!({"jql": q, "maxResults": uint(m, "max_results", 25, 100)?,
                "fields": fields(m)?});
            if let Some(t) = text(m, "next_page_token", 4000)? {
                body["nextPageToken"] = json!(t);
            }
            let req = Req {
                method: Method::POST,
                path: "/search/jql".into(),
                body: Some(body),
            };
            let guard = if limit.limited() {
                Guard::Search
            } else {
                Guard::Open
            };
            Ok(Plan {
                req,
                resource: project.map(str::to_owned),
                guard,
                key: None,
            })
        }
        _ => Err(format!("{op}: no such operation")),
    }
}

fn project_of(issue: &Value) -> Option<&str> {
    issue["fields"]["project"]["key"].as_str()
}

/// The pre-read of a change: its issue must be in a permitted project.
pub fn check_preread(v: &Value, limit: &Limit) -> Result<(), String> {
    match project_of(v) {
        Some(p) if limit.permits(p) => Ok(()),
        Some(p) => Err(outside(p)),
        None => Err("the issue's project could not be read".into()),
    }
}

/// The answer of `plan`, checked and cut to the limit.
pub fn check_result(guard: Guard, mut v: Value, limit: &Limit) -> Result<Value, String> {
    match guard {
        Guard::Read => check_preread(&v, limit).map(|()| v),
        Guard::Search => {
            let issues = v["issues"]
                .as_array()
                .ok_or("the search answer is unreadable")?;
            for i in issues {
                check_preread(i, limit)?;
            }
            Ok(v)
        }
        Guard::Projects => {
            if let Some(list) = v["values"].as_array_mut() {
                list.retain(|p| p["key"].as_str().is_some_and(|k| limit.permits(k)));
            }
            if limit.limited() {
                // The upstream totals count projects the caller may not see.
                if let Some(o) = v.as_object_mut() {
                    o.remove("total");
                    o.remove("nextPage");
                    o.remove("isLast");
                }
            }
            Ok(v)
        }
        Guard::Open | Guard::Preread => Ok(v),
    }
}
