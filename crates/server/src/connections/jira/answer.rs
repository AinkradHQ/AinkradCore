//! Checks around a call: the one refusal for anything outside the limit, the fields a limited
//! connection may read, and the scan of an answer for projects it may not reach.

use serde_json::Value;

use super::cred::issue_key;
use super::ops::{Guard, Limit};

/// The one refusal for anything outside the limit. It must not say WHICH project: that would let a
/// limited caller learn the names of projects it may not see.
pub(super) const OUTSIDE: &str =
    "outside_limit: the request or the answer reaches beyond what this connection may reach";

pub(super) fn outside() -> String {
    OUTSIDE.to_owned()
}

/// The fields a limited connection may read. Everything else can embed other projects' issues
/// (links, parent, subtasks, issue-picker custom fields, worklogs, comments with mentions).
pub(super) const SAFE_FIELDS: [&str; 11] = [
    "summary",
    "status",
    "priority",
    "assignee",
    "reporter",
    "labels",
    "created",
    "updated",
    "description",
    "issuetype",
    "project",
];

fn project_of(issue: &Value) -> Option<&str> {
    issue.get("fields")?.get("project")?.get("key")?.as_str()
}

/// A field that should hold an issue key: absent is fine, present must be a key of a permitted
/// project.
fn key_ok(v: Option<&Value>, limit: &Limit) -> bool {
    v.is_none_or(|k| {
        k.as_str()
            .and_then(issue_key)
            .is_some_and(|p| limit.permits(p))
    })
}

/// The structured fields of an issue that carry other issues' keys: its own `key`, the parent,
/// the subtasks and the links. Free text (summary, description, labels, comments) is not scanned:
/// a mention there ("UTF-8", "see XYZ-5") is a string, not a reach into another project, and the
/// field allowlist already keeps a limited read from asking for the structured ones.
fn structured_ok(issue: &Value, limit: &Limit) -> bool {
    let fields = issue.get("fields");
    let sub = |name: &str| fields.and_then(|f| f.get(name));
    let list_ok = |name: &str, each: &dyn Fn(&Value) -> bool| {
        sub(name)
            .and_then(Value::as_array)
            .is_none_or(|a| a.iter().all(each))
    };
    key_ok(issue.get("key"), limit)
        && key_ok(sub("parent").and_then(|p| p.get("key")), limit)
        && list_ok("subtasks", &|s| key_ok(s.get("key"), limit))
        && list_ok("issuelinks", &|l| {
            ["inwardIssue", "outwardIssue"]
                .iter()
                .all(|side| key_ok(l.get(side).and_then(|i| i.get("key")), limit))
        })
}

/// The pre-read of a change: its issue must be in a permitted project.
pub fn check_preread(v: &Value, limit: &Limit) -> Result<(), String> {
    match project_of(v) {
        Some(p) if limit.permits(p) => Ok(()),
        Some(_) => Err(outside()),
        None => Err("the issue's project could not be read".into()),
    }
}

/// The answer of `plan`, checked and cut to the limit.
///
/// Known limits, accepted: (1) a change is a pre-read of the issue's project and then the write,
/// two requests, so an issue moved between them is written in its new project (TOCTOU; Jira has
/// no conditional write on the project). (2) A limited search is an existence oracle for other
/// projects through JQL functions and clauses that count or compare across projects
/// (`issuekey in ...` only narrows our own `project in (...)`, but a function such as
/// `issuesWithin...` can make an in-limit row appear or vanish depending on a row outside): the
/// ROWS never leave the limit, one bit about the outside can.
pub fn check_result(guard: Guard, mut v: Value, limit: &Limit) -> Result<Value, String> {
    match guard {
        Guard::Read => {
            check_preread(&v, limit)?;
            structured_ok(&v, limit).then_some(v).ok_or_else(outside)
        }
        Guard::Search => {
            let issues = v
                .get("issues")
                .and_then(Value::as_array)
                .ok_or("the search answer is unreadable")?;
            for i in issues {
                check_preread(i, limit)?;
                if !structured_ok(i, limit) {
                    return Err(outside());
                }
            }
            Ok(v)
        }
        Guard::Projects => {
            match v.get_mut("values").and_then(Value::as_array_mut) {
                Some(list) => list.retain(|p| {
                    p.get("key")
                        .and_then(Value::as_str)
                        .is_some_and(|k| limit.permits(k))
                }),
                // A limited list that cannot be read cannot be cut: refuse it.
                None if limit.limited() => return Err("the project list is unreadable".into()),
                None => {}
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
