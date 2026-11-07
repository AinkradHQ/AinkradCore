//! Checks around a call: the one refusal for anything outside the limit, the fields a limited
//! connection may read, and the scan of an answer for projects it may not reach.

use serde_json::Value;

use super::cred::project_key;
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

/// Whether a string holds an issue key (`ABC-12`, at a word boundary) of a project the limit does
/// not permit. Deliberately blunt: `UTF-8` reads as a key of project `UTF`, so a limited
/// connection refuses an answer that merely mentions it.
fn names_outside(s: &str, limit: &Limit) -> bool {
    let b = s.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_uppercase() && (i == 0 || !word(b[i - 1])) {
            let mut j = i;
            while j < b.len()
                && (b[j].is_ascii_uppercase() || b[j].is_ascii_digit() || b[j] == b'_')
            {
                j += 1;
            }
            let mut k = j + 1;
            while j < b.len() && b[j] == b'-' && k < b.len() && b[k].is_ascii_digit() {
                k += 1;
            }
            let digits = k > j + 1;
            if j < b.len() && b[j] == b'-' && digits && (k == b.len() || !word(b[k])) {
                let project = &s[i..j];
                if project_key(project) && !limit.permits(project) {
                    return true;
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

fn embeds_outside(v: &Value, limit: &Limit) -> bool {
    match v {
        Value::String(s) => names_outside(s, limit),
        Value::Array(a) => a.iter().any(|x| embeds_outside(x, limit)),
        Value::Object(o) => o.values().any(|x| embeds_outside(x, limit)),
        _ => false,
    }
}

fn project_of(issue: &Value) -> Option<&str> {
    issue["fields"]["project"]["key"].as_str()
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
            (!embeds_outside(&v, limit))
                .then_some(v)
                .ok_or_else(outside)
        }
        Guard::Search => {
            let issues = v["issues"]
                .as_array()
                .ok_or("the search answer is unreadable")?;
            for i in issues {
                check_preread(i, limit)?;
                if embeds_outside(i, limit) {
                    return Err(outside());
                }
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
