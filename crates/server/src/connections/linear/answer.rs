//! Checks around a call: the one refusal for anything outside the limit, and the scan of an answer
//! for teams it may not reach. Only STRUCTURED fields are read (an issue's `team.key` and its
//! `identifier`): free text (title, description) is not scanned, since a mention there is a string,
//! not a reach into another team, and the fixed selection never asks for the fields that carry
//! other issues (`parent`, `children`, `relations`).

use serde_json::Value;

use super::cred::{issue_identifier, uuid};
use super::ops::Limit;

/// The one refusal for anything outside the limit. It must not say WHICH team: that would let a
/// limited caller learn the names of teams it may not see.
pub(super) const OUTSIDE: &str =
    "outside_limit: the request or the answer reaches beyond what this connection may reach";

pub(super) fn outside() -> String {
    OUTSIDE.to_owned()
}

fn team_of(v: &Value) -> Option<&str> {
    v.get("team")?.get("key")?.as_str()
}

/// An issue as an answer carries it: its team must be present and permitted, and its identifier
/// (when present) must be well formed with a permitted prefix.
pub fn check_issue(v: &Value, limit: &Limit) -> Result<(), String> {
    match team_of(v) {
        Some(t) if limit.permits(t) => {}
        Some(_) => return Err(outside()),
        None => return Err("the issue's team could not be read".into()),
    }
    match v.get("identifier") {
        None => Ok(()),
        Some(i) => i
            .as_str()
            .and_then(issue_identifier)
            .filter(|p| limit.permits(p))
            .map(|_| ())
            .ok_or_else(outside),
    }
}

/// The pre-read of a change: the issue's UUID and its team (the one it is in NOW, whatever its
/// identifier said), which must be permitted.
pub fn check_ref(v: &Value, limit: &Limit) -> Result<(String, String), String> {
    let team = match team_of(v) {
        Some(t) if limit.permits(t) => t.to_owned(),
        Some(_) => return Err(outside()),
        None => return Err("the issue's team could not be read".into()),
    };
    match v.get("id").and_then(Value::as_str) {
        Some(id) if uuid(id) => Ok((id.to_owned(), team)),
        _ => Err("the issue's id could not be read".into()),
    }
}

/// The `nodes` array of a connection in an answer.
pub fn nodes<'a>(v: &'a Value, what: &str) -> Result<&'a Vec<Value>, String> {
    v.get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the {what} answer is unreadable"))
}

/// Keeps the nodes whose `key` the limit permits (a team list or a project list through teams).
pub fn retain_teams(list: &mut Vec<Value>, limit: &Limit) {
    list.retain(|t| {
        t.get("key")
            .and_then(Value::as_str)
            .is_some_and(|k| limit.permits(k))
    });
}
