//! What leaves a call: every answer is rebuilt from a small typed set of fields, never forwarded.
//! A message must name (`channelIdentity`) the team and channel asked for, an id must be
//! well-formed, free text is bounded, and nothing else Microsoft sent (attachments' content,
//! reactions, mention targets, hosted content, history, e-mail addresses, other channels) is
//! returned. Reads use `get`, never an index, so an odd body is an unreadable answer and not a
//! panic. A page cursor is the skip token alone, base64url: Microsoft's own next-page URL is
//! never handed on.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};

use super::cred::{channel_id, channel_key, cursor, guid, message_id};
use super::http::CallError;
use super::ops::Limit;

/// The one refusal for anything outside the limit. It must not say WHICH channel: that would let
/// a limited caller learn what it may not see.
pub(super) const OUTSIDE: &str =
    "outside_limit: the request or the answer reaches beyond what this connection may reach";

pub(super) fn outside() -> String {
    OUTSIDE.to_owned()
}

fn denied() -> CallError {
    CallError::Refused(outside())
}

fn unreadable() -> CallError {
    CallError::Upstream(200)
}

/// The longest message content returned.
pub const MAX_CONTENT: usize = 4_000;
/// The most messages one answer holds (Graph pages are at most 50).
const MAX_MESSAGES: usize = 50;
/// The most teams or channels one answer reads, and returns unlimited.
const MAX_LISTED: usize = 500;
const MAX_RETURNED: usize = 100;
/// The longest skip token handed on.
const MAX_SKIP: usize = 3_000;

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// The skip token of the `@odata.nextLink` Graph handed back, as a cursor a later call may send;
/// `None` when there is none or it is odd. Only the `$skiptoken` value is taken: the link's host,
/// path and every other parameter are dropped.
pub fn next_cursor(body: &Value) -> Option<String> {
    let link = body.get("@odata.nextLink")?.as_str()?;
    let url = reqwest::Url::parse(link).ok()?;
    let (_, token) = url.query_pairs().find(|(k, _)| k == "$skiptoken")?;
    let ok = (1..=MAX_SKIP).contains(&token.len()) && !token.chars().any(char::is_control);
    let c = URL_SAFE_NO_PAD.encode(token.as_bytes());
    (ok && cursor(&c)).then_some(c)
}

/// The skip token a cursor stands for; `None` when it is not one [`next_cursor`] made.
pub fn skip_token(c: &str) -> Option<String> {
    if !cursor(c) {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(c).ok()?;
    let t = String::from_utf8(raw).ok()?;
    ((1..=MAX_SKIP).contains(&t.len()) && !t.chars().any(char::is_control)).then_some(t)
}

fn values(body: &Value) -> Result<&Vec<Value>, CallError> {
    body.get("value")
        .and_then(Value::as_array)
        .ok_or_else(unreadable)
}

/// One message, projected. The message must say it is in `team`'s `channel`.
fn message(m: &Value, team: &str, channel: &str) -> Result<Value, CallError> {
    let ci = m.get("channelIdentity").ok_or_else(denied)?;
    if str_of(ci, "teamId") != Some(team) || str_of(ci, "channelId") != Some(channel) {
        return Err(denied());
    }
    let id = str_of(m, "id")
        .filter(|i| message_id(i))
        .ok_or_else(unreadable)?;
    let mut o = Map::new();
    o.insert("id".into(), json!(id));
    if let Some(r) = str_of(m, "replyToId").filter(|r| message_id(r)) {
        o.insert("reply_to".into(), json!(r));
    }
    for (key, from) in [
        ("type", "messageType"),
        ("created", "createdDateTime"),
        ("modified", "lastModifiedDateTime"),
    ] {
        if let Some(s) = str_of(m, from) {
            o.insert(key.into(), json!(clean(s, 40)));
        }
    }
    o.insert(
        "deleted".into(),
        json!(m.get("deletedDateTime").is_some_and(|d| !d.is_null())),
    );
    if let Some(s) = str_of(m, "subject") {
        o.insert("subject".into(), json!(clean(s, 200)));
    }
    if let Some(from) = m.get("from") {
        let who = |v: &Value| {
            let mut w = Map::new();
            if let Some(i) = str_of(v, "id").filter(|i| guid(i)) {
                w.insert("id".into(), json!(i));
            }
            w.insert(
                "name".into(),
                json!(clean(str_of(v, "displayName").unwrap_or_default(), 120)),
            );
            Value::Object(w)
        };
        if let Some(u) = from.get("user").filter(|u| u.is_object()) {
            o.insert("from".into(), who(u));
        } else if let Some(a) = from.get("application").filter(|a| a.is_object()) {
            let mut w = who(a);
            if let Some(w) = w.as_object_mut() {
                w.insert("application".into(), json!(true));
            }
            o.insert("from".into(), w);
        }
    }
    let body = m.get("body");
    let kind = match body.and_then(|b| str_of(b, "contentType")) {
        Some("text") => "text",
        Some("html") => "html",
        _ => "unknown",
    };
    o.insert("content_type".into(), json!(kind));
    let content = body.and_then(|b| str_of(b, "content")).unwrap_or_default();
    // Content keeps its line breaks; every other control character goes.
    let kept: String = content
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    if kept.chars().count() > MAX_CONTENT {
        o.insert(
            "content".into(),
            json!(kept.chars().take(MAX_CONTENT).collect::<String>()),
        );
        o.insert("content_truncated".into(), json!(true));
    } else {
        o.insert("content".into(), json!(kept));
    }
    for (key, from) in [("attachments", "attachments"), ("mentions", "mentions")] {
        if let Some(n) = m.get(from).and_then(Value::as_array) {
            o.insert(format!("{key}_count"), json!(n.len()));
        }
    }
    Ok(Value::Object(o))
}

/// A page of messages or replies: the typed messages and the cursor for the next page.
pub fn messages(body: &Value, team: &str, channel: &str) -> Result<Value, CallError> {
    let list = values(body)?;
    if list.len() > MAX_MESSAGES {
        return Err(unreadable());
    }
    let out = list
        .iter()
        .map(|m| message(m, team, channel))
        .collect::<Result<Vec<_>, _>>()?;
    let mut o = Map::new();
    o.insert("messages".into(), Value::Array(out));
    if let Some(c) = next_cursor(body) {
        o.insert("next_cursor".into(), json!(c));
    }
    Ok(Value::Object(o))
}

/// One message (`get_message`).
pub fn one_message(
    body: &Value,
    team: &str,
    channel: &str,
    want: &str,
) -> Result<Value, CallError> {
    let m = message(body, team, channel)?;
    if str_of(&m, "id") != Some(want) {
        return Err(unreadable());
    }
    Ok(m)
}

/// A post's answer. The message is live by now, so this never fails: when Graph's answer names
/// the channel and a well-formed id they are returned as they are; anything else (another
/// channel, an odd id, an odd body) is returned as `unverified` with no id the agent could trust.
/// The broker audits that as `ok_unverified`.
pub fn posted(body: &Value, team: &str, channel: &str) -> Value {
    match message(body, team, channel) {
        Ok(m) => json!({"id": m["id"], "created": m.get("created")}),
        Err(_) => unverified(),
    }
}

/// The answer to a write whose message is live but whose answer could not be checked.
pub fn unverified() -> Value {
    json!({"unverified": true,
        "warning": "the message was sent but Microsoft's answer could not be checked; do not send it again"})
}

/// `GET /teams/{t}/channels/{c}`: the channel must be the one asked for, in `tenant`, of a plain
/// kind (`standard` or `private`), and in the team asked for (its `webUrl` names the team in
/// `groupId`, which must be `team`). A shared channel belongs to another team and tenant and is
/// refused with a plain reason. Anything the answer does not say is a no.
pub fn channel_ok(body: &Value, team: &str, channel: &str, tenant: &str) -> Result<(), String> {
    if str_of(body, "id") != Some(channel) {
        return Err(outside());
    }
    match str_of(body, "membershipType") {
        Some("standard" | "private") => {}
        Some("shared") => return Err(SHARED.to_owned()),
        _ => return Err(outside()),
    }
    if str_of(body, "tenantId") != Some(tenant) {
        return Err(SHARED.to_owned());
    }
    let group = str_of(body, "webUrl")
        .and_then(|u| reqwest::Url::parse(u).ok())
        .and_then(|u| {
            let g = u.query_pairs().find(|(k, _)| k == "groupId");
            g.map(|(_, v)| v.into_owned())
        });
    if group.as_deref() == Some(team) {
        Ok(())
    } else {
        Err(outside())
    }
}

/// Why a shared channel is refused.
pub(super) const SHARED: &str = "shared_channel_unsupported: shared channels, and channels of another tenant, are not supported";

/// The teams of `/me/joinedTeams` the limit permits, typed, with `truncated`.
pub fn teams(body: &Value, limit: &Limit) -> Result<Value, CallError> {
    let list = values(body)?;
    if list.len() > MAX_LISTED {
        return Err(unreadable());
    }
    let mut out = Vec::new();
    for t in list {
        let Some(id) = str_of(t, "id").filter(|i| guid(i) && limit.permits_team(i)) else {
            continue;
        };
        out.push(json!({"id": id,
            "name": clean(str_of(t, "displayName").unwrap_or_default(), 120),
            "description": clean(str_of(t, "description").unwrap_or_default(), 200)}));
    }
    let truncated = out.len() > MAX_RETURNED;
    out.truncate(MAX_RETURNED);
    Ok(json!({"teams": out, "truncated": truncated}))
}

/// The channels of `team` the limit permits, typed, with `truncated`. Each carries its limit key.
pub fn channels(body: &Value, team: &str, limit: &Limit) -> Result<Value, CallError> {
    let list = values(body)?;
    if list.len() > MAX_LISTED {
        return Err(unreadable());
    }
    let mut out = Vec::new();
    for c in list {
        let Some(id) = str_of(c, "id").filter(|i| channel_id(i)) else {
            continue;
        };
        let Some(key) = channel_key(team, id).filter(|k| limit.permits(team, k)) else {
            continue;
        };
        let kind = ["standard", "private", "shared"]
            .into_iter()
            .find(|k| str_of(c, "membershipType") == Some(k))
            .unwrap_or("unknown");
        out.push(json!({"id": id, "key": key,
            "name": clean(str_of(c, "displayName").unwrap_or_default(), 120),
            "description": clean(str_of(c, "description").unwrap_or_default(), 200),
            "membership_type": kind}));
    }
    let truncated = out.len() > MAX_RETURNED;
    out.truncate(MAX_RETURNED);
    Ok(json!({"channels": out, "truncated": truncated}))
}
