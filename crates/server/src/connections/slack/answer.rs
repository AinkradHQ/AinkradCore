//! What leaves a call: every answer is rebuilt from a small typed set of fields, never forwarded.
//! A channel must be the one asked for (and permitted), a message needs a well-formed timestamp,
//! free text is bounded, and nothing else Slack sent (files, blocks, attachments, profiles,
//! reactions, e-mail addresses, other channels) is returned. Reads use `get`, never an index, so
//! an odd body is an unreadable answer and not a panic.

use serde_json::{Map, Value, json};

use super::cred::{channel_id, cursor, message_ts, team_id, user_id};
use super::http::CallError;
use super::ops::Limit;

/// The one refusal for anything outside the limit. It must not say WHICH channel: that would let
/// a limited caller learn what it may not see.
pub(super) const OUTSIDE: &str =
    "outside_limit: the request or the answer reaches beyond what this connection may reach";

pub(super) fn outside() -> String {
    OUTSIDE.to_owned()
}

/// The longest message text returned.
pub const MAX_MESSAGE_TEXT: usize = 4_000;
/// The most messages one answer holds (Slack pages are at most 15 here).
const MAX_MESSAGES: usize = 50;

fn unreadable() -> CallError {
    CallError::Upstream(200)
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn flag(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(Value::as_bool)
}

/// The page cursor Slack handed back, when it is one a later call may send.
pub fn next_cursor(body: &Value) -> Option<String> {
    let c = body
        .get("response_metadata")?
        .get("next_cursor")?
        .as_str()?;
    cursor(c).then(|| c.to_owned())
}

/// One message, projected. `None` when it has no usable timestamp.
fn message(m: &Value) -> Option<Value> {
    let ts = str_of(m, "ts").filter(|t| message_ts(t))?;
    let mut o = Map::new();
    o.insert("ts".into(), json!(ts));
    if let Some(u) = str_of(m, "user").filter(|u| user_id(u)) {
        o.insert("user".into(), json!(u));
    }
    if let Some(b) = str_of(m, "bot_id") {
        o.insert("bot_id".into(), json!(clean(b, 16)));
    }
    if let Some(s) = str_of(m, "subtype") {
        o.insert("subtype".into(), json!(clean(s, 40)));
    }
    if let Some(t) = str_of(m, "thread_ts").filter(|t| message_ts(t)) {
        o.insert("thread_ts".into(), json!(t));
    }
    if let Some(n) = m.get("reply_count").and_then(Value::as_u64) {
        o.insert("reply_count".into(), json!(n));
    }
    let text = str_of(m, "text").unwrap_or_default();
    // Text keeps its line breaks; every other control character goes.
    let kept: String = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    if kept.chars().count() > MAX_MESSAGE_TEXT {
        o.insert(
            "text".into(),
            json!(kept.chars().take(MAX_MESSAGE_TEXT).collect::<String>()),
        );
        o.insert("text_truncated".into(), json!(true));
    } else {
        o.insert("text".into(), json!(kept));
    }
    Some(Value::Object(o))
}

/// The answer of `conversations.history` or `.replies`: the typed messages, `has_more` and the
/// cursor for the next page. A message that cannot be read makes the whole answer unreadable.
pub fn messages(body: &Value) -> Result<Value, CallError> {
    let list = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(unreadable)?;
    if list.len() > MAX_MESSAGES {
        return Err(unreadable());
    }
    let out: Option<Vec<Value>> = list.iter().map(message).collect();
    let out = out.ok_or_else(unreadable)?;
    let mut o = Map::new();
    o.insert("messages".into(), Value::Array(out));
    o.insert(
        "has_more".into(),
        json!(flag(body, "has_more").unwrap_or(false)),
    );
    if let Some(c) = next_cursor(body) {
        o.insert("next_cursor".into(), json!(c));
    }
    Ok(Value::Object(o))
}

/// The channels of a `conversations.list` page the limit permits, typed. Direct and group
/// messages are dropped even though they are never asked for.
pub fn channels(body: &Value, limit: &Limit) -> Result<Vec<Value>, CallError> {
    let list = body
        .get("channels")
        .and_then(Value::as_array)
        .ok_or_else(unreadable)?;
    let mut out = Vec::new();
    for c in list {
        let Some(id) = str_of(c, "id").filter(|i| channel_id(i) && limit.permits(i)) else {
            continue;
        };
        if flag(c, "is_im") == Some(true) || flag(c, "is_mpim") == Some(true) {
            continue;
        }
        let mut o = Map::new();
        o.insert("id".into(), json!(id));
        o.insert(
            "name".into(),
            json!(clean(str_of(c, "name").unwrap_or_default(), 80)),
        );
        o.insert(
            "is_private".into(),
            json!(flag(c, "is_private").unwrap_or(false)),
        );
        o.insert(
            "is_member".into(),
            json!(flag(c, "is_member").unwrap_or(false)),
        );
        if let Some(n) = c.get("num_members").and_then(Value::as_u64) {
            o.insert("num_members".into(), json!(n));
        }
        out.push(Value::Object(o));
    }
    Ok(out)
}

/// `conversations.info` of the channel `want`: it must be that channel, neither a direct message
/// nor a multi-person DM, and say whether it is private. A `G…` id (an older private channel, or a
/// multi-person DM) must also be private. Anything the answer does not say is a no.
pub fn channel_ok(body: &Value, want: &str) -> Result<(), String> {
    let c = body.get("channel").ok_or_else(outside)?;
    let same = str_of(c, "id") == Some(want);
    let plain = flag(c, "is_im") != Some(true) && flag(c, "is_mpim") == Some(false);
    let private = flag(c, "is_private");
    let kind_ok = match want.starts_with('G') {
        true => private == Some(true),
        false => private.is_some(),
    };
    if same && plain && kind_ok {
        Ok(())
    } else {
        Err("that conversation is not a channel this connection may use".into())
    }
}

/// `users.info`: a tiny typed set, never an e-mail address, phone number or profile field.
pub fn user(body: &Value, want: &str) -> Result<Value, CallError> {
    let u = body.get("user").ok_or_else(unreadable)?;
    if str_of(u, "id") != Some(want) {
        return Err(unreadable());
    }
    let profile = u.get("profile");
    let display = profile.and_then(|p| str_of(p, "display_name"));
    let mut o = Map::new();
    o.insert("id".into(), json!(want));
    o.insert(
        "name".into(),
        json!(clean(str_of(u, "name").unwrap_or_default(), 80)),
    );
    o.insert(
        "real_name".into(),
        json!(clean(str_of(u, "real_name").unwrap_or_default(), 120)),
    );
    o.insert(
        "display_name".into(),
        json!(clean(display.unwrap_or_default(), 120)),
    );
    o.insert("is_bot".into(), json!(flag(u, "is_bot").unwrap_or(false)));
    o.insert("deleted".into(), json!(flag(u, "deleted").unwrap_or(false)));
    if let Some(t) = str_of(u, "team_id").filter(|t| team_id(t)) {
        o.insert("team_id".into(), json!(t));
    }
    Ok(Value::Object(o))
}

/// `chat.postMessage`: the channel Slack posted to must be the one asked for.
pub fn posted(body: &Value, want: &str) -> Result<Value, String> {
    let channel = str_of(body, "channel");
    let ts = str_of(body, "ts").filter(|t| message_ts(t));
    match (channel, ts) {
        (Some(c), Some(ts)) if c == want => Ok(json!({"channel": c, "ts": ts})),
        _ => Err(outside()),
    }
}
