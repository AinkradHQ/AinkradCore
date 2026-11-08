//! The typed operations: each is a fixed Web API method ([`super::http::Method`]), the capability
//! that allows it (the descriptor) and the channel it touches (the resource). Form values are
//! rebuilt from validated parts; nothing a caller sends is forwarded raw. A limited connection (a
//! grant with `channels`) is enforced on the REQUEST (the channel ID, compared exactly: never a
//! name, never another case) and again on the ANSWER ([`super::answer`], [`super::calls`]).
//!
//! Arguments are objects with a fixed set of names; any other name is refused, which keeps a
//! caller from smuggling `blocks`, `attachments`, `metadata`, `username`, `icon_*`, `as_user`,
//! `reply_broadcast`, `link_names`, `parse` or a second `channel` in.
//!
//! **Message text** is plain text: `&`, `<` and `>` are escaped (so `<!channel>`, `<!here>`,
//! `<!subteam^…>`, `<@U…>`, `<#C…>` and `<url|label>` all arrive as literal text), and a bare
//! `@here`, `@channel` or `@everyone` is refused. It is sent with `parse=none` and no `link_names`
//! and with unfurling off. At most [`MAX_TEXT`] characters.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::answer::outside;
use super::cred::{channel_id, cursor, emoji_name, message_ts, user_id};

/// Characters of one message. Slack advises 4,000 and may split longer text.
pub const MAX_TEXT: usize = 4_000;
/// Messages a page may ask for. Slack gives apps that are not in its Marketplace and are
/// distributed 15 at most, so more is never asked.
pub const MAX_PAGE: u64 = 15;
/// Channels of one `list_channels` page of an unlimited connection.
pub const MAX_CHANNELS: u64 = 100;

/// The channels a use may reach: any, or only these (validated) IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit(Option<Vec<String>>);

impl Limit {
    pub fn any() -> Self {
        Self(None)
    }

    /// Only `ids`; a value that is not a channel ID is dropped, so a malformed entry (a name, a
    /// lower-case ID, a DM) can only shrink what is allowed.
    pub fn only(ids: &[String]) -> Self {
        Self(Some(
            ids.iter().filter(|k| channel_id(k)).cloned().collect(),
        ))
    }

    /// The limit of the EFFECTIVE limits `connections::resolve` returns: its `channels` values; no
    /// `channels` key is any. There is no wildcard: `*` is a literal there, so it is not an ID and
    /// is dropped like any other malformed entry.
    pub fn from_grant(limits: &BTreeMap<String, Vec<String>>) -> Self {
        limits
            .get("channels")
            .map_or_else(Self::any, |v| Self::only(v))
    }

    pub(super) fn permits(&self, channel: &str) -> bool {
        self.0
            .as_ref()
            .is_none_or(|k| k.iter().any(|p| p == channel))
    }

    pub(super) fn limited(&self) -> bool {
        self.0.is_some()
    }

    /// The permitted IDs, when limited.
    pub(super) fn keys(&self) -> Option<&[String]> {
        self.0.as_deref()
    }
}

/// What to do for one operation, built from validated arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    ListChannels {
        limit: u64,
        cursor: Option<String>,
    },
    ReadChannel {
        channel: String,
        limit: u64,
        cursor: Option<String>,
        oldest: Option<String>,
        latest: Option<String>,
    },
    ReadThread {
        channel: String,
        ts: String,
        limit: u64,
        cursor: Option<String>,
    },
    GetUser {
        user: String,
    },
    Post {
        channel: String,
        /// Already escaped.
        text: String,
        thread_ts: Option<String>,
    },
    React {
        channel: String,
        ts: String,
        name: String,
    },
}

impl Plan {
    /// The channel it touches: the `resource` for `connections::resolve` (limit key `channels`).
    pub fn resource(&self) -> Option<&str> {
        match self {
            Self::ReadChannel { channel, .. }
            | Self::ReadThread { channel, .. }
            | Self::Post { channel, .. }
            | Self::React { channel, .. } => Some(channel),
            Self::ListChannels { .. } | Self::GetUser { .. } => None,
        }
    }
}

/// The channel an operation touches, for `resolve`'s resource; none for `list_channels` and
/// `get_user`. `Err` is a plain refusal.
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
        let shown: String = k.chars().filter(|c| !c.is_control()).take(40).collect();
        return Err(format!("{op}: no argument named {shown:?}"));
    }
    Ok(m)
}

fn text<'a>(m: &'a Map<String, Value>, k: &str, max: usize) -> Result<Option<&'a str>, String> {
    match m.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= max => Ok(Some(s)),
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

/// A channel ID argument, validated and checked against the limit.
fn channel<'a>(m: &'a Map<String, Value>, limit: &Limit) -> Result<&'a str, String> {
    let c = need(m, "channel", 16)?;
    if !channel_id(c) {
        return Err("channel is a channel ID like C0123456789 (not a name)".into());
    }
    if !limit.permits(c) {
        return Err(outside());
    }
    Ok(c)
}

fn ts_arg<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, String> {
    match text(m, k, 20)? {
        Some(t) if message_ts(t) => Ok(Some(t)),
        Some(_) => Err(format!("{k} is a message timestamp like 1355517523.000005")),
        None => Ok(None),
    }
}

fn cursor_arg(m: &Map<String, Value>) -> Result<Option<String>, String> {
    match text(m, "cursor", 200)? {
        Some(c) if cursor(c) => Ok(Some(c.to_owned())),
        Some(_) => Err("cursor is what a previous page gave".into()),
        None => Ok(None),
    }
}

/// Escapes what Slack reads as markup, and refuses text that addresses everyone. Plain text in,
/// plain text shown.
fn message_text(raw: &str) -> Result<String, String> {
    if raw
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return Err("text has a control character".into());
    }
    let lower = raw.to_lowercase();
    if ["@here", "@channel", "@everyone"]
        .iter()
        .any(|w| lower.contains(w))
    {
        return Err("text may not address @here, @channel or @everyone".into());
    }
    Ok(raw
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

/// Builds the plan for `op`, or says why not. `limit` is the channel limit of the grant that let
/// the call through.
pub fn plan(op: &str, args: &Value, limit: &Limit) -> Result<Plan, String> {
    match op {
        "slack.list_channels" => {
            let m = obj(op, args, &["limit", "cursor"])?;
            if matches!(limit.keys(), Some([])) {
                return Err("this connection may reach no channel".into());
            }
            Ok(Plan::ListChannels {
                limit: uint(m, "limit", MAX_CHANNELS, MAX_CHANNELS)?,
                cursor: cursor_arg(m)?,
            })
        }
        "slack.read_channel" => {
            let m = obj(
                op,
                args,
                &["channel", "limit", "cursor", "oldest", "latest"],
            )?;
            Ok(Plan::ReadChannel {
                channel: channel(m, limit)?.to_owned(),
                limit: uint(m, "limit", MAX_PAGE, MAX_PAGE)?,
                cursor: cursor_arg(m)?,
                oldest: ts_arg(m, "oldest")?.map(str::to_owned),
                latest: ts_arg(m, "latest")?.map(str::to_owned),
            })
        }
        "slack.read_thread" => {
            let m = obj(op, args, &["channel", "ts", "limit", "cursor"])?;
            Ok(Plan::ReadThread {
                channel: channel(m, limit)?.to_owned(),
                ts: ts_arg(m, "ts")?.ok_or("ts is required")?.to_owned(),
                limit: uint(m, "limit", MAX_PAGE, MAX_PAGE)?,
                cursor: cursor_arg(m)?,
            })
        }
        "slack.get_user" => {
            let m = obj(op, args, &["user"])?;
            let u = need(m, "user", 16)?;
            if !user_id(u) {
                return Err("user is a user ID like U0123456789".into());
            }
            Ok(Plan::GetUser { user: u.to_owned() })
        }
        "slack.post_message" => {
            let m = obj(op, args, &["channel", "text", "thread_ts"])?;
            let channel = channel(m, limit)?.to_owned();
            let text = message_text(need(m, "text", MAX_TEXT)?)?;
            Ok(Plan::Post {
                channel,
                text,
                thread_ts: ts_arg(m, "thread_ts")?.map(str::to_owned),
            })
        }
        "slack.add_reaction" => {
            let m = obj(op, args, &["channel", "ts", "name"])?;
            let name = need(m, "name", 100)?;
            if !emoji_name(name) {
                return Err("name is an emoji name like thumbsup, without colons".into());
            }
            Ok(Plan::React {
                channel: channel(m, limit)?.to_owned(),
                ts: ts_arg(m, "ts")?.ok_or("ts is required")?.to_owned(),
                name: name.to_owned(),
            })
        }
        _ => Err(format!("{op}: no such operation")),
    }
}
