//! The typed operations: each is a fixed Graph request ([`super::calls`]), the capability that
//! allows it (the descriptor) and the channel it touches (the resource). Everything that reaches a
//! URL is rebuilt from validated parts; nothing a caller sends is forwarded raw. A limited
//! connection (a grant with `channels`) is enforced on the REQUEST (the team GUID and the channel
//! id, compared exactly: never a name, never another case) and again on the ANSWER
//! ([`super::answer`]).
//!
//! The limit holds KEYS, `<team id>/<channel id without 19: and @thread.*>` (see
//! [`super::cred::channel_key`]), or `<team id>/*` for every channel of one team: the same two
//! forms the store compares, so the broker's decision and this adapter's agree.
//!
//! Arguments are objects with a fixed set of names; any other name is refused, which keeps a
//! caller from smuggling `$filter`, `$expand`, `$select`, `$orderby`, `$search`, a second
//! `channel`, `mentions`, `attachments`, `importance` or `contentType` in.
//!
//! **Message text** is plain text: sent as `contentType: text`, with nothing else in the body (no
//! `mentions`, no attachments, no `importance`). `<at` (a mention tag), `@channel`, `@team`,
//! `@everyone` and `@here` are refused, so a message cannot ping a channel or a team. At most
//! [`MAX_TEXT`] characters.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::answer::outside;
use super::cred::{channel_key, cursor, guid, key_ok, message_id};

/// Characters of one message.
pub const MAX_TEXT: usize = 4_000;
/// Messages a page may ask for (Graph's own most is 50).
pub const MAX_PAGE: u64 = 50;
const DEFAULT_PAGE: u64 = 20;

/// One entry of a limit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// `<team>/<middle>[.skype]`.
    Channel(String),
    /// `<team>/*`.
    Team(String),
}

/// The channels a use may reach: any, or only these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit(Option<Vec<Entry>>);

impl Limit {
    pub fn any() -> Self {
        Self(None)
    }

    /// Only `values`; one that is not a well-formed key or `<team id>/*` (a name, an upper-case
    /// GUID, a bare team, a pattern) is dropped, so a malformed entry can only shrink what is
    /// allowed.
    pub fn only(values: &[String]) -> Self {
        let entries = values.iter().filter_map(|v| match v.strip_suffix("/*") {
            Some(team) if guid(team) => Some(Entry::Team(team.to_owned())),
            Some(_) => None,
            None => key_ok(v).then(|| Entry::Channel(v.clone())),
        });
        Self(Some(entries.collect()))
    }

    /// The limit of the EFFECTIVE limits `connections::resolve` returns: its `channels` values; no
    /// `channels` key is any.
    pub fn from_grant(limits: &BTreeMap<String, Vec<String>>) -> Self {
        limits
            .get("channels")
            .map_or_else(Self::any, |v| Self::only(v))
    }

    /// Whether channel `key` of `team` is permitted.
    pub(super) fn permits(&self, team: &str, key: &str) -> bool {
        self.0.as_ref().is_none_or(|e| {
            e.iter().any(|x| match x {
                Entry::Channel(k) => k == key,
                Entry::Team(t) => t == team,
            })
        })
    }

    /// Whether anything of `team` is permitted.
    pub(super) fn permits_team(&self, team: &str) -> bool {
        self.0.as_ref().is_none_or(|e| {
            e.iter().any(|x| match x {
                Entry::Channel(k) => k.split_once('/').is_some_and(|(t, _)| t == team),
                Entry::Team(t) => t == team,
            })
        })
    }

    fn reaches_nothing(&self) -> bool {
        matches!(&self.0, Some(e) if e.is_empty())
    }
}

/// What to do for one operation, built from validated arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    ListTeams,
    ListChannels {
        team: String,
    },
    ListMessages {
        team: String,
        channel: String,
        top: u64,
        cursor: Option<String>,
    },
    GetMessage {
        team: String,
        channel: String,
        message: String,
    },
    ListReplies {
        team: String,
        channel: String,
        message: String,
        top: u64,
        cursor: Option<String>,
    },
    Post {
        team: String,
        channel: String,
        text: String,
    },
    Reply {
        team: String,
        channel: String,
        message: String,
        text: String,
    },
}

impl Plan {
    /// The channel it touches: the `resource` for `connections::resolve` (limit key `channels`).
    pub fn resource(&self) -> Option<String> {
        match self {
            Self::ListMessages { team, channel, .. }
            | Self::GetMessage { team, channel, .. }
            | Self::ListReplies { team, channel, .. }
            | Self::Post { team, channel, .. }
            | Self::Reply { team, channel, .. } => channel_key(team, channel),
            Self::ListTeams | Self::ListChannels { .. } => None,
        }
    }

    /// Whether the caller supplied a page cursor (a request that can make Graph fail on input).
    pub fn has_cursor(&self) -> bool {
        matches!(
            self,
            Self::ListMessages {
                cursor: Some(_),
                ..
            } | Self::ListReplies {
                cursor: Some(_),
                ..
            }
        )
    }
}

/// The channel key an operation touches, for `resolve`'s resource; none for `list_teams` and
/// `list_channels`. `Err` is a plain refusal.
pub fn resource_of(op: &str, args: &Value) -> Result<Option<String>, String> {
    plan(op, args, &Limit::any()).map(|p| p.resource())
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

fn team(m: &Map<String, Value>) -> Result<&str, String> {
    let t = need(m, "team", 40)?;
    if guid(t) {
        Ok(t)
    } else {
        Err("team is a team id (a lower-case GUID, not a name; list_teams gives it)".into())
    }
}

/// The team and channel arguments, validated and checked against the limit.
fn pair<'a>(m: &'a Map<String, Value>, limit: &Limit) -> Result<(&'a str, &'a str), String> {
    let t = team(m)?;
    let c = need(m, "channel", 120)?;
    let Some(key) = channel_key(t, c) else {
        return Err(
            "channel is a channel id like 19:...@thread.tacv2 (not a name; list_channels gives it)"
                .into(),
        );
    };
    if !limit.permits(t, &key) {
        return Err(outside());
    }
    Ok((t, c))
}

fn message_arg(m: &Map<String, Value>) -> Result<&str, String> {
    let id = need(m, "message", 24)?;
    if message_id(id) {
        Ok(id)
    } else {
        Err("message is a message id (digits) a read gave".into())
    }
}

fn cursor_arg(m: &Map<String, Value>) -> Result<Option<String>, String> {
    match text(m, "cursor", 4096)? {
        Some(c) if cursor(c) => Ok(Some(c.to_owned())),
        Some(_) => Err("cursor is what a previous page gave".into()),
        None => Ok(None),
    }
}

/// Plain text only: no control characters, no mention tag, nothing that addresses a channel or a
/// team. It is sent as `contentType: text`.
fn message_text(raw: &str) -> Result<String, String> {
    if raw
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return Err("text has a control character".into());
    }
    let lower = raw.to_lowercase();
    if lower.contains("<at") {
        return Err("text may not hold a mention tag".into());
    }
    if ["@channel", "@team", "@everyone", "@here"]
        .iter()
        .any(|w| lower.contains(w))
    {
        return Err("text may not address @channel, @team, @everyone or @here".into());
    }
    Ok(raw.to_owned())
}

/// Builds the plan for `op`, or says why not. `limit` is the channel limit of the grant that let
/// the call through.
pub fn plan(op: &str, args: &Value, limit: &Limit) -> Result<Plan, String> {
    let owned = |s: &str| s.to_owned();
    match op {
        "teams.list_teams" => {
            obj(op, args, &[])?;
            if limit.reaches_nothing() {
                return Err("this connection may reach no channel".into());
            }
            Ok(Plan::ListTeams)
        }
        "teams.list_channels" => {
            let m = obj(op, args, &["team"])?;
            let t = team(m)?;
            if !limit.permits_team(t) {
                return Err(outside());
            }
            Ok(Plan::ListChannels { team: owned(t) })
        }
        "teams.list_messages" => {
            let m = obj(op, args, &["team", "channel", "top", "cursor"])?;
            let (t, c) = pair(m, limit)?;
            Ok(Plan::ListMessages {
                team: owned(t),
                channel: owned(c),
                top: uint(m, "top", DEFAULT_PAGE, MAX_PAGE)?,
                cursor: cursor_arg(m)?,
            })
        }
        "teams.get_message" => {
            let m = obj(op, args, &["team", "channel", "message"])?;
            let (t, c) = pair(m, limit)?;
            Ok(Plan::GetMessage {
                team: owned(t),
                channel: owned(c),
                message: owned(message_arg(m)?),
            })
        }
        "teams.list_replies" => {
            let m = obj(op, args, &["team", "channel", "message", "top", "cursor"])?;
            let (t, c) = pair(m, limit)?;
            Ok(Plan::ListReplies {
                team: owned(t),
                channel: owned(c),
                message: owned(message_arg(m)?),
                top: uint(m, "top", DEFAULT_PAGE, MAX_PAGE)?,
                cursor: cursor_arg(m)?,
            })
        }
        "teams.post_message" => {
            let m = obj(op, args, &["team", "channel", "text"])?;
            let (t, c) = pair(m, limit)?;
            Ok(Plan::Post {
                team: owned(t),
                channel: owned(c),
                text: message_text(need(m, "text", MAX_TEXT)?)?,
            })
        }
        "teams.reply_message" => {
            let m = obj(op, args, &["team", "channel", "message", "text"])?;
            let (t, c) = pair(m, limit)?;
            Ok(Plan::Reply {
                team: owned(t),
                channel: owned(c),
                message: owned(message_arg(m)?),
                text: message_text(need(m, "text", MAX_TEXT)?)?,
            })
        }
        _ => Err(format!("{op}: no such operation")),
    }
}

#[cfg(test)]
impl Plan {
    /// Whether `limit` lets a read of `channel` in `team` through: the request-side decision.
    pub(crate) fn from_test(limit: &Limit, team: &str, channel: &str) -> bool {
        let args = serde_json::json!({"team": team, "channel": channel});
        plan("teams.list_messages", &args, limit).is_ok()
    }
}
