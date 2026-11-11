//! The one item format every collector sends (plan §4.1) and the checks the Core re-runs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One item's text is at most this many bytes; a bigger session is split into ordered parts.
pub const MAX_TEXT: usize = 256 * 1024;
/// One upload batch stays under the signed-body cap (C-22).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_TITLE: usize = 300;
pub const MAX_LINKS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    ClaudeCode,
    Codex,
    Opencode,
    Antigravity,
    Cursor,
    Kimi,
    CoreTranscript,
    Doc,
    Vault,
    AgentsMd,
    Jira,
    Linear,
    Github,
    Chat,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::Opencode => "opencode",
            Self::Antigravity => "antigravity",
            Self::Cursor => "cursor",
            Self::Kimi => "kimi",
            Self::CoreTranscript => "core_transcript",
            Self::Doc => "doc",
            Self::Vault => "vault",
            Self::AgentsMd => "agents_md",
            Self::Jira => "jira",
            Self::Linear => "linear",
            Self::Github => "github",
            Self::Chat => "chat",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Origin {
    pub device: String,
    /// A file path or a URL.
    pub path: String,
    /// Line or byte offsets inside `path`, when the item is a part of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorKind {
    Person,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Author {
    pub kind: AuthorKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Item {
    /// A ULID the collector made.
    pub item_id: String,
    pub source_kind: SourceKind,
    /// SHA-256 (lowercase hex) of `normalize(text)`.
    pub content_hash: String,
    pub origin: Origin,
    /// Raw signals for room discovery: a working folder, a repo remote, a tracker key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_hint: Option<String>,
    pub author: Author,
    pub title: String,
    pub text: String,
    #[serde(default)]
    pub links: Vec<String>,
    /// RFC 3339 UTC, e.g. `2026-11-11T09:30:00Z`.
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
}

/// The text a hash is taken over: line ends as `\n`, no trailing whitespace.
pub fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_owned()
}

pub fn hash_of(text: &str) -> String {
    let d = Sha256::digest(normalize(text).as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why an item is refused at intake. `code()` is the stable word the API answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    ItemId,
    ContentHash,
    HashMismatch,
    Title,
    TextTooLarge,
    TextEmpty,
    Links,
    Origin,
    Time,
}

impl Invalid {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ItemId => "item_id_invalid",
            Self::ContentHash => "content_hash_invalid",
            Self::HashMismatch => "hash_mismatch",
            Self::Title => "title_invalid",
            Self::TextTooLarge => "text_too_large",
            Self::TextEmpty => "text_empty",
            Self::Links => "links_invalid",
            Self::Origin => "origin_invalid",
            Self::Time => "time_invalid",
        }
    }
}

fn is_ulid(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SS` with an optional fraction and a `Z` or offset: shape only, the Core never
/// does date arithmetic on it.
fn is_time(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20
        && b.len() <= 40
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[..4].iter().all(u8::is_ascii_digit)
        && (s.ends_with('Z') || s[19..].contains(['+', '-']))
}

impl Item {
    pub fn validate(&self) -> Result<(), Invalid> {
        if !is_ulid(&self.item_id) {
            return Err(Invalid::ItemId);
        }
        if self.content_hash.len() != 64
            || !self
                .content_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Invalid::ContentHash);
        }
        let t = self.title.trim();
        if t.is_empty() || self.title.chars().count() > MAX_TITLE {
            return Err(Invalid::Title);
        }
        if self.text.len() > MAX_TEXT {
            return Err(Invalid::TextTooLarge);
        }
        if self.text.trim().is_empty() {
            return Err(Invalid::TextEmpty);
        }
        if self.links.len() > MAX_LINKS || self.links.iter().any(|l| l.len() > 2000) {
            return Err(Invalid::Links);
        }
        if self.origin.device.is_empty()
            || self.origin.device.len() > 100
            || self.origin.path.is_empty()
            || self.origin.path.len() > 2000
        {
            return Err(Invalid::Origin);
        }
        if !is_time(&self.started_at) || self.ended_at.as_deref().is_some_and(|e| !is_time(e)) {
            return Err(Invalid::Time);
        }
        if hash_of(&self.text) != self.content_hash {
            return Err(Invalid::HashMismatch);
        }
        Ok(())
    }
}

/// The JSON Schema of an item, for the contract and for collectors.
pub fn schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(Item)).expect("the item schema serialises")
}

#[cfg(test)]
pub(crate) fn fixture(text: &str) -> Item {
    Item {
        item_id: "01JD0000000000000000000000".to_owned(),
        source_kind: SourceKind::ClaudeCode,
        content_hash: hash_of(text),
        origin: Origin {
            device: "mac-1".to_owned(),
            path: "/synthetic/projects/alpha/s1.jsonl".to_owned(),
            range: None,
        },
        project_hint: Some("/synthetic/work/alpha".to_owned()),
        author: Author {
            kind: AuthorKind::Person,
            name: "dev".to_owned(),
        },
        title: "A session".to_owned(),
        text: text.to_owned(),
        links: vec![],
        started_at: "2026-11-11T09:30:00Z".to_owned(),
        ended_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_validates() {
        let i = fixture("hello\r\nworld  ");
        assert_eq!(i.validate(), Ok(()));
        let back: Item = serde_json::from_str(&serde_json::to_string(&i).unwrap()).unwrap();
        assert_eq!(back, i);
        // normalised: CRLF and trailing space do not change the hash
        assert_eq!(hash_of("hello\r\nworld  "), hash_of("hello\nworld"));
    }

    #[test]
    fn refuses_each_bad_field_with_its_code() {
        let ok = fixture("text");
        let cases: Vec<(Item, &str)> = vec![
            (
                Item {
                    item_id: "nope".into(),
                    ..ok.clone()
                },
                "item_id_invalid",
            ),
            (
                Item {
                    content_hash: "abc".into(),
                    ..ok.clone()
                },
                "content_hash_invalid",
            ),
            (
                Item {
                    title: " ".into(),
                    ..ok.clone()
                },
                "title_invalid",
            ),
            (
                Item {
                    text: "x".repeat(MAX_TEXT + 1),
                    ..ok.clone()
                },
                "text_too_large",
            ),
            (
                Item {
                    text: "  ".into(),
                    ..ok.clone()
                },
                "text_empty",
            ),
            (
                Item {
                    started_at: "yesterday".into(),
                    ..ok.clone()
                },
                "time_invalid",
            ),
            (
                Item {
                    text: "other".into(),
                    ..ok.clone()
                },
                "hash_mismatch",
            ),
        ];
        for (i, code) in cases {
            assert_eq!(i.validate().unwrap_err().code(), code);
        }
    }

    #[test]
    fn missing_required_field_fails_to_parse_and_schema_lists_it() {
        let v = serde_json::json!({"item_id": "01JD0000000000000000000000"});
        assert!(serde_json::from_value::<Item>(v).is_err());
        let s = schema();
        let req = s["required"].as_array().unwrap();
        assert!(req.iter().any(|r| r == "content_hash"));
        assert!(!req.iter().any(|r| r == "ended_at"));
    }
}
