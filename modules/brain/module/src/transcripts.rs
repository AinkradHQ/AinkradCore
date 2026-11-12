//! A finished AI session's transcript as Brain items (E5-1): the user's and the assistant's text
//! only (no tool calls, no tool output, no reasoning), in the one item format. The transcript was
//! redacted by the runner and by the Core when stored, and the intake cleans it again.

use brain_model::item::{Author, AuthorKind, Item, MAX_TEXT, Origin, SourceKind, hash_of};
use serde_json::Value;

/// A part is cut here, under the item cap, so one hash covers one part.
const PART_BYTES: usize = MAX_TEXT - 4096;

/// Text of one harness event as `User: ...` or `Assistant: ...`; none for anything else.
pub(crate) fn render(body: &Value) -> Option<String> {
    let role = body["message"]["role"]
        .as_str()
        .or_else(|| body["role"].as_str())
        .or_else(|| body["type"].as_str())
        .or_else(|| body["event"].as_str())?;
    let who = match role {
        "user" => "User",
        "assistant" => "Assistant",
        _ => return None,
    };
    let content = if body["message"]["content"].is_null() {
        &body["content"]
    } else {
        &body["message"]["content"]
    };
    let text = match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter(|b| b["type"] == "text")
            .filter_map(|b| b["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    let text = text.trim();
    (!text.is_empty()).then(|| format!("{who}: {text}"))
}

pub(crate) fn ulid(now_ms: u64) -> String {
    const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).expect("the system random source");
    let time = (0..10)
        .rev()
        .map(|i| A[((now_ms >> (5 * i)) & 31) as usize]);
    let rand = r.iter().map(|b| A[(b & 31) as usize]);
    time.chain(rand).map(char::from).collect()
}

fn cut(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// What one session gives the Brain.
pub(crate) struct Meta<'a> {
    pub id: &'a str,
    pub harness: &'a str,
    pub title: &'a str,
    pub project_hint: Option<String>,
    pub started_at: &'a str,
    pub ended_at: Option<&'a str>,
}

/// Items for the entries `(seq, body)`, oldest first: one per part of at most `PART_BYTES`.
/// Each item's origin range is the entries it covers, so a session that is resumed and ends again
/// gives only its new entries.
pub(crate) fn items(s: &Meta, entries: &[(u64, Value)], now_ms: u64) -> Vec<Item> {
    // (first seq, last seq, text) per part.
    let mut parts: Vec<(u64, u64, String)> = vec![];
    for (seq, body) in entries {
        let Some(block) = render(body) else { continue };
        let block = cut(&block, PART_BYTES).to_owned();
        match parts.last_mut() {
            Some((_, last, text)) if text.len() + block.len() < PART_BYTES => {
                text.push_str("\n\n");
                text.push_str(&block);
                *last = *seq;
            }
            _ => parts.push((*seq, *seq, block)),
        }
    }
    let total = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, (first, last, text))| {
            let text = format!(
                "AI session {} ({}), entries {first}-{last}\n\n{text}",
                s.id, s.harness
            );
            Item {
                item_id: ulid(now_ms),
                source_kind: SourceKind::CoreTranscript,
                content_hash: hash_of(&text),
                origin: Origin {
                    device: "core".to_owned(),
                    path: format!("core://ai-session/{}", s.id),
                    range: Some((first, last)),
                },
                project_hint: s.project_hint.clone(),
                author: Author {
                    kind: AuthorKind::Agent,
                    name: s.harness.to_owned(),
                },
                title: if total > 1 {
                    format!("{} (part {} of {total})", s.title, i + 1)
                } else {
                    s.title.to_owned()
                },
                text,
                links: vec![],
                started_at: s.started_at.to_owned(),
                ended_at: s.ended_at.map(str::to_owned),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn session() -> Meta<'static> {
        Meta {
            id: "as_abc",
            harness: "claude",
            title: "Fix the build",
            project_hint: None,
            started_at: "2026-11-12T08:00:00.000Z",
            ended_at: None,
        }
    }

    #[test]
    fn keeps_only_what_was_said() {
        let user = json!({"type": "user", "message": {"role": "user", "content": "hello"}});
        let tool = json!({"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t", "content": "SECRET OUTPUT"}]}});
        let reply = json!({"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "hmm"},
            {"type": "tool_use", "name": "Bash"},
            {"type": "text", "text": "done"}]}});
        let odd = json!({"type": "rate_limit_event"});
        let out = items(
            &session(),
            &[(1, user), (2, tool), (3, reply), (4, odd)],
            1_000,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].text.ends_with("User: hello\n\nAssistant: done"));
        assert!(!out[0].text.contains("SECRET"));
        assert_eq!(out[0].origin.range, Some((1, 3)));
        assert_eq!(out[0].validate(), Ok(()));
    }

    #[test]
    fn a_long_session_is_split_into_ordered_valid_parts() {
        let big =
            json!({"type": "user", "message": {"role": "user", "content": "x".repeat(150_000)}});
        let entries: Vec<_> = (1..=3).map(|n| (n, big.clone())).collect();
        let out = items(&session(), &entries, 1_000);
        assert_eq!(out.len(), 3);
        assert!(out[1].title.ends_with("(part 2 of 3)"));
        assert!(out.iter().all(|i| i.validate().is_ok()));
        assert_eq!(out[2].origin.range, Some((3, 3)));
    }

    #[test]
    fn nothing_said_gives_no_item() {
        let out = items(&session(), &[(1, json!({"type": "ended"}))], 1_000);
        assert!(out.is_empty());
    }
}
