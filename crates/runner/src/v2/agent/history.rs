//! `history.read` (E5-3): the runner's own harness history as parts of text for the Brain. Off
//! unless the runner was started with `--share-history`; then it lists the `history-read`
//! capability and answers. It reads only the harness's session files under one folder
//! (`~/.claude/projects`), keeps only what the user and the assistant said (no tool calls, tool
//! output or reasoning), redacts it, and never opens or sends a path under a restricted name
//! (keys, certificates, `.env`, contract folders): those are only counted as skipped.
//! ponytail: the claude harness only; each other harness is one more reader with its own format.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{
    ErrorCode, HistoryChunk, HistoryItem, HistoryRead, HistorySkip, MAX_HISTORY_BYTES,
    MAX_HISTORY_PART, StreamError, restricted_path,
};
use serde_json::Value;

use super::AgentDriver;

/// A session file larger than this is skipped, not read into memory.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

impl AgentDriver {
    pub async fn history_read(
        self: &Arc<Self>,
        req: HistoryRead,
    ) -> Result<HistoryChunk, StreamError> {
        let root = match (&self.config.history_root, self.config.history_read) {
            (Some(root), true) => root.clone(),
            _ => {
                return Err(StreamError::new(
                    ErrorCode::UnsupportedCommand,
                    "history sharing is off on this runner (ainkrad-runner connect --share-history)",
                ));
            }
        };
        if req.harness != "claude" {
            return Err(StreamError::new(
                ErrorCode::InvalidArgs,
                "only the claude harness's history is readable yet",
            ));
        }
        tokio::task::spawn_blocking(move || read_claude(&root, &req))
            .await
            .map_err(|_| StreamError::new(ErrorCode::Internal, "the history read did not finish"))
    }
}

/// `User: ...` or `Assistant: ...` and the line's time, for a line that says something.
fn render(line: &Value) -> Option<(String, String)> {
    let who = match line["type"].as_str()? {
        "user" => "User",
        "assistant" => "Assistant",
        _ => return None,
    };
    if line["isMeta"] == Value::Bool(true) {
        return None;
    }
    let content = &line["message"]["content"];
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
    let at = line["timestamp"].as_str()?;
    (!text.is_empty()).then(|| (at.to_owned(), format!("{who}: {text}")))
}

fn cut(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

struct Part {
    first: u64,
    last: u64,
    from: String,
    to: String,
    text: String,
}

/// The new parts of one session file after line `from`, and the folder the session ran in.
fn parts_of(body: &str, from: u64) -> (Vec<Part>, Option<String>, Option<String>) {
    let (mut parts, mut cwd, mut title): (Vec<Part>, Option<String>, Option<String>) =
        (vec![], None, None);
    for (i, raw) in body.lines().enumerate() {
        let n = i as u64 + 1;
        let Ok(line) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        if cwd.is_none() {
            cwd = line["cwd"].as_str().map(str::to_owned);
        }
        if n <= from {
            continue;
        }
        let Some((at, block)) = render(&line) else {
            continue;
        };
        if title.is_none() && block.starts_with("User: ") {
            title = block[6..]
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(|l| l.chars().take(60).collect());
        }
        let block = cut(&block, MAX_HISTORY_PART).to_owned();
        match parts.last_mut() {
            Some(p) if p.text.len() + block.len() < MAX_HISTORY_PART => {
                p.text.push_str("\n\n");
                p.text.push_str(&block);
                p.last = n;
                p.to = at;
            }
            _ => parts.push(Part {
                first: n,
                last: n,
                from: at.clone(),
                to: at,
                text: block,
            }),
        }
    }
    (parts, cwd, title)
}

/// Reads `root` (`~/.claude/projects`): folders of `<session>.jsonl`, oldest names first, so the
/// same cursor always gives the same parts.
pub(super) fn read_claude(root: &Path, req: &HistoryRead) -> HistoryChunk {
    let budget = req.max_bytes.min(MAX_HISTORY_BYTES) as usize;
    let redactor = Redactor::new();
    let mut out = HistoryChunk {
        items: vec![],
        cursor: BTreeMap::new(),
        skipped: vec![],
        more: false,
    };
    let mut skips: BTreeMap<&str, u64> = BTreeMap::new();
    let mut used = 0;
    let sorted = |dir: &Path| {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    };
    'all: for dir in sorted(root) {
        let Some(project) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !dir.is_dir() {
            continue;
        }
        for file in sorted(&dir) {
            let (Some(name), Some("jsonl")) = (
                file.file_name().and_then(|n| n.to_str()),
                file.extension().and_then(|e| e.to_str()),
            ) else {
                continue;
            };
            let session = name.trim_end_matches(".jsonl");
            // A project folder is named for the path it ran in (`-Users-x-contracts-nda`).
            let rel = format!("claude/{}/{name}", project.replace('-', "/"));
            if restricted_path(&rel) {
                *skips.entry("restricted_path").or_default() += 1;
                continue;
            }
            let from = req.cursor.get(session).copied().unwrap_or(0);
            let Some(body) = std::fs::metadata(&file)
                .ok()
                .filter(|m| m.len() <= MAX_FILE_BYTES)
                .and_then(|_| std::fs::read_to_string(&file).ok())
            else {
                *skips.entry("unreadable").or_default() += 1;
                continue;
            };
            let (parts, cwd, title) = parts_of(&body, from);
            // A working folder is a directory: its own name counts, not only its parents'.
            if cwd
                .as_deref()
                .is_some_and(|c| restricted_path(&format!("{c}/_")))
            {
                *skips.entry("restricted_path").or_default() += 1;
                continue;
            }
            let title = title.unwrap_or_else(|| format!("Claude Code session {session}"));
            for p in parts {
                if used + p.text.len() > budget && !out.items.is_empty() {
                    out.more = true;
                    break 'all;
                }
                used += p.text.len();
                let text = redactor.text(&format!(
                    "Claude Code session {session}, entries {}-{}\n\n{}",
                    p.first, p.last, p.text
                ));
                out.cursor.insert(session.to_owned(), p.last);
                out.items.push(HistoryItem {
                    session: session.to_owned(),
                    project: cwd.clone(),
                    path: format!("claude/{project}/{name}"),
                    title: title.clone(),
                    text,
                    started_at: p.from,
                    ended_at: Some(p.to),
                    first: p.first,
                    last: p.last,
                });
            }
        }
    }
    out.skipped = skips
        .into_iter()
        .map(|(reason, count)| HistorySkip {
            reason: reason.to_owned(),
            count,
        })
        .collect();
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::super::AgentConfig;
    use super::*;

    fn line(role: &str, text: &str, n: u32, cwd: &str) -> String {
        json!({"type": role, "cwd": cwd, "timestamp": format!("2026-11-12T08:{n:02}:00.000Z"),
            "message": {"role": role, "content": [{"type": "text", "text": text}]}})
        .to_string()
    }

    fn tool_line() -> String {
        json!({"type": "user", "timestamp": "2026-11-12T08:30:00.000Z", "message": {"role": "user",
            "content": [{"type": "tool_result", "content": "TOOL OUTPUT"}]}})
        .to_string()
    }

    fn put(root: &Path, project: &str, session: &str, lines: &[String]) {
        let dir = root.join(project);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{session}.jsonl")),
            lines.join("\n") + "\n",
        )
        .unwrap();
    }

    fn req(cursor: &[(&str, u64)], max: u32) -> HistoryRead {
        HistoryRead {
            harness: "claude".to_owned(),
            cursor: cursor.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
            max_bytes: max,
        }
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hist-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn it_reads_what_was_said_redacts_and_never_reads_restricted_paths() {
        let root = fixture("read");
        let token = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
        put(
            &root,
            "-Users-x-Projects-Alpha",
            "s1",
            &[
                line(
                    "user",
                    &format!("Fix the build. My token is {token}"),
                    1,
                    "/Users/x/Projects/Alpha",
                ),
                tool_line(),
                line("assistant", "Done.", 2, "/Users/x/Projects/Alpha"),
            ],
        );
        // A project folder named for a contracts path, and a session that ran inside one.
        put(
            &root,
            "-Users-x-contracts-nda",
            "s2",
            &[line("user", "SECRET CONTRACT", 1, "/Users/x/contracts/nda")],
        );
        put(
            &root,
            "-Users-x-Projects-Beta",
            "s3",
            &[line(
                "user",
                "ALSO SECRET",
                1,
                "/Users/x/Projects/Beta/contracts",
            )],
        );
        let got = read_claude(&root, &req(&[], 100_000));
        assert_eq!(got.items.len(), 1);
        let i = &got.items[0];
        assert_eq!((i.session.as_str(), i.first, i.last), ("s1", 1, 3));
        assert_eq!(i.project.as_deref(), Some("/Users/x/Projects/Alpha"));
        assert!(i.text.ends_with("Assistant: Done."), "{}", i.text);
        assert!(
            !i.text.contains(&token) && !i.text.contains("TOOL OUTPUT"),
            "{}",
            i.text
        );
        let all = serde_json::to_string(&got).unwrap();
        assert!(
            !all.contains("SECRET"),
            "no byte of a restricted path is sent"
        );
        assert_eq!(
            got.skipped,
            vec![HistorySkip {
                reason: "restricted_path".to_owned(),
                count: 2
            }]
        );
        assert_eq!(got.cursor["s1"], 3);
        assert!(!got.more);
    }

    #[test]
    fn a_cursor_gives_only_what_is_new_and_a_budget_gives_more() {
        let root = fixture("cursor");
        let mut lines = vec![
            line("user", "first", 1, "/p"),
            line("assistant", "second", 2, "/p"),
        ];
        put(&root, "-p", "s1", &lines);
        let first = read_claude(&root, &req(&[], 100_000));
        assert_eq!(first.cursor["s1"], 2);
        // Nothing new: nothing sent.
        assert!(
            read_claude(&root, &req(&[("s1", 2)], 100_000))
                .items
                .is_empty()
        );
        // A resumed session gives only its new entries.
        lines.push(line("user", "third", 3, "/p"));
        put(&root, "-p", "s1", &lines);
        let next = read_claude(&root, &req(&[("s1", 2)], 100_000));
        assert_eq!(
            (next.items.len(), next.items[0].first, next.items[0].last),
            (1, 3, 3)
        );
        assert!(
            next.items[0].text.contains("User: third") && !next.items[0].text.contains("first")
        );
        // Two sessions and a budget for one: the second waits.
        put(
            &root,
            "-q",
            "s2",
            &[line("user", &"x".repeat(5000), 1, "/q")],
        );
        let capped = read_claude(&root, &req(&[], 5_040));
        assert!(
            capped.more && capped.items.iter().all(|i| i.session == "s1"),
            "{capped:?}"
        );
    }

    #[test]
    fn the_op_is_refused_unless_the_runner_was_switched_on_and_only_for_claude() {
        let mut off = AgentConfig::new(fixture("a").join("a"), fixture("b").join("b"));
        assert!(!off.history_read, "off by default");
        off.history_root = Some(fixture("c"));
        let d = Arc::new(
            AgentDriver::new(off.clone(), crate::executor::FakeExecutor::default()).unwrap(),
        );
        assert!(
            !d.info()
                .commands
                .iter()
                .any(|c| c == ainkrad_proto::v2::CAP_HISTORY_READ)
        );
        let e = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(d.history_read(req(&[], 1000)))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::UnsupportedCommand);
        off.history_read = true;
        let d = Arc::new(AgentDriver::new(off, crate::executor::FakeExecutor::default()).unwrap());
        assert!(
            d.info()
                .commands
                .iter()
                .any(|c| c == ainkrad_proto::v2::CAP_HISTORY_READ)
        );
        let mut other = req(&[], 1000);
        other.harness = "codex".to_owned();
        let e = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(d.history_read(other))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
    }
}
