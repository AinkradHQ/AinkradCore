//! A turn's tool calls in flight (1.18): each `ToolResult` becomes a `tool_result` transcript
//! event with the call's name and duration and its output cut to size; a pause waits for none
//! to be in flight (1.19).

use std::collections::HashMap;
use std::time::Instant;

use ainkrad_harness::HarnessEvent;
use serde_json::{Value, json};

/// The most text (every change's `old` and `new`) a file edit's `edit` carries; past it the
/// texts are cut and `truncated` is set.
pub(super) const MAX_EDIT_BYTES: usize = 64 * 1024;
/// A cut edit's `input` keeps only its fields up to this size (its path, not its texts).
const MAX_INPUT_FIELD: usize = 1024;

/// An event as its transcript event. A file edit's `tool_use` (Claude's Edit, MultiEdit, Write and
/// NotebookEdit, Codex's fileChange, OpenCode's edit, multiedit and write) also carries
/// `edit: {changes: [{path, old, new}], truncated}`: the text each change took out and put in,
/// whatever the harness's own shape. A new file's `old` is empty.
pub(super) fn event(event: &HarnessEvent) -> Value {
    let mut v = serde_json::to_value(event).expect("events serialise");
    if let HarnessEvent::Thinking { text } = event {
        v["text"] = cut_thinking(text).into();
        return v;
    }
    if let HarnessEvent::ToolUse { name, input, .. } = event
        && let Some(changes) = changes(name, input)
    {
        let (changes, truncated) = capped(changes, MAX_EDIT_BYTES);
        // The input holds the same texts: cut, it would carry them whole.
        if truncated && let Some(o) = v["input"].as_object_mut() {
            o.retain(|_, x| x.to_string().len() <= MAX_INPUT_FIELD);
        }
        let changes: Vec<Value> = changes
            .into_iter()
            .map(|(path, old, new)| json!({"path": path, "old": old, "new": new}))
            .collect();
        v["edit"] = json!({"changes": changes, "truncated": truncated});
    }
    v
}

/// Reasoning cut to `MAX_THINKING_BYTES` at a char boundary, marked when cut.
pub(super) fn cut_thinking(text: &str) -> String {
    let max = ainkrad_proto::v2::MAX_THINKING_BYTES;
    if text.len() <= max {
        return text.to_owned();
    }
    let at = text.floor_char_boundary(max - 6);
    format!("{}\n[cut]", &text[..at])
}

/// `(path, old, new)` of each change a file edit makes; `None` for any other tool.
fn changes(name: &str, input: &Value) -> Option<Vec<(String, String, String)>> {
    let s = |v: &Value, keys: &[&str]| {
        keys.iter()
            .find_map(|k| v[*k].as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let path = ["file_path", "filePath", "notebook_path", "path"]
        .iter()
        .find_map(|k| input[*k].as_str())
        .map(str::to_owned);
    let pair = |e: &Value| {
        (
            s(e, &["old_string", "oldString"]),
            s(e, &["new_string", "newString"]),
        )
    };
    let list = |k: &str| input[k].as_array().cloned().unwrap_or_default();
    let changes: Vec<(String, String, String)> = match name.to_lowercase().as_str() {
        "edit" => {
            let (old, new) = pair(input);
            vec![(path?, old, new)]
        }
        "multiedit" => {
            let path = path?;
            list("edits")
                .iter()
                .map(pair)
                .map(|(old, new)| (path.clone(), old, new))
                .collect()
        }
        "write" => vec![(path?, String::new(), s(input, &["content"]))],
        "notebookedit" => vec![(path?, String::new(), s(input, &["new_source"]))],
        // Codex: an added file's `diff` is its text, a deleted one's what it held, an updated
        // one's a unified diff.
        "filechange" => list("changes")
            .iter()
            .filter_map(|c| {
                let diff = s(c, &["diff"]);
                let (old, new) = match c["kind"]["type"].as_str() {
                    Some("add") => (String::new(), diff),
                    Some("delete") => (diff, String::new()),
                    _ => split(&diff),
                };
                Some((c["path"].as_str()?.to_owned(), old, new))
            })
            .collect(),
        _ => return None,
    };
    (!changes.is_empty()).then_some(changes)
}

/// A unified diff's lines as the text before and after. ponytail: hunks are joined with no marker
/// between them; a hunk's line numbers are dropped.
fn split(diff: &str) -> (String, String) {
    let body = diff.find("@@").map_or(diff, |i| &diff[i..]);
    let (mut old, mut new) = (Vec::new(), Vec::new());
    for line in body.lines() {
        match line.split_at_checked(1).unwrap_or((line, "")) {
            ("@" | "\\", _) => {}
            ("-", rest) => old.push(rest),
            ("+", rest) => new.push(rest),
            (" ", rest) => {
                old.push(rest);
                new.push(rest);
            }
            _ => {
                old.push(line);
                new.push(line);
            }
        }
    }
    (old.join("\n"), new.join("\n"))
}

/// `changes` with their texts cut to `max` bytes in all, each cut at a line end where there is
/// one; and whether any was cut.
fn capped(
    changes: Vec<(String, String, String)>,
    max: usize,
) -> (Vec<(String, String, String)>, bool) {
    let mut left = max;
    let mut truncated = false;
    let mut cut = |t: String| {
        if t.len() <= left {
            left -= t.len();
            return t;
        }
        truncated = true;
        let at = t.floor_char_boundary(left);
        let at = t[..at].rfind('\n').map_or(at, |i| i + 1);
        left = 0;
        t[..at].to_owned()
    };
    let changes = changes
        .into_iter()
        .map(|(path, old, new)| {
            let old = cut(old);
            (path, old, cut(new))
        })
        .collect();
    (changes, truncated)
}

/// The tool calls of one harness process still running, for their results' names and durations.
#[derive(Default)]
pub(super) struct Tools(pub HashMap<String, (String, Instant)>);

impl Tools {
    pub fn started(&mut self, event: &HarnessEvent) {
        if let HarnessEvent::ToolUse { id, name, .. } = event {
            self.0.insert(id.clone(), (name.clone(), Instant::now()));
        }
    }

    /// A `ToolResult` as its transcript event (1.18): `status` `ok` or `error`, the exit code
    /// when known, the output cut to `max` bytes (`summary`) with its full size, and how long
    /// the call took since its `ToolUse`. The run's task redacts it like every chunk.
    pub fn result(&mut self, event: &HarnessEvent, max: usize) -> serde_json::Value {
        let HarnessEvent::ToolResult {
            id,
            ok,
            exit_code,
            output,
        } = event
        else {
            unreachable!("only tool results are summarised");
        };
        let (name, at) = self.0.remove(id).unzip();
        json!({"type": "tool_result", "id": id, "name": name,
            "status": if *ok { "ok" } else { "error" }, "exit_code": exit_code,
            "output": summary(output, max), "output_bytes": output.len(),
            "duration_ms": at.map(|at| at.elapsed().as_millis() as u64)})
    }
}

/// `output` cut to at most about `max` bytes: its head and its tail (where a failure's summary
/// usually is), with how much was left out between them. Each cut falls on whitespace when
/// there is some, so a secret (one word) is kept whole for the redactor or dropped whole.
fn summary(output: &str, max: usize) -> String {
    if output.len() <= max {
        return output.to_owned();
    }
    let at = output.floor_char_boundary(max / 2);
    let head = &output[..output[..at].rfind(char::is_whitespace).unwrap_or(at)];
    let from = output.ceil_char_boundary(output.len() - max / 2);
    let tail = &output[output[from..]
        .find(char::is_whitespace)
        .map_or(from, |i| from + i)..];
    let cut = output.len() - head.len() - tail.len();
    format!("{head}\n… {cut} bytes cut …\n{tail}")
}

#[cfg(test)]
mod tests {
    use super::{MAX_EDIT_BYTES, event, summary};
    use ainkrad_harness::HarnessEvent;
    use serde_json::{Value, json};

    fn edit(name: &str, input: Value) -> Value {
        let id = "t1".to_owned();
        let name = name.to_owned();
        event(&HarnessEvent::ToolUse { id, name, input })["edit"].clone()
    }

    #[test]
    fn reasoning_is_its_own_entry_cut_to_16_kib() {
        let say = |t: String| event(&HarnessEvent::Thinking { text: t });
        assert_eq!(say("hm".into()), json!({"type": "thinking", "text": "hm"}));
        let long = say("é".repeat(20_000));
        let text = long["text"].as_str().unwrap();
        assert!(text.len() <= 16 * 1024 && text.ends_with("[cut]"));
    }

    #[test]
    fn a_file_edit_carries_its_old_and_new_text() {
        let one = |path: &str, old: &str, new: &str| json!({"changes": [{"path": path, "old": old, "new": new}], "truncated": false});
        let input = json!({"file_path": "/w/a.rs", "old_string": "a\nb", "new_string": "a\nc"});
        assert_eq!(edit("Edit", input), one("/w/a.rs", "a\nb", "a\nc"));
        let input = json!({"file_path": "/w/n.rs", "content": "fn main() {}"});
        assert_eq!(edit("Write", input), one("/w/n.rs", "", "fn main() {}"));
        let input = json!({"file_path": "/w/a.rs", "edits": [
            {"old_string": "x", "new_string": "y"}, {"old_string": "p", "new_string": "q"}]});
        assert_eq!(
            edit("MultiEdit", input)["changes"][1],
            json!({"path": "/w/a.rs", "old": "p", "new": "q"})
        );
        // OpenCode's own names and keys.
        let input = json!({"filePath": "/w/a.rs", "oldString": "1", "newString": "2"});
        assert_eq!(edit("edit", input), one("/w/a.rs", "1", "2"));
        // Codex: an update is a unified diff, an added file its text.
        let input = json!({"type": "fileChange", "changes": [
            {"path": "/w/a.rs", "kind": {"type": "update"}, "diff": "@@ -1,2 +1,2 @@\n keep\n-old\n+new\n"},
            {"path": "/w/h.txt", "kind": {"type": "add"}, "diff": "hi\n"}]});
        let e = edit("fileChange", input);
        assert_eq!(
            e["changes"][0],
            json!({"path": "/w/a.rs", "old": "keep\nold", "new": "keep\nnew"})
        );
        assert_eq!(
            e["changes"][1],
            json!({"path": "/w/h.txt", "old": "", "new": "hi\n"})
        );
        // Any other tool has none.
        assert_eq!(edit("Bash", json!({"command": "ls"})), Value::Null);
        // The input itself is left as the harness sent it.
        let input = json!({"file_path": "/w/n.rs", "content": "x"});
        let v = event(&HarnessEvent::ToolUse {
            id: "t".into(),
            name: "Write".into(),
            input: input.clone(),
        });
        assert_eq!(v["input"], input);
    }

    #[test]
    fn a_huge_write_is_cut_and_says_so() {
        let line = "0123456789abcdef\n";
        let content = line.repeat(MAX_EDIT_BYTES / line.len() * 4);
        let input = json!({"file_path": "/w/big.txt", "content": content});
        let v = event(&HarnessEvent::ToolUse {
            id: "t".into(),
            name: "Write".into(),
            input,
        });
        let new = v["edit"]["changes"][0]["new"].as_str().unwrap();
        assert_eq!(v["edit"]["truncated"], true);
        assert!(new.len() <= MAX_EDIT_BYTES && new.ends_with('\n') && new.starts_with(line));
        // The input no longer carries the whole text, only its path.
        assert_eq!(v["input"], json!({"file_path": "/w/big.txt"}));
        assert!(v.to_string().len() < 2 * MAX_EDIT_BYTES);
    }

    #[test]
    fn a_long_output_keeps_its_head_and_tail() {
        assert_eq!(summary("short", 16), "short");
        let long = format!("{}{}", "a".repeat(100), "z".repeat(100));
        let cut = summary(&long, 20);
        assert_eq!(cut, "aaaaaaaaaa\n… 180 bytes cut …\nzzzzzzzzzz");
        // A word on a cut is kept out whole, never half shown.
        let secret = format!("ok {} done", "s".repeat(40));
        assert_eq!(summary(&secret, 20), "ok\n… 41 bytes cut …\n done");
        // Never splits a character.
        assert_eq!(summary(&"é".repeat(50), 7), "é\n… 96 bytes cut …\né");
    }
}
