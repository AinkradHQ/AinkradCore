//! A turn's tool calls in flight (1.18): each `ToolResult` becomes a `tool_result` transcript
//! event with the call's name and duration and its output cut to size; a pause waits for none
//! to be in flight (1.19).

use std::collections::HashMap;
use std::time::Instant;

use ainkrad_harness::HarnessEvent;
use serde_json::json;

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
    use super::summary;

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
