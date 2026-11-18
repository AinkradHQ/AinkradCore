//! The Brain's Claude Code hooks, given through the `--settings` flag (B8-03).
//!
//! SECURITY MODEL (read before changing anything here)
//! 1. The hook command is the runner's own executable run as `hook <kind> <socket>` inside the
//!    sandbox, like the `mcp-stdio` shim. The socket path is an argument; no credential, token or
//!    variable is in the command, the settings or the shim's environment. The session IS the socket
//!    (see `tools/sock.rs`): the Core decides what the hook may read for that session alone, and
//!    `brainAiContext` / `brainAiCheckpoint` are the existing allow-listed ops.
//! 2. `"disableAllHooks": false` is pinned. `--setting-sources local` still reads the workspace's
//!    `.claude/settings.local.json`, which the agent can write; flag settings outrank it, so it cannot
//!    switch our hooks off. Hook entries merge across sources, so a workspace file cannot replace
//!    or remove ours either (it can only add its own, as the agent could already run commands).
//! 3. Fail open: the shim always exits 0 and prints one JSON object or nothing, so a Core error,
//!    timeout or missing socket never blocks the user's prompt. Its own deadline is 1.5 s; the `timeout`
//!    here (whole seconds, Claude's unit) is only a backstop above it.
//! 4. The bundle reaches the model as `additionalContext` (a system reminder beside the prompt),
//!    never as user text, and keeps the outside-data envelope `brainAiContext` wrapped it in. The
//!    shim adds and strips nothing, and never logs or stores the prompt (it is only a lookup key).
//! 5. Only Claude gets hooks in 0.9 (B8-01 spike); codex and agy use the Core-side checkpoint.

use serde_json::{Value, json};

use crate::Spec;
use crate::connections::slot;

/// Claude's own kill time for a hook, in whole seconds: above the shim's 1.5 s deadline.
const BACKSTOP_SECS: u64 = 2;

/// `s` single-quoted for `sh`.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn entry(exe: &str, kind: &str, sock: &str) -> Value {
    json!([{"hooks": [{"type": "command", "timeout": BACKSTOP_SECS,
        "command": format!("{} hook {kind} {}", quoted(exe), quoted(sock))}]}])
}

/// Adds the pin and the three hooks to the flag settings `v` of a session that has the tools slot
/// (a session without the socket has nothing to ask, so it gets none).
pub(super) fn add(v: &mut Value, spec: &Spec) {
    let Some((sock, exe)) = slot(&spec.env) else {
        return;
    };
    v["disableAllHooks"] = false.into();
    v["hooks"] = json!({
        "UserPromptSubmit": entry(&exe, "prompt", &sock),
        "PreCompact": entry(&exe, "checkpoint", &sock),
        "SessionEnd": entry(&exe, "checkpoint", &sock),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude::args;
    use crate::connections::{SLOT_FWD, SLOT_SOCK};

    fn with_slot() -> Spec {
        Spec {
            env: vec![
                (SLOT_SOCK.into(), "/state/as_x/tools.sock".into()),
                (SLOT_FWD.into(), "/opt/ainkrad/ainkrad-runner".into()),
            ],
            ..Spec::default()
        }
    }

    fn flag_of(spec: &Spec) -> Value {
        let argv = args(spec, None);
        let at = argv.iter().position(|a| a == "--settings").unwrap();
        serde_json::from_str(&argv[at + 1]).unwrap()
    }

    #[test]
    fn the_flag_pins_hooks_on_and_has_all_three() {
        let v = flag_of(&with_slot());
        assert_eq!(v["disableAllHooks"], false);
        for (event, kind) in [
            ("UserPromptSubmit", "prompt"),
            ("PreCompact", "checkpoint"),
            ("SessionEnd", "checkpoint"),
        ] {
            let h = &v["hooks"][event][0]["hooks"][0];
            assert_eq!(h["type"], "command", "{event}");
            assert_eq!(
                h["command"],
                format!("'/opt/ainkrad/ainkrad-runner' hook {kind} '/state/as_x/tools.sock'")
            );
            assert!(h["timeout"].as_u64().unwrap() >= 2, "{event}: above 1.5 s");
        }
        assert_eq!(v["attribution"]["commit"], "", "other settings are kept");
    }

    #[test]
    fn no_credential_is_in_the_hooks() {
        let text = flag_of(&with_slot())["hooks"].to_string();
        for bad in ["Bearer", "Authorization", "token", "key", "env"] {
            assert!(!text.contains(bad), "{bad}");
        }
    }

    #[test]
    fn a_session_without_the_slot_has_no_hooks_and_no_pin() {
        let v = flag_of(&Spec::default());
        assert!(v.get("hooks").is_none() && v.get("disableAllHooks").is_none());
    }

    #[test]
    fn a_path_with_a_quote_stays_one_shell_word() {
        assert_eq!(quoted("/a b/it's"), r"'/a b/it'\''s'");
    }
}
