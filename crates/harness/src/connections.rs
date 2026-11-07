//! The Core's connection tools in a harness's MCP config (C4b): one stdio server,
//! `ainkrad-connections`, which is the runner's own executable run as `mcp-stdio <socket>` inside
//! the sandbox. The socket path is an argument (never a variable), and no credential is in any
//! of this: the shim is a byte pipe to the runner, which asks the Core.
//!
//! Each harness has its own config shape (the same files `mcp_config` of each adapter writes for
//! the Citadel server), so [`add`] merges the entry into the shape of `harness`, or makes the
//! config when a session has no Citadel server.

use serde_json::{Map, Value, json};

use crate::last_env;

/// The server's name as a harness sees it (`mcp__ainkrad-connections__github_get_issue`).
pub const SERVER: &str = "ainkrad-connections";

/// The slot's variables (the runner sets them for a session whose sandbox is given the socket).
pub const SLOT_SOCK: &str = "AINKRAD_SANDBOX_TOOLS_SOCK";
pub const SLOT_FWD: &str = "AINKRAD_SANDBOX_TOOLS_FWD";

/// How long a harness waits for one tool call: above the runner's own 120 s bound on a call, so a
/// call that outlives the wait is ended by the runner (`outcome_unknown` for a write) and not by
/// the harness's own default.
const TOOL_TIMEOUT_SECS: u64 = 130;

/// The socket and shim of a session's slot, when its environment has one.
pub fn slot<V: AsRef<std::ffi::OsStr>>(env: &[(String, V)]) -> Option<(String, String)> {
    let get = |k| {
        last_env(env, k)
            .map(|v| v.as_ref().to_string_lossy().into_owned())
            .filter(|v| !v.is_empty())
    };
    Some((get(SLOT_SOCK)?, get(SLOT_FWD)?))
}

/// `config` (the harness's MCP config, or none) with the connections server added; `None` for a
/// harness this runner has no format for.
pub fn add(harness: &str, config: Option<Value>, exe: &str, sock: &str) -> Option<Value> {
    let mut config = config.unwrap_or_else(|| json!({}));
    let root = config.as_object_mut()?;
    let args = json!(["mcp-stdio", sock]);
    // The table the harness reads its servers from, and the entry's shape in it.
    let (table, entry): (Option<&str>, Value) = match harness {
        "claude" => (
            Some("mcpServers"),
            json!({"type": "stdio", "command": exe, "args": args}),
        ),
        "agy" => (
            Some("mcpServers"),
            json!({"command": exe, "args": args, "disabled": false}),
        ),
        "opencode" => (
            Some("mcp"),
            json!({"type": "local", "command": [exe, "mcp-stdio", sock], "enabled": true}),
        ),
        // Codex's file is the `mcp_servers` table itself (`thread_params` wraps it).
        "codex" => (
            None,
            json!({"command": exe, "args": args, "startup_timeout_sec": 30,
                "tool_timeout_sec": TOOL_TIMEOUT_SECS}),
        ),
        _ => return None,
    };
    let servers = match table {
        None => root,
        Some(t) => root
            .entry(t)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()?,
    };
    servers.insert(SERVER.to_owned(), entry);
    Some(config)
}

/// Whether `tool`, as a harness names it in an approval request, is one of the connection tools
/// (Claude `mcp__ainkrad-connections__<tool>`, OpenCode `<server>_<tool>` with the dashes as
/// underscores or kept). The Core decides each call (user, agent, allowlist); the runner's policy
/// has nothing to add, as for the Citadel server's tools.
pub fn is_tool(tool: &str) -> bool {
    tool.starts_with("mcp__ainkrad-connections__")
        || tool.starts_with("ainkrad-connections_")
        || tool.starts_with("ainkrad_connections_")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "/opt/ainkrad/ainkrad-runner";
    const SOCK: &str = "/state/agents/as_x/tools.sock";

    #[test]
    fn claude_gets_a_stdio_server_beside_citadel() {
        let base = crate::claude::mcp_config("http://127.0.0.1:1/x", "tok");
        let got = add("claude", Some(base), EXE, SOCK).unwrap();
        assert_eq!(
            got["mcpServers"][SERVER],
            json!({"type": "stdio", "command": EXE, "args": ["mcp-stdio", SOCK]})
        );
        assert_eq!(got["mcpServers"]["citadel"]["type"], "http", "citadel kept");
        // No Citadel server: the config is just ours.
        assert_eq!(
            add("claude", None, EXE, SOCK).unwrap(),
            json!({"mcpServers": {SERVER: {"type": "stdio", "command": EXE,
                "args": ["mcp-stdio", SOCK]}}})
        );
    }

    #[test]
    fn codex_gets_its_mcp_servers_table_with_a_timeout_above_the_runners() {
        let base = crate::codex::mcp_config("http://127.0.0.1:1/x", "tok");
        let got = add("codex", Some(base), EXE, SOCK).unwrap();
        assert_eq!(
            got[SERVER],
            json!({"command": EXE, "args": ["mcp-stdio", SOCK], "startup_timeout_sec": 30,
                "tool_timeout_sec": 130})
        );
        assert!(got["citadel"]["url"].is_string());
        assert_eq!(
            add("codex", None, EXE, SOCK)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn agy_and_opencode_get_their_own_shapes() {
        let agy = add("agy", None, EXE, SOCK).unwrap();
        assert_eq!(
            agy,
            json!({"mcpServers": {SERVER: {"command": EXE, "args": ["mcp-stdio", SOCK],
                "disabled": false}}})
        );
        let base = crate::opencode::mcp_config("http://127.0.0.1:1/x", "tok");
        let oc = add("opencode", Some(base), EXE, SOCK).unwrap();
        assert_eq!(
            oc["mcp"][SERVER],
            json!({"type": "local", "command": [EXE, "mcp-stdio", SOCK], "enabled": true})
        );
        assert_eq!(oc["mcp"]["citadel"]["type"], "remote");
        assert!(add("pi", None, EXE, SOCK).is_none());
    }

    #[test]
    fn nothing_but_paths_is_in_the_entry() {
        for h in ["claude", "codex", "agy", "opencode"] {
            let text = add(h, None, EXE, SOCK).unwrap().to_string();
            for bad in ["Bearer", "Authorization", "token", "key"] {
                assert!(!text.contains(bad), "{h}: {bad}");
            }
        }
    }

    #[test]
    fn the_slot_needs_both_variables() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert_eq!(
            slot(&env(&[(SLOT_SOCK, "/s"), (SLOT_FWD, "/f")])),
            Some(("/s".to_owned(), "/f".to_owned()))
        );
        assert_eq!(slot(&env(&[(SLOT_SOCK, "/s")])), None);
        assert_eq!(slot(&env(&[(SLOT_SOCK, ""), (SLOT_FWD, "/f")])), None);
    }

    #[test]
    fn only_this_servers_tools_are_recognised() {
        assert!(is_tool("mcp__ainkrad-connections__github_get_issue"));
        assert!(is_tool("ainkrad-connections_github_get_issue"));
        assert!(!is_tool("mcp__citadel__x"));
        assert!(!is_tool("mcp__ainkrad-connectionsX__x"));
        assert!(!is_tool("Bash"));
    }

    #[test]
    fn claude_allows_the_server_only_with_a_slot() {
        let mut spec = crate::Spec::default();
        let allowed = |spec: &crate::Spec| {
            let a = crate::claude::args(spec, None);
            let at = a.iter().position(|x| x == "--allowedTools").unwrap();
            a[at + 1].clone()
        };
        assert_eq!(allowed(&spec), "mcp__citadel");
        spec.env = vec![
            (SLOT_SOCK.into(), "/s".into()),
            (SLOT_FWD.into(), "/f".into()),
        ];
        assert_eq!(allowed(&spec), "mcp__citadel,mcp__ainkrad-connections");
    }
}
