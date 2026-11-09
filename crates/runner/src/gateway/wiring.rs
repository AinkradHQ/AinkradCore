//! What the harness is given to talk to the gateway (KAN-435 G6, spec 4.2): a base URL on the
//! session's loopback port and a placeholder in the key's place, per harness.
//!
//! These are written by the runner, after `account_var_problem` has passed and outside the grant
//! list: a grant still may not redirect traffic, and the agent cannot set them through a grant.
//! They come last, so they win over anything earlier in the environment, and every other provider
//! variable (a key, a base URL, a cloud switch) is dropped from the session first.
//!
//! What this does not do is stop the agent from changing its own harness's configuration: it
//! can write files the harness reads (Claude's `.claude/settings.local.json` in the workspace,
//! Codex's `config.toml` in its home, which is writable). Claude's `--settings` flag outranks the
//! local settings, so the adapter pins the base URL and key there; Codex has no such flag, and
//! the file is rewritten at each start but not locked. The containment is that there is nothing to
//! steal and nowhere to go: the only credential in the sandbox is the constant placeholder, the
//! real key is in the runner's memory, and a session with no network (or only the filtered proxy)
//! reaches no host of the agent's choosing. A harness pointed elsewhere gets no model, nothing more.
//!
//! A session is a gateway session when its sandbox slot is set ([`gateway_port`]); wiring needs it
//! to be sandboxed too ([`wire`]), so Codex's `config.toml` can never land in the runner-wide home.

use std::ffi::OsString;
use std::path::Path;

/// What stands in for the key. The gateway strips whatever auth the agent sends.
pub const PLACEHOLDER: &str = "placeholder";

/// The sandbox slot's port variable (`AINKRAD_SANDBOX_GW_PORT`): present only for a gateway session.
const SLOT_PORT: &str = "AINKRAD_SANDBOX_GW_PORT";

/// Variable name prefixes that carry a provider's key, endpoint or account switch for some
/// harness. A gateway session keeps none of them but the ones set here.
const PROVIDER_PREFIXES: [&str; 6] = [
    "ANTHROPIC_",
    "CLAUDE_CODE_",
    "OPENAI_",
    "CODEX_",
    "GEMINI_",
    "GOOGLE_",
];

fn provider_var(name: &str) -> bool {
    PROVIDER_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The slot's variables (`AINKRAD_SANDBOX_GW_{SOCK,FWD,PORT}`): any of them marks a gateway session.
const SLOT: [&str; 3] = [
    "AINKRAD_SANDBOX_GW_SOCK",
    "AINKRAD_SANDBOX_GW_FWD",
    SLOT_PORT,
];

/// The gateway's loopback port when `env` is a gateway session's (any of its slot is set); `None`
/// for any other session. A slot with no valid port is an error, never a session run unwired.
pub fn gateway_port(env: &[(String, OsString)]) -> Result<Option<u16>, String> {
    if !SLOT
        .iter()
        .any(|n| ainkrad_harness::last_env(env, n).is_some())
    {
        return Ok(None);
    }
    ainkrad_harness::last_env(env, SLOT_PORT)
        .and_then(|v| v.to_str()?.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .map(Some)
        .ok_or_else(|| "the auth gateway's slot has no valid port".to_owned())
}

/// The variables `harness` is given: its base URL and a placeholder key. `None` is a harness with
/// no gateway wiring (OpenCode has no account binding yet).
fn vars(harness: &str, port: u16) -> Option<Vec<(&'static str, String)>> {
    let url = format!("http://127.0.0.1:{port}");
    Some(match harness {
        "claude" => vec![
            ("ANTHROPIC_BASE_URL", url),
            ("ANTHROPIC_API_KEY", PLACEHOLDER.to_owned()),
        ],
        // agy's `modelProvider: "gemini"` setting is written by the agy adapter, which sees this
        // base URL in its spec.
        "agy" => vec![
            ("GOOGLE_GEMINI_BASE_URL", url),
            ("GEMINI_API_KEY", PLACEHOLDER.to_owned()),
        ],
        // The URL is in `config.toml`: Codex ignores `OPENAI_BASE_URL`.
        "codex" => vec![("OPENAI_API_KEY", PLACEHOLDER.to_owned())],
        _ => return None,
    })
}

/// Wires a gateway session's `harness`: drops every other provider variable from `env` and from
/// the runner variables the child may inherit (`allow`), adds the harness's own, and for Codex
/// writes `config.toml` into `config_dir` (its `CODEX_HOME`). Refused unless the session is
/// sandboxed (`AINKRAD_SANDBOX` set), which is also what gives it a home of its own. An `Err` is a
/// reason fit for the session's failure; it never holds a key.
pub fn wire(
    harness: &str,
    port: u16,
    config_dir: &Path,
    env: &mut Vec<(String, OsString)>,
    allow: &mut Vec<String>,
) -> Result<(), String> {
    if ainkrad_harness::last_env(env, "AINKRAD_SANDBOX").is_none() {
        return Err("a gateway session must run in the sandbox".to_owned());
    }
    let own = vars(harness, port)
        .ok_or_else(|| format!("the auth gateway has no wiring for harness {harness:?}"))?;
    env.retain(|(n, _)| !provider_var(n));
    allow.retain(|n| !provider_var(n));
    env.extend(own.into_iter().map(|(n, v)| (n.to_owned(), v.into())));
    if harness == "codex" {
        crate::codex_config::write(config_dir, &crate::codex_config::gateway(port))
            .map_err(|e| format!("the codex config for the gateway: {e}"))?;
    }
    Ok(())
}
