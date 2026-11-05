//! What the harness is given to talk to the gateway (KAN-435 G6, spec 4.2): a base URL on the
//! session's loopback port and a placeholder in the key's place, per harness.
//!
//! These are written by the runner, after `account_var_problem` has passed and outside the grant
//! list: a grant still may not redirect traffic, and the agent cannot set them. They come last, so
//! they win over anything earlier in the environment, and every other provider variable (a key, a
//! base URL, a cloud switch) is dropped from the session first, so nothing steers the harness
//! around the gateway or hands it a key of its own. The placeholder is a constant: the real key
//! is in the runner's memory only.

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

/// The gateway's loopback port when `env` is a gateway session's (its slot is set), else `None`.
pub fn port_in(env: &[(String, OsString)]) -> Option<u16> {
    let v = ainkrad_harness::last_env(env, SLOT_PORT)?;
    v.to_str()?.parse().ok().filter(|p| *p != 0)
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
/// writes `config.toml` into `config_dir` (its `CODEX_HOME`). An `Err` is a reason fit for the
/// session's failure; it never holds a key.
pub fn wire(
    harness: &str,
    port: u16,
    config_dir: &Path,
    env: &mut Vec<(String, OsString)>,
    allow: &mut Vec<String>,
) -> Result<(), String> {
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
