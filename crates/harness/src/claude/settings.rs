//! The `--settings` flag's value (KAN-435 G6).
//!
//! `--setting-sources local` still reads `<cwd>/.claude/settings.local.json`, which the agent can
//! write, and its `env` and `apiKeyHelper` would override the runner's variables: an agent could
//! point Claude at another endpoint or hand it another key. Settings given by flag outrank the
//! local file, so a gateway session (the runner has set its base URL in the spec) pins both there.
//! `apiKeyHelper` is the placeholder too, so a helper in the local file cannot supply a key.

use serde_json::{Value, json};

use super::ATTRIBUTION_OFF;
use crate::{Spec, last_env};

/// The flag's value: attribution off, and for a gateway session the base URL and key the runner
/// set, as `env` and as the key helper.
pub(super) fn flag(spec: &Spec) -> String {
    let var = |n: &str| last_env(&spec.env, n).and_then(|v| v.to_str());
    let (Some(url), Some(key)) = (var("ANTHROPIC_BASE_URL"), var("ANTHROPIC_API_KEY")) else {
        return ATTRIBUTION_OFF.to_owned();
    };
    // The helper is a shell command: the placeholder is plain, and anything else is not echoed.
    let plain = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric());
    let mut v: Value = serde_json::from_str(ATTRIBUTION_OFF).expect("a constant");
    v["env"] = json!({"ANTHROPIC_BASE_URL": url, "ANTHROPIC_API_KEY": key});
    if plain {
        v["apiKeyHelper"] = format!("echo {key}").into();
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claude::args;

    fn gateway() -> Spec {
        Spec {
            env: vec![
                (
                    "ANTHROPIC_BASE_URL".to_owned(),
                    "http://127.0.0.1:47833".into(),
                ),
                ("ANTHROPIC_API_KEY".to_owned(), "placeholder".into()),
            ],
            ..Spec::default()
        }
    }

    fn settings_of(spec: &Spec) -> Value {
        let argv = args(spec, None);
        let at = argv.iter().position(|a| a == "--settings").unwrap();
        serde_json::from_str(&argv[at + 1]).unwrap()
    }

    #[test]
    fn a_gateway_session_pins_its_url_and_key_in_the_flag_settings() {
        let v = settings_of(&gateway());
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:47833");
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "placeholder");
        assert_eq!(v["apiKeyHelper"], "echo placeholder");
        assert_eq!(v["attribution"]["commit"], "");
        // The flag is not an env var and not a second flag: one `--settings`.
        let argv = args(&gateway(), None);
        assert_eq!(argv.iter().filter(|a| *a == "--settings").count(), 1);
    }

    #[test]
    fn any_other_session_keeps_the_settings_it_had() {
        assert_eq!(flag(&Spec::default()), ATTRIBUTION_OFF);
        // A URL with no key, or the reverse, is not a gateway session.
        let mut half = gateway();
        half.env.pop();
        assert_eq!(flag(&half), ATTRIBUTION_OFF);
    }

    #[test]
    fn a_key_that_is_not_plain_is_pinned_in_env_but_never_made_a_shell_command() {
        let mut spec = gateway();
        spec.env[1].1 = "a b;rm -rf x".into();
        let v = settings_of(&spec);
        assert!(v.get("apiKeyHelper").is_none());
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "a b;rm -rf x");
    }
}
