//! The provider presets as data (E7-3, D-19): the providers a person picks and pastes a key for.
//! Their definitions are `providers::presets`.

/// A preset's row (D-19, E7-3): what the app lists so a person picks a provider and pastes a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub base_url: &'static str,
    /// The authenticated path of the one-shot account test (see [`Definition::test_path`]).
    pub test_path: Option<&'static str>,
    /// The vendor's page where a person creates a key.
    pub key_url: &'static str,
    /// How the vendor's keys start, as a hint for the paste field only: never a binding (a preset
    /// key is bound to its account and frozen host).
    pub key_hint: Option<&'static str>,
    /// The model an AI-order entry on this preset runs when it names none: OpenCode has no model
    /// the gateway would grant by itself. The vendor's id as it was documented on 2026-11-25.
    pub default_model: Option<&'static str>,
}

const fn preset(
    id: &'static str,
    name: &'static str,
    base_url: &'static str,
    test_path: Option<&'static str>,
    key_url: &'static str,
    key_hint: Option<&'static str>,
    default_model: Option<&'static str>,
) -> Preset {
    Preset {
        id,
        name,
        base_url,
        test_path,
        key_url,
        key_hint,
        default_model,
    }
}

/// The presets (D-19): OpenAI-wire providers, delivered through the gateway, signed in by a pasted
/// key, run on OpenCode ([`session_harness`]). The URLs and model-list paths were read from each
/// vendor's public docs on 2026-11-19 (Together, Fireworks, Vercel AI Gateway on 2026-11-25). A
/// model list that is public (OpenRouter's) gets an authenticated path so a revoked key does not
/// read as `ok`; the rest list models with the key, or (AIMLAPI, APInex: undocumented; Vercel's
/// list is public) declare none and answer `inconclusive` on success.
pub const PRESETS: [Preset; 10] = [
    preset(
        "openrouter",
        "OpenRouter",
        "https://openrouter.ai/api/v1",
        Some("/key"),
        "https://openrouter.ai/settings/keys",
        Some("sk-or-v1-"),
        Some("openai/gpt-4o-mini"),
    ),
    preset(
        "aimlapi",
        "AIMLAPI",
        "https://api.aimlapi.com/v1",
        None,
        "https://aimlapi.com/app/keys",
        None,
        Some("gpt-4o-mini"),
    ),
    preset(
        "groq",
        "Groq",
        "https://api.groq.com/openai/v1",
        Some("/models"),
        "https://console.groq.com/keys",
        Some("gsk_"),
        Some("llama-3.3-70b-versatile"),
    ),
    preset(
        "deepseek",
        "DeepSeek",
        "https://api.deepseek.com",
        Some("/models"),
        "https://platform.deepseek.com/api_keys",
        Some("sk-"),
        Some("deepseek-chat"),
    ),
    preset(
        "mistral",
        "Mistral",
        "https://api.mistral.ai/v1",
        Some("/models"),
        "https://console.mistral.ai/api-keys",
        None,
        Some("open-mistral-nemo"),
    ),
    preset(
        "xai",
        "xAI",
        "https://api.x.ai/v1",
        Some("/models"),
        "https://console.x.ai",
        Some("xai-"),
        Some("grok-3-mini"),
    ),
    // OpenAI-compatible (chat completions, `/v1/responses`, Bearer), base URL read from its own
    // site's bundle: https://apinex.bond serves the docs, https://api.apinex.bond/v1 the API.
    preset(
        "apinex",
        "APInex",
        "https://api.apinex.bond/v1",
        None,
        "https://apinex.bond",
        None,
        None,
    ),
    preset(
        "together",
        "Together AI",
        "https://api.together.xyz/v1",
        Some("/models"),
        "https://api.together.xyz/settings/api-keys",
        None,
        Some("meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    ),
    preset(
        "fireworks",
        "Fireworks AI",
        "https://api.fireworks.ai/inference/v1",
        Some("/models"),
        "https://fireworks.ai/account/api-keys",
        None,
        Some("accounts/fireworks/models/llama-v3p3-70b-instruct"),
    ),
    preset(
        "vercel",
        "Vercel AI Gateway",
        "https://ai-gateway.vercel.sh/v1",
        None,
        "https://vercel.com/docs/ai-gateway/authentication",
        Some("vck_"),
        Some("openai/gpt-4o-mini"),
    ),
];

/// The preset `id`, if it is one.
pub fn preset_of(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}
