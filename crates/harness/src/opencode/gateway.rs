//! OpenCode on the runner's auth gateway (KAN-435 G6, E7-5): a provider with no harness of its own
//! (a preset such as OpenRouter, or a user definition) runs its sessions on OpenCode, configured
//! inline to reach the gateway on the sandbox's loopback with a placeholder key.

use std::io;

use serde_json::{Value, json};

use crate::Spec;

/// The provider a gateway session's model runs on (KAN-435 G6, E7-5): OpenCode's own provider
/// entry pointed at the runner's auth gateway. A provider of its own, so any model id (OpenRouter's
/// `vendor/model` included) is its model id whole.
pub const GW_PROVIDER: &str = "ainkrad";
/// The wire the gateway speaks upstream, set by the runner beside the slot's port; like every
/// `AINKRAD_SANDBOX_*` variable it never reaches the child.
pub const GW_WIRE_VAR: &str = "AINKRAD_SANDBOX_GW_WIRE";
const GW_PORT_VAR: &str = "AINKRAD_SANDBOX_GW_PORT";

/// The AI SDK package (bundled in OpenCode, nothing is installed) and the base path for `wire`:
/// chat completions for the OpenAI wire (the gateway's `/v1/chat/completions` route), Messages,
/// or Gemini's `generateContent`.
pub fn gateway_sdk(wire: &str) -> Option<(&'static str, &'static str)> {
    match wire {
        "openai-responses" => Some(("@ai-sdk/openai-compatible", "/v1")),
        "anthropic-messages" => Some(("@ai-sdk/anthropic", "/v1")),
        "gemini-generate" => Some(("@ai-sdk/google", "/v1beta")),
        _ => None,
    }
}

/// Whether the spec is a gateway session's (the runner set the slot's port).
fn is_gateway(spec: &Spec) -> bool {
    crate::last_env(&spec.env, GW_PORT_VAR).is_some()
}

/// A gateway session's inline config: one provider at the gateway's loopback URL with the
/// constant placeholder key (the gateway strips it and puts the real key on upstream), the
/// session's model as its only model and as the small model, and no other provider enabled, so
/// nothing (a title, a summary) goes to a model the gateway did not grant. `None` when the spec is
/// not a gateway session's, or its slot is incomplete.
pub fn gateway_config(spec: &Spec) -> Option<serde_json::Map<String, Value>> {
    let port: u16 = crate::last_env(&spec.env, GW_PORT_VAR)?
        .to_str()?
        .parse()
        .ok()
        .filter(|p| *p != 0)?;
    let wire = crate::last_env(&spec.env, GW_WIRE_VAR)?.to_str()?;
    let (npm, path) = gateway_sdk(wire)?;
    let mut options = json!({"baseURL": format!("http://127.0.0.1:{port}{path}"),
                             "apiKey": "placeholder"});
    if npm == "@ai-sdk/openai-compatible" {
        // The usage the gateway meters arrives in the stream's last chunk only when asked for.
        options["includeUsage"] = json!(true);
    }
    let model = format!("{GW_PROVIDER}/{}", spec.model);
    let provider = json!({GW_PROVIDER: {"npm": npm, "name": "Ainkrad gateway", "options": options,
                                        "models": {spec.model.as_str(): {"name": spec.model}}}});
    let Value::Object(map) = json!({"provider": provider, "enabled_providers": [GW_PROVIDER],
                                    "model": model, "small_model": model, "share": "disabled"})
    else {
        unreachable!()
    };
    Some(map)
}

/// `{providerID, modelID}` for the spec: a gateway session's whole model id on [`GW_PROVIDER`],
/// any other's `provider/model`.
pub(super) fn model_of(spec: &Spec) -> io::Result<Value> {
    let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
    if is_gateway(spec) {
        if gateway_config(spec).is_none() || spec.model.is_empty() {
            return Err(invalid(
                "the auth gateway's slot has no wire OpenCode speaks".to_owned(),
            ));
        }
        return Ok(json!({"providerID": GW_PROVIDER, "modelID": spec.model}));
    }
    let (provider, model) = spec.model.split_once('/').ok_or_else(|| {
        invalid(format!(
            "opencode model {:?} is not provider/model",
            spec.model
        ))
    })?;
    Ok(json!({"providerID": provider, "modelID": model}))
}
