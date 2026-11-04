//! What the gateway lets through, per wire (KAN-435 G3, spec 4.5, threat T6): exact method and
//! path, one fixed query. Nothing else is dialled, so an admin path, a file or batch endpoint, a
//! model list or a `..` never reaches the upstream. The upstream target is built from this table,
//! never copied from the request.

use ainkrad_proto::v2::Wire;

use super::request::{Refusal, refuse};

/// A request that passed the table.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Routed {
    /// Path and query to send the upstream, base path included.
    pub target: String,
    /// The model named in the path (the Gemini wire), checked like the body's.
    pub path_model: Option<String>,
}

/// (agent-facing path, path under the upstream's base path, allowed query items)
type Row = (&'static str, &'static str, &'static [&'static str]);

fn rows(wire: Wire) -> &'static [Row] {
    match wire {
        Wire::AnthropicMessages => &[
            ("/v1/messages", "/v1/messages", &["beta=true"]),
            (
                "/v1/messages/count_tokens",
                "/v1/messages/count_tokens",
                &["beta=true"],
            ),
        ],
        // The harness's base URL ends `/v1`; the upstream's base path is where `responses` hangs.
        Wire::OpenaiResponses => &[
            ("/v1/responses", "/responses", &[]),
            ("/v1/chat/completions", "/chat/completions", &[]),
        ],
        Wire::GeminiGenerate => &[],
    }
}

const GEMINI_PREFIX: &str = "/v1beta/models/";

fn model_ok(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(super) fn route(
    wire: Wire,
    base_path: &str,
    method: &str,
    target: &str,
) -> Result<Routed, Refusal> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (suffix, allowed, path_model): (String, &[&str], Option<String>) = match wire {
        Wire::GeminiGenerate => {
            let rest = path.strip_prefix(GEMINI_PREFIX);
            let (model, action) = rest
                .and_then(|r| r.rsplit_once(':'))
                .filter(|(m, a)| {
                    model_ok(m) && matches!(*a, "generateContent" | "streamGenerateContent")
                })
                .ok_or(refuse(403, "path_not_allowed"))?;
            let allowed: &[&str] = if action == "streamGenerateContent" {
                &["alt=sse"]
            } else {
                &[]
            };
            (path.to_owned(), allowed, Some(model.to_owned()))
        }
        _ => {
            let row = rows(wire)
                .iter()
                .find(|r| r.0 == path)
                .ok_or(refuse(403, "path_not_allowed"))?;
            (row.1.to_owned(), row.2, None)
        }
    };
    if method != "POST" {
        return Err(refuse(405, "method_not_allowed"));
    }
    // Query: `key` is auth an agent might add, so it is dropped (the real key goes in a header);
    // every other item must be one this route lists, once.
    let mut kept: Vec<&str> = Vec::new();
    for item in query.split('&').filter(|i| !i.is_empty()) {
        if item.split('=').next() == Some("key") {
            continue;
        }
        match allowed.iter().find(|a| **a == item) {
            Some(a) if !kept.contains(a) => kept.push(a),
            _ => return Err(refuse(403, "query_not_allowed")),
        }
    }
    let mut out = format!("{base_path}{suffix}");
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    Ok(Routed {
        target: out,
        path_model,
    })
}
