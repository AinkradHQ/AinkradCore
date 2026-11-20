//! `gemini-decision-1`, the Gemini Decisions API (§2.2). The whole wire format lives here: the
//! request the Core builds, the response it reads, nothing else knows either.
//!
//! Verified 2026-11-20 against the official reference (aistudio.google.com/docs/decisions-api) and
//! the launch notes (blog.google, 2026-11-11):
//!
//! - `POST https://generativelanguage.googleapis.com/v1beta/decisions`, key in `x-goog-api-key`
//!   (the runner's gateway sets it; this file never sees a key).
//! - Body: `model`, `input` (a string, or content blocks) and `questions`, a map of 1 to 1000 keys
//!   (`[A-Za-z0-9_-]{1,64}`) to `{type, instructions, criteria}`. A `choice` question's `criteria`
//!   maps each option key (1 to 128 characters, at most 512 bytes; 2 to 255 options) to a
//!   description, which may be empty.
//! - Response: `answers` has one entry per key; a `choice` answer carries `choice`,
//!   `probabilities` (they sum to 1) and `confidence`. `usage` has `total_input_tokens`,
//!   `input_tokens_by_modality`, `total_output_tokens` (always 0) and `total_tokens`. Only input
//!   tokens are billed, so the cost is tokens times the `decisions.input_price_micros_per_mtok`
//!   setting: the API reports no price.
//! - A limit or safety refusal is HTTP 400; a spend limit is 429. Overload codes are not
//!   documented, so the runner's classes (`rate_limited`, `server_error`) are the retryable ones.
//!
//! Not pinned by the reference (so read both ways): whether a `choice` answer's `probabilities` is
//! a map by option key or an array in `criteria` order. The adapter reads a map by key; an array
//! is read in the order the options were sent (sorted by key, as `serde_json` writes a map).
//!
//! # How a consumer reaches this
//!
//! A consumer never builds a request. It asks the service ([`super::Decide`]) with options and
//! questions; the provider call that results has these conventions in `ProviderCall::context`:
//! `task` is the shared instruction (what is being decided), and `option:<id>` describes option
//! `<id>`. Every other context entry becomes a `key: value` line of the shared `input`. A
//! question's `text` and `facts` become that question's `instructions`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{GatewayCalled, UpstreamStatus};
use futures_util::future::{BoxFuture, FutureExt};
use serde_json::{Value, json};

use super::provider::{Metered, MeteredProvider, Transport, Usage};
use super::{DecisionProvider, ProviderCall, ProviderError};

/// The provider's id in the registry and in `Source::Model`.
pub const ID: &str = "gemini-decision-1";
/// The model named in the request body (and in the ledger).
pub const MODEL: &str = "gemini-decision-1";
/// The request path under the account's base URL.
pub const PATH: &str = "/v1beta/decisions";
/// An option key is 1 to 128 characters and at most 512 UTF-8 bytes (the API's limit). Question
/// keys are `q0`, `q1`, ..., well inside its `[A-Za-z0-9_-]{1,64}`.
const OPTION_BYTES: usize = 512;
const OPTION_CHARS: usize = 128;
/// What the model is told when the consumer gives no `task`.
const DEFAULT_TASK: &str = "For each question, choose the option that fits best.";
/// Pause before the one retry of an overloaded call, at most (the upstream's own ask, capped).
const RETRY_PAUSE_MAX: Duration = Duration::from_secs(2);

/// `gemini-decision-1` behind a [`Transport`] (the Core's gateway call to the built-in runner).
pub struct Gemini {
    transport: Arc<dyn Transport>,
}

impl Gemini {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self { transport }
    }
}

/// The request body for `call`: `q<i>` is `call.questions[i]`.
pub fn request_body(call: &ProviderCall) -> Result<String, ProviderError> {
    for o in &call.options {
        if o.is_empty() || o.chars().count() > OPTION_CHARS || o.len() > OPTION_BYTES {
            return Err(ProviderError::Failed(
                "an option id is not 1 to 128 characters".to_owned(),
            ));
        }
    }
    let task = call
        .context
        .get("task")
        .map_or(DEFAULT_TASK, String::as_str);
    let mut input = task.to_owned();
    for (k, v) in &call.context {
        if k != "task" && !k.starts_with("option:") {
            input.push_str(&format!("\n{k}: {v}"));
        }
    }
    let criteria: BTreeMap<&str, &str> = call
        .options
        .iter()
        .map(|o| {
            let said = call.context.get(&format!("option:{o}"));
            (o.as_str(), said.map_or("", String::as_str))
        })
        .collect();
    let mut questions = serde_json::Map::new();
    for (i, text) in call.questions.iter().enumerate() {
        let mut instructions = text.clone();
        for (k, v) in call.facts.get(i).into_iter().flatten() {
            instructions.push_str(&format!("\n{k}: {v}"));
        }
        questions.insert(
            format!("q{i}"),
            json!({"type": "choice", "instructions": instructions, "criteria": criteria}),
        );
    }
    Ok(json!({"model": MODEL, "input": input, "questions": questions}).to_string())
}

/// The scores one `choice` answer gives, in `options` order.
fn answer_scores(answer: &Value, options: &[String]) -> Option<Vec<f32>> {
    let p = answer.get("probabilities");
    let by_key = |m: &serde_json::Map<String, Value>| {
        options
            .iter()
            .map(|o| m.get(o).and_then(Value::as_f64).map(|f| f as f32))
            .collect::<Option<Vec<f32>>>()
    };
    let scores = match p {
        Some(Value::Object(m)) => by_key(m)?,
        Some(Value::Array(a)) if a.len() == options.len() => {
            // Positional: the order the options were sent in, which is sorted by key.
            let mut sorted: Vec<&String> = options.iter().collect();
            sorted.sort();
            let at = |o: &String| {
                let i = sorted.iter().position(|s| *s == o)?;
                a[i].as_f64().map(|f| f as f32)
            };
            options.iter().map(at).collect::<Option<Vec<f32>>>()?
        }
        // Only the winner: it gets the confidence, the rest share what is left.
        _ => {
            let choice = answer.get("choice").and_then(Value::as_str)?;
            let sure = answer
                .get("confidence")
                .and_then(Value::as_f64)
                .map_or(1.0, |c| c.clamp(0.0, 1.0)) as f32;
            let rest = (1.0 - sure) / (options.len().saturating_sub(1)).max(1) as f32;
            options
                .iter()
                .map(|o| if o == choice { sure } else { rest })
                .collect()
        }
    };
    scores
        .iter()
        .all(|s| s.is_finite() && (0.0..=1.0001).contains(s))
        .then_some(scores)
}

/// What a response says: one score vector per question in `call` order, and the input tokens used.
pub fn parse_response(
    body: &str,
    call: &ProviderCall,
) -> Result<(Vec<Vec<f32>>, u64), ProviderError> {
    let bad = |why: &str| ProviderError::Failed(format!("the Decisions answer {why}"));
    let v: Value = serde_json::from_str(body).map_err(|_| bad("is not JSON"))?;
    let answers = v
        .get("answers")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("has no answers"))?;
    let mut scores = Vec::with_capacity(call.questions.len());
    for i in 0..call.questions.len() {
        let one = answers
            .get(&format!("q{i}"))
            .and_then(|a| answer_scores(a, &call.options))
            .ok_or_else(|| bad("misses a question or an option"))?;
        scores.push(one);
    }
    let tokens = v
        .pointer("/usage/total_input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok((scores, tokens))
}

/// How a `gateway.call` outcome that is not a usable body ends the call.
fn refusal(a: &GatewayCalled) -> ProviderError {
    match a.result {
        UpstreamStatus::RateLimited | UpstreamStatus::ServerError => ProviderError::Overloaded,
        UpstreamStatus::Unreachable => ProviderError::Unavailable,
        other => ProviderError::Failed(super::provider::class_name(other, a.http_status)),
    }
}

impl Gemini {
    async fn once(
        &self,
        call: &ProviderCall,
        body: &str,
    ) -> Result<Metered, (ProviderError, Option<u64>)> {
        let called = self
            .transport
            .call(call.user, PATH, body.to_owned(), call.timeout_ms)
            .await
            .map_err(|e| (e, None))?;
        let a = &called.answer;
        if a.result != UpstreamStatus::Ok {
            return Err((refusal(a), a.retry_after));
        }
        if a.truncated {
            return Err((
                ProviderError::Failed("the Decisions answer was cut".to_owned()),
                None,
            ));
        }
        let (scores, tokens) = parse_response(&a.body, call).map_err(|e| (e, None))?;
        Ok(Metered {
            scores,
            usage: Usage {
                // The body's own count; the runner's is the same number, read generically.
                input_tokens: if tokens > 0 { tokens } else { a.usage.input },
                account: Some(called.account),
                model: MODEL.to_owned(),
            },
        })
    }
}

impl DecisionProvider for Gemini {
    fn id(&self) -> &'static str {
        ID
    }

    fn score<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Vec<Vec<f32>>, ProviderError>> {
        async move { self.score_metered(call).await.map(|m| m.scores) }.boxed()
    }
}

impl MeteredProvider for Gemini {
    fn score_metered<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Metered, ProviderError>> {
        async move {
            let body = request_body(call)?;
            match self.once(call, &body).await {
                // One retry, only when the upstream reports overload (§2.3).
                Err((ProviderError::Overloaded, after)) => {
                    let pause = Duration::from_secs(after.unwrap_or(1)).min(RETRY_PAUSE_MAX);
                    tokio::time::sleep(pause).await;
                    self.once(call, &body).await.map_err(|(e, _)| e)
                }
                other => other.map_err(|(e, _)| e),
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests;
