//! Token usage out of a model reply (KAN-435 G4), per wire, for a buffered JSON body and for a
//! server-sent-event stream, fed in whatever pieces the upstream sent.
//!
//! Counts are normalised so nothing is priced twice: `input` is the input that was not served from
//! a cache, `cache_read` and `cache_write` are the cached parts, `output` includes reasoning.
//!
//! - Anthropic: `input_tokens` already excludes the cache fields; `message_start` and
//!   `message_delta` carry cumulative counts.
//! - OpenAI (responses and chat): `input_tokens` / `prompt_tokens` include `cached_tokens`, which
//!   is subtracted.
//! - Gemini: `promptTokenCount` includes `cachedContentTokenCount`; `thoughtsTokenCount` is billed
//!   as output. Every chunk carries the cumulative count.
//!
//! Every count is cumulative, so each field takes the largest value seen. The scan reads what the
//! upstream says; nothing here trusts it for anything but the ledger.

use ainkrad_proto::v2::Wire;
use serde_json::Value;

/// The longest SSE line or buffered body kept; past it the scan gives up on exact counts.
const MAX_LINE: usize = 1024 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl Usage {
    fn merge(&mut self, o: Usage) {
        self.input = self.input.max(o.input);
        self.output = self.output.max(o.output);
        self.cache_read = self.cache_read.max(o.cache_read);
        self.cache_write = self.cache_write.max(o.cache_write);
    }
}

/// A usage object, when the value is one: `"usage": null` (a Responses `response.created`, every
/// chat chunk but the last with `include_usage`) reports nothing and is not a report.
fn object(v: Option<&Value>) -> Option<&Value> {
    v.filter(|u| u.is_object())
}

fn n(v: &Value, path: &[&str]) -> u64 {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// The usage object of one JSON value of `wire`, when it carries one.
fn usage_of(wire: Wire, v: &Value) -> Option<Usage> {
    match wire {
        Wire::AnthropicMessages => {
            let u = object(v.pointer("/message/usage")).or_else(|| object(v.get("usage")))?;
            Some(Usage {
                input: n(u, &["input_tokens"]),
                output: n(u, &["output_tokens"]),
                cache_read: n(u, &["cache_read_input_tokens"]),
                cache_write: n(u, &["cache_creation_input_tokens"]),
            })
        }
        Wire::OpenaiResponses => {
            let u = object(v.pointer("/response/usage")).or_else(|| object(v.get("usage")))?;
            let total = n(u, &["input_tokens"]).max(n(u, &["prompt_tokens"]));
            let cached = n(u, &["input_tokens_details", "cached_tokens"])
                .max(n(u, &["prompt_tokens_details", "cached_tokens"]));
            Some(Usage {
                input: total.saturating_sub(cached),
                output: n(u, &["output_tokens"]).max(n(u, &["completion_tokens"])),
                cache_read: cached,
                cache_write: 0,
            })
        }
        Wire::GeminiGenerate => {
            let u = object(v.get("usageMetadata")).or_else(|| object(v.get("usage_metadata")))?;
            let cached = n(u, &["cachedContentTokenCount"]);
            Some(Usage {
                input: n(u, &["promptTokenCount"])
                    .saturating_add(n(u, &["toolUsePromptTokenCount"]))
                    .saturating_sub(cached),
                output: n(u, &["candidatesTokenCount"])
                    .saturating_add(n(u, &["thoughtsTokenCount"])),
                cache_read: cached,
                cache_write: 0,
            })
        }
    }
}

/// The event that ends a reply of `wire`: nothing after it changes the count. Anthropic's
/// `message_stop`; OpenAI's `response.completed` / `incomplete` / `failed`; a Gemini chunk with a
/// `finishReason`. (OpenAI chat ends with a `[DONE]` line, read separately.) A stream that ends
/// without one was cut, or ended in an `error` event, whatever the connection said.
fn closes(wire: Wire, v: &Value) -> bool {
    let kind = v.get("type").and_then(Value::as_str);
    match wire {
        Wire::AnthropicMessages => kind == Some("message_stop"),
        Wire::OpenaiResponses => matches!(
            kind,
            Some("response.completed" | "response.incomplete" | "response.failed")
        ),
        Wire::GeminiGenerate => v
            .get("candidates")
            .and_then(Value::as_array)
            .is_some_and(|c| {
                c.iter()
                    .any(|c| c.get("finishReason").is_some_and(|f| !f.is_null()))
            }),
    }
}

/// Characters of generated text in one event: the estimate behind a cut stream.
fn text_chars(v: &Value) -> u64 {
    // An OpenAI event that restates what its deltas already carried is not counted twice.
    if let Some(t) = v.get("type").and_then(Value::as_str)
        && t.starts_with("response.")
        && !t.ends_with(".delta")
    {
        return 0;
    }
    fn walk(v: &Value) -> u64 {
        match v {
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| match (k.as_str(), v) {
                    (
                        "text" | "partial_json" | "thinking" | "delta" | "content",
                        Value::String(s),
                    ) => s.chars().count() as u64,
                    _ => walk(v),
                })
                .sum(),
            Value::Array(a) => a.iter().map(walk).sum(),
            _ => 0,
        }
    }
    walk(v)
}

/// A reply being read: the usage it reports and the text it has produced.
pub(crate) struct Scan {
    wire: Wire,
    sse: bool,
    /// The unfinished SSE line, or the buffered JSON body.
    buf: Vec<u8>,
    /// The `data:` lines of the SSE event being read.
    data: Vec<u8>,
    /// A line or body was too long to read: the counts are not exact.
    overflow: bool,
    skipping: bool,
    usage: Usage,
    reported: bool,
    /// The closing event was read.
    closed: bool,
    chars: u64,
    bytes: u64,
}

impl Scan {
    /// `content_type` decides: an event stream is read line by line, anything else is one JSON
    /// body (a Gemini stream without `alt=sse` is a JSON array of chunks).
    pub(crate) fn new(wire: Wire, content_type: Option<&str>) -> Scan {
        Scan {
            wire,
            sse: content_type.is_some_and(|c| c.to_ascii_lowercase().contains("text/event-stream")),
            buf: Vec::new(),
            data: Vec::new(),
            overflow: false,
            skipping: false,
            usage: Usage::default(),
            reported: false,
            closed: false,
            chars: 0,
            bytes: 0,
        }
    }

    pub(crate) fn feed(&mut self, piece: &[u8]) {
        self.bytes += piece.len() as u64;
        if !self.sse {
            if self.buf.len() + piece.len() > MAX_BODY {
                self.overflow = true;
            } else {
                self.buf.extend_from_slice(piece);
            }
            return;
        }
        for &b in piece {
            if b != b'\n' {
                if self.skipping {
                    continue;
                }
                if self.buf.len() >= MAX_LINE {
                    self.overflow = true;
                    self.skipping = true;
                    self.buf.clear();
                } else {
                    self.buf.push(b);
                }
                continue;
            }
            if !std::mem::take(&mut self.skipping) {
                self.line();
            }
            self.buf.clear();
        }
    }

    /// One complete SSE line is in `buf`.
    fn line(&mut self) {
        let line = self.buf.strip_suffix(b"\r").unwrap_or(&self.buf);
        if line.is_empty() {
            return self.event();
        }
        if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            if self.data.len() + rest.len() + 1 > MAX_LINE {
                self.overflow = true;
                return;
            }
            if !self.data.is_empty() {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(rest);
        }
    }

    fn event(&mut self) {
        let data = std::mem::take(&mut self.data);
        if data == b"[DONE]" {
            self.closed = true;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(&data) {
            self.absorb(&v);
        }
    }

    fn absorb(&mut self, v: &Value) {
        if let Some(u) = usage_of(self.wire, v) {
            self.usage.merge(u);
            self.reported = true;
        }
        self.closed |= closes(self.wire, v);
        self.chars += text_chars(v);
    }

    /// The reply ended (or was cut): whatever is pending is read.
    pub(crate) fn finish(&mut self) {
        if self.sse {
            if !self.skipping && !self.buf.is_empty() {
                self.line();
            }
            self.buf.clear();
            self.event();
        } else if !self.overflow
            && let Ok(v) = serde_json::from_slice::<Value>(&std::mem::take(&mut self.buf))
        {
            match &v {
                Value::Array(chunks) => chunks.iter().for_each(|c| self.absorb(c)),
                _ => self.absorb(&v),
            }
            // A whole JSON body that parsed is a reply that ended.
            self.closed = true;
        }
    }

    /// What the reply reported, when it reported anything.
    pub(crate) fn reported(&self) -> Option<Usage> {
        self.reported.then_some(self.usage)
    }

    /// What the reply reported, when it can be taken as the count: the closing event was read, it
    /// reported some input (plain or cached), and nothing could not be read. A stream that ended
    /// without its closing event (cut, or ended by an `error` event) holds only what the start of
    /// the reply said, and a report of no input at all is partial too; both are estimated.
    pub(crate) fn exact(&self) -> Option<Usage> {
        self.reported()
            .filter(|u| self.closed && u.input + u.cache_read + u.cache_write > 0 && !self.overflow)
    }

    /// Output tokens so far by the estimate: streamed characters / 4 (a JSON body, which is not
    /// read until its end, by its bytes / 4).
    pub(crate) fn estimated_output(&self) -> u64 {
        let basis = if self.sse { self.chars } else { self.bytes };
        basis.div_ceil(4)
    }

    /// Part of the reply could not be read: no count from it is exact.
    #[cfg(test)]
    pub(crate) fn overflowed(&self) -> bool {
        self.overflow
    }

    /// The usage so far as one number a ceiling can be held against: what was reported, with the
    /// output raised to the estimate and the input to `input_floor` when nothing was reported.
    pub(crate) fn running(&self, input_floor: u64) -> Usage {
        match self.reported() {
            Some(mut u) => {
                u.output = u.output.max(self.estimated_output());
                if u.input + u.cache_read + u.cache_write == 0 {
                    u.input = input_floor;
                }
                u
            }
            None => Usage {
                input: input_floor,
                output: self.estimated_output(),
                ..Usage::default()
            },
        }
    }
}

#[cfg(test)]
mod tests;
