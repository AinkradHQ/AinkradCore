//! Log redaction for the helper: one `Redactor` (shapes, from `ainkrad-proto`), the shared
//! secret-name pass, a text form of that pass for `key=value` lines, and PEM masking that spans
//! journal entries. **Redact first, truncate after**: a cut made first could split a key shape and
//! let half of it through.
//!
//! Known residual: values with no shape (connection tokens, AWS secret keys on their own) cannot
//! be masked here, and the helper does not hold the secrets. That is why runner and backup logs
//! need a step-up in the Core.

use ainkrad_proto::redact::{Redactor, names};
use serde_json::Value;

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM: &str = "[redacted:pem_block]";
/// One log line is cut to this many bytes after redaction.
pub const LINE_CAP: usize = 4096;

fn key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// The secret-named key just before the separator at `i` (a closing quote is skipped).
fn key_before(s: &str, i: usize, floor: usize) -> Option<&str> {
    let b = s.as_bytes();
    let mut end = i;
    if end > floor && matches!(b[end - 1], b'"' | b'\'') {
        end -= 1;
    }
    let mut start = end;
    while start > floor && key_byte(b[start - 1]) {
        start -= 1;
    }
    (start < end).then(|| &s[start..end])
}

/// `[start, end)` of the value after a separator: a quoted string, or one token (two after an
/// auth scheme word such as `Bearer`).
fn value_span(s: &str, from: usize) -> (usize, usize) {
    let b = s.as_bytes();
    let token_end = |mut p: usize| {
        while p < b.len()
            && !(b[p].is_ascii_whitespace()
                || matches!(b[p], b',' | b';' | b'}' | b'&' | b'"' | b'\''))
        {
            p += 1;
        }
        p
    };
    let mut p = from;
    while p < b.len() && matches!(b[p], b' ' | b'\t') {
        p += 1;
    }
    if p < b.len() && matches!(b[p], b'"' | b'\'') {
        let end = s[p + 1..]
            .find(b[p] as char)
            .map_or(b.len(), |e| p + 1 + e + 1);
        return (p, end);
    }
    let mut end = token_end(p);
    let word = s[p..end].to_ascii_lowercase();
    if matches!(word.as_str(), "bearer" | "basic" | "token" | "digest")
        && end < b.len()
        && b[end] == b' '
    {
        end = token_end(end + 1);
    }
    (p, end)
}

/// Masks the value after every `key=` / `key:` / `"key":` whose key is named like a secret.
pub fn names_text(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if matches!(b[i], b'=' | b':')
            && let Some(key) = key_before(s, i, copied).filter(|k| names::secret_name(k))
            && let (start, end) = value_span(s, i + 1)
            && end > start
        {
            out.push_str(&s[copied..start]);
            out.push_str(&format!("[redacted:{key}]"));
            (copied, i) = (end, end);
            continue;
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

fn strings(v: &mut Value, f: &impl Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| strings(x, f)),
        Value::Object(m) => m.values_mut().for_each(|x| strings(x, f)),
        _ => {}
    }
}

fn base64_body(s: &str) -> bool {
    let t = s.trim();
    let body = t.trim_end_matches('=');
    (60..=76).contains(&t.len())
        && t.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

/// One entry's text with every secret shape and secret-named value masked. A JSON object is
/// masked structurally (names, then shapes), then by text inside its strings.
pub fn one(text: &str) -> String {
    if base64_body(text) {
        // The middle of a PEM block whose BEGIN line is on another page.
        return PEM.to_owned();
    }
    let r = Redactor::new();
    if text.trim_start().starts_with('{')
        && let Ok(mut v) = serde_json::from_str::<Value>(text)
    {
        names::mask(&mut v);
        r.json(&mut v);
        strings(&mut v, &names_text);
        return v.to_string();
    }
    names_text(&r.text(text))
}

/// A `BEGIN … KEY` line opens a masking state that continues across entries to the matching
/// `END` line. With no `END` in the page, everything to the end of the page is masked.
pub fn pem_across(texts: &mut [String]) {
    let mut inside = false;
    for t in texts {
        if inside {
            inside = !t.contains(PEM_END);
            *t = PEM.to_owned();
        } else if let Some(p) = t.find(PEM_BEGIN).filter(|p| !t[*p..].contains(PEM_END)) {
            t.truncate(p);
            t.push_str(PEM);
            inside = true;
        }
    }
}

/// Cuts `s` to `max` bytes on a character boundary.
pub fn cap(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut n = max;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests;
