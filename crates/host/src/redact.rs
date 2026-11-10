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

/// The lowercase words of a key (split at non-alphanumerics and lower-to-upper changes).
fn words(key: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut prev_lower = false;
    for c in key.chars() {
        if !c.is_alphanumeric() {
            out.push(String::new());
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower {
            out.push(String::new());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        out.last_mut()
            .expect("never empty")
            .extend(c.to_lowercase());
    }
    out
}

/// Host-only secret words, on top of the shared name pass (`names::secret_name`), which the
/// server also uses and which must not change. A cookie is the whole rest of the line.
fn is_cookie(key: &str) -> bool {
    words(key).iter().any(|w| w == "cookie" || w == "cookies")
}

fn secret_key(key: &str) -> bool {
    names::secret_name(key)
        || is_cookie(key)
        || words(key)
            .iter()
            .any(|w| matches!(w.as_str(), "pass" | "pwd" | "passphrase"))
}

/// The key just before the separator at `i`: spaces and tabs, then a closing quote (plain or
/// escaped as `\"`), are skipped first.
fn key_before(s: &str, i: usize, floor: usize) -> Option<&str> {
    let b = s.as_bytes();
    let mut end = i;
    while end > floor && matches!(b[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if end > floor && matches!(b[end - 1], b'"' | b'\'') {
        end -= 1;
        if end > floor && b[end - 1] == b'\\' {
            end -= 1;
        }
    }
    let mut start = end;
    while start > floor && key_byte(b[start - 1]) {
        start -= 1;
    }
    (start < end).then(|| &s[start..end])
}

/// `[start, end)` of the value after a separator: a quoted string (plain or `\"` escaped, with
/// escaped quotes inside), or one token (two after an auth scheme word such as `Bearer`), or, for
/// a cookie, the rest of the line.
fn value_span(s: &str, from: usize, to_eol: bool) -> (usize, usize) {
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
    if to_eol {
        return (p, s[p..].find('\n').map_or(b.len(), |e| p + e));
    }
    let escaped = b.get(p) == Some(&b'\\') && matches!(b.get(p + 1), Some(b'"' | b'\''));
    if escaped || matches!(b.get(p), Some(b'"' | b'\'')) {
        let q = b[p + usize::from(escaped)];
        let mut i = p + 1 + usize::from(escaped);
        while i < b.len() {
            if b[i] == b'\\' {
                // One step over the whole run of backslashes (a run is never recounted). Before
                // a quote: odd means the quote is escaped, even means the quote is not. In an
                // escaped string (`\"`) exactly one backslash is the closing `\"`.
                let run = b[i..].iter().take_while(|c| **c == b'\\').count();
                if b.get(i + run) == Some(&q) {
                    if (escaped && run == 1) || (!escaped && run % 2 == 0) {
                        return (p, i + run + 1);
                    }
                    i += run + 1;
                } else {
                    i += run;
                }
            } else if !escaped && b[i] == q {
                return (p, i + 1);
            } else {
                i += 1;
            }
        }
        return (p, b.len());
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

/// Masks the value after every `key=` / `key:` / `"key":` / `key = ` whose key is named like a
/// secret.
pub fn names_text(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if matches!(b[i], b'=' | b':')
            && let Some(key) = key_before(s, i, copied).filter(|k| secret_key(k))
            && let (start, end) = value_span(s, i + 1, is_cookie(key))
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

fn user_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'~' | b'%' | b'-' | b'+')
}

/// How far a password is searched for (bytes after the colon).
const CRED_REACH: usize = 256;

/// `scheme://user:password@host`: the password goes, whatever it holds (`/`, `?`, `#`, spaces,
/// quotes): it runs to the last `@` within [`CRED_REACH`] bytes on the same line, so a stray `@`
/// later in the line can over-mask, which is the safe side. Also `user:password@host` without a
/// scheme, as one whitespace-free token (a password with a space is only caught after `://`).
pub fn url_creds(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        // The start of a `user:` candidate: after `://`, or at the start of a token.
        let after_scheme = b[i..].starts_with(b"://");
        let start = if after_scheme { i + 3 } else { i };
        let token_start = after_scheme
            || i == 0
            || b[i - 1].is_ascii_whitespace()
            || matches!(b[i - 1], b'"' | b'\'' | b'(' | b'<' | b'=');
        if token_start && user_byte(b.get(start).copied().unwrap_or(0)) {
            let user = b[start..].iter().take_while(|c| user_byte(**c)).count();
            let colon = start + user;
            // `scheme://…` is handled at the `://`, not as a user named after the scheme.
            if b.get(colon) == Some(&b':') && !s[colon + 1..].starts_with("//") {
                let line_end = s[colon..].find('\n').map_or(b.len(), |e| colon + e);
                let mut reach = line_end.min(colon + 1 + CRED_REACH);
                while !s.is_char_boundary(reach) {
                    reach -= 1;
                }
                let window = &s[colon + 1..reach];
                // Scheme-less: the token ends at whitespace or a quote.
                let window = if after_scheme {
                    window
                } else {
                    &window[..window
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                        .unwrap_or(window.len())]
                };
                if let Some(at) = window.rfind('@')
                    && at > 0
                    && !window[..at].starts_with("[redacted")
                {
                    out.push_str(&s[copied..=colon]);
                    out.push_str("[redacted:url_password]");
                    copied = colon + 1 + at;
                    i = copied;
                    continue;
                }
            }
        }
        i += if after_scheme { 3 } else { 1 };
    }
    out.push_str(&s[copied..]);
    out
}

/// One entry is cut to this many bytes before anything is redacted, so the redaction work is
/// bounded however long a line the Core prints.
pub const PRE_CUT: usize = 64 * 1024;

/// Cuts an over-long entry to [`PRE_CUT`] bytes and masks whatever was cut off. The cut backs up to
/// the last whitespace (or at most 512 bytes), so it never leaves the front of a token whose tail
/// is gone; the marker stands for the cut part.
pub fn pre_cut(mut s: String) -> String {
    if s.len() <= PRE_CUT {
        return s;
    }
    let mut n = PRE_CUT;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    let floor = n.saturating_sub(512);
    n = s[floor..n]
        .rfind(char::is_whitespace)
        .map_or(floor, |w| floor + w);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s.truncate(n);
    s.push_str("[redacted:cut]");
    s
}

fn strings(v: &mut Value, f: &impl Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| strings(x, f)),
        Value::Object(m) => m.values_mut().for_each(|x| strings(x, f)),
        _ => {}
    }
}

/// Any run of 60 or more base64 / base64url characters (with at least 20 letters or digits) is the
/// middle of a PEM body or a token: PEM bodies are 64 or 70 wide, but a prefixed line, a longer
/// line or a base64url alphabet must not slip past the shape pass. A false positive costs a masked
/// run in a log line.
pub fn mask_runs(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::new(), 0, 0);
    while i < b.len() {
        let in_run = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'_' | b'-');
        if !in_run(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && in_run(b[i]) {
            i += 1;
        }
        let body = i - start;
        while i < b.len() && b[i] == b'=' && i - start < body + 2 {
            i += 1;
        }
        if i - start >= 60
            && b[start..i]
                .iter()
                .filter(|c| c.is_ascii_alphanumeric())
                .count()
                >= 20
        {
            out.push_str(&s[copied..start]);
            out.push_str(PEM);
            copied = i;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// One entry's text with every secret shape and secret-named value masked. A JSON object is
/// masked structurally (names, then shapes), then by text inside its strings.
pub fn one(text: &str) -> String {
    let r = Redactor::new();
    let text_pass = |t: &str| mask_runs(&url_creds(&names_text(&r.text(t))));
    if text.trim_start().starts_with('{')
        && let Ok(mut v) = serde_json::from_str::<Value>(text)
    {
        names::mask(&mut v);
        r.json(&mut v);
        strings(&mut v, &|t| mask_runs(&url_creds(&names_text(t))));
        return v.to_string();
    }
    text_pass(text)
}

/// A line that could be a base64 body line: no spaces, base64 characters only, at least 8 long.
fn body_like(t: &str) -> bool {
    t.len() >= 8
        && t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-'))
}

/// A `BEGIN … KEY` line opens a masking state that continues across entries to the matching
/// `END` line. With no `END` in the page, everything to the end of the page is masked. The
/// reverse holds too: an `END` with no `BEGIN` before it means the block began before this page,
/// so that entry and the run of body-like entries just before it are masked (not the whole page). The last `BEGIN` and
/// last `END` in an entry decide whether it leaves a block open, so an entry that closes one block
/// and opens another keeps masking.
pub fn pem_across(texts: &mut [String]) {
    let mut inside = false;
    for i in 0..texts.len() {
        let (b, e) = (texts[i].find(PEM_BEGIN), texts[i].find(PEM_END));
        let (lb, le) = (texts[i].rfind(PEM_BEGIN), texts[i].rfind(PEM_END));
        let open_after = match (lb, le) {
            (Some(x), Some(y)) => x > y,
            (Some(_), None) | (None, None) => true,
            (None, Some(_)) => false,
        };
        if inside {
            texts[i] = PEM.to_owned();
            inside = open_after;
        } else if let Some(e0) = e
            && b.is_none_or(|b0| e0 < b0)
        {
            // The block began before this page: mask this entry and the run of base64-looking
            // entries just before it (the body lines), and stop at the first ordinary line, so
            // an `END` line a client can print cannot hide the whole page.
            texts[i] = PEM.to_owned();
            for t in texts[..i].iter_mut().rev().take_while(|t| body_like(t)) {
                *t = PEM.to_owned();
            }
            inside = lb.is_some() && open_after;
        } else if let Some(b0) = b
            && open_after
        {
            texts[i].truncate(b0);
            texts[i].push_str(PEM);
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
