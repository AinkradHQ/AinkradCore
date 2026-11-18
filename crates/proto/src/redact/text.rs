//! The text pass shared by the root-side host helper (log lines) and the Leyline module (run
//! output and approval cards): masks `key=value` / `key: value` / `"key": "value"` where the key is
//! named like a secret, `user:password@host` URLs, and long base64 runs, anywhere in a line.
//! Moved from `crates/host/src/redact.rs` so every caller uses the same pass.

use serde_json::Value;

use super::{Redactor, names};

const PEM: &str = "[redacted:pem_block]";

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

/// How far a password is searched for (bytes after the `://` or the user). Every search is bounded
/// by this, so the pass costs at most `CRED_REACH` per candidate however long the line is.
const CRED_REACH: usize = 256;

/// The text after `from`, at most [`CRED_REACH`] bytes, up to the end of the line, on a char boundary.
fn window(s: &str, from: usize) -> &str {
    let mut end = s.len().min(from + CRED_REACH);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let w = &s[from..end];
    &w[..w.find('\n').unwrap_or(w.len())]
}

/// After `scheme://`: `(offset of the colon, offset of the '@')` of a `user:password@` prefix, with
/// the user possibly empty (`redis://:secret@host`) and made of any characters but the delimiters.
///
/// The password may hold anything (`/ ? #`, spaces, quotes, more `@`): it runs to the last `@` of
/// the first token (up to whitespace or a quote). If that token has no `@` but still looks like
/// userinfo (a colon, no `/ ? #` yet), the search goes on past whitespace and quotes to the last
/// `@` of the window. So `http://h:8080/path … someone@corp` (a `/` before the first space) is left
/// alone, and `http://h:8080/a@b` is still read as user:password (over-masking, the safe side).
fn scheme_creds(s: &str, start: usize) -> Option<(usize, usize)> {
    let w = window(s, start);
    let token = &w[..w
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .unwrap_or(w.len())];
    let at = match token.rfind('@') {
        Some(at) => at,
        // Everything after the colon being digits means a port (`redis://192.0.2.10:6379 …`), not a
        // password with a space in it: no look past the token.
        None if token.contains(':')
            && !token.contains(['/', '?', '#'])
            && !token
                .split_once(':')
                .is_some_and(|(_, after)| after.bytes().all(|c| c.is_ascii_digit())) =>
        {
            w.rfind('@')?
        }
        None => return None,
    };
    let colon = w[..at].find(':')?;
    let user = &w[..colon];
    (!user.contains(['/', '?', '#', '@', ' ', '\t', '"', '\'']))
        .then_some((start + colon, start + at))
}

/// Without a scheme: one token `user:password@host.example` (a dot in the host, and no space in the
/// password). `mailto:bob@x` and `ERROR:foo@bar` have no dotted host and are left alone;
/// `ERROR:foo@example.com` is masked, which is the trade-off for catching
/// `admin:hunter2@db.example.net`.
fn bare_creds(s: &str, start: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let user = b[start..].iter().take_while(|c| user_byte(**c)).count();
    let colon = start + user;
    if user == 0
        || b.get(colon) != Some(&b':')
        || b[colon + 1..].starts_with(b"//")
        || b[colon + 1..].starts_with(b"\\/\\/")
    {
        return None;
    }
    let w = window(s, colon + 1);
    let token = &w[..w
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<')
        .unwrap_or(w.len())];
    let at = token.rfind('@')?;
    let host = &token[at + 1..];
    let host_len = host
        .bytes()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        .count();
    let host = &host[..host_len];
    (at > 0
        && host.contains('.')
        && host.ends_with(|c: char| c.is_ascii_alphanumeric())
        && !token[..at].starts_with("[redacted"))
    .then_some((colon, colon + 1 + at))
}

/// `scheme://user:password@host`, and `user:password@host.example` without a scheme: the password goes.
/// See [`scheme_creds`] and [`bare_creds`] for what counts and the over-masking trade-offs.
pub fn url_creds(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        // `://`, or the JSON-escaped `:\/\/` a logged string holds.
        let sep = if b[i..].starts_with(b"://") {
            3
        } else if b[i..].starts_with(b":\\/\\/") {
            5
        } else {
            0
        };
        let after_scheme = sep > 0;
        let found = if after_scheme {
            scheme_creds(s, i + sep)
        } else if i == 0
            || b[i - 1].is_ascii_whitespace()
            || matches!(b[i - 1], b'"' | b'\'' | b'(' | b'<' | b'=')
        {
            bare_creds(s, i)
        } else {
            None
        };
        if let Some((colon, at)) = found {
            out.push_str(&s[copied..=colon]);
            out.push_str("[redacted:url_password]");
            (copied, i) = (at, at);
            continue;
        }
        i += if after_scheme { sep } else { 1 };
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
