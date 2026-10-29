//! Secret redaction (E3.9, brainstorm §7): transcripts and failure reasons are redacted
//! before they are written anywhere, by the runner and again by the server.
//!
//! Two passes. Known secrets (the run token, the runner key, git askpass answers, secret env
//! values) are replaced wherever they appear by `[redacted:<name>]`. Then key shapes are
//! replaced by `[redacted:<kind>]`: Anthropic, OpenAI, Google, GitHub and AWS keys, Citadel's
//! own run tokens and runner keys, `Bearer` credentials, and PEM blocks.
//!
//! Files (E15.18): a text file an agent publishes as an artifact (`is_text`) goes through the
//! same two passes before it is hashed or stored (`Redactor::file`); any other file is kept as
//! it is and marked unscanned.
//!
//! ponytail: prefix shapes only, no entropy scan; a bare secret with no known prefix and no
//! known value (an AWS secret access key on its own) gets through. Add an entropy pass if one
//! ever shows up in a transcript.

use serde_json::Value;

/// A key shape: `prefix` (ASCII; matched case-insensitively when `fold`), then at least
/// `min` bytes for which `body` holds, not preceded by a letter or digit.
struct Shape {
    prefix: &'static str,
    name: &'static str,
    min: usize,
    body: fn(u8) -> bool,
    fold: bool,
}

fn key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

/// Base64, base64url and JWT bytes.
fn bearer_byte(b: u8) -> bool {
    key_byte(b) || b"./+=~".contains(&b)
}

const fn shape(prefix: &'static str, name: &'static str, min: usize) -> Shape {
    Shape {
        prefix,
        name,
        min,
        body: key_byte,
        fold: false,
    }
}

/// Longer prefixes before the shorter ones they extend.
const SHAPES: &[Shape] = &[
    shape("sk-ant-", "anthropic_key", 20),
    shape("sk-proj-", "openai_key", 20),
    shape("sk-", "openai_key", 20),
    shape("AIza", "google_key", 30),
    shape("github_pat_", "github_token", 20),
    shape("ghp_", "github_token", 30),
    shape("gho_", "github_token", 30),
    shape("ghu_", "github_token", 30),
    shape("ghs_", "github_token", 30),
    shape("ghr_", "github_token", 30),
    Shape {
        body: upper_digit,
        ..shape("AKIA", "aws_key", 16)
    },
    Shape {
        body: upper_digit,
        ..shape("ASIA", "aws_key", 16)
    },
    shape("cit_runner_", "runner_key", 32),
    shape("cit_run_", "run_token", 32),
    Shape {
        body: bearer_byte,
        fold: true,
        ..shape("bearer ", "bearer", 8)
    },
    Shape {
        body: bearer_byte,
        fold: true,
        ..shape("aws_secret_access_key=", "aws_secret", 30)
    },
];

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";

/// Values shorter than this are not treated as known secrets: redacting every `1` or `true`
/// would wreck a transcript and protect nothing.
const MIN_KNOWN: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// (name, value), longest value first, so a secret containing another goes whole.
    known: Vec<(String, String)>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Redacts `value` as `[redacted:<name>]` from now on. Values under 8 bytes are ignored.
    pub fn known(&mut self, name: &str, value: &str) {
        let value = value.trim();
        if value.len() < MIN_KNOWN || self.known.iter().any(|(_, v)| v == value) {
            return;
        }
        self.known.push((name.to_owned(), value.to_owned()));
        self.known.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    }

    /// `text` with every known secret and key shape replaced.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (name, value) in &self.known {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("[redacted:{name}]"));
            }
        }
        shapes(&out)
    }

    /// Redacts every string in `value`, object keys included.
    pub fn json(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.json(v)),
            Value::Object(map) => {
                let taken = std::mem::take(map);
                for (key, mut v) in taken {
                    self.json(&mut v);
                    map.insert(self.text(&key), v);
                }
            }
            _ => {}
        }
    }
}

/// The marker every redaction leaves.
const MARKER: &str = "[redacted:";

/// File extensions whose content is text, and so scanned for secrets before it is stored as
/// an artifact. Every artifact type the server allows that is not here (images, PDF, zip) is
/// stored as it is, marked unscanned.
const TEXT_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "log", "csv", "json", "yaml", "yml", "diff", "patch", "html", "htm",
    "svg", "xml", "toml",
];

/// Whether a file called `name` is text, by its extension.
pub fn is_text(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| TEXT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

impl Redactor {
    /// The bytes of file `name` with every known secret and key shape replaced, and how many
    /// redaction markers the result holds (those of an earlier pass, e.g. the runner's,
    /// included), when the file is text (`is_text`; bytes that are not UTF-8 are decoded
    /// lossily). Any other file comes back as it is, with `None`: not scanned.
    pub fn file(&self, name: &str, bytes: Vec<u8>) -> (Vec<u8>, Option<usize>) {
        if !is_text(name) {
            return (bytes, None);
        }
        let out = self.text(&String::from_utf8_lossy(&bytes));
        let count = out.matches(MARKER).count();
        (out.into_bytes(), Some(count))
    }
}

/// Where the secret starting at byte `i` ends, and its kind.
fn secret_at(s: &str, i: usize) -> Option<(usize, &'static str)> {
    let b = s.as_bytes();
    if !s.is_char_boundary(i) || (i > 0 && b[i - 1].is_ascii_alphanumeric()) {
        return None;
    }
    let rest = &s[i..];
    if rest.starts_with(PEM_BEGIN) {
        // To the end of the `-----END …-----` line, or of the text if it never closes.
        let end = rest
            .find(PEM_END)
            .and_then(|e| {
                let after = e + PEM_END.len();
                rest[after..].find("-----").map(|d| after + d + 5)
            })
            .unwrap_or(rest.len());
        return Some((i + end, "pem_block"));
    }
    SHAPES.iter().find_map(|shape| {
        let head = rest.get(..shape.prefix.len())?;
        let matched = if shape.fold {
            head.eq_ignore_ascii_case(shape.prefix)
        } else {
            head == shape.prefix
        };
        if !matched {
            return None;
        }
        let body = rest.as_bytes()[shape.prefix.len()..]
            .iter()
            .take_while(|b| (shape.body)(**b))
            .count();
        (body >= shape.min).then(|| (i + shape.prefix.len() + body, shape.name))
    })
}

fn shapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut i, mut copied) = (0, 0);
    while i < text.len() {
        match secret_at(text, i) {
            Some((end, name)) => {
                out.push_str(&text[copied..i]);
                out.push_str(&format!("{MARKER}{name}]"));
                (i, copied) = (end, end);
            }
            None => i += 1,
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// One fake secret of each shape with its kind, shaped like the real thing but never valid:
/// for tests here and in the crates that redact.
pub const PLANTED: &[(&str, &str)] = &[
    (
        "anthropic_key",
        "sk-ant-api03-Zx9QWERTYuiopASDFghjkl0123456789-_abcdEF",
    ),
    ("openai_key", "sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ("openai_key", "sk-Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm"),
    ("google_key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"),
    ("github_token", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
    (
        "github_token",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    ),
    ("aws_key", "AKIAIOSFODNN7EXAMPLE"),
    (
        "aws_secret",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "run_token",
        "cit_run_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    (
        "runner_key",
        "cit_runner_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    (
        "bearer",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
    ),
    (
        "pem_block",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
    ),
];

#[cfg(test)]
mod tests;
