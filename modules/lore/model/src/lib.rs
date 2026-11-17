//! The Lore note model (T5). Pure Rust: no I/O, no DB, no Markdown crate.
//!
//! `parse` turns one note's Markdown (the document, T1) into what the store and index need: title, headings,
//! wikilinks, tags, task items, links, attachment refs and a word count. The text is untrusted (imports, AI writes),
//! so everything is bounded: input size, nesting, per-field length, items per kind, and every scan is linear
//! (no backtracking, no recursion, no allocation proportional to anything but the input). Output is deterministic:
//! only `Vec`s, in document order, first occurrence wins on duplicates. `parse` never panics (fuzzed).
//!
//! Parser choice: a hand-rolled line scanner, not pulldown-cmark or comrak. We need seven facts out of a note, not a
//! document tree; neither crate knows `[[wikilinks]]` or `#tags` (both would still need our own scanner over the
//! text events), pulldown-cmark adds a dependency tree to a crate that must stay auditable at the trust boundary,
//! and comrak is much heavier still. The price is CommonMark corner cases we do not model, listed below.
//!
//! Subset, deliberately (a `ponytail:` ceiling each): ATX headings only (no setext); fenced code only (no indented
//! code blocks); inline code spans are matched within one line; `\` escapes apply to `[`, `]`, `#` and `\` only;
//! only inline `[t](u)` / `![a](u)` links (no reference links, no bare URLs, no `<autolinks>`); raw HTML is plain text.

mod inline;

use serde::Serialize;

/// Hard limits. Every loop is bounded by the input length or one of these.
pub mod limits {
    /// The note text (matches `lore_notes.text CHECK (length(text) <= 2000000)`, T1).
    pub const MAX_TEXT_BYTES: usize = 2_000_000;
    /// Blockquote depth + list indentation (2 columns each); a deeper line gets no block structure.
    pub const MAX_NESTING: usize = 32;
    /// Only this many leading bytes of one line are scanned for inline items.
    pub const MAX_LINE_SCAN: usize = 64 * 1024;
    pub const MAX_FRONT_MATTER_LINES: usize = 100;
    pub const MAX_TITLE_CHARS: usize = 200;
    pub const MAX_HEADING_CHARS: usize = 200;
    pub const MAX_TASK_CHARS: usize = 200;
    pub const MAX_CONTEXT_CHARS: usize = 160;
    pub const MAX_TAG_CHARS: usize = 64;
    pub const MAX_URL_BYTES: usize = 2048;
    pub const MAX_LINK_TEXT_BYTES: usize = 400;
    pub const MAX_WIKILINK_BYTES: usize = 400;
    pub const MAX_HEADINGS: usize = 2_000;
    pub const MAX_WIKILINKS: usize = 5_000;
    pub const MAX_LINKS: usize = 5_000;
    pub const MAX_TASKS: usize = 5_000;
    pub const MAX_TAGS: usize = 200;
    pub const MAX_ATTACHMENTS: usize = 1_000;
}

/// The title of a note with no text at all.
pub const UNTITLED: &str = "Untitled";
/// Scheme of an attachment reference: `![name](lore-attachment:<sha256 hex>)` (T8).
pub const ATTACHMENT_SCHEME: &str = "lore-attachment:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooLarge { len: usize, max: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "note text is {len} bytes, the limit is {max}")
            }
        }
    }
}
impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Heading {
    pub level: u8,
    pub text: String,
    /// 1-based line in the whole document.
    pub line: usize,
}

/// `[[Title]]`, `[[Title#Heading]]`, `[[Title|alias]]`, `[[Title#Heading|alias]]` (also `![[...]]`). One per
/// `(title_norm, heading)`: the first occurrence. A link with an empty title (`[[#Heading]]`) is not a note link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wikilink {
    pub title: String,
    pub title_norm: String,
    pub heading: Option<String>,
    pub alias: Option<String>,
    /// The line the link is on, trimmed and cut to `MAX_CONTEXT_CHARS` (backlink context).
    pub context: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Task {
    pub done: bool,
    pub text: String,
    pub line: usize,
}

/// `[text](url)` or `![alt](url)` (`image`), url as written. Attachment refs are not here, see `attachments`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub text: String,
    pub url: String,
    pub image: bool,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Parsed {
    pub title: String,
    pub title_norm: String,
    pub headings: Vec<Heading>,
    pub wikilinks: Vec<Wikilink>,
    /// Lower-cased, front matter first then inline, no duplicates.
    pub tags: Vec<String>,
    pub tasks: Vec<Task>,
    pub links: Vec<Link>,
    /// sha256 hex (64 lower-case chars) of each referenced attachment, first occurrence order.
    pub attachments: Vec<String>,
    /// Whitespace-separated words containing a letter or digit, front matter excluded.
    pub words: usize,
    /// Some cap in `limits` dropped something.
    pub truncated: bool,
}

/// Link-target normalisation (T6): whitespace runs collapse to one space, trimmed, lower-cased. No Unicode
/// normalisation form (needs a dependency; ponytail: add NFC if imports from macOS file names show NFD titles).
pub fn normalize_title(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Cut to at most `max` chars, never inside a char.
pub(crate) fn clip(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

pub(crate) struct Acc {
    pub p: Parsed,
}

impl Acc {
    pub fn push_tag(&mut self, raw: &str) {
        let Some(tag) = inline::clean_tag(raw) else {
            return;
        };
        if self.p.tags.contains(&tag) {
            return;
        }
        if self.p.tags.len() >= limits::MAX_TAGS {
            self.p.truncated = true;
        } else {
            self.p.tags.push(tag);
        }
    }
}

pub fn parse(text: &str) -> Result<Parsed, ParseError> {
    if text.len() > limits::MAX_TEXT_BYTES {
        return Err(ParseError::TooLarge {
            len: text.len(),
            max: limits::MAX_TEXT_BYTES,
        });
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut acc = Acc {
        p: Parsed::default(),
    };
    let skip = front_matter(text, &mut acc);
    let (mut h1, mut first_line): (Option<String>, Option<String>) = (None, None);
    // an open fence: (marker char, run length)
    let mut fence: Option<(u8, usize)> = None;

    for (i, raw) in text.lines().enumerate().skip(skip) {
        let no = i + 1;
        acc.p.words += raw
            .split_whitespace()
            .filter(|w| w.chars().any(char::is_alphanumeric))
            .count();
        // blockquote prefixes, then indentation
        let (mut s, mut depth) = (raw, 0usize);
        loop {
            let t = s.trim_start_matches(' ');
            match t.strip_prefix('>') {
                Some(rest) if depth <= limits::MAX_NESTING => {
                    depth += 1;
                    s = rest.strip_prefix(' ').unwrap_or(rest);
                }
                _ => break,
            }
        }
        let t = s.trim_start_matches([' ', '\t']);
        let cols: usize = s[..s.len() - t.len()]
            .bytes()
            .map(|b| if b == b'\t' { 4 } else { 1 })
            .sum();
        let structural = depth + cols / 2 <= limits::MAX_NESTING;

        if let Some((c, n)) = fence {
            if structural && is_fence_close(t, c, n) {
                fence = None;
            }
            continue;
        }
        if structural && let Some(f) = fence_open(t) {
            fence = Some(f);
            continue;
        }
        if t.trim().is_empty() {
            continue;
        }
        if structural
            && cols < 4
            && let Some((level, text)) = atx(t)
        {
            if !text.is_empty() {
                let text = clip(text, limits::MAX_HEADING_CHARS);
                if level == 1 && h1.is_none() {
                    h1 = Some(text.to_string());
                }
                first_line.get_or_insert_with(|| text.to_string());
                if acc.p.headings.len() < limits::MAX_HEADINGS {
                    acc.p.headings.push(Heading {
                        level,
                        text: text.to_string(),
                        line: no,
                    });
                } else {
                    acc.p.truncated = true;
                }
                inline::scan(text, raw, no, &mut acc);
            }
            continue;
        }
        first_line.get_or_insert_with(|| clip(t.trim(), limits::MAX_TITLE_CHARS).to_string());
        if structural && let Some((done, rest)) = task(t) {
            if acc.p.tasks.len() < limits::MAX_TASKS {
                let text = clip(rest.trim(), limits::MAX_TASK_CHARS).to_string();
                acc.p.tasks.push(Task {
                    done,
                    text,
                    line: no,
                });
            } else {
                acc.p.truncated = true;
            }
            inline::scan(rest, raw, no, &mut acc);
        } else {
            inline::scan(s, raw, no, &mut acc);
        }
    }

    let title = h1.or(first_line).filter(|t| !t.is_empty());
    acc.p.title = title.unwrap_or_else(|| UNTITLED.to_string());
    acc.p.title_norm = normalize_title(&acc.p.title);
    Ok(acc.p)
}

/// `---` on the first line, closed by `---` or `...` within `MAX_FRONT_MATTER_LINES`. Reads `tags:` (inline list,
/// comma/space separated, or a `- x` block). Returns the number of lines to skip (0 = no front matter).
fn front_matter(text: &str, acc: &mut Acc) -> usize {
    let mut lines = text.lines();
    if lines.next().map(str::trim_end) != Some("---") {
        return 0;
    }
    let fm: Vec<&str> = lines.take(limits::MAX_FRONT_MATTER_LINES).collect();
    let Some(end) = fm
        .iter()
        .position(|l| matches!(l.trim_end(), "---" | "..."))
    else {
        return 0;
    };
    let mut block = false;
    for l in &fm[..end] {
        let t = l.trim();
        if block && let Some(item) = t.strip_prefix('-') {
            acc.push_tag(item);
            continue;
        }
        block = false;
        let Some((k, v)) = t.split_once(':') else {
            continue;
        };
        if !matches!(k.trim().to_ascii_lowercase().as_str(), "tags" | "tag") {
            continue;
        }
        let v = v.trim().trim_start_matches('[').trim_end_matches(']');
        block = v.is_empty();
        for item in v.split([',', ' ', '\t']) {
            acc.push_tag(item);
        }
    }
    end + 2
}

fn fence_open(t: &str) -> Option<(u8, usize)> {
    let c = *t.as_bytes().first().filter(|c| matches!(c, b'`' | b'~'))?;
    let n = t.bytes().take_while(|&b| b == c).count();
    // a backtick fence's info string may not hold a backtick (else it is an inline code span)
    (n >= 3 && !(c == b'`' && t[n..].contains('`'))).then_some((c, n))
}

fn is_fence_close(t: &str, c: u8, n: usize) -> bool {
    let run = t.bytes().take_while(|&b| b == c).count();
    run >= n && t[run..].trim().is_empty()
}

/// `# text` .. `###### text`; closing `#`s dropped.
fn atx(t: &str) -> Option<(u8, &str)> {
    let n = t.bytes().take_while(|&b| b == b'#').count();
    let rest = &t[n..];
    if n == 0 || n > 6 || !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
        return None;
    }
    let rest = rest.trim();
    let body = rest.trim_end_matches('#');
    let text = if body.is_empty() || body.ends_with([' ', '\t']) {
        body
    } else {
        rest
    };
    Some((n as u8, text.trim()))
}

/// `- [ ] x`, `* [x] x`, `+ [X] x`, `1. [ ] x`; returns (done, text after the box).
fn task(t: &str) -> Option<(bool, &str)> {
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    let rest = if digits > 0 && digits <= 9 {
        t[digits..].strip_prefix(['.', ')'])?
    } else {
        t.strip_prefix(['-', '*', '+'])?
    };
    let rest = rest.trim_start_matches([' ', '\t']);
    let done = match rest.get(..3)? {
        "[ ]" => false,
        "[x]" | "[X]" => true,
        _ => return None,
    };
    let after = &rest[3..];
    (after.is_empty() || after.starts_with([' ', '\t'])).then_some((done, after))
}

/// `text` with every wikilink to the note titled `old_title` pointed at `new_title` (T6 rename), outside code spans,
/// fences and front matter; `#Heading` and `|alias` kept. `None` when no link matched or `new_title` could not
/// sit inside a wikilink. Line endings and every other byte are kept.
pub fn rename_wikilinks(text: &str, old_title: &str, new_title: &str) -> Option<String> {
    if new_title.is_empty() || new_title.contains(['[', ']', '|', '#', '`', '\n', '\r', '\\']) {
        return None;
    }
    let old_norm = normalize_title(old_title);
    let mut scratch = Acc {
        p: Parsed::default(),
    };
    let skip = front_matter(text, &mut scratch);
    let (mut out, mut changed) = (String::with_capacity(text.len() + 64), false);
    let mut fence: Option<(u8, usize)> = None;
    for (i, raw) in text.split_inclusive('\n').enumerate() {
        let body = raw.strip_suffix('\n').unwrap_or(raw);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let t = body.trim_start_matches([' ', '>', '\t']);
        if let Some((c, n)) = fence {
            if is_fence_close(t, c, n) {
                fence = None;
            }
        } else if let Some(f) = fence_open(t) {
            fence = Some(f);
        } else if i >= skip
            && let Some(new) = inline::rename_in_line(body, &old_norm, new_title)
        {
            out.push_str(&new);
            out.push_str(&raw[body.len()..]);
            changed = true;
            continue;
        }
        out.push_str(raw);
    }
    changed.then_some(out)
}
