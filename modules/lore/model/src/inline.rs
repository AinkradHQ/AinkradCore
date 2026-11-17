//! The inline scanner: wikilinks, links, attachment refs and `#tags` in one line of text, skipping code spans.
//! Linear: every probe stops at the next `[` / backtick / limit, so a hostile line cannot make it quadratic.

use std::collections::HashMap;

use crate::{ATTACHMENT_SCHEME, Acc, Link, Wikilink, clip, limits, normalize_title};

/// Normalise a tag candidate (`#` and quotes optional): lower-case, letters/digits/`_`/`-`/`/`, not all digits.
pub(crate) fn clean_tag(raw: &str) -> Option<String> {
    let t = raw
        .trim()
        .trim_matches(['"', '\''])
        .trim_start_matches('#')
        .trim_end_matches(['-', '/']);
    let ok = !t.is_empty()
        && t.chars().count() <= limits::MAX_TAG_CHARS
        && t.chars().all(is_tag_char)
        && t.chars().any(|c| !c.is_ascii_digit());
    ok.then(|| t.to_lowercase())
}

fn is_tag_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '/')
}

/// Byte ranges of inline code spans: a backtick run closed by the next run of the same length on the same line.
fn code_spans(b: &[u8]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'`' {
            let n = b[i..].iter().take_while(|&&c| c == b'`').count();
            runs.push((i, n));
            i += n;
        } else {
            i += 1;
        }
    }
    // closer[k] = the next run after k with the same length, found right to left in O(runs)
    let mut next: HashMap<usize, usize> = HashMap::new();
    let mut closer = vec![None; runs.len()];
    for k in (0..runs.len()).rev() {
        closer[k] = next.insert(runs[k].1, k);
    }
    let mut spans = Vec::new();
    let mut k = 0;
    while k < runs.len() {
        match closer[k] {
            Some(j) => {
                spans.push((runs[k].0, runs[j].0 + runs[j].1));
                k = j + 1;
            }
            None => k += 1,
        }
    }
    spans
}

/// Scan `text` (one line, block markers already removed); `ctx_line` is the whole raw line for backlink context.
pub(crate) fn scan(text: &str, ctx_line: &str, no: usize, acc: &mut Acc) {
    let text = if text.len() > limits::MAX_LINE_SCAN {
        acc.p.truncated = true;
        let mut end = limits::MAX_LINE_SCAN;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    } else {
        text
    };
    let b = text.as_bytes();
    let spans = code_spans(b);
    let (mut si, mut i) = (0, 0);
    while i < b.len() {
        while si < spans.len() && spans[si].1 <= i {
            si += 1;
        }
        if si < spans.len() && spans[si].0 <= i {
            i = spans[si].1;
            continue;
        }
        match b[i] {
            b'\\' if matches!(b.get(i + 1), Some(b'[' | b']' | b'#' | b'\\')) => i += 2,
            b'[' if b.get(i + 1) == Some(&b'[') => match wikilink(text, i) {
                Some((end, w)) => {
                    add_wikilink(w, ctx_line, no, acc);
                    i = end;
                }
                None => i += 1,
            },
            b'[' => match link(text, i) {
                Some((end, t, u)) => {
                    add_link(t, u, i > 0 && b[i - 1] == b'!', no, acc);
                    i = end;
                }
                None => i += 1,
            },
            b'#' if i == 0 || b[i - 1].is_ascii_whitespace() || b[i - 1] == b'(' => {
                let run: usize = text[i + 1..]
                    .chars()
                    .take_while(|&c| is_tag_char(c))
                    .map(char::len_utf8)
                    .sum();
                acc.push_tag(&text[i + 1..i + 1 + run]);
                i += 1 + run;
            }
            _ => i += 1,
        }
    }
}

/// `[[inner]]` at `i`: (index after `]]`, inner). The inner text holds no `[`, `]` or backtick.
fn wikilink(text: &str, i: usize) -> Option<(usize, &str)> {
    let b = text.as_bytes();
    let stop = b.len().min(i + 2 + limits::MAX_WIKILINK_BYTES);
    for j in i + 2..stop {
        match b[j] {
            b']' if b.get(j + 1) == Some(&b']') => return Some((j + 2, &text[i + 2..j])),
            b'[' | b']' | b'`' => return None,
            _ => {}
        }
    }
    None
}

fn add_wikilink(inner: &str, ctx_line: &str, no: usize, acc: &mut Acc) {
    let (target, alias) = match inner.split_once('|') {
        Some((t, a)) => (t.trim_end_matches('\\'), Some(a.trim())),
        None => (inner, None),
    };
    let (title, heading) = match target.split_once('#') {
        Some((t, h)) => (t.trim(), Some(h.trim())),
        None => (target.trim(), None),
    };
    if title.is_empty() || title.chars().count() > limits::MAX_TITLE_CHARS {
        return;
    }
    let heading = heading
        .filter(|h| !h.is_empty())
        .map(|h| clip(h, limits::MAX_HEADING_CHARS).to_string());
    let title_norm = normalize_title(title);
    if acc
        .p
        .wikilinks
        .iter()
        .any(|w| w.title_norm == title_norm && w.heading == heading)
    {
        return;
    }
    if acc.p.wikilinks.len() >= limits::MAX_WIKILINKS {
        acc.p.truncated = true;
        return;
    }
    acc.p.wikilinks.push(Wikilink {
        title: title.to_string(),
        title_norm,
        heading,
        alias: alias
            .filter(|a| !a.is_empty())
            .map(|a| clip(a, limits::MAX_TITLE_CHARS).to_string()),
        context: clip(ctx_line.trim(), limits::MAX_CONTEXT_CHARS).to_string(),
        line: no,
    });
}

/// `[text](url)` at `i`: (index after `)`, text, url). Optional `"title"` after the url is accepted and dropped.
fn link(text: &str, i: usize) -> Option<(usize, &str, &str)> {
    let b = text.as_bytes();
    let stop = b.len().min(i + 1 + limits::MAX_LINK_TEXT_BYTES);
    let j = (i + 1..stop).find(|&j| matches!(b[j], b'[' | b']' | b'`'))?;
    if b[j] != b']' || b.get(j + 1) != Some(&b'(') {
        return None;
    }
    let start = j + 2;
    let stop = b.len().min(start + limits::MAX_URL_BYTES);
    let mut depth = 0usize;
    for k in start..stop {
        match b[k] {
            b'(' => depth += 1,
            b')' if depth == 0 => {
                return (k > start).then(|| (k + 1, &text[i + 1..j], &text[start..k]));
            }
            b')' => depth -= 1,
            b' ' | b'\t' if k > start => {
                // `[a](url "title")`: the next non-space byte opens a quote and a `)` follows within reach
                let rest = &text[k..];
                let q = rest.trim_start();
                let reach = clip(q, 300);
                if q.starts_with(['"', '\''])
                    && let Some(e) = reach.find(')')
                {
                    let close = k + (rest.len() - q.len()) + e;
                    return Some((close + 1, &text[i + 1..j], &text[start..k]));
                }
                return None;
            }
            b' ' | b'\t' | b'[' | b']' | b'<' | b'`' => return None,
            _ => {}
        }
    }
    None
}

fn add_link(label: &str, url: &str, image: bool, no: usize, acc: &mut Acc) {
    if let Some(sha) = url.strip_prefix(ATTACHMENT_SCHEME)
        && sha.len() == 64
        && sha.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        if acc.p.attachments.iter().any(|a| a == sha) {
            return;
        }
        if acc.p.attachments.len() >= limits::MAX_ATTACHMENTS {
            acc.p.truncated = true;
        } else {
            acc.p.attachments.push(sha.to_string());
        }
        return;
    }
    if acc.p.links.len() >= limits::MAX_LINKS {
        acc.p.truncated = true;
        return;
    }
    acc.p.links.push(Link {
        text: clip(label.trim(), limits::MAX_TITLE_CHARS).to_string(),
        url: url.to_string(),
        image,
        line: no,
    });
}

/// Rewrite the target title of every `[[old...]]` in one line (code spans and `\[` escapes skipped) to `new_title`,
/// keeping a `#Heading` and a `|alias` as written. `None` when nothing matched.
pub(crate) fn rename_in_line(line: &str, old_norm: &str, new_title: &str) -> Option<String> {
    let b = line.as_bytes();
    let spans = code_spans(b);
    let (mut si, mut i, mut last) = (0, 0, 0);
    let mut out = String::new();
    while i < b.len() {
        while si < spans.len() && spans[si].1 <= i {
            si += 1;
        }
        if si < spans.len() && spans[si].0 <= i {
            i = spans[si].1;
            continue;
        }
        match b[i] {
            b'\\' if matches!(b.get(i + 1), Some(b'[' | b']' | b'#' | b'\\')) => i += 2,
            b'[' if b.get(i + 1) == Some(&b'[') => match wikilink(line, i) {
                Some((end, inner)) => {
                    // the title is the text before the first `#` or `|`
                    let cut = inner.find(['#', '|']).unwrap_or(inner.len());
                    let title = inner[..cut].trim_end_matches('\\');
                    if !title.trim().is_empty() && normalize_title(title) == old_norm {
                        out.push_str(&line[last..i + 2]);
                        out.push_str(new_title);
                        out.push_str(&inner[cut..]);
                        out.push_str("]]");
                        last = end;
                    }
                    i = end;
                }
                None => i += 1,
            },
            _ => i += 1,
        }
    }
    if last == 0 {
        return None;
    }
    out.push_str(&line[last..]);
    Some(out)
}
