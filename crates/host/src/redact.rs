//! Log redaction for the helper: one `Redactor` (shapes, from `ainkrad-proto`), the shared
//! secret-name pass, a text form of that pass for `key=value` lines, and PEM masking that spans
//! journal entries. **Redact first, truncate after**: a cut made first could split a key shape and
//! let half of it through.
//!
//! Known residual: values with no shape (connection tokens, AWS secret keys on their own) cannot
//! be masked here, and the helper does not hold the secrets. That is why runner and backup logs
//! need a step-up in the Core.

pub use ainkrad_proto::redact::one;
// Only the tests reach the other passes through this module.
#[cfg(test)]
use ainkrad_proto::redact::{names_text, url_creds};

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM: &str = "[redacted:pem_block]";
/// One log line is cut to this many bytes after redaction.
pub const LINE_CAP: usize = 4096;

/// One entry is cut to this many bytes before anything is redacted, so the redaction work is
/// bounded however long a line the Core prints.
pub const PRE_CUT: usize = 64 * 1024;

/// Cuts an over-long entry to [`PRE_CUT`] bytes and masks whatever was cut off.
///
/// The cut backs up to the last whitespace anywhere in the kept part, so the front of a token whose
/// tail was cut is dropped with it; an entry over 64 KiB with no whitespace at all is reduced to
/// the marker. A `-----BEGIN ` header split by the cut is dropped too, and one that is whole but has
/// lost its `END` is masked to the end by [`pem_across`]. The marker stands for the cut part.
pub fn pre_cut(mut s: String) -> String {
    if s.len() <= PRE_CUT {
        return s;
    }
    let mut n = PRE_CUT;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    n = s[..n].rfind(char::is_whitespace).unwrap_or(0);
    s.truncate(n);
    for k in (5..PEM_BEGIN.len()).rev() {
        if s.ends_with(&PEM_BEGIN[..k]) {
            s.truncate(s.len() - k);
            break;
        }
    }
    s.push_str("[redacted:cut]");
    s
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
