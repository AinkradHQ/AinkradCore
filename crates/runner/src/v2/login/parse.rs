//! What the sign-in CLI prints, read as text (KAN-441 L2). The PTY output is raw: colour and
//! cursor codes, CR and LF, a line that was wrapped by the terminal width, and reads that cut
//! anywhere. [`Screen`] turns it into lines; [`find_url`] and [`find_token`] pick the two things
//! the runner wants out of them; [`redact`] is the one way any text that came from the child (or
//! holds the code) leaves this module.
//!
//! Nothing here logs. A [`Screen`] holds the token once it was printed, so it is wiped on drop.

use zeroize::{Zeroize, Zeroizing};

/// The start of a Claude subscription token.
pub const TOKEN_PREFIX: &str = "sk-ant-oat01-";
/// What follows the prefix, at least (a real token is far longer).
const TOKEN_MIN: usize = 20;
/// Lines kept: a sign-in prints a few dozen.
const KEEP_LINES: usize = 400;

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Text,
    Esc,
    Csi,
    Osc,
    OscEsc,
    /// `ESC (` `ESC )` and the like: one more byte belongs to the sequence.
    One,
}

/// Terminal output as lines.
///
/// A physical line that fills the terminal width and ends in an open URL or token is joined to
/// the next one when that has no space (the terminal wrapped it). ponytail: a URL that ends
/// exactly at the width, followed by a one-word line, is glued to it; the runner asks for a very
/// wide terminal so this needs a URL longer than that.
pub struct Screen {
    cols: usize,
    st: St,
    cur: Vec<u8>,
    cr: bool,
    lines: Vec<String>,
    open: bool,
}

impl Screen {
    pub fn new(cols: usize) -> Self {
        Self {
            cols,
            st: St::Text,
            cur: Vec::new(),
            cr: false,
            lines: Vec::new(),
            open: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        match self.st {
            St::Esc => {
                self.st = match b {
                    b'[' => St::Csi,
                    b']' => St::Osc,
                    b'(' | b')' | b'*' | b'+' | b'#' => St::One,
                    _ => St::Text,
                }
            }
            St::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    self.st = St::Text;
                }
            }
            St::Osc => match b {
                0x07 => self.st = St::Text,
                0x1b => self.st = St::OscEsc,
                _ => {}
            },
            St::OscEsc => self.st = if b == b'\\' { St::Text } else { St::Osc },
            St::One => self.st = St::Text,
            St::Text => match b {
                0x1b => self.st = St::Esc,
                b'\n' => {
                    self.cr = false;
                    self.end_line();
                }
                b'\r' => self.cr = true,
                0x08 => {
                    self.cur.pop();
                }
                b'\t' => self.put(b' '),
                0x00..=0x1f | 0x7f => {}
                _ => self.put(b),
            },
        }
    }

    fn put(&mut self, b: u8) {
        if self.cr {
            // A lone CR sends the cursor home: what follows overwrites the line.
            self.cur.clear();
            self.cr = false;
        }
        self.cur.push(b);
    }

    fn end_line(&mut self) {
        let mut raw = String::from_utf8_lossy(&self.cur).into_owned();
        self.cur.zeroize();
        self.cur.clear();
        let p = raw.trim_end();
        let tail = p.trim_start();
        if self.open && !tail.is_empty() && !tail.contains(' ') {
            if let Some(last) = self.lines.last_mut() {
                last.push_str(tail);
            }
        } else {
            self.lines.push(p.to_owned());
        }
        let full = p.chars().count() + 1 >= self.cols;
        self.open = full
            && self.lines.last().is_some_and(|l| {
                let w = l.rsplit(' ').next().unwrap_or_default();
                w.starts_with("http://") || w.starts_with("https://") || w.starts_with("sk-ant-")
            });
        raw.zeroize();
        if self.lines.len() > KEEP_LINES {
            let n = self.lines.len() - KEEP_LINES;
            for l in &mut self.lines[..n] {
                l.zeroize();
            }
            self.lines.drain(..n);
        }
    }

    /// Ends the line being written (output went quiet), and any join still open.
    pub fn flush(&mut self) {
        if !self.cur.is_empty() {
            self.end_line();
        }
        self.open = false;
    }

    /// The lines that are final: the last is left out while the terminal may still continue it.
    pub fn done(&self) -> &[String] {
        &self.lines[..self.lines.len() - usize::from(self.open)]
    }

    /// The line being written, which a prompt is (no newline after it).
    pub fn tail(&self) -> String {
        String::from_utf8_lossy(&self.cur).into_owned()
    }

    /// Whether the line being written is empty.
    pub fn idle(&self) -> bool {
        self.cur.is_empty() && !self.open
    }

    /// Forgets everything seen.
    pub fn wipe(&mut self) {
        self.cur.zeroize();
        self.lines.zeroize();
        self.lines.clear();
        self.open = false;
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The first `http(s)://` word in `lines`, as printed. Whether it is Claude's is the Core's call
/// (it checks the host); the runner never opens it.
pub fn find_url(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .flat_map(|l| l.split_whitespace())
        .find(|w| w.starts_with("https://") || w.starts_with("http://"))
        .map(str::to_owned)
}

/// Whether the text the child printed after the URL is asking for the code.
pub fn asks_for_code(lines: &[String], tail: &str) -> bool {
    lines
        .iter()
        .map(String::as_str)
        .chain([tail])
        .filter(|l| !l.contains("://"))
        .any(|l| {
            let l = l.to_ascii_lowercase();
            l.contains("code") && (l.contains("paste") || l.contains("enter") || l.contains("here"))
        })
}

/// The first `sk-ant-oat01-…` in `lines`.
pub fn find_token(lines: &[String]) -> Option<Zeroizing<String>> {
    for l in lines {
        let Some(at) = l.find(TOKEN_PREFIX) else {
            continue;
        };
        let rest = &l[at + TOKEN_PREFIX.len()..];
        let n = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            .count();
        if n >= TOKEN_MIN {
            return Some(Zeroizing::new(
                l[at..at + TOKEN_PREFIX.len() + n].to_owned(),
            ));
        }
    }
    None
}

/// `text` with every `secrets` (when not empty) and anything shaped like an Anthropic key
/// (`sk-ant-…`) replaced by `[redacted]`.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        out = out.replace(s, "[redacted]");
    }
    let mut res = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(i) = rest.find("sk-ant-") {
        res.push_str(&rest[..i]);
        res.push_str("[redacted]");
        let tail = &rest[i + "sk-ant-".len()..];
        let n = tail
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            .count();
        rest = &tail[n..];
    }
    res.push_str(rest);
    res
}

/// The last non-empty line of `lines`, redacted and shortened: what an error may say of the
/// child's output.
pub fn last_line(lines: &[String], tail: &str, secrets: &[&str]) -> Option<String> {
    let l = [tail]
        .into_iter()
        .chain(lines.iter().rev().map(String::as_str))
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    Some(redact(l, secrets).chars().take(120).collect())
}
