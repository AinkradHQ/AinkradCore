//! The cast: what a recording holds and how it is written to a file (Y3-02). Pure, no I/O: the
//! scrubbing of output text (echo-off prompts masked, secrets redacted), the asciicast v2 lines,
//! and the framed zstd + age blocks. Security model: see `record.rs`.

use std::io::{Read, Write};

use age::x25519::{Identity, Recipient};
use ainkrad_core_server::api::v1::TerminalSize;
use ainkrad_proto::redact::Redactor;

/// A block is written when this much cast text is waiting (the writer also flushes on a timer).
pub const BLOCK: usize = 32 * 1024;
/// The most plaintext one recording keeps; it ends with a marker line.
const MAX_PLAIN: usize = 64 * 1024 * 1024;
/// The most one block may decompress to (a bomb guard when replaying).
const MAX_BLOCK: usize = 8 * 1024 * 1024;
/// The longest unfinished word held back, and the line tail kept for prompt detection.
const WORD_MAX: usize = 512;
const LINE_MAX: usize = 256;
const STOPPED: &str = "\r\n[recording stopped: size limit]\r\n";

// ---- text scrubbing ----------------------------------------------------------------------------

/// Words that, before a closing `:` or `?`, make a line a prompt for a secret.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "pin",
    "otp",
    "secret",
    "token",
    "pw",
];

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            it.next();
            for d in it.by_ref() {
                if ('@'..='~').contains(&d) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether `line` (the unfinished last line of output) is a prompt for something typed with echo
/// off: it ends with `:` or `?` and names a secret.
fn is_prompt(line: &str) -> bool {
    let plain = strip_ansi(line).to_lowercase();
    let t = plain.trim_end();
    if !(t.ends_with(':') || t.ends_with('?')) {
        return false;
    }
    t.contains("verification code")
        || t.contains("one-time")
        || t.split(|c: char| !c.is_alphanumeric())
            .any(|w| SECRET_WORDS.contains(&w))
}

/// How many bytes at the end of `buf` start a UTF-8 sequence that is not finished yet.
fn incomplete_tail(buf: &[u8]) -> usize {
    for k in 1..=buf.len().min(3) {
        let b = buf[buf.len() - k];
        if b & 0xC0 == 0x80 {
            continue; // a continuation byte: look further back for its start
        }
        let need = match b {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        return if need > k { k } else { 0 };
    }
    0
}

/// Output text on its way into the cast: prompts masked, secrets redacted.
pub struct Scrub {
    red: Redactor,
    carry: Vec<u8>,
    line: String,
    masked: bool,
    word: String,
}

impl Default for Scrub {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrub {
    pub fn new() -> Self {
        Self {
            red: Redactor::new(),
            carry: Vec::new(),
            line: String::new(),
            masked: false,
            word: String::new(),
        }
    }

    /// Bytes were lost between two pushes (the queue was full): a half character before the gap
    /// cannot be finished.
    pub fn gap(&mut self) {
        self.carry.clear();
    }

    /// Drops what an echo-off prompt is waiting for, up to and including no more than the line
    /// break that ends it.
    fn mask(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for seg in text.split_inclusive(['\n', '\r']) {
            let ends = seg.ends_with(['\n', '\r']);
            if self.masked {
                if ends {
                    self.masked = false;
                    self.line.clear();
                    out.extend(seg.chars().last());
                }
                continue;
            }
            out.push_str(seg);
            if ends {
                self.line.clear();
                continue;
            }
            self.line.push_str(seg);
            if self.line.len() > LINE_MAX {
                let mut cut = self.line.len() - LINE_MAX;
                while !self.line.is_char_boundary(cut) {
                    cut += 1;
                }
                self.line.drain(..cut);
            }
            self.masked = is_prompt(&self.line);
        }
        out
    }

    /// The scrubbed text of `bytes`, less the unfinished last word (see `release`).
    pub fn push(&mut self, bytes: &[u8]) -> String {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(bytes);
        self.carry = buf.split_off(buf.len() - incomplete_tail(&buf));
        let visible = self.mask(&String::from_utf8_lossy(&buf));
        let mut all = std::mem::take(&mut self.word);
        all.push_str(&visible);
        let mut cut = all
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace() || c.is_control())
            .map_or(0, |(i, c)| i + c.len_utf8());
        if all.len() - cut > WORD_MAX {
            cut = all.len();
        }
        self.word = all.split_off(cut);
        self.red.text(&all)
    }

    /// The held word, redacted: at the end of the recording, or when the output went quiet.
    pub fn release(&mut self) -> String {
        let w = std::mem::take(&mut self.word);
        self.red.text(&w)
    }
}

// ---- the cast ----------------------------------------------------------------------------------

/// An asciicast v2 file being written: a header line, then `[seconds, "o", text]` lines.
pub struct Cast {
    scrub: Scrub,
    out: Vec<u8>,
    /// The terminal's output offset already recorded (a re-attach is replayed history).
    next: u64,
    plain: usize,
    capped: bool,
}

impl Cast {
    pub fn new(size: TerminalSize, started_unix: i64) -> Self {
        let head = serde_json::json!({"version": 2, "width": size.cols, "height": size.rows,
            "timestamp": started_unix});
        Self {
            scrub: Scrub::new(),
            out: format!("{head}\n").into_bytes(),
            next: 0,
            plain: 0,
            capped: false,
        }
    }

    fn event(&mut self, at: f64, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.plain + text.len() > MAX_PLAIN {
            if !self.capped {
                self.capped = true;
                let line = serde_json::to_string(&(at, "o", STOPPED)).unwrap_or_default();
                self.out.extend_from_slice(line.as_bytes());
                self.out.push(b'\n');
            }
            return;
        }
        self.plain += text.len();
        let at = (at * 1e6).round() / 1e6;
        if let Ok(line) = serde_json::to_string(&(at, "o", text)) {
            self.out.extend_from_slice(line.as_bytes());
            self.out.push(b'\n');
        }
    }

    /// Output bytes that belong at terminal offset `offset`, seen `at` seconds into the session.
    pub fn push(&mut self, offset: u64, data: &[u8], at: f64) {
        let end = offset.saturating_add(data.len() as u64);
        if end <= self.next {
            return; // already recorded: the history a later attach is replayed
        }
        let data = if offset < self.next {
            &data[usize::try_from(self.next - offset)
                .unwrap_or(0)
                .min(data.len())..]
        } else {
            if offset > self.next {
                self.scrub.gap();
            }
            data
        };
        self.next = end;
        let text = self.scrub.push(data);
        self.event(at, &text);
    }

    /// The output went quiet: the held word is whole as far as we will ever know.
    pub fn idle(&mut self, at: f64) {
        let text = self.scrub.release();
        self.event(at, &text);
    }

    pub fn pending(&self) -> usize {
        self.out.len()
    }

    /// The cast lines waiting to be written.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }
}

// ---- blocks on disk ----------------------------------------------------------------------------

/// One block: zstd, then age to `to`, framed with its length.
pub fn seal_block(plain: &[u8], to: &Recipient) -> std::io::Result<Vec<u8>> {
    let z = zstd::bulk::compress(plain, 3)?;
    let mut sealed = Vec::new();
    let enc = age::Encryptor::with_recipients(std::iter::once(to as &dyn age::Recipient))
        .map_err(std::io::Error::other)?;
    let mut w = enc.wrap_output(&mut sealed)?;
    w.write_all(&z)?;
    w.finish()?;
    let len = u32::try_from(sealed.len()).map_err(std::io::Error::other)?;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(&sealed);
    Ok(framed)
}

/// The whole cast of a recording file. A torn last block (a crash mid-write) ends it quietly.
pub fn open_cast(file: &[u8], with: &Identity) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut p = 0;
    while let Some(head) = file.get(p..p + 4) {
        let n = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let Some(blob) = file.get(p + 4..p + 4 + n) else {
            break;
        };
        let d = age::Decryptor::new(blob).map_err(|e| e.to_string())?;
        let mut r = d
            .decrypt(std::iter::once(with as &dyn age::Identity))
            .map_err(|e| e.to_string())?;
        let mut z = Vec::new();
        r.read_to_end(&mut z).map_err(|e| e.to_string())?;
        out.extend(zstd::bulk::decompress(&z, MAX_BLOCK).map_err(|e| e.to_string())?);
        p += 4 + n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ainkrad_proto::redact::PLANTED;

    use super::*;

    const SIZE: TerminalSize = TerminalSize { rows: 24, cols: 80 };

    fn texts(cast: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(cast)
            .lines()
            .skip(1)
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                assert_eq!(v[1], "o", "only output events exist");
                v[2].as_str().unwrap().to_owned()
            })
            .collect()
    }

    #[test]
    fn echo_off_prompts_are_recognised_and_ordinary_lines_are_not() {
        for p in [
            "Password: ",
            "[sudo] password for ahmed: ",
            "Enter passphrase for key '/home/a/.ssh/id_ed25519': ",
            "\x1b[1mPassword:\x1b[0m ",
            "Verification code: ",
            "Enter PIN: ",
            "MFA token? ",
        ] {
            assert!(is_prompt(p), "{p:?}");
        }
        for p in [
            "user@host:~$ ",
            "spinning: ",
            "password reset done",
            "Enter your name: ",
        ] {
            assert!(!is_prompt(p), "{p:?}");
        }
    }

    #[test]
    fn what_follows_a_password_prompt_is_never_recorded() {
        let mut c = Cast::new(SIZE, 0);
        c.push(0, b"[sudo] password for bob: ", 0.1);
        // a remote that echoes: the typed characters come back one by one
        let typed = b"hunter2-correct-horse";
        let mut off = 25;
        for b in typed {
            c.push(off, &[*b], 0.2);
            off += 1;
        }
        c.push(off, b"\r\nSorry, try again.\r\n", 0.3);
        c.idle(0.4);
        let all = texts(&c.take()).join("");
        assert!(all.contains("[sudo] password for bob: "));
        assert!(!all.contains("hunter2") && !all.contains("horse"), "{all}");
        assert!(all.contains("Sorry, try again."));
    }

    #[test]
    fn a_secret_the_remote_prints_is_redacted_even_when_split_across_chunks() {
        let (_, secret) = PLANTED[0];
        let (a, b) = secret.split_at(12);
        let mut c = Cast::new(SIZE, 0);
        c.push(0, format!("token is {a}").as_bytes(), 0.1);
        c.push(a.len() as u64 + 9, format!("{b}\r\n").as_bytes(), 0.2);
        c.idle(0.3);
        let all = texts(&c.take()).join("");
        assert!(!all.contains(a) && !all.contains(b), "{all}");
        assert!(all.contains("[redacted:"), "{all}");
    }

    #[test]
    fn every_planted_secret_is_redacted() {
        for (name, secret) in PLANTED {
            let mut c = Cast::new(SIZE, 0);
            c.push(0, format!("x {secret} y\r\n").as_bytes(), 0.1);
            let all = texts(&c.take()).join("");
            assert!(!all.contains(secret), "{name}: {all}");
        }
    }

    #[test]
    fn replayed_history_is_recorded_once_and_a_split_character_is_whole() {
        let mut c = Cast::new(SIZE, 0);
        let text = "caf\u{e9} ok\r\n".as_bytes();
        c.push(0, &text[..4], 0.1); // ends inside the two-byte e-acute
        c.push(4, &text[4..], 0.2);
        c.push(0, text, 0.3); // a fresh attach is replayed everything
        c.idle(0.4);
        let all = texts(&c.take()).join("");
        assert_eq!(all, "caf\u{e9} ok\r\n");
    }

    #[test]
    fn blocks_round_trip_and_only_the_identity_opens_them() {
        let id = Identity::generate();
        let mut c = Cast::new(SIZE, 1_700_000_000);
        c.push(0, b"hello\r\n", 0.5);
        let plain = c.take();
        let mut file = seal_block(&plain, &id.to_public()).unwrap();
        file.extend(seal_block(b"[1.0,\"o\",\"more\\r\\n\"]\n", &id.to_public()).unwrap());
        let full = open_cast(&file, &id).unwrap();
        assert!(full.starts_with(&plain));
        assert!(String::from_utf8_lossy(&full).contains("more"));
        assert!(!file.windows(5).any(|w| w == b"hello"), "plaintext on disk");
        assert!(open_cast(&file, &Identity::generate()).is_err());
        // a torn last block (a crash) leaves the earlier ones readable
        let torn = &file[..file.len() - 10];
        assert!(open_cast(torn, &id).unwrap().starts_with(&plain));
    }

    #[test]
    fn the_header_names_no_host_and_no_input_event_exists() {
        let c = Cast::new(SIZE, 42);
        let head: serde_json::Value =
            serde_json::from_slice(c.out.split(|b| *b == b'\n').next().unwrap()).unwrap();
        let keys: std::collections::BTreeSet<&str> = head
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["height", "timestamp", "version", "width"]
                .into_iter()
                .collect()
        );
        assert_eq!(head["timestamp"], 42);
    }
}
