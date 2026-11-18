//! What a recording does to output text before it is written (Y3-02): echo-off prompts masked,
//! secrets redacted. Pure, no I/O. Security model: see `record.rs`.
//!
//! The rules here are recording-only and deliberately greedy (a false positive costs a masked word
//! in a replay; a miss writes a secret to disk): they are not the shared run-output pass.
//!
//! The unfinished line is held (bounded by `HOLD`) until its newline, so a secret split across
//! relay chunks is always seen whole. A held tail that outgrows the bound is masked, never
//! flushed. A PEM block is dropped from its `-----BEGIN ` line to its `-----END ...-----` line.

use ainkrad_proto::redact::{Redactor, url_creds};

/// The longest unfinished line held back; past it the rest of the line is masked.
const HOLD: usize = 8 * 1024;
/// The line tail looked at for a prompt.
const PROMPT_TAIL: usize = 256;
/// What is kept of a PEM body that has no line break yet (an `-----END ` marker is shorter).
const PEM_KEEP: usize = 64;
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_MARK: &str = "[redacted:pem_block]";
const LONG_MARK: &str = "[redacted:long_line]";

/// Words that, at the end of a line, make it a prompt for a secret typed with echo off.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "passwort",
    "contraseña",
    "パスワード",
    "pin",
    "otp",
    "secret",
    "token",
    "credential",
    "credentials",
    "apikey",
    "pw",
];
/// Phrases that do the same.
const SECRET_PHRASES: &[&str] = &[
    "mot de passe",
    "api key",
    "api-key",
    "2fa code",
    "authenticator code",
    "verification code",
    "one-time",
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
/// off: it ends like a prompt (`:`, `?`, `>`, a full-width colon, or "press enter") and names a
/// secret.
pub(crate) fn is_prompt(line: &str) -> bool {
    let plain = strip_ansi(line).to_lowercase();
    let t = plain.trim_end();
    if !(t.ends_with([':', '?', '>', '：']) || t.ends_with("press enter")) {
        return false;
    }
    SECRET_PHRASES.iter().any(|p| t.contains(p))
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

/// The byte index just after the `-----END ...-----` line marker in `s`, if it is whole.
fn pem_end(s: &str) -> Option<usize> {
    let e = s.find(PEM_END)? + PEM_END.len();
    Some(e + s[e..].find("-----")? + 5)
}

// ---- the recording-only passes -----------------------------------------------------------------

fn key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// `key=value` and `key: value` where the key contains pass, secret, token or key: the value goes.
fn key_values(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if !matches!(b[i], b'=' | b':') || b[i + 1..].starts_with(b"//") {
            i += 1;
            continue;
        }
        let mut end = i;
        while end > copied && matches!(b[end - 1], b' ' | b'\t' | b'"' | b'\'') {
            end -= 1;
        }
        let mut start = end;
        while start > copied && key_byte(b[start - 1]) {
            start -= 1;
        }
        let key = s[start..end].to_ascii_lowercase();
        let secret = ["pass", "secret", "token", "key"]
            .iter()
            .any(|w| key.contains(w));
        let mut v = i + 1;
        while v < b.len() && matches!(b[v], b' ' | b'\t') {
            v += 1;
        }
        let mut e = v;
        if matches!(b.get(v), Some(b'"' | b'\'')) {
            e = v + 1;
            while e < b.len() && b[e] != b[v] && b[e] != b'\n' {
                e += 1;
            }
            e = (e + 1).min(b.len());
        } else {
            while e < b.len()
                && !(b[e].is_ascii_whitespace() || matches!(b[e], b',' | b';' | b'&' | b'}'))
            {
                e += 1;
            }
        }
        if secret && e > v && !s[v..e].starts_with("[redacted") {
            out.push_str(&s[copied..v]);
            out.push_str("[redacted:secret_value]");
            (copied, i) = (e, e);
        } else {
            i += 1;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// `scheme://user@host` and `scheme://user:password@host`: the whole userinfo goes.
fn userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("://") {
        let (head, tail) = rest.split_at(p + 3);
        out.push_str(head);
        let auth = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\''))
            .unwrap_or(tail.len());
        match tail[..auth].rfind('@') {
            Some(at) if at > 0 => {
                out.push_str("[redacted:userinfo]");
                rest = &tail[at..];
            }
            _ => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

/// `-psecret` (mysql style): a word that starts `-p` and goes on.
fn dash_p(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = true;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if prev_space && s[i..].starts_with("-p") {
            let after = s[i + 2..].chars().next();
            if after.is_some_and(|a| !a.is_whitespace() && a != '-') {
                let end = s[i..].find(char::is_whitespace).map_or(s.len(), |n| i + n);
                out.push_str("-p[redacted:password]");
                while it.peek().is_some_and(|(j, _)| *j < end) {
                    it.next();
                }
                prev_space = false;
                continue;
            }
        }
        prev_space = c.is_whitespace();
        out.push(c);
    }
    out
}

fn entropy(s: &[u8]) -> f64 {
    let mut n = [0u32; 256];
    for b in s {
        n[*b as usize] += 1;
    }
    let len = s.len() as f64;
    n.iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Any run of 20 or more key-ish characters that looks random (a high entropy, and digits or
/// mixed case): a token the shape list does not know.
fn random_runs(s: &str) -> String {
    let b = s.as_bytes();
    let in_run = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'_' | b'=' | b'-');
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if !in_run(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && in_run(b[i]) {
            i += 1;
        }
        let run = &b[start..i];
        let mixed = run.iter().any(u8::is_ascii_digit)
            || (run.iter().any(u8::is_ascii_uppercase) && run.iter().any(u8::is_ascii_lowercase));
        if run.len() >= 20 && mixed && entropy(run) >= 3.5 {
            out.push_str(&s[copied..start]);
            out.push_str("[redacted:high_entropy]");
            copied = i;
        }
    }
    out.push_str(&s[copied..]);
    out
}

// ---- the scrubber ------------------------------------------------------------------------------

/// Output text on its way into the cast.
pub struct Scrub {
    red: Redactor,
    carry: Vec<u8>,
    /// The unfinished line; in a PEM block, the last few bytes of it.
    line: String,
    /// An echo-off prompt was seen: everything up to the next `\n` is dropped.
    masked: bool,
    /// Inside a PEM block: everything up to its END line is dropped.
    pem: bool,
    /// The held line outgrew `HOLD`: the rest of it is dropped.
    over: bool,
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
            pem: false,
            over: false,
        }
    }

    /// `text` with every secret shape and recording-only rule applied.
    fn clean(&self, text: &str) -> String {
        let t = self.red.text(text);
        random_runs(&dash_p(&key_values(&userinfo(&url_creds(&t)))))
    }

    /// One segment of output (up to and including a `\n` when `done`).
    fn seg(&mut self, seg: &str, done: bool, out: &mut String) {
        // Masking and overflow end at `\n` only: a `\r` rewrites the line, it does not end it.
        if self.masked || self.over {
            if done {
                out.push_str(if seg.ends_with("\r\n") { "\r\n" } else { "\n" });
                (self.masked, self.over) = (false, false);
            }
            return;
        }
        self.line.push_str(seg);
        loop {
            if self.pem {
                let Some(e) = pem_end(&self.line) else {
                    if done {
                        self.line.clear();
                    } else if self.line.len() > PEM_KEEP {
                        let mut cut = self.line.len() - PEM_KEEP;
                        while !self.line.is_char_boundary(cut) {
                            cut += 1;
                        }
                        self.line.drain(..cut);
                    }
                    return;
                };
                self.line.drain(..e);
                self.pem = false;
            }
            let Some(b) = self.line.find(PEM_BEGIN) else {
                break;
            };
            let tail = self.line.split_off(b);
            let before = std::mem::replace(&mut self.line, tail);
            out.push_str(&self.clean(&before));
            out.push_str(PEM_MARK);
            self.pem = true;
        }
        if done {
            let line = std::mem::take(&mut self.line);
            out.push_str(&self.clean(&line));
        } else if is_prompt(tail(&self.line, PROMPT_TAIL)) {
            let line = std::mem::take(&mut self.line);
            out.push_str(&self.clean(&line));
            self.masked = true;
        } else if self.line.len() > HOLD {
            self.line.clear();
            out.push_str(LONG_MARK);
            self.over = true;
        }
    }

    /// The scrubbed text of `bytes`: whole lines only; the unfinished line is held.
    pub fn push(&mut self, bytes: &[u8]) -> String {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(bytes);
        self.carry = buf.split_off(buf.len() - incomplete_tail(&buf));
        let text = String::from_utf8_lossy(&buf);
        let mut out = String::new();
        for seg in text.split_inclusive('\n') {
            self.seg(seg, seg.ends_with('\n'), &mut out);
        }
        out
    }

    /// The held line, scrubbed: at the end of the recording, or when the output went quiet. A PEM
    /// body is never released.
    pub fn release(&mut self) -> String {
        let line = std::mem::take(&mut self.line);
        if self.pem {
            return String::new();
        }
        self.clean(&line)
    }

    /// Bytes were lost between two pushes (the queue was full): a half character before the gap
    /// cannot be finished, and the held line is let go.
    pub fn gap(&mut self) -> String {
        self.carry.clear();
        self.release()
    }
}

/// The last `n` bytes of `s`, on a char boundary.
fn tail(s: &str, n: usize) -> &str {
    let mut from = s.len().saturating_sub(n);
    while !s.is_char_boundary(from) {
        from += 1;
    }
    &s[from..]
}

#[cfg(test)]
mod tests {
    use ainkrad_proto::redact::PLANTED;

    use super::*;

    fn all(s: &mut Scrub, chunks: &[&str]) -> String {
        let mut out: String = chunks.iter().map(|c| s.push(c.as_bytes())).collect();
        out.push_str(&s.release());
        out
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
            "Passwort: ",
            "Mot de passe : ",
            "Contraseña: ",
            "パスワード: ",
            "パスワード：",
            "Password> ",
            "Enter password and press enter",
            "API key: ",
            "2FA code: ",
            "Authenticator code: ",
            "credential: ",
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
    fn a_pem_key_split_across_chunks_is_dropped_whole() {
        let mut s = Scrub::new();
        let out = all(
            &mut s,
            &[
                "cat id\r\n-----BE",
                "GIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\r\nQyNTUx",
                "OQAAACDmoreSecretBodyhere123\r\n-----END OPENSSH PRIV",
                "ATE KEY-----\r\nuser@h:~$ ",
            ],
        );
        assert!(!out.contains("b3Blbn") && !out.contains("QyNTUx") && !out.contains("moreSecret"));
        assert!(out.contains("cat id") && out.contains("[redacted:pem_block]"));
        assert!(
            out.contains("user@h:~$ "),
            "text after the END line is kept"
        );
    }

    #[test]
    fn a_bearer_token_split_at_the_space_is_redacted() {
        let mut s = Scrub::new();
        let out = all(
            &mut s,
            &[
                "curl -H 'Authorization: Bearer",
                " abcDEF0123456789xyzTOKEN'\r\n",
            ],
        );
        assert!(!out.contains("abcDEF0123456789"), "{out}");
        assert!(out.contains("[redacted:"), "{out}");
    }

    #[test]
    fn a_held_line_over_the_bound_is_masked_not_flushed() {
        let mut s = Scrub::new();
        let big = "a1".repeat(HOLD);
        let out = s.push(big.as_bytes());
        assert_eq!(out, LONG_MARK);
        assert_eq!(s.push(b"more of it"), "", "the rest of the line is dropped");
        assert_eq!(s.push(b" end\r\nnext\r\n"), "\r\nnext\r\n");
    }

    #[test]
    fn masking_ends_at_a_line_feed_not_a_carriage_return() {
        let mut s = Scrub::new();
        let out = all(&mut s, &["Password: ", "hun", "ter2\r", "more\r\nok\r\n"]);
        assert!(!out.contains("hunter2") && !out.contains("more"), "{out:?}");
        assert!(out.starts_with("Password: ") && out.ends_with("ok\r\n"));
    }

    #[test]
    fn recording_only_rules() {
        let mut s = Scrub::new();
        let out = all(
            &mut s,
            &[
                "db_password=hunter2 api-key: abc123 Token = \"s p a c e\"\r\n",
                "git clone https://bob@example.com/x.git https://bob:pw@example.com/y.git\r\n",
                "mysql -psecretpw -u root -p -h x\r\n",
                "x aB3dE6gH9jK2mN5pQ8sT1vW4yZ7 y\r\n",
            ],
        );
        for leak in [
            "hunter2",
            "abc123",
            "s p a c e",
            "bob",
            "secretpw",
            "aB3dE6gH9jK2",
        ] {
            assert!(!out.contains(leak), "{leak}: {out}");
        }
        assert!(out.contains("-u root -p -h x"), "{out}");
        assert!(out.contains("example.com/x.git"), "{out}");
    }

    #[test]
    fn every_planted_secret_is_redacted() {
        for (name, secret) in PLANTED {
            let mut s = Scrub::new();
            let out = all(&mut s, &[&format!("x {secret} y\r\n")]);
            assert!(!out.contains(secret), "{name}: {out}");
        }
    }
}
