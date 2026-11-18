//! The cast: what a recording holds and how it is written to a file (Y3-02). Pure, no I/O: the
//! scrubbing of output text (echo-off prompts masked, secrets redacted), the asciicast v2 lines,
//! and the framed zstd + age blocks. Security model: see `record.rs`.

use std::io::{Read, Write};

use crate::scrub::Scrub;

use age::x25519::{Identity, Recipient};
use ainkrad_core_server::api::v1::TerminalSize;

/// A block is written when this much cast text is waiting (the writer also flushes on a timer).
pub const BLOCK: usize = 32 * 1024;
/// The most plaintext one recording keeps; it ends with a marker line.
const MAX_PLAIN: usize = 64 * 1024 * 1024;
/// The most one block may decompress to (a bomb guard when replaying).
const MAX_BLOCK: usize = 8 * 1024 * 1024;
const STOPPED: &str = "\r\n[recording stopped: size limit]\r\n";
const GAP: &str = "\r\n[gap]\r\n";
/// The most a replay returns, header and markers included.
pub const REPLAY_MAX: usize = MAX_PLAIN + 1024 * 1024;

// ---- the cast ----------------------------------------------------------------------------------

/// An asciicast v2 file being written: a header line, then `[seconds, "o", text]` lines.
pub struct Cast {
    scrub: Scrub,
    out: Vec<u8>,
    /// The terminal's output offset already recorded (a re-attach is replayed history).
    next: u64,
    plain: usize,
    capped: bool,
    paused: bool,
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
            paused: false,
        }
    }

    fn event(&mut self, at: f64, text: &str) {
        if text.is_empty() {
            return;
        }
        let at = (at * 1e6).round() / 1e6;
        let Ok(line) = serde_json::to_string(&(at, "o", text)) else {
            return;
        };
        // The escaped line is what is stored and what a replay returns: that is what is counted.
        if self.plain + line.len() + 1 > MAX_PLAIN {
            if !self.capped {
                self.capped = true;
                let stop = serde_json::to_string(&(at, "o", STOPPED)).unwrap_or_default();
                self.out.extend_from_slice(stop.as_bytes());
                self.out.push(b'\n');
            }
            return;
        }
        self.plain += line.len() + 1;
        self.out.extend_from_slice(line.as_bytes());
        self.out.push(b'\n');
    }

    /// Recording is paused or resumed: the held line goes, a marker says so, and while paused
    /// output is only counted (never scrubbed or written).
    pub fn pause(&mut self, on: bool, at: f64) {
        if on == self.paused {
            return;
        }
        if on {
            let t = self.scrub.release();
            self.event(at, &t);
        }
        self.paused = on;
        self.event(
            at,
            if on {
                "\r\n[recording paused]\r\n"
            } else {
                "\r\n[recording resumed]\r\n"
            },
        );
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
            if offset > self.next && !self.paused {
                // Bytes were lost (a full queue, or a snapshot): say so, never glue lines together.
                let held = self.scrub.gap();
                self.event(at, &held);
                self.event(at, GAP);
            }
            data
        };
        self.next = end;
        if self.paused {
            return;
        }
        let text = self.scrub.push(data);
        self.event(at, &text);
    }

    /// The output went quiet. Nothing is released: a half-typed secret (`export TOKEN=abc`, a
    /// pause, `def`) must not leak its tail. The line is held (capped by the scrubber) until its
    /// newline, a gap, or `finish`.
    pub fn idle(&mut self, _at: f64) {}

    /// The recording ends: the held line is scrubbed and let go.
    pub fn finish(&mut self, at: f64) {
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

/// The blocks of a recording file, one at a time, with the total capped at `REPLAY_MAX`. A torn
/// last block (a crash mid-write) ends it quietly.
pub struct Blocks<R> {
    r: R,
    total: usize,
}

impl<R: Read> Blocks<R> {
    pub fn new(r: R) -> Self {
        Self { r, total: 0 }
    }

    pub fn next(&mut self, with: &Identity) -> Result<Option<Vec<u8>>, String> {
        let mut head = [0u8; 4];
        if self.r.read_exact(&mut head).is_err() {
            return Ok(None);
        }
        let n = u32::from_be_bytes(head) as usize;
        if n > MAX_BLOCK {
            return Err("a block is larger than any block written".to_owned());
        }
        let mut blob = vec![0; n];
        if self.r.read_exact(&mut blob).is_err() {
            return Ok(None);
        }
        let d = age::Decryptor::new(&blob[..]).map_err(|e| e.to_string())?;
        let mut r = d
            .decrypt(std::iter::once(with as &dyn age::Identity))
            .map_err(|e| e.to_string())?;
        let mut z = Vec::new();
        r.read_to_end(&mut z).map_err(|e| e.to_string())?;
        let room = REPLAY_MAX.saturating_sub(self.total).min(MAX_BLOCK);
        if room == 0 {
            return Err("the recording is larger than a replay returns".to_owned());
        }
        let plain = zstd::bulk::decompress(&z, room).map_err(|e| e.to_string())?;
        self.total += plain.len();
        Ok(Some(plain))
    }
}

/// The whole cast of a recording file, in memory (tests and small files; replay streams `Blocks`).
pub fn open_cast(file: &[u8], with: &Identity) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut blocks = Blocks::new(file);
    while let Some(b) = blocks.next(with)? {
        out.extend(b);
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
        c.finish(0.4);
        let all = texts(&c.take()).join("");
        assert!(all.contains("[sudo] password for bob: "));
        assert!(!all.contains("hunter2") && !all.contains("horse"), "{all}");
        assert!(all.contains("Sorry, try again."));
    }

    #[test]
    fn a_pause_in_typing_does_not_release_the_half_typed_secret() {
        for (head, tail) in [
            ("export API_TOKEN=abc", "def123"),
            ("export DB_PASSWORD=hunt", "er2"),
            ("mysql -phunt", "er2"),
        ] {
            let mut c = Cast::new(SIZE, 0);
            c.push(0, head.as_bytes(), 0.1);
            c.idle(2.5);
            c.push(head.len() as u64, format!("{tail}\n").as_bytes(), 3.0);
            c.finish(3.1);
            let all = texts(&c.take()).join("");
            assert!(!all.contains(tail), "{head}: {all}");
        }
    }

    #[test]
    fn a_secret_the_remote_prints_is_redacted_even_when_split_across_chunks() {
        let (_, secret) = PLANTED[0];
        let (a, b) = secret.split_at(12);
        let mut c = Cast::new(SIZE, 0);
        c.push(0, format!("token is {a}").as_bytes(), 0.1);
        c.push(a.len() as u64 + 9, format!("{b}\r\n").as_bytes(), 0.2);
        c.finish(0.3);
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
        c.finish(0.4);
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
    fn skipped_offsets_write_a_gap_marker_and_pause_writes_nothing() {
        let mut c = Cast::new(SIZE, 0);
        c.push(0, b"one\r\n", 0.1);
        c.push(100, b"two\r\n", 0.2); // 94 bytes never arrived
        c.pause(true, 0.3);
        c.push(106, b"hidden-while-paused\r\n", 0.4);
        c.pause(false, 0.5);
        c.push(130, b"three\r\n", 0.6);
        let all = texts(&c.take()).join("");
        assert!(all.contains("one") && all.contains("two") && all.contains("three"));
        assert!(all.contains("[gap]"), "{all}");
        assert!(all.contains("[recording paused]") && all.contains("[recording resumed]"));
        assert!(!all.contains("hidden"), "{all}");
    }

    #[test]
    fn the_replay_total_is_capped() {
        let id = Identity::generate();
        let big = vec![b'a'; MAX_BLOCK];
        let mut file = Vec::new();
        for _ in 0..(REPLAY_MAX / MAX_BLOCK + 2) {
            file.extend(seal_block(&big, &id.to_public()).unwrap());
        }
        assert!(open_cast(&file, &id).is_err());
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
