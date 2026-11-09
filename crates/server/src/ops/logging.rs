//! Structured, redacted logs (E1-13.4, threat model T-SEC-3): `tracing` as text or JSON lines on
//! stderr, every line passed through the store's redaction before it is written.
//!
//! JSON lines get both passes of `store::redact::json`: a field named like a secret
//! (`password`, `api_key`, `authorization`, …) becomes `[redacted:<name>]`, and secret shapes
//! (provider keys, `Bearer …`, PEM blocks, device keys) are masked wherever they appear. Text
//! lines (no ANSI colour) get the same: each `name=value` word through the same rules, then the
//! shape pass over the line.
//! ponytail: in text, a quoted value with spaces under a secret name is masked only up to its
//! first space; JSON has no such gap, so production logs use JSON.
//!
//! The authenticated `/metrics` endpoint of E1-13.4 is not here: it needs the new device auth
//! (E1-07) and comes with it.

use std::io::{self, Write};

use ainkrad_proto::redact::Redactor;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// What never reaches the log, at any level: the passkey verifier's own lines (E1-08). At
/// debug and trace webauthn-rs prints its ceremony state and the browser's responses (the
/// challenge, the credential, the attestation) and its parse errors carry input bytes; the
/// Core logs its own reason for every passkey refusal instead.
pub fn quiet() -> Targets {
    Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_target("webauthn_rs", LevelFilter::OFF)
        .with_target("webauthn_rs_core", LevelFilter::OFF)
}

/// Installs the global subscriber: JSON lines when `json`, else text; both redacted.
pub fn init(json: bool) {
    let writer = Redacting {
        json,
        sink: io::stderr,
    };
    let fmt = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false);
    if json {
        fmt.json().finish().with(quiet()).init();
    } else {
        fmt.finish().with(quiet()).init();
    }
}

/// A `MakeWriter` that buffers each event's line and writes it, redacted, to `sink` when the
/// event is done.
#[derive(Clone)]
pub struct Redacting<M> {
    pub json: bool,
    pub sink: M,
}

pub struct Line<W: Write> {
    json: bool,
    buf: Vec<u8>,
    sink: W,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = Line<M::Writer>;
    fn make_writer(&'a self) -> Self::Writer {
        Line {
            json: self.json,
            buf: Vec::new(),
            sink: self.sink.make_writer(),
        }
    }
}

impl<W: Write> Write for Line<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One formatted event, redacted.
pub fn redact(json: bool, line: &str) -> String {
    let line = line.trim_end_matches('\n');
    if json && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) {
        crate::store::redact::json(&mut value);
        return format!("{value}\n");
    }
    format!("{}\n", Redactor::new().text(&mask_named(line)))
}

/// Each `name=value` word of a text line, its value masked when the name is a secret's.
fn mask_named(line: &str) -> String {
    let word = |w: &str| {
        let Some((name, value)) = w.split_once('=') else {
            return w.to_owned();
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || "_.".contains(c))
        {
            return w.to_owned();
        }
        let mut v = serde_json::json!({ name: value });
        crate::store::redact::json(&mut v);
        match v[name].as_str() {
            Some(masked) if masked != value => format!("{name}={masked}"),
            _ => w.to_owned(),
        }
    };
    line.split(' ').map(word).collect::<Vec<_>>().join(" ")
}

impl<W: Write> Drop for Line<W> {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf);
        let _ = self.sink.write_all(redact(self.json, &text).as_bytes());
        let _ = self.sink.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    const PLANTED: &str = "hunter2-planted-secret-value";
    const SHAPED: &str = "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED";

    fn logged(json: bool) -> String {
        let out = Captured::default();
        let writer = Redacting {
            json,
            sink: out.clone(),
        };
        let fmt = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false);
        let log = || {
            tracing::info!(password = PLANTED, user = "ahmed", "signing in");
            tracing::warn!(header = %format!("Bearer {PLANTED}"), "a request");
            tracing::error!("provider said no to {SHAPED}");
        };
        if json {
            tracing::subscriber::with_default(fmt.json().finish(), log);
        } else {
            tracing::subscriber::with_default(fmt.finish(), log);
        }
        String::from_utf8(out.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn a_planted_secret_never_reaches_the_json_log() {
        let out = logged(true);
        assert_eq!(out.lines().count(), 3, "{out}");
        assert!(
            !out.contains("hunter2") && !out.contains("PLANTED"),
            "{out}"
        );
        assert!(out.contains("[redacted:password]"), "{out}");
        assert!(
            out.contains("\"user\":\"ahmed\""),
            "the rest is kept: {out}"
        );
        for line in out.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("still JSON");
        }
    }

    #[test]
    fn a_planted_secret_never_reaches_the_text_log() {
        let out = logged(false);
        assert_eq!(out.lines().count(), 3, "{out}");
        assert!(!out.contains(SHAPED) && !out.contains("hunter2"), "{out}");
        assert!(out.contains("password=[redacted:password]"), "{out}");
        assert!(!out.contains(&format!("Bearer {PLANTED}")), "{out}");
        assert!(out.contains("signing in"), "{out}");
    }
}
