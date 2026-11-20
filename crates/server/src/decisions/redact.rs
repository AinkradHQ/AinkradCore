//! Redaction for the Decisions service (§2.3): only redacted text ever leaves the Core.
//!
//! First `ainkrad_proto::redact` (key shapes), then, per whitespace-separated word: workspace paths
//! become `$WS/…`, home folders `~`, env assignments `NAME=…`, URLs lose their userinfo, query and
//! fragment; last, runs of 16 or more hex digits (which covers digit runs: ids, hashes, tokens)
//! become `#`. The same output feeds the cache key, so equal questions share an answer whatever
//! their paths or ids were.

use std::collections::BTreeMap;
use std::path::Path;

/// What a Core knows about its own layout: the workspace root and the service user's home.
#[derive(Debug, Clone)]
pub struct Redactor {
    ws_root: String,
    home: Option<String>,
}

impl Redactor {
    pub fn new(ws_root: &Path, home: Option<&Path>) -> Self {
        let clean = |p: &Path| p.to_string_lossy().trim_end_matches('/').to_owned();
        Self {
            ws_root: clean(ws_root),
            home: home.map(clean).filter(|h| h.len() > 1),
        }
    }

    /// `text` as the provider may see it.
    pub fn text(&self, text: &str) -> String {
        let shaped = ainkrad_proto::redact::Redactor::new().text(text);
        let mut out = String::with_capacity(shaped.len());
        let mut word = String::new();
        for c in shaped.chars() {
            if c.is_whitespace() {
                out.push_str(&hex_runs(&self.word(&word)));
                word.clear();
                out.push(c);
            } else {
                word.push(c);
            }
        }
        out.push_str(&hex_runs(&self.word(&word)));
        out
    }

    /// Every value of `facts` redacted; keys are the consumer's own fixed names and stay.
    pub fn facts(&self, facts: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        facts
            .iter()
            .map(|(k, v)| (k.clone(), self.text(v)))
            .collect()
    }

    fn word(&self, w: &str) -> String {
        if w.is_empty() {
            return String::new();
        }
        let w = url(w);
        if let Some((name, _)) = w.split_once('=')
            && is_env_name(name)
        {
            return format!("{name}=…");
        }
        let mut w = replace_root(&w, &self.ws_root, "$WS");
        if let Some(home) = &self.home {
            w = replace_root(&w, home, "~");
        }
        generic_home(&w)
    }
}

fn is_env_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// A URL word without its userinfo, query and fragment.
fn url(w: &str) -> String {
    let Some(i) = w.find("://") else {
        return w.to_owned();
    };
    let (head, rest) = w.split_at(i + 3);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (auth, tail) = rest.split_at(end);
    let auth = auth.rsplit_once('@').map_or(auth, |(_, host)| host);
    let tail = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    format!("{head}{auth}{tail}")
}

/// `root` as `repl` wherever it is a whole path prefix (followed by `/`, the end, or a character
/// that cannot continue a name).
fn replace_root(w: &str, root: &str, repl: &str) -> String {
    if root.is_empty() {
        return w.to_owned();
    }
    let (mut out, mut rest) = (String::new(), w);
    while let Some(i) = rest.find(root) {
        let after = &rest[i + root.len()..];
        let boundary = after
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || "-_.".contains(c)));
        out.push_str(&rest[..i]);
        out.push_str(if boundary { repl } else { root });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Any `/home/<user>` or `/Users/<user>` (a path of another user, or of a runner host) as `~`.
fn generic_home(w: &str) -> String {
    let mut out = w.to_owned();
    for base in ["/home/", "/Users/"] {
        while let Some(i) = out.find(base) {
            let name_end = out[i + base.len()..]
                .find(['/', ':', '"', '\''])
                .map_or(out.len(), |n| i + base.len() + n);
            out.replace_range(i..name_end, "~");
        }
    }
    out
}

/// Runs of 16 or more hex digits as `#`.
fn hex_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        out.push_str(if run.len() >= 16 { "#" } else { run });
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(
            Path::new("/var/lib/ainkrad-ws"),
            Some(Path::new("/home/ainkrad")),
        )
    }

    #[test]
    fn paths_become_ws_and_home() {
        let t = r().text("cargo build --manifest-path /var/lib/ainkrad-ws/p/7/repo/Cargo.toml");
        assert_eq!(t, "cargo build --manifest-path $WS/p/7/repo/Cargo.toml");
        assert_eq!(r().text("ls /home/ainkrad/src /home/bob/x"), "ls ~/src ~/x");
        assert_eq!(r().text("/Users/ahmed/Home"), "~/Home");
        // A sibling that only starts like the root is not the root.
        assert_eq!(
            r().text("/var/lib/ainkrad-ws-old/x"),
            "/var/lib/ainkrad-ws-old/x"
        );
    }

    #[test]
    fn env_assignments_and_urls_lose_their_values() {
        let t = r().text("RUST_LOG=debug API_TOKEN=abc cargo test --features=x");
        assert_eq!(t, "RUST_LOG=… API_TOKEN=… cargo test --features=x");
        assert_eq!(
            r().text("git clone https://user:pw@github.com/a/b.git?token=1#frag"),
            "git clone https://github.com/a/b.git"
        );
    }

    #[test]
    fn long_hex_and_digit_runs_become_a_hash_mark() {
        assert_eq!(
            r().text("checkout 0123456789abcdef0123 now"),
            "checkout # now"
        );
        assert_eq!(r().text("id 1234567890123456"), "id #");
        assert_eq!(
            r().text("short 123456789012345 stays?"),
            "short 123456789012345 stays?"
        );
        assert_eq!(r().text("a\tb\n"), "a\tb\n");
    }

    #[test]
    fn key_shapes_go_first() {
        let t = r().text("curl -H x-goog-api-key:AIzaSyA1234567890abcdefghijklmnopqrstuv x");
        assert!(!t.contains("SyA1234567890"), "{t}");
    }
}
