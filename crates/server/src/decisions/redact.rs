//! Redaction for the Decisions service (§2.3): only redacted text ever leaves the Core.
//!
//! First `ainkrad_proto::redact` (key shapes), then, per whitespace-separated word: workspace paths
//! become `$WS/…`, home folders `~`, env assignments `NAME=…`, URLs lose their userinfo, query and
//! fragment; last, runs of 16 or more hex digits (which covers digit runs: ids, hashes, tokens)
//! become `#`. Secrets by position and shape (E15 security review M10): the value of any name or
//! flag that names a secret (`pass`, `secret`, `token`, `key`, `auth`, `cred`, any case), the word
//! after `-u`/`--user` or such a flag, `-p<value>`, the credential after `Authorization:` and its
//! scheme, JWTs and Stripe-style `sk_live_`/`rk_live_` keys. The same output feeds the cache key, so equal questions share an answer whatever
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
        let mut mask_next = false;
        for piece in shaped.split_inclusive(char::is_whitespace) {
            let (word, ws) = piece.split_at(piece.trim_end_matches(char::is_whitespace).len());
            out.push_str(&hex_runs(&self.positional(word, &mut mask_next)));
            out.push_str(ws);
        }
        out
    }

    /// One word, with what the word before it said (`mask_next`: it was a secret's flag or an
    /// `Authorization:`).
    fn positional(&self, w: &str, mask_next: &mut bool) -> String {
        if w.is_empty() {
            return String::new();
        }
        let bare = w.trim_matches(['"', '\'']).to_ascii_lowercase();
        let scheme = ["basic", "bearer", "token", "digest"].contains(&bare.as_str());
        if *mask_next {
            if !scheme {
                *mask_next = false;
                return "…".to_owned();
            }
            return self.word(w);
        }
        let flag = bare.starts_with('-') && !bare.contains('=');
        *mask_next = bare.ends_with("authorization:")
            || (scheme && bare != "token")
            || (flag && (bare == "-u" || bare == "--user" || secret_named(&bare)));
        self.word(w)
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
            && (is_env_name(name) || secret_named(name))
        {
            return format!("{name}=…");
        }
        // `mysql -pSecret`: the password is glued to the flag.
        if w.len() > 2 && w.starts_with("-p") && !w.starts_with("--") {
            return "-p…".to_owned();
        }
        let w = shaped_tokens(&w);
        let mut w = replace_root(&w, &self.ws_root, "$WS");
        if let Some(home) = &self.home {
            w = replace_root(&w, home, "~");
        }
        generic_home(&w)
    }
}

/// A name or flag that names a secret: any case, any of these parts (`--password`, `apiKey`,
/// `db_token`, `X-Auth`). Over-masking (`--author`) only costs a word the model does not need.
fn secret_named(name: &str) -> bool {
    let l = name.trim_start_matches('-').to_ascii_lowercase();
    !l.is_empty()
        && ["pass", "secret", "token", "key", "auth", "cred"]
            .iter()
            .any(|p| l.contains(p))
}

/// JWTs (`eyJ…` with two dots) and Stripe-style keys inside a word, as `…`.
fn shaped_tokens(w: &str) -> String {
    let tok = |c: char| c.is_ascii_alphanumeric() || "_-.".contains(c);
    let secret = |t: &str| {
        (t.starts_with("eyJ") && t.matches('.').count() >= 2 && t.len() >= 20)
            || (["sk_live_", "rk_live_", "sk_test_", "rk_test_"]
                .iter()
                .any(|p| t.starts_with(p))
                && t.len() >= 16)
    };
    let mut out = String::with_capacity(w.len());
    let mut run = String::new();
    for c in w.chars().chain(std::iter::once('\0')) {
        if tok(c) {
            run.push(c);
            continue;
        }
        out.push_str(if secret(&run) { "…" } else { &run });
        run.clear();
        if c != '\0' {
            out.push(c);
        }
    }
    out
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
    fn secrets_by_name_flag_position_and_shape_are_masked() {
        // M10: each of these went to the model with its secret in it.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3Zh";
        for (input, secret) in [
            ("mysql -pProdPw -h db", "ProdPw"),
            ("tool --password=hunter2x", "hunter2x"),
            ("tool --Password hunter2x", "hunter2x"),
            ("app token=abcSecret9", "abcSecret9"),
            ("app db_Pass=abcSecret9", "abcSecret9"),
            ("curl -u admin:s3cretPw https://x.example", "s3cretPw"),
            ("curl --user admin:s3cretPw x", "s3cretPw"),
            (
                "curl -H 'Authorization: Basic YWRtaW46czNjcmV0' x",
                "YWRtaW46czNjcmV0",
            ),
            ("curl -H \"Authorization: Bearer opaqueTok\" x", "opaqueTok"),
            ("curl -H 'Authorization: rawCredValue' x", "rawCredValue"),
            ("deploy --api-key zzTopSecret", "zzTopSecret"),
            (&format!("call {jwt}"), "eyJzdWIiOiIxMjM0In0"),
            ("stripe sk_live_51HxQkPZabcdefgh", "51HxQkPZabcdefgh"),
            ("stripe --key=rk_live_51HxQkPZabcdefgh", "51HxQkPZabcdefgh"),
        ] {
            let t = r().text(input);
            assert!(!t.contains(secret), "{input} -> {t}");
        }
        // What is not a secret keeps its words, so equal questions still share an answer.
        assert_eq!(r().text("mkdir -p a/b"), "mkdir -p a/b");
        assert_eq!(
            r().text("cargo build --release -j 4"),
            "cargo build --release -j 4"
        );
        assert_eq!(r().text("gh auth token"), "gh auth token");
    }

    #[test]
    fn key_shapes_go_first() {
        let t = r().text("curl -H x-goog-api-key:AIzaSyA1234567890abcdefghijklmnopqrstuv x");
        assert!(!t.contains("SyA1234567890"), "{t}");
    }
}
