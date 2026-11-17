//! Field rules for a host, ported from the old Leyline plugin (`SSHCommand` / `LeylineConnectAction`:
//! every field that can reach an `ssh` argv is validated, because `-o ProxyCommand=...` is code
//! execution). The same rules are the CHECKs of `leyline_hosts` (`migrations/0001_leyline.up.sql`):
//! two layers, kept equal by the table test in `tests/gate.rs`.
//!
//! A failed check says only "invalid"; nothing here ever builds a message from the input.

fn only(s: &str, extra: &[char]) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// A DNS name, an IPv4 or an IPv6 address (with `%zone`): never empty, never a leading `-`,
/// letters, digits and `. : % _ -` only, so no space, `=`, quote, `;` or newline can pass.
pub fn address(s: &str) -> bool {
    (1..=255).contains(&s.len()) && !s.starts_with('-') && only(s, &['.', ':', '%', '_', '-'])
}

/// A login name: 1 to 32 of letters, digits and `. _ -`, never a leading `-`.
pub fn username(s: &str) -> bool {
    (1..=32).contains(&s.len()) && !s.starts_with('-') && only(s, &['.', '_', '-'])
}

pub fn port(n: i64) -> Option<u16> {
    u16::try_from(n).ok().filter(|p| *p >= 1)
}

/// A label or a group name: 1 to 64 characters, no control character, no edge whitespace.
/// Unicode is fine (it is data, never an argv); the label rule of addressing lives in `address.rs`.
pub fn label(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && s == s.trim() && !s.chars().any(char::is_control)
}

/// One tag: 1 to 32 of letters, digits and `. _ -`.
pub fn tag(s: &str) -> bool {
    (1..=32).contains(&s.len()) && only(s, &['.', '_', '-'])
}

/// At most 20 valid tags, lowercased and de-duplicated in order.
pub fn tags(list: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for t in list {
        if !tag(t) {
            return None;
        }
        let t = t.to_ascii_lowercase();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    (out.len() <= 20).then_some(out)
}

/// `h_` + 16 hex, as minted by `new_id`.
pub fn host_id(s: &str) -> bool {
    s.len() == 18 && s.starts_with("h_") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

pub fn key_id(s: &str) -> bool {
    s.len() == 18 && s.starts_with("k_") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// A runner device id (`d_...`): shape only, no foreign key into a Core table.
pub fn runner(s: &str) -> bool {
    s.len() <= 40 && s.starts_with("d_") && only(s, &['_', '-'])
}

pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    format!(
        "{prefix}{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_addresses_users_and_ports_are_refused() {
        for bad in [
            "",
            "-oProxyCommand=x",
            "-host",
            "a b",
            "ProxyCommand=touch /tmp/x",
            "host;rm",
            "a\nb",
            "host\u{e9}",
            "a'b",
            "a=b",
            "$(id)",
            "a`b`",
            "a/b",
            &"a".repeat(256),
        ] {
            assert!(!address(bad), "address {bad:?}");
        }
        for ok in [
            "example.com",
            "10.0.0.1",
            "fe80::1%en0",
            "db_1.internal",
            "a-b.c",
        ] {
            assert!(address(ok), "address {ok:?}");
        }
        for bad in ["", "-o", "root user", "a=b", "u;id", "u\n", &"u".repeat(33)] {
            assert!(!username(bad), "username {bad:?}");
        }
        for ok in ["root", "deploy.bot", "a_b-c", &"u".repeat(32)] {
            assert!(username(ok), "username {ok:?}");
        }
        assert_eq!([port(0), port(-1), port(65536)], [None; 3]);
        assert_eq!(
            [port(1), port(22), port(65535)],
            [Some(1), Some(22), Some(65535)]
        );
    }

    #[test]
    fn tags_are_lowercased_deduplicated_and_bounded() {
        assert_eq!(
            tags(&["Web".into(), "web".into(), "db-1".into()]),
            Some(vec!["web".into(), "db-1".into()])
        );
        assert_eq!(tags(&["a b".into()]), None);
        assert_eq!(
            tags(&(0..21).map(|n| format!("t{n}")).collect::<Vec<_>>()),
            None
        );
    }

    #[test]
    fn labels_allow_unicode_but_no_control_or_edge_space() {
        assert!(label("web 1") && label("\u{645}\u{648}\u{642}\u{639}"));
        for bad in ["", " a", "a ", "a\nb", "a\u{0}b", &"x".repeat(65)] {
            assert!(!label(bad), "{bad:?}");
        }
    }
}
