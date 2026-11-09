//! What a Slack connection's sealed material holds, and the strict shapes of everything that
//! reaches a request. The credential is stored BARE and is always a BOT token: a user token
//! (`xoxp-`) would send messages as a person and reaches that person's DMs, so it is never
//! accepted. Two kinds of bot token exist:
//!
//! - a pasted or OAuth-installed `xoxb-` token: long lived, no refresh token;
//! - a token-rotation token (`xoxe.xoxb-`, 12 hours) with its `xoxe-` refresh token: OAuth only.
//!   A pasted rotating token would expire with nothing to renew it, so it is refused.

use std::fmt;

use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::connections::material::Material;

const BOT: &str = "xoxb-";
const ROTATING_BOT: &str = "xoxe.xoxb-";
const REFRESH: &str = "xoxe-";

fn tail_ok(s: &str, prefix: &str) -> bool {
    let rest = &s[prefix.len()..];
    s.len() <= 256 && rest.len() >= 8 && rest.bytes().all(|b| b.is_ascii_graphic())
}

/// A bot access token Core will hold: `xoxb-…`, or `xoxe.xoxb-…` when `rotating` is allowed.
fn access_ok(s: &str, rotating: bool) -> bool {
    (s.starts_with(BOT) && tail_ok(s, BOT))
        || (rotating && s.starts_with(ROTATING_BOT) && tail_ok(s, ROTATING_BOT))
}

fn refresh_ok(s: &str) -> bool {
    s.starts_with(REFRESH) && tail_ok(s, REFRESH)
}

/// `prefix` then `lo..=hi` of `[A-Z0-9]`.
fn id_of(s: &str, prefixes: &[u8], lo: usize, hi: usize) -> bool {
    let b = s.as_bytes();
    let rest = b.get(1..).unwrap_or_default();
    b.first().is_some_and(|c| prefixes.contains(c))
        && (lo..=hi).contains(&rest.len())
        && rest
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// A channel id the adapter will address: `C…` (public, and private since 2018) or `G…` (older
/// private channels, but also multi-person DMs: the adapter checks those with `conversations.info`).
/// A DM (`D…`), a user (`U…`, `W…`) or a name never is one.
pub fn channel_id(s: &str) -> bool {
    id_of(s, b"CG", 8, 11)
}

pub fn user_id(s: &str) -> bool {
    id_of(s, b"UW", 8, 11)
}

/// A workspace id (`T…`); an enterprise (`E…`) is not a workspace.
pub fn team_id(s: &str) -> bool {
    id_of(s, b"T", 8, 11)
}

/// A message timestamp: `1355517523.000005`.
pub fn message_ts(s: &str) -> bool {
    match s.split_once('.') {
        Some((a, b)) => {
            (10..=11).contains(&a.len())
                && b.len() == 6
                && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// An emoji name, without colons or skin tones.
pub fn emoji_name(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'+')
        })
}

/// A pagination cursor as Slack makes them (base64-ish).
pub fn cursor(s: &str) -> bool {
    (1..=200).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
}

/// The material of a pasted bot token (no refresh token, never a rotating one).
pub fn token_material(token: &str) -> Option<Material> {
    let t = token.trim();
    access_ok(t, false).then(|| Material::new(t, None, None))?
}

/// The material of an OAuth install: a bot token with, only when the app rotates tokens, its
/// refresh token and expiry.
pub fn oauth_material(
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<&str>,
) -> Option<Material> {
    let (access, refresh) = (access.trim(), refresh.map(str::trim));
    let ok = access_ok(access, refresh.is_some()) && refresh.is_none_or(refresh_ok);
    // A rotating token without its refresh token, or a refresh token beside a plain one, is not
    // something this adapter can keep alive.
    let paired = refresh.is_some() == access.starts_with(ROTATING_BOT);
    (ok && paired).then(|| Material::new(access, refresh, expires_at))?
}

/// A credential, unpacked. Prints nothing.
pub enum Cred {
    /// A bot token that does not expire.
    Bot(Zeroizing<String>),
    /// A rotating bot token: it has a refresh token and is renewed.
    Rotating(Zeroizing<String>),
}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cred(<redacted>)")
    }
}

/// `None` when the stored value is not what would be accepted on the way in.
pub fn unpack(m: &Material) -> Option<Cred> {
    let token = Zeroizing::new(m.access().to_owned());
    match m.refresh() {
        Some(r) if refresh_ok(r) && access_ok(m.access(), true) => Some(Cred::Rotating(token)),
        None if access_ok(m.access(), false) => Some(Cred::Bot(token)),
        _ => None,
    }
}

impl Cred {
    /// Whether it has a refresh token (only a rotating token does).
    pub fn is_rotating(&self) -> bool {
        matches!(self, Self::Rotating(_))
    }

    /// `Authorization: Bearer <token>`, marked sensitive so no debug print shows it.
    pub fn authorization(&self) -> Option<HeaderValue> {
        let (Self::Bot(t) | Self::Rotating(t)) = self;
        let text = Zeroizing::new(format!("Bearer {}", t.as_str()));
        let mut v = HeaderValue::from_str(&text).ok()?;
        v.set_sensitive(true);
        Some(v)
    }
}

/// What an identity line says about a workspace id (`T…`) a credential belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamCheck {
    Same,
    Different,
    /// The connection records no workspace (never tested, or tested before ids were kept).
    Unknown,
}

/// Compares the workspace id of a connection's stored identity with `team`, by id only: never a
/// name, which can be renamed.
pub fn check_team(old: Option<&str>, team: &str) -> TeamCheck {
    match old.and_then(workspace_of) {
        Some(t) if t == team => TeamCheck::Same,
        Some(_) => TeamCheck::Different,
        None => TeamCheck::Unknown,
    }
}

/// The workspace id inside an identity line (`<bot user id> in <team id>`).
pub fn workspace_of(identity: &str) -> Option<&str> {
    let (user, team) = identity.split_once(" in ")?;
    (user_id(user) && team_id(team)).then_some(team)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_strict() {
        for ok in ["C012AB3CD", "G012AB3CDEF", "C0123456789A"] {
            assert!(channel_id(ok), "{ok}");
        }
        let long = format!("C{}", "A".repeat(12));
        for bad in [
            "",
            "C",
            "c012ab3cd",
            "D012AB3CD",
            "U012AB3CD",
            "W012AB3CD",
            "C012AB3C",
            "general",
            "#general",
            "C012AB3CD ",
            "C012AB3CD\n",
            "C012AB3C\u{FF24}",
            "C012-B3CD",
            "C012AB3CD,G012AB3CD",
            "C012AB3CD/../",
            "%43012AB3CD",
            long.as_str(),
        ] {
            assert!(!channel_id(bad), "{bad:?}");
        }
        assert!(user_id("U012AB3CD") && user_id("W012AB3CD") && !user_id("C012AB3CD"));
        assert!(team_id("T012AB3CD") && !team_id("E012AB3CD") && !team_id("U012AB3CD"));
        assert!(message_ts("1355517523.000005"));
        for bad in [
            "",
            "1355517523",
            "1355517523.5",
            ".000005",
            "13555175.000005",
            "1355517523.00000a",
            "1355517523.000005 ",
        ] {
            assert!(!message_ts(bad), "{bad:?}");
        }
        assert!(
            emoji_name("thumbsup")
                && emoji_name("+1")
                && !emoji_name(":x:")
                && !emoji_name("A")
                && !emoji_name("")
        );
        assert!(
            cursor("dXNlcjpVMDYxTk5UMDI=") && !cursor("a b") && !cursor("a&b=c") && !cursor("")
        );
    }

    #[test]
    fn only_bot_tokens_are_held_and_a_pasted_rotating_one_is_refused() {
        assert!(token_material(" xoxb-test-111-222-abc\n").is_some());
        for bad in [
            "xoxp-test-111-222-abc",
            "xoxe.xoxp-test-111-222-abc",
            "xoxe.xoxb-test-111-222-abc",
            "xoxe-1-test-111-222-abc",
            "xapp-1-test-111-222-abc",
            "xoxb-short",
            "xoxb-has space-inside-1",
            "bearer xoxb-test-111-222-abc",
            "",
        ] {
            assert!(token_material(bad).is_none(), "{bad:?}");
        }
        assert!(oauth_material("xoxb-test-111-222-abc", None, None).is_some());
        let rot = oauth_material(
            "xoxe.xoxb-test-111-222-abc",
            Some("xoxe-1-test-333-444"),
            None,
        );
        assert!(rot.is_some());
        for (a, r) in [
            ("xoxe.xoxb-test-111-222-abc", None),
            ("xoxb-test-111-222-abc", Some("xoxe-1-test-333-444")),
            ("xoxe.xoxp-test-111-222-abc", Some("xoxe-1-test-333-444")),
            ("xoxe.xoxb-test-111-222-abc", Some("xoxb-test-333-444-ab")),
            ("xoxe.xoxb-test-111-222-abc", Some("not-a-refresh-token")),
        ] {
            assert!(oauth_material(a, r, None).is_none(), "{a} {r:?}");
        }
    }

    #[test]
    fn the_credential_prints_nothing_and_is_a_bearer() {
        let k = token_material("xoxb-test-111-222-abc").unwrap();
        for text in [format!("{k:?}"), format!("{k}")] {
            assert!(!text.contains("111-222"), "{text}");
        }
        let c = unpack(&k).unwrap();
        assert!(!c.is_rotating() && !format!("{c:?}").contains("111-222"));
        let h = c.authorization().unwrap();
        assert!(h.is_sensitive() && !format!("{h:?}").contains("xoxb"));
        assert_eq!(h.to_str().unwrap(), "Bearer xoxb-test-111-222-abc");
        let r = oauth_material(
            "xoxe.xoxb-test-111-222-abc",
            Some("xoxe-1-test-333-444"),
            None,
        )
        .unwrap();
        assert!(unpack(&r).unwrap().is_rotating());
        // What is stored is trusted no further than what would be accepted.
        let odd = Material::new("xoxp-test-111-222-abc", None, None).unwrap();
        assert!(unpack(&odd).is_none());
        assert_eq!(workspace_of("U012AB3CD in T012AB3CD"), Some("T012AB3CD"));
        for bad in [
            "",
            "T012AB3CD",
            "U012AB3CD in E012AB3CD",
            "x in T012AB3CD",
            "U012AB3CD at T012AB3CD",
        ] {
            assert_eq!(workspace_of(bad), None, "{bad}");
        }
    }
}
