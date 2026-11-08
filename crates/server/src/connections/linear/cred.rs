//! What a Linear connection's sealed material holds, and the strict shapes of everything that
//! reaches a request. The credential is stored BARE (a personal API key, or an OAuth access token
//! with its refresh token): the kind's key shape must be the whole access value for the secret gate
//! to admit it. The two are told apart by the refresh token: only a sign-in has one.
//!
//! - a personal API key is sent as `Authorization: <key>` (no `Bearer`),
//! - an OAuth access token as `Authorization: Bearer <token>`.

use std::fmt;

use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::connections::material::Material;

/// A Linear team key: `[A-Z][A-Z0-9]{0,6}` (Linear keys are at most 7 characters). A longer key is
/// simply not addressable here, which can only shrink what is allowed.
pub fn team_key(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=7).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// The team key of an issue IDENTIFIER (`ENG-12`); `None` for anything else, a UUID included.
pub fn issue_identifier(s: &str) -> Option<&str> {
    let (team, n) = s.rsplit_once('-')?;
    let number =
        (1..=9).contains(&n.len()) && !n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit());
    (number && team_key(team)).then_some(team)
}

/// A UUID, lowercase: what Linear gives an entity as `id`.
pub fn uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

fn token_ok(s: &str) -> bool {
    (8..=256).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// The material of a personal API key (no refresh token).
pub fn key_material(token: &str) -> Option<Material> {
    let t = token.trim();
    token_ok(t).then(|| Material::new(t, None, None))?
}

/// The material of an OAuth sign-in: the access token, its refresh token and expiry.
pub fn oauth_material(access: &str, refresh: &str, expires_at: Option<&str>) -> Option<Material> {
    (token_ok(access.trim()) && token_ok(refresh.trim()))
        .then(|| Material::new(access, Some(refresh), expires_at))?
}

/// A credential, unpacked. Prints nothing.
pub enum Cred {
    Key(Zeroizing<String>),
    Oauth(Zeroizing<String>),
}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cred(<redacted>)")
    }
}

/// `None` when the access value is not a usable token (a sealed value is trusted no further than
/// what would be accepted on the way in).
pub fn unpack(m: &Material) -> Option<Cred> {
    if !token_ok(m.access()) {
        return None;
    }
    let token = Zeroizing::new(m.access().to_owned());
    Some(match m.refresh() {
        Some(_) => Cred::Oauth(token),
        None => Cred::Key(token),
    })
}

impl Cred {
    pub fn is_oauth(&self) -> bool {
        matches!(self, Self::Oauth(_))
    }

    /// The `Authorization` header, marked sensitive so no debug print shows it.
    pub fn authorization(&self) -> Option<HeaderValue> {
        let text = match self {
            Self::Key(t) => Zeroizing::new(t.to_string()),
            Self::Oauth(t) => Zeroizing::new(format!("Bearer {}", t.as_str())),
        };
        let mut v = HeaderValue::from_str(&text).ok()?;
        v.set_sensitive(true);
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_identifiers_are_strict() {
        for ok in ["E", "ENG", "A1", "ABCDEFG"] {
            assert!(team_key(ok), "{ok}");
        }
        for bad in [
            "", "eng", "1AB", "ABCDEFGH", "EN-G", "EN G", "ENG\n", "ÉNG", "E_G",
        ] {
            assert!(!team_key(bad), "{bad:?}");
        }
        assert_eq!(issue_identifier("ENG-12"), Some("ENG"));
        for bad in [
            "ENG-0",
            "ENG-012",
            "eng-1",
            "ENG-",
            "-1",
            "ENG-1x",
            "ENG--1",
            "ENG-1/../OPS-2",
            "ENG-1 ",
            "9cfb482a-81e3-4154-b5b9-2c805e70a02d",
            "ENG-1234567890",
        ] {
            assert_eq!(issue_identifier(bad), None, "{bad:?}");
        }
        assert!(uuid("9cfb482a-81e3-4154-b5b9-2c805e70a02d"));
        for bad in [
            "ENG-1",
            "9CFB482A-81E3-4154-B5B9-2C805E70A02D",
            "9cfb482a81e341544b5b92c805e70a02d00",
            "9cfb482a-81e3-4154-b5b9-2c805e70a02",
            "../9cfb482a-81e3-4154-b5b9-2c805e70a0",
        ] {
            assert!(!uuid(bad), "{bad}");
        }
    }

    #[test]
    fn the_credential_is_bare_and_prints_nothing() {
        let k = key_material(" lin-key-4f9a1c7b2d8e\n").unwrap();
        for text in [format!("{k:?}"), format!("{k}")] {
            assert!(!text.contains("4f9a1c7b"), "{text}");
        }
        let c = unpack(&k).unwrap();
        assert!(!c.is_oauth() && !format!("{c:?}").contains("4f9a1c7b"));
        let h = c.authorization().unwrap();
        assert!(h.is_sensitive() && !format!("{h:?}").contains("lin-key"));
        assert_eq!(h.to_str().unwrap(), "lin-key-4f9a1c7b2d8e");
        let o = oauth_material("acc-7f3a9d41e0b2", "ref-91c4d2b7a6e1", None).unwrap();
        let c = unpack(&o).unwrap();
        assert!(c.is_oauth());
        assert_eq!(
            c.authorization().unwrap().to_str().unwrap(),
            "Bearer acc-7f3a9d41e0b2"
        );
        for bad in [
            "",
            "short",
            "has space in it",
            "tab\tbad-token-value",
            "ünï-token-value-x",
        ] {
            assert!(key_material(bad).is_none(), "{bad:?}");
        }
        assert!(oauth_material("acc-7f3a9d41e0b2", " ", None).is_none());
    }
}
