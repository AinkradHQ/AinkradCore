//! The credential of one connection. It has no `Serialize` and prints nothing: `Debug` and
//! `Display` are fixed text, so a log line, an error or a panic message cannot carry it.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The most bytes one token may be.
pub const MAX_TOKEN_BYTES: usize = 8192;

/// Access token, optional refresh token, optional expiry (RFC 3339, not secret).
pub struct Material {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
struct WireOut<'a> {
    a: &'a str,
    r: Option<&'a str>,
}

#[derive(Deserialize)]
struct WireIn {
    a: Zeroizing<String>,
    r: Option<Zeroizing<String>>,
}

impl Material {
    /// Trims both tokens (a pasted one often ends in a newline). `None` when a token is empty,
    /// too long or has a control character.
    pub fn new(access: &str, refresh: Option<&str>, expires_at: Option<&str>) -> Option<Self> {
        let ok = |s: &str| {
            !s.is_empty() && s.len() <= MAX_TOKEN_BYTES && !s.chars().any(char::is_control)
        };
        let (access, refresh) = (access.trim(), refresh.map(str::trim));
        if !ok(access) || refresh.is_some_and(|r| !ok(r)) {
            return None;
        }
        Some(Self {
            access: Zeroizing::new(access.to_owned()),
            refresh: refresh.map(|r| Zeroizing::new(r.to_owned())),
            expires_at: expires_at.map(str::to_owned),
        })
    }

    /// The access token: the one reader, for an adapter's test and the broker's upstream call.
    pub fn access(&self) -> &str {
        &self.access
    }

    pub fn refresh(&self) -> Option<&str> {
        self.refresh.as_ref().map(|r| r.as_str())
    }

    /// The bytes that are sealed (the expiry is stored beside them, in the clear).
    pub(crate) fn to_sealed(&self) -> Zeroizing<Vec<u8>> {
        let w = WireOut {
            a: &self.access,
            r: self.refresh(),
        };
        Zeroizing::new(serde_json::to_vec(&w).expect("two strings serialise"))
    }

    pub(crate) fn from_sealed(bytes: &[u8], expires_at: Option<String>) -> Option<Self> {
        let w: WireIn = serde_json::from_slice(bytes).ok()?;
        Some(Self {
            access: w.a,
            refresh: w.r,
            expires_at,
        })
    }
}

impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Material(<redacted>)")
    }
}

impl fmt::Display for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted credential>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_nothing_and_round_trips() {
        let m = Material::new(" acc-7f3a9d41e0b2 \n", Some("ref-91c4d2b7a6e1"), None).unwrap();
        for text in [format!("{m:?}"), format!("{m}"), format!("{m:#?}")] {
            assert!(
                !text.contains("7f3a9d41") && !text.contains("91c4d2b7"),
                "{text}"
            );
        }
        let back = Material::from_sealed(&m.to_sealed(), None).unwrap();
        assert_eq!(back.access(), "acc-7f3a9d41e0b2");
        assert_eq!(back.refresh(), Some("ref-91c4d2b7a6e1"));
        assert!(Material::new("", None, None).is_none());
        assert!(Material::new("a\nb", None, None).is_none());
        assert!(Material::new("ok", Some(" "), None).is_none());
    }
}
