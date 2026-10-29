//! Signed requests (§5.1, §5.2): the six `Ainkrad-*` headers parsed to their exact formats, the
//! request-target checks, and the canonical string every request signs. Pure functions: the
//! verification order lives in `api::v1::gate`.

use axum::http::HeaderMap;

use super::crypto::{b64, is_id, sha256, unb64};

/// The only algorithm in v1.
pub const ALG: &str = "ES256";

pub const DEVICE: &str = "ainkrad-device";
pub const SESSION: &str = "ainkrad-session";
pub const ALG_HEADER: &str = "ainkrad-alg";
pub const TIMESTAMP: &str = "ainkrad-timestamp";
pub const NONCE: &str = "ainkrad-nonce";
pub const SIGNATURE: &str = "ainkrad-signature";

/// The parsed headers of a signed request. Nothing here is secret, but the signature and the
/// nonce are never logged anyway.
#[derive(Clone, PartialEq, Eq)]
pub struct Headers {
    pub device: String,
    /// `None` on the session-less calls (`/handshake/session`), signed as `-`.
    pub session: Option<String>,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Headers")
            .field("device", &self.device)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

/// The one value of header `name`; `None` when absent, `Err` when repeated or not text.
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, &'static str> {
    let mut all = headers.get_all(name).iter();
    let Some(first) = all.next() else {
        return Ok(None);
    };
    if all.next().is_some() {
        return Err("a signing header is repeated");
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| "a signing header is not ASCII")
}

/// The headers, each in its exact format (`Err` is a reason for a 400). `session` says
/// whether the call carries a session (`Ainkrad-Session` required) or none (must be absent).
pub fn parse(headers: &HeaderMap, session: bool) -> Result<Headers, &'static str> {
    let need = |name| one(headers, name)?.ok_or("a signing header is missing");
    let device = need(DEVICE)?;
    if !is_id(device, "d_") {
        return Err("Ainkrad-Device is not a device id");
    }
    let session = match (one(headers, SESSION)?, session) {
        (Some(s), true) if is_id(s, "s_") => Some(s.to_owned()),
        (Some(_), true) => return Err("Ainkrad-Session is not a session id"),
        (None, true) => return Err("Ainkrad-Session is missing"),
        (Some(_), false) => return Err("this call takes no Ainkrad-Session"),
        (None, false) => None,
    };
    if need(ALG_HEADER)? != ALG {
        return Err("Ainkrad-Alg must be ES256");
    }
    let ts = need(TIMESTAMP)?;
    let canonical = !ts.is_empty()
        && ts.len() <= 12
        && ts.bytes().all(|b| b.is_ascii_digit())
        && (ts == "0" || !ts.starts_with('0'));
    let timestamp = ts
        .parse()
        .ok()
        .filter(|_| canonical)
        .ok_or("Ainkrad-Timestamp is unix seconds, decimal")?;
    let nonce = need(NONCE)?;
    unb64(nonce, 22).ok_or("Ainkrad-Nonce is 16 bytes, base64url")?;
    // A DER signature (70-72 bytes) has another length: refused here, before any lookup.
    let signature =
        unb64(need(SIGNATURE)?, 86).ok_or("Ainkrad-Signature is raw r||s, base64url")?;
    Ok(Headers {
        device: device.to_owned(),
        session,
        timestamp,
        nonce: nonce.to_owned(),
        signature,
    })
}

/// Whether the request-target path is one the signer and the router see alike (§5.2): no
/// `..`, no `//`, no NUL, no lowercase percent-escape, and nothing but URI path characters.
pub fn canonical_path(path: &str) -> bool {
    let b = path.as_bytes();
    if !path.starts_with('/') || path.contains("..") || path.contains("//") {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = |c: u8| c.is_ascii_digit() || (b'A'..=b'F').contains(&c);
                if !(i + 2 < b.len() && hex(b[i + 1]) && hex(b[i + 2])) {
                    return false;
                }
                if b[i + 1] == b'0' && b[i + 2] == b'0' {
                    return false;
                }
                i += 3;
                continue;
            }
            0 => return false,
            c if c.is_ascii_graphic() => {}
            _ => return false,
        }
        i += 1;
    }
    true
}

/// What a request signs (§5.2).
#[derive(Debug, Clone, Copy)]
pub struct Canonical<'a> {
    pub core_fp: &'a str,
    pub device: &'a str,
    pub session: Option<&'a str>,
    /// Upper-case ASCII.
    pub method: &'a str,
    /// The path bytes exactly as sent, still percent-encoded.
    pub path: &'a str,
    /// The raw query after `?`, or empty.
    pub query: &'a str,
    pub timestamp: i64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

impl Canonical<'_> {
    /// The exact bytes: 11 fields joined by `\n`, no trailing newline.
    pub fn bytes(&self) -> Vec<u8> {
        [
            "AINKRAD-REQ-V1",
            self.core_fp,
            ALG,
            self.device,
            self.session.unwrap_or("-"),
            self.method,
            self.path,
            self.query,
            &self.timestamp.to_string(),
            self.nonce,
            &b64(&sha256(self.body)),
        ]
        .join("\n")
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_refused_unless_canonical() {
        for ok in ["/api/v1/me", "/api/v1/devices/d_x", "/a%2Fb", "/a%2Eb", "/"] {
            assert!(canonical_path(ok), "{ok}");
        }
        for bad in [
            "/api/../v1",
            "/a..b",
            "//api",
            "/api//v1",
            "/a%2fb",
            "/a%00b",
            "/a%2",
            "/a%zz",
            "api",
            "",
            "/a b",
            "/a\u{0}",
        ] {
            assert!(!canonical_path(bad), "{bad:?}");
        }
    }
}
