//! What a Microsoft Teams connection's sealed material holds, and the strict shapes of every id
//! that reaches a URL.
//!
//! **Envelope.** `KindAdapter::test` sees only a `Material`, so the tenant travels INSIDE it: the
//! access slot holds `v1|<tenant id>|<access token>` and the refresh slot the refresh token. Both
//! tokens are stored base32 (lower case, no padding), not as Microsoft sent them. Why: the secret
//! gate refuses a credential the redactor recognises as a real key, and a JWT is base64url, so by
//! chance (about 1 in 5,000 tokens) it holds `_sk-<20 key bytes>` or another prefix shape. A
//! renewal that hit that after Microsoft rotated the refresh token would lose the new one and
//! strand the connection. Lower-case base32 has no `-`, `_`, digit-led prefix or capital, so no
//! shape can match. No JWT shape is added to the redactor (see the descriptor).
//!
//! **Tenant.** A connection belongs to ONE Entra tenant, by its stable id (the `tid` claim of the
//! id token Microsoft issued at sign-in), never a name. It is the tenant in every token URL.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::HeaderValue;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::connections::material::Material;

/// The tenant of personal Microsoft accounts: they have no Teams channels.
pub const CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const TAG: &str = "v1";
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Lower-case base32 without padding.
pub fn b32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buf >> bits) & 31) as usize]));
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The bytes of canonical [`b32`] text; `None` for anything else.
pub fn unb32(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (bits < 5 && buf == 0).then_some(out)
}

/// A token Core will hold: printable ASCII, 16 to 5,000 bytes.
fn token_ok(s: &str) -> bool {
    (16..=5000).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// A GUID as Graph writes it: 36 characters, lower-case hex, dashes at 8, 13, 18 and 23. An upper
/// case, braced, encoded or suffixed one is not a GUID here.
pub fn guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// A tenant a connection may belong to: a GUID that is not the personal-account tenant.
pub fn tenant_id(s: &str) -> bool {
    guid(s) && s != CONSUMER_TENANT
}

fn middle_ok(m: &str) -> bool {
    (8..=80).contains(&m.len())
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `19:<middle>@thread.tacv2` (or the older `@thread.skype`): the middle and whether it is the
/// old kind. A chat (`@unq.gbl.spaces`, `@thread.v2`), a meeting or a name never is one.
fn channel_parts(s: &str) -> Option<(&str, bool)> {
    let rest = s.strip_prefix("19:")?;
    let (mid, old) = match rest.strip_suffix("@thread.tacv2") {
        Some(m) => (m, false),
        None => (rest.strip_suffix("@thread.skype")?, true),
    };
    middle_ok(mid).then_some((mid, old))
}

/// A channel id as Graph gives it.
pub fn channel_id(s: &str) -> bool {
    channel_parts(s).is_some()
}

/// The LIMIT KEY of a channel: `<team id>/<middle>` (`.skype` after the middle for an old id). It
/// is what a grant's `channels` limit holds and what the store compares, because the store takes
/// no `@` in a limit value; the middle never has a `.`, so the two kinds cannot collide.
pub fn channel_key(team: &str, channel: &str) -> Option<String> {
    let (mid, old) = channel_parts(channel)?;
    guid(team).then(|| format!("{team}/{mid}{}", if old { ".skype" } else { "" }))
}

/// Whether `k` is a well-formed limit key (`<team id>/<middle>[.skype]`).
pub fn key_ok(k: &str) -> bool {
    match k.split_once('/') {
        Some((team, rest)) => guid(team) && middle_ok(rest.strip_suffix(".skype").unwrap_or(rest)),
        None => false,
    }
}

/// A message or reply id: Graph's millisecond timestamp, as digits.
pub fn message_id(s: &str) -> bool {
    (10..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// A page cursor as Core hands it out (the skip token, base64url): never Microsoft's own URL.
pub fn cursor(s: &str) -> bool {
    (1..=4096).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The material of a sign-in: both tokens, the tenant they were issued in and the expiry.
pub fn oauth_material(
    tenant: &str,
    access: &str,
    refresh: &str,
    expires_at: &str,
) -> Option<Material> {
    let (access, refresh) = (access.trim(), refresh.trim());
    if !tenant_id(tenant) || !token_ok(access) || !token_ok(refresh) {
        return None;
    }
    Material::new(
        &format!("{TAG}|{tenant}|{}", b32(access.as_bytes())),
        Some(&b32(refresh.as_bytes())),
        Some(expires_at),
    )
}

/// A credential, unpacked. Prints nothing.
pub struct Cred {
    tenant: String,
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cred(<redacted>)")
    }
}

fn open(s: &str) -> Option<Zeroizing<String>> {
    let text = Zeroizing::new(String::from_utf8(unb32(s)?).ok()?);
    token_ok(&text).then_some(text)
}

/// `None` when the stored value is not what would be accepted on the way in.
pub fn unpack(m: &Material) -> Option<Cred> {
    let mut p = m.access().splitn(3, '|');
    let (tag, tenant, token) = (p.next()?, p.next()?, p.next()?);
    if tag != TAG || !tenant_id(tenant) {
        return None;
    }
    Some(Cred {
        tenant: tenant.to_owned(),
        access: open(token)?,
        refresh: open(m.refresh()?)?,
    })
}

impl Cred {
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn refresh(&self) -> &str {
        &self.refresh
    }

    /// `Authorization: Bearer <token>`, marked sensitive so no debug print shows it.
    pub fn authorization(&self) -> Option<HeaderValue> {
        let text = Zeroizing::new(format!("Bearer {}", self.access.as_str()));
        let mut v = HeaderValue::from_str(&text).ok()?;
        v.set_sensitive(true);
        Some(v)
    }

    /// The raw tokens, for the broker's scrub of an answer.
    pub fn secrets(&self) -> Vec<String> {
        vec![self.access.to_string(), self.refresh.to_string()]
    }
}

/// Every raw token of a credential: what the broker scrubs from an answer (the stored values are
/// base32, which no answer could carry).
pub fn secrets_of(m: &Material) -> Vec<String> {
    unpack(m).map(|c| c.secrets()).unwrap_or_default()
}

/// The identity line: `<user object id> in <tenant id>`; both are stable ids, never names.
pub fn subject(user: &str, tenant: &str) -> String {
    format!("{user} in {tenant}")
}

/// The tenant id inside an identity line.
pub fn tenant_of(identity: &str) -> Option<&str> {
    let (user, tenant) = identity.split_once(" in ")?;
    (guid(user) && tenant_id(tenant)).then_some(tenant)
}

/// What an identity line says about the tenant a credential belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantCheck {
    Same,
    Different,
    /// The connection records no tenant (never tested).
    Unknown,
}

/// Compares the recorded tenant with `tid`, by id only.
pub fn check_tenant(old: Option<&str>, tid: &str) -> TenantCheck {
    match old.and_then(tenant_of) {
        Some(t) if t == tid => TenantCheck::Same,
        Some(_) => TenantCheck::Different,
        None => TenantCheck::Unknown,
    }
}

/// The `tid` of the id token Microsoft's token endpoint issued to `client_id`. It is read from the
/// payload WITHOUT checking the signature: it came straight from the endpoint over TLS (the
/// documented exception), and it only ever names which tenant to pin, never grants anything.
pub fn id_token_tenant(jwt: &str, client_id: &str) -> Option<String> {
    if jwt.len() > 16_384 {
        return None;
    }
    let mut p = jwt.split('.');
    let (_, payload, _) = (p.next()?, p.next()?, p.next()?);
    if p.next().is_some() {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    let aud = v.get("aud")?.as_str()?;
    if !aud.eq_ignore_ascii_case(client_id) {
        return None;
    }
    let tid = v.get("tid")?.as_str()?;
    tenant_id(tid).then(|| tid.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const TEAM: &str = "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b";
    pub const CH: &str = "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2";

    #[test]
    fn base32_round_trips_and_has_no_key_shape_characters() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(unb32(&b32(&bytes)).unwrap(), bytes, "{len}");
        }
        let jwt = "eyJ0eXAi.OiJKV1Qi_sk-AbCdEfGhIjKlMnOpQrStUv.sig-AIzaSyA1234567890123456789012345678901";
        let wrapped = b32(jwt.as_bytes());
        assert!(
            wrapped
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        );
        for bad in ["A", "ab=", "ab-", "a b", "ab9", "b"] {
            assert!(unb32(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn ids_are_strict() {
        assert!(guid(TEAM) && tenant_id(TEAM));
        let upper = TEAM.to_uppercase();
        for bad in [
            "",
            upper.as_str(),
            "fbe2bf47-16c8-47cf-b4a5-4b9b187c508",
            "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b ",
            "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/..",
            "{fbe2bf47-16c8-47cf-b4a5-4b9b187c508b}",
            "fbe2bf4716c847cfb4a54b9b187c508b",
            "fbe2bf47_16c8_47cf_b4a5_4b9b187c508b",
            "%66be2bf47-16c8-47cf-b4a5-4b9b187c508b",
            "fbe2bf47-16c8-47cf-b4a5-4b9b187c508g",
        ] {
            assert!(!guid(bad), "{bad:?}");
        }
        assert!(!tenant_id(CONSUMER_TENANT));
        assert!(channel_id(CH));
        assert!(channel_id(
            "19:ZmNjZDMxYmQtYzA3Zi00MGQ5LTk4MTAtMzg0NTA4NTg4YjQ2@thread.skype"
        ));
        for bad in [
            "",
            "19:abc@thread.tacv2",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.v2",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@unq.gbl.spaces",
            "19:meeting_4a95f7d8db4c4e7fae857bcebe0623e6@thread.v2",
            "20:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2",
            "19:4a95f7d8db4c4e7f/../e6@thread.tacv2",
            "19%3A4a95f7d8db4c4e7fae857bcebe0623e6%40thread.tacv2",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2/messages",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2?x=1",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2 ",
            "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2\n",
            "19:4a95f7d8db4c4e7f@e857bcebe0623e6@thread.tacv2",
            TEAM,
            "general",
        ] {
            assert!(!channel_id(bad), "{bad:?}");
        }
        let key = channel_key(TEAM, CH).unwrap();
        assert_eq!(key, format!("{TEAM}/4a95f7d8db4c4e7fae857bcebe0623e6"));
        assert!(key_ok(&key));
        let old = channel_key(TEAM, "19:abcdefgh12345678@thread.skype").unwrap();
        assert!(old.ends_with(".skype") && key_ok(&old));
        assert_eq!(channel_key(&upper, CH), None);
        assert_eq!(channel_key(CH, TEAM), None, "swapped");
        let (slash, dots) = (format!("{TEAM}/"), format!("{TEAM}/../../x1234567"));
        for bad in ["", TEAM, "x/y", slash.as_str(), dots.as_str()] {
            assert!(!key_ok(bad), "{bad:?}");
        }
        assert!(message_id("1616990032035") && message_id("16169900320"));
        for bad in [
            "",
            "123",
            "16169900320a",
            "-1616990032035",
            "1616990032035 ",
        ] {
            assert!(!message_id(bad), "{bad:?}");
        }
        assert!(cursor("abcDEF-_09") && !cursor("a=b") && !cursor("a&b") && !cursor(""));
    }

    #[test]
    fn the_credential_round_trips_prints_nothing_and_is_a_bearer() {
        let (a, r) = (
            "eyJhbGciOi.payload-111.sig-abc-222",
            "0.ARoA-refresh-token-333-444",
        );
        let m = oauth_material(TEAM, a, r, "2026-11-06T11:00:00.000Z").unwrap();
        for text in [format!("{m:?}"), format!("{m}")] {
            assert!(!text.contains("111") && !text.contains("333"), "{text}");
        }
        assert!(!m.access().contains("eyJ") && !m.refresh().unwrap().contains("0.AR"));
        let c = unpack(&m).unwrap();
        assert_eq!(c.tenant(), TEAM);
        assert_eq!(c.refresh(), r);
        assert!(!format!("{c:?}").contains("111"));
        let h = c.authorization().unwrap();
        assert!(h.is_sensitive() && !format!("{h:?}").contains("eyJ"));
        assert_eq!(h.to_str().unwrap(), format!("Bearer {a}"));
        assert_eq!(c.secrets(), vec![a.to_owned(), r.to_owned()]);
        for (t, x, y) in [
            ("not-a-tenant", a, r),
            (CONSUMER_TENANT, a, r),
            (TEAM, "short", r),
            (TEAM, a, "short"),
            (TEAM, "has a space in the access token", r),
        ] {
            assert!(
                oauth_material(t, x, y, "2026-11-06T11:00:00.000Z").is_none(),
                "{t} {x}"
            );
        }
        // What is stored is trusted no further than what would be accepted.
        let raw = Material::new(a, Some(r), None).unwrap();
        assert!(unpack(&raw).is_none());
        let other = Material::new(
            &format!("v1|not-a-tenant|{}", b32(a.as_bytes())),
            Some(&b32(r.as_bytes())),
            None,
        )
        .unwrap();
        assert!(unpack(&other).is_none());
        let none = Material::new(m.access(), None, None).unwrap();
        assert!(unpack(&none).is_none(), "no refresh token, no credential");
    }

    #[test]
    fn identity_lines_name_ids_and_the_tenant_check_compares_ids() {
        let oid = "8ea0e38b-efb3-4757-924a-5f94061cf8c2";
        let line = subject(oid, TEAM);
        assert_eq!(tenant_of(&line), Some(TEAM));
        let (name, at) = (format!("{oid} in Contoso"), format!("{oid} at {TEAM}"));
        let bads = [
            "",
            TEAM,
            "Robin Kline in fbe2bf47-16c8-47cf-b4a5-4b9b187c508b",
            name.as_str(),
            at.as_str(),
        ];
        for bad in bads {
            assert_eq!(tenant_of(bad), None, "{bad}");
        }
        let other = "2432b57b-0abd-43db-aa7b-16eadd115d34";
        assert_eq!(check_tenant(Some(&line), TEAM), TenantCheck::Same);
        assert_eq!(check_tenant(Some(&line), other), TenantCheck::Different);
        assert_eq!(check_tenant(None, TEAM), TenantCheck::Unknown);
        assert_eq!(check_tenant(Some("Robin"), TEAM), TenantCheck::Unknown);
    }

    fn jwt(payload: &str) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn the_tenant_comes_from_an_id_token_issued_to_this_client() {
        let ok = jwt(&format!(r#"{{"aud":"cli-1","tid":"{TEAM}"}}"#));
        assert_eq!(id_token_tenant(&ok, "cli-1").as_deref(), Some(TEAM));
        assert_eq!(id_token_tenant(&ok, "cli-2"), None, "another audience");
        for bad in [
            jwt(&format!(r#"{{"aud":"cli-1","tid":"{CONSUMER_TENANT}"}}"#)),
            jwt(r#"{"aud":"cli-1","tid":"contoso.onmicrosoft.com"}"#),
            jwt(r#"{"aud":"cli-1"}"#),
            jwt("not json"),
            "a.b".to_owned(),
            format!("{ok}.extra"),
            "x".repeat(20_000),
        ] {
            assert_eq!(id_token_tenant(&bad, "cli-1"), None, "{bad:.40}");
        }
    }
}
