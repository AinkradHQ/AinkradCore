//! What a Jira connection's sealed material holds, and the strict shapes of everything that
//! reaches a URL. `KindAdapter::test` sees only a `Material`, so the routing data (the site, the
//! cloud id) travels INSIDE it, as one envelope only this module writes and reads:
//!
//! - `oauth|<cloud id>|<site url>|<access token>` (the refresh token is the material's own),
//! - `token|<site host>|<email>|<api token>` (Basic auth against the site).
//!
//! Nothing outside this module may treat `Material::access()` as a bearer token.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::connections::material::Material;

/// The only suffix a token-auth site host may have; exactly one label sits before it.
pub const SITE_SUFFIX: &str = ".atlassian.net";

/// `acme.atlassian.net`: one lowercase DNS label and the suffix. No scheme, userinfo, port, path,
/// uppercase, extra label (`a.b.atlassian.net`) or text after the suffix, so no suffix trick.
pub fn site_host(h: &str) -> bool {
    let Some(label) = h.strip_suffix(SITE_SUFFIX) else {
        return false;
    };
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The host of `https://acme.atlassian.net` or `https://acme.atlassian.net/`, or a bare host.
pub fn site_host_of(input: &str) -> Option<String> {
    let rest = input.strip_prefix("https://").unwrap_or(input);
    let host = rest.strip_suffix('/').unwrap_or(rest);
    site_host(host).then(|| host.to_owned())
}

/// A Jira project key: `[A-Z][A-Z0-9_]+`, at most 10 characters.
pub fn project_key(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=10).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// The project key of an issue KEY (`ABC-12`); `None` for anything else, a numeric id included.
pub fn issue_key(s: &str) -> Option<&str> {
    let (project, n) = s.rsplit_once('-')?;
    let number =
        (1..=10).contains(&n.len()) && !n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit());
    (number && project_key(project)).then_some(project)
}

/// An Atlassian cloud id: a UUID.
pub fn cloud_id(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && !s.bytes().any(|b| b.is_ascii_uppercase())
}

fn plain(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && !s.contains('|')
        && !s.chars().any(|c| c.is_control() || c == ' ')
}

/// The envelope of an OAuth credential for one site. `site` is the `url` Atlassian listed.
pub fn oauth_material(
    cloud: &str,
    site: &str,
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<&str>,
) -> Option<Material> {
    if !cloud_id(cloud) || !site.starts_with("https://") || !plain(site, 200) {
        return None;
    }
    Material::new(
        &format!("oauth|{cloud}|{site}|{access}"),
        refresh,
        expires_at,
    )
}

/// The envelope of an email and API token for `host` (see [`site_host`]).
pub fn token_material(host: &str, email: &str, token: &str) -> Option<Material> {
    let email_ok = plain(email, 254) && email.contains('@') && !email.contains(':');
    if !site_host(host) || !email_ok || token.trim().is_empty() {
        return None;
    }
    Material::new(
        &format!("token|{host}|{email}|{}", token.trim()),
        None,
        None,
    )
}

/// A credential, unpacked. Prints nothing.
pub enum Cred {
    Oauth {
        cloud_id: String,
        site: String,
        token: Zeroizing<String>,
    },
    Basic {
        host: String,
        email: String,
        token: Zeroizing<String>,
    },
}

impl fmt::Debug for Cred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cred(<redacted>)")
    }
}

/// `None` when the material is not a Jira envelope, or its routing data is not strictly valid
/// (a sealed value is trusted no further than what would be accepted on the way in).
pub fn unpack(m: &Material) -> Option<Cred> {
    let mut p = m.access().splitn(4, '|');
    let (tag, a, b, rest) = (p.next()?, p.next()?, p.next()?, p.next()?);
    let token = Zeroizing::new(rest.to_owned());
    match tag {
        "oauth" if cloud_id(a) && b.starts_with("https://") && plain(b, 200) => Some(Cred::Oauth {
            cloud_id: a.to_owned(),
            site: b.to_owned(),
            token,
        }),
        "token" if site_host(a) && plain(b, 254) && b.contains('@') && !b.contains(':') => {
            Some(Cred::Basic {
                host: a.to_owned(),
                email: b.to_owned(),
                token,
            })
        }
        _ => None,
    }
}

impl Cred {
    pub fn is_oauth(&self) -> bool {
        matches!(self, Self::Oauth { .. })
    }

    /// The site as a person reads it.
    pub fn site(&self) -> String {
        match self {
            Self::Oauth { site, .. } => site.clone(),
            Self::Basic { host, .. } => format!("https://{host}"),
        }
    }

    /// The `Authorization` header, marked sensitive so no debug print shows it.
    pub fn authorization(&self) -> Option<HeaderValue> {
        let text = match self {
            Self::Oauth { token, .. } => Zeroizing::new(format!("Bearer {}", token.as_str())),
            Self::Basic { email, token, .. } => Zeroizing::new(format!(
                "Basic {}",
                STANDARD.encode(format!("{email}:{}", token.as_str()))
            )),
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
    fn a_site_host_is_one_lowercase_label_and_the_suffix_only() {
        let at = '@';
        let tricks = [
            "acme.atlassian.net.evil.test",
            "evil.test/acme.atlassian.net",
            "acme.atlassian.net:8443",
            "acme.atlassian.net/",
            "https://acme.atlassian.net",
            "Acme.atlassian.net",
            "acme.Atlassian.net",
            "a.b.atlassian.net",
            "-acme.atlassian.net",
            "acme-.atlassian.net",
            ".atlassian.net",
            "atlassian.net",
            "acmeatlassian.net",
            "acme.atlassian.net.",
            "acme.atlassian.com",
            "api.atlassian.com",
            "127.0.0.1",
            "acme_x.atlassian.net",
            "acme.atlassian.net%2f",
            "acme.atlassian.net\n",
            "acme.atlassian.net evil.test",
        ];
        for t in tricks {
            assert!(!site_host(t), "{t:?}");
        }
        assert!(!site_host(&format!("evil{at}acme.atlassian.net")));
        assert!(!site_host(&format!("{}.atlassian.net", "a".repeat(64))));
        assert!(site_host("acme.atlassian.net") && site_host("a-1.atlassian.net"));
        assert_eq!(
            site_host_of("https://acme.atlassian.net/").as_deref(),
            Some("acme.atlassian.net")
        );
        assert_eq!(site_host_of("http://acme.atlassian.net"), None);
        assert_eq!(site_host_of("https://acme.atlassian.net/jira"), None);
    }

    #[test]
    fn keys_are_strict() {
        assert!(project_key("ABC") && project_key("A1_B") && !project_key("abc"));
        assert!(!project_key("A") && !project_key("1AB") && !project_key("ABCDEFGHIJK"));
        assert!(!project_key("AB-C") && !project_key("AB C") && !project_key(""));
        assert_eq!(issue_key("ABC-12"), Some("ABC"));
        for bad in [
            "10042", "ABC-0", "ABC-012", "abc-1", "ABC-", "-1", "ABC-1x", "ABC--1",
        ] {
            assert_eq!(issue_key(bad), None, "{bad}");
        }
        assert_eq!(issue_key("AB-1/../XYZ-2"), None);
        assert!(cloud_id("1324a887-451d-4b3e-b3a5-0bfbb4c7d8f1") && !cloud_id("../x"));
    }

    #[test]
    fn the_envelope_round_trips_and_prints_nothing() {
        let tok = "tok-4f9a1c7b2d8e|with|bars";
        let m = token_material("acme.atlassian.net", "me@example.com", tok).unwrap();
        for text in [format!("{m:?}"), format!("{m}")] {
            assert!(!text.contains("4f9a1c7b"), "{text}");
        }
        let c = unpack(&m).unwrap();
        assert!(!format!("{c:?}").contains("4f9a1c7b"));
        assert_eq!(c.site(), "https://acme.atlassian.net");
        let h = c.authorization().unwrap();
        assert!(h.is_sensitive() && !format!("{h:?}").contains("Basic"));
        assert!(token_material("evil.test", "me@example.com", tok).is_none());
        assert!(token_material("acme.atlassian.net", "me|x@example.com", tok).is_none());
        assert!(token_material("acme.atlassian.net", "a:b@example.com", tok).is_none());
        let cloud = "1324a887-451d-4b3e-b3a5-0bfbb4c7d8f1";
        let o = oauth_material(
            cloud,
            "https://acme.atlassian.net",
            "acc-77",
            Some("ref-88"),
            None,
        );
        let c = unpack(&o.unwrap()).unwrap();
        assert!(c.is_oauth());
        assert!(oauth_material("../x", "https://acme.atlassian.net", "a", None, None).is_none());
        assert!(oauth_material(cloud, "http://acme.atlassian.net", "a", None, None).is_none());
    }
}
