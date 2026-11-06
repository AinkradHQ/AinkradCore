//! The one door to GitHub (C2; design §5: strict upstream host list, no redirects, size and time
//! limits, no credential in an error or a log line).
//!
//! The same rules as the runner's KAN-435 gateway dialer, which lives in a crate the server does
//! not link: one request per call, `https` only, bundled roots only, no proxy from the
//! environment, **every** answer of the lookup checked against the public address rules and the
//! connection made to the address that was checked (a mixed answer is refused outright), no
//! redirect followed, a total time and a body ceiling.
//!
//! A request names a [`Host`], never a URL: the two hosts are fixed at construction
//! (`api.github.com`, and `github.com` for the device flow endpoints), so a path cannot move a
//! request to another host. Nothing here prints a token, a URL or a body: [`Req`], [`Resp`] and
//! [`NetError`] have fixed `Debug` text.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::addr::public;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Url};

/// The hosts a request may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// `api.github.com`: the REST API.
    Api,
    /// `github.com`: the device flow endpoints only.
    Web,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Patch,
    Put,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Put => "PUT",
        }
    }
}

/// A request body; `Debug` shows its size only (a device code travels in one).
#[derive(Clone, PartialEq, Eq)]
pub struct Body {
    content_type: &'static str,
    bytes: Vec<u8>,
}

impl Body {
    pub(super) fn json(bytes: Vec<u8>) -> Self {
        Self {
            content_type: "application/json",
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Body({} bytes)", self.bytes.len())
    }
}

/// One request: no credential in it (the bearer is given to [`Transport::send`] beside it).
/// Only this module and the kind's own builders make one; the fields are read through getters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Req {
    host: Host,
    method: Method,
    /// Starts with `/`; already percent-encoded, query included.
    path: String,
    body: Option<Body>,
}

impl Req {
    pub(super) fn new(host: Host, method: Method, path: String, body: Option<Body>) -> Self {
        Self {
            host,
            method,
            path,
            body,
        }
    }

    pub(super) fn get(host: Host, path: String) -> Self {
        Self::new(host, Method::Get, path, None)
    }

    /// A form POST (`application/x-www-form-urlencoded`).
    pub(super) fn form(host: Host, path: &str, fields: &[(&str, &str)]) -> Self {
        let bytes = fields
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let body = Body {
            content_type: "application/x-www-form-urlencoded",
            bytes: bytes.into_bytes(),
        };
        Self::new(host, Method::Post, path.to_owned(), Some(body))
    }

    pub fn host(&self) -> Host {
        self.host
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }
}

/// What the rate limit headers say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rate {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    /// Unix seconds the window resets.
    pub reset: Option<i64>,
    /// Seconds, from `Retry-After`.
    pub retry_after: Option<u64>,
}

/// A reply: the status, the few headers the Core reads, the body (at most [`MAX_BODY`] bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Resp {
    pub status: u16,
    pub rate: Rate,
    /// `X-OAuth-Scopes`: what a classic token may do.
    pub scopes: Option<String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for Resp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Resp({}, {} bytes)", self.status, self.body.len())
    }
}

/// Why no reply came. Deliberately no text: a transport error prints the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// The host resolved to an address no upstream may be at.
    Refused,
    /// No connection, a failed handshake, or a broken one.
    Unreachable,
    Timeout,
    /// The body is longer than [`MAX_BODY`].
    TooLarge,
    /// The request is not one this door sends.
    BadRequest,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused => "GitHub resolved to an address Core will not dial",
            Self::Unreachable => "GitHub could not be reached",
            Self::Timeout => "GitHub did not answer in time",
            Self::TooLarge => "GitHub's answer is larger than Core accepts",
            Self::BadRequest => "that request is not one Core sends to GitHub",
        })
    }
}

impl StdError for NetError {}

/// The most of a body that is read.
pub const MAX_BODY: usize = 2 * 1024 * 1024;
const CONNECT: Duration = Duration::from_secs(5);
const RESOLVE: Duration = Duration::from_secs(5);
const TOTAL: Duration = Duration::from_secs(30);
const API: &str = "https://api.github.com";
const WEB: &str = "https://github.com";

/// Everything but the unreserved characters, percent-encoded.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The lookup, every answer checked; the client connects to what this returns, never to a second
/// lookup.
struct Public;

#[derive(Debug)]
struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refused address")
    }
}

impl StdError for Refused {}

impl Resolve for Public {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::time::timeout(RESOLVE, tokio::net::lookup_host((host, 0)))
                .await
                .map_err(|_| Box::new(Refused) as Box<dyn StdError + Send + Sync>)?
                .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)?;
            let answers: Vec<_> = found.take(16).collect();
            if answers.is_empty() || answers.iter().any(|a| !public(a.ip())) {
                return Err(Box::new(Refused) as Box<dyn StdError + Send + Sync>);
            }
            Ok(Box::new(answers.into_iter()) as Addrs)
        })
    }
}

/// Splits a path (before any `?`) into raw segments and refuses what could leave it: a
/// `.`/`..` segment in any spelling (a URL parser resolves them), a backslash, a control
/// character, an authority-looking start.
pub fn safe_path(path: &str) -> bool {
    let (p, _) = path.split_once('?').unwrap_or((path, ""));
    p.starts_with('/')
        && !p.starts_with("//")
        && !p.bytes().any(|b| b == b'\\' || b < 0x21 || b == 0x7f)
        && p[1..].split('/').all(|seg| {
            let plain = seg.replace("%2e", ".").replace("%2E", ".");
            !plain.is_empty() && !plain.chars().all(|c| c == '.')
        })
}

#[derive(Clone)]
pub struct Transport {
    client: Client,
    api: Url,
    web: Url,
}

impl Transport {
    /// The real one: GitHub's two hosts over `https`, the public-address rule, no proxy.
    pub fn strict() -> Self {
        Self::build(API, WEB, true, Some(Arc::new(Public)))
    }

    /// Plain `http` to a loopback fake at `base` for both hosts (tests only).
    #[cfg(test)]
    pub fn local(base: &str) -> Self {
        Self::build(base, base, false, None)
    }

    fn build(api: &str, web: &str, https: bool, resolver: Option<Arc<Public>>) -> Self {
        let mut b = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https)
            .no_proxy()
            .connect_timeout(CONNECT)
            .timeout(TOTAL)
            .pool_max_idle_per_host(0)
            .user_agent("ainkrad-core");
        if let Some(r) = resolver {
            b = b.dns_resolver(r);
        }
        Self {
            client: b.build().expect("a client with these settings builds"),
            api: Url::parse(api).expect("a constant base is a URL"),
            web: Url::parse(web).expect("a constant base is a URL"),
        }
    }

    fn url(&self, host: Host, path: &str) -> Result<Url, NetError> {
        let base = match host {
            Host::Api => &self.api,
            Host::Web => &self.web,
        };
        if !safe_path(path) {
            return Err(NetError::BadRequest);
        }
        let url = base.join(path).map_err(|_| NetError::BadRequest)?;
        // The host, scheme and port are the base's, whatever the path said.
        let same = url.scheme() == base.scheme()
            && url.host_str() == base.host_str()
            && url.port_or_known_default() == base.port_or_known_default();
        if same && url.username().is_empty() && url.password().is_none() {
            Ok(url)
        } else {
            Err(NetError::BadRequest)
        }
    }

    /// Sends `req`, with `bearer` as the credential when there is one. A redirect is a reply
    /// like any other (its status), never followed.
    pub async fn send(&self, req: &Req, bearer: Option<&str>) -> Result<Resp, NetError> {
        // A credential goes to the REST API only, never to the device flow host.
        if bearer.is_some() && req.host != Host::Api {
            return Err(NetError::BadRequest);
        }
        let url = self.url(req.host, &req.path)?;
        let method = match req.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Patch => reqwest::Method::PATCH,
            Method::Put => reqwest::Method::PUT,
        };
        let accept = match req.host {
            Host::Api => "application/vnd.github+json",
            Host::Web => "application/json",
        };
        let mut rb = self
            .client
            .request(method, url)
            .header("accept", accept)
            .header("x-github-api-version", "2022-11-28");
        if let Some(t) = bearer {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = &req.body {
            rb = rb
                .header("content-type", b.content_type)
                .body(b.bytes.clone());
        }
        let mut resp = rb.send().await.map_err(|e| net(&e))?;
        let h = resp.headers();
        let num = |name: &str| h.get(name)?.to_str().ok()?.trim().parse::<u64>().ok();
        let rate = Rate {
            limit: num("x-ratelimit-limit"),
            remaining: num("x-ratelimit-remaining"),
            reset: num("x-ratelimit-reset").and_then(|n| i64::try_from(n).ok()),
            retry_after: num("retry-after"),
        };
        let scopes = h
            .get("x-oauth-scopes")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect::<String>());
        let status = resp.status().as_u16();
        if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
            return Err(NetError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(piece) = resp.chunk().await.map_err(|e| net(&e))? {
            if body.len() + piece.len() > MAX_BODY {
                return Err(NetError::TooLarge);
            }
            body.extend_from_slice(&piece);
        }
        Ok(Resp {
            status,
            rate,
            scopes,
            body,
        })
    }
}

fn net(e: &reqwest::Error) -> NetError {
    let mut at: Option<&(dyn StdError + 'static)> = Some(e);
    while let Some(x) = at {
        if x.is::<Refused>() {
            return NetError::Refused;
        }
        at = x.source();
    }
    if e.is_timeout() {
        NetError::Timeout
    } else {
        NetError::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_everything_but_unreserved() {
        assert_eq!(encode("a b/c?d=é~-._"), "a%20b%2Fc%3Fd%3D%C3%A9~-._");
    }

    #[test]
    fn a_path_cannot_leave_or_carry_an_authority() {
        for bad in [
            "",
            "repos/x",
            "//evil.example/x",
            "/repos/../admin",
            "/repos/%2e%2E/admin",
            "/repos/./x",
            "/repos//x",
            "/repos\\x",
            "/repos/x y",
            "/repos/x\n",
        ] {
            assert!(!safe_path(bad), "{bad:?}");
        }
        assert!(safe_path("/repos/o/r/issues?state=open&q=a%2F..%2Fb"));
        let t = Transport::strict();
        assert_eq!(
            t.url(Host::Api, "/@evil.example/x").unwrap().host_str(),
            Some("api.github.com")
        );
        assert_eq!(
            t.url(Host::Web, "/login/device/code").unwrap().host_str(),
            Some("github.com")
        );
    }

    #[tokio::test]
    async fn the_lookup_refuses_a_host_that_resolves_to_this_machine() {
        let name: Name = "localhost".parse().unwrap();
        assert!(Public.resolve(name).await.is_err());
    }
}
