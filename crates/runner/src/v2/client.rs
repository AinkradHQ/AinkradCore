//! The runner's HTTP side of the Core (handshake spec §5, §6): signed requests, the
//! `/handshake` fingerprint check, and sessions by challenge-response.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ainkrad_proto::v2::{ErrorCode, StreamError};
use serde_json::{Value, json};

use super::key::{Key, b64, random, sha256};

/// Why the runner could not reach, or was refused by, its Core.
#[derive(Debug)]
pub enum LinkError {
    /// The URL, the state or the TLS setup cannot be used; retrying cannot help.
    Config(String),
    /// The Core is not the one pinned (handshake spec §13): nothing was sent to it.
    Mismatch { pinned: String, presented: String },
    /// The Core answered an error: HTTP status and its `code`.
    Refused(u16, String),
    /// The connection failed or ended; a retry may help.
    Transport(String),
    /// A protocol `error`, or the connection proof failed.
    Protocol(StreamError),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(why) | Self::Transport(why) => f.write_str(why),
            Self::Mismatch { pinned, presented } => write!(
                f,
                "core_identity_mismatch: this runner pinned the Core {pinned}, but the server \
                 presents {presented}; refusing it (re-pair if the Core really changed)"
            ),
            Self::Refused(status, code) => write!(f, "the Core refused: HTTP {status} {code}"),
            Self::Protocol(e) => write!(f, "{:?}: {}", e.code, e.message),
        }
    }
}

impl std::error::Error for LinkError {}

impl LinkError {
    /// The Core was not who the runner pinned.
    pub fn mismatch(&self) -> bool {
        matches!(self, Self::Mismatch { .. })
            || matches!(self, Self::Protocol(e) if e.code == ErrorCode::CoreIdentityMismatch)
    }
}

fn transport(e: impl std::fmt::Display) -> LinkError {
    LinkError::Transport(e.to_string())
}

fn loopback(host: &str) -> bool {
    let ip = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The canonical string of a signed request (§5.2), exactly.
#[allow(clippy::too_many_arguments)]
pub fn canonical(
    core_fp: &str,
    device: &str,
    session: Option<&str>,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "AINKRAD-REQ-V1\n{core_fp}\nES256\n{device}\n{}\n{method}\n{path}\n\n{timestamp}\n{nonce}\n{}",
        session.unwrap_or("-"),
        b64(&sha256(body))
    )
    .into_bytes()
}

/// Who signs: the routine key, its device id and the Core it signs for.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub key: &'a Key,
    pub device: &'a str,
    pub core_fp: &'a str,
}

impl Signer<'_> {
    /// The six `Ainkrad-*` headers for `method path` with `body`, now.
    pub fn headers(
        &self,
        session: Option<&str>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Vec<(&'static str, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let nonce = b64(&random::<16>());
        let message = canonical(
            self.core_fp,
            self.device,
            session,
            method,
            path,
            now,
            &nonce,
            body,
        );
        let mut h = vec![
            ("ainkrad-device", self.device.to_owned()),
            ("ainkrad-alg", "ES256".to_owned()),
            ("ainkrad-timestamp", now.to_string()),
            ("ainkrad-nonce", nonce),
            ("ainkrad-signature", b64(&self.key.sign(&message))),
        ];
        if let Some(s) = session {
            h.push(("ainkrad-session", s.to_owned()));
        }
        h
    }
}

/// The Core's HTTP surface at `base` (`https://host[:port]`, or `http://` to loopback).
pub struct Client {
    pub base: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Self, LinkError> {
        let base = base.trim_end_matches('/').to_owned();
        let url = reqwest::Url::parse(&base)
            .map_err(|e| LinkError::Config(format!("bad Core URL {base}: {e}")))?;
        match (url.scheme(), url.host_str()) {
            ("https", Some(_)) => {}
            ("http", Some(h)) if loopback(h) => {}
            _ => {
                return Err(LinkError::Config(
                    "the Core URL is https:// (http:// only to a loopback host)".to_owned(),
                ));
            }
        }
        if url.path() != "/" || url.query().is_some() {
            return Err(LinkError::Config(
                "the Core URL has no path or query".to_owned(),
            ));
        }
        let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        let builder = match tls {
            Some(config) => builder.use_preconfigured_tls((*config).clone()),
            None => builder,
        };
        let http = builder
            .build()
            .map_err(|e| LinkError::Config(e.to_string()))?;
        Ok(Self { base, http })
    }

    /// The hub's WebSocket URL.
    pub fn hub_url(&self) -> String {
        let rest = self.base.split_once("://").map_or("", |(_, r)| r);
        let scheme = if self.base.starts_with("https") {
            "wss"
        } else {
            "ws"
        };
        format!("{scheme}://{rest}/runner/v2/connect")
    }

    /// The fingerprint `/handshake` reports: unsigned, so it only catches the wrong Core
    /// before anything signed is sent; the connection proof is what binds the identity.
    pub async fn core_fp(&self) -> Result<String, LinkError> {
        let (_, v) = self.call("GET", "/handshake", None, None).await?;
        v["identity_fingerprint"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| LinkError::Transport("no identity fingerprint".to_owned()))
    }

    /// A new session for `signer` (§6).
    pub async fn session(&self, signer: Signer<'_>) -> Result<String, LinkError> {
        let body = json!({"device_id": signer.device});
        let (_, c) = self
            .call("POST", "/handshake/challenge", Some(&body), None)
            .await?;
        let body = json!({"challenge": c["challenge"]});
        let (_, s) = self
            .call(
                "POST",
                "/handshake/session",
                Some(&body),
                Some((signer, None)),
            )
            .await?;
        s["session_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| LinkError::Transport("no session id".to_owned()))
    }

    /// One call: a JSON body, signed when `signed` names the signer and its session. A status
    /// of 400 and above is `Refused` with the error's code.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        signed: Option<(Signer<'_>, Option<&str>)>,
    ) -> Result<(u16, Value), LinkError> {
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let m = reqwest::Method::from_bytes(method.as_bytes()).expect("a method");
        let mut req = self.http.request(m, format!("{}{path}", self.base));
        if body.is_some() {
            req = req
                .header("content-type", "application/json")
                .body(bytes.clone());
        }
        if let Some((signer, session)) = signed {
            for (n, v) in signer.headers(session, method, path, &bytes) {
                req = req.header(n, v);
            }
        }
        let res = req.send().await.map_err(transport)?;
        let status = res.status().as_u16();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if status >= 400 {
            let code = v["code"].as_str().unwrap_or("unknown").to_owned();
            return Err(LinkError::Refused(status, code));
        }
        Ok((status, v))
    }
}
