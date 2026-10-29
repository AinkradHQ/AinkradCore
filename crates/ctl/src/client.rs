//! A paired device talking to its Core: the identity check before anything is signed, the
//! session challenge-response (spec §6) with transparent renewal, and signed requests (§5).

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Error;
use crate::keystore::Keystore;
use crate::net::{Net, Response};
use crate::proto::{Canonical, nonce};

/// Renew a session this many seconds before it expires (§6.3: refresh before expiry).
const RENEW_BEFORE: i64 = 60;

/// `GET /handshake`, the fields ctl reads.
#[derive(Debug, Clone, Deserialize)]
pub struct Handshake {
    pub server_version: Option<String>,
    pub api_minor: Option<u32>,
    pub identity_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub expires: i64,
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
struct Grant {
    session_id: Option<String>,
    expires_at: Option<String>,
    scopes: Option<Vec<String>>,
}

pub struct Client {
    pub net: Net,
    pub store: Keystore,
    session: Option<Session>,
    /// Seconds added to this machine's clock when signing. Zero but in tests that prove the
    /// Core refuses a skewed clock.
    pub clock_offset: i64,
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `2026-10-21T12:00:00.250Z` as unix seconds (the contract's one timestamp shape).
pub fn parse_timestamp(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || !ts.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// A refusal as the error the spec's model gives (§14), with `server_time` when present.
pub fn refusal(res: &Response, local_time: i64) -> Error {
    #[derive(Deserialize, Default)]
    struct Body {
        code: Option<String>,
        message: Option<String>,
        server_time: Option<i64>,
        floor: Option<i64>,
    }
    let body: Body = serde_json::from_slice(&res.body).unwrap_or_default();
    if res.status == 410
        && let Some(floor) = body.floor
    {
        return Error::PastRetention { floor };
    }
    Error::Refused {
        status: res.status,
        code: body.code.unwrap_or_else(|| "unknown".into()),
        message: body.message.unwrap_or_default(),
        server_time: body.server_time,
        local_time,
    }
}

/// The JSON body of a 2xx response.
pub fn parse<T: DeserializeOwned>(res: &Response) -> Result<T, Error> {
    serde_json::from_slice(&res.body)
        .map_err(|e| Error::Protocol(format!("an answer that is not the contract's: {e}")))
}

/// `GET /handshake`: unsigned, so nothing about this device goes out.
pub async fn handshake(net: &Net) -> Result<Handshake, Error> {
    let res = net.send("GET", "/handshake", &[], Vec::new()).await?;
    if res.status != 200 {
        return Err(refusal(&res, unix_now()));
    }
    parse(&res)
}

impl Client {
    pub fn new(net: Net, store: Keystore) -> Self {
        Self {
            net,
            store,
            session: None,
            clock_offset: 0,
        }
    }

    pub fn now(&self) -> i64 {
        unix_now() + self.clock_offset
    }

    /// The Core must be the pinned one before anything is signed (§13: native clients check
    /// `/handshake` on each connect). The served fingerprint is a claim, not a proof: the
    /// server's `/handshake` carries no `core_sig` (see the conformance notes).
    pub async fn check_identity(&self) -> Result<Handshake, Error> {
        let h = handshake(&self.net).await?;
        let served = h.identity_fingerprint.clone().unwrap_or_default();
        if served != self.store.core_fp {
            return Err(Error::Identity {
                pinned: self.store.core_fp.clone(),
                served,
            });
        }
        Ok(h)
    }

    /// The signed headers for one request (§5.1).
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        session: Option<&str>,
        body: &[u8],
    ) -> Vec<(&'static str, String)> {
        let nonce = nonce();
        Canonical {
            core_fp: &self.store.core_fp,
            device: &self.store.device_id,
            session,
            method,
            path,
            query,
            timestamp: self.now().max(0) as u64,
            nonce: &nonce,
            body,
        }
        .headers(&self.store.key)
    }

    /// A signed request with session `-` (`/handshake/session`, `/pair/status`).
    pub async fn sessionless(&self, path: &str, body: Vec<u8>) -> Result<Response, Error> {
        let headers = self.sign("POST", path, "", None, &body);
        self.net.send("POST", path, &headers, body).await
    }

    /// Challenge, then session (§6.1, §6.2), after the identity check.
    pub async fn open_session(&mut self) -> Result<&Session, Error> {
        self.session = None;
        self.check_identity().await?;
        let ask = serde_json::to_vec(&serde_json::json!({"device_id": self.store.device_id}))
            .expect("serialisable");
        let mut res = self
            .net
            .send("POST", "/handshake/challenge", &[], ask.clone())
            .await?;
        if res.status == 429 {
            // Honour Retry-After once (§11: 30 challenges a minute per address).
            let wait = res
                .headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                .unwrap_or(1)
                .min(60);
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            res = self
                .net
                .send("POST", "/handshake/challenge", &[], ask)
                .await?;
        }
        if res.status != 200 {
            return Err(refusal(&res, self.now()));
        }
        let c: Value = parse(&res)?;
        let challenge = c["challenge"]
            .as_str()
            .filter(|c| c.len() == 43)
            .ok_or_else(|| Error::Protocol("a challenge that is not 32 bytes".into()))?;
        let body =
            serde_json::to_vec(&serde_json::json!({"challenge": challenge})).expect("serialisable");
        let res = self.sessionless("/handshake/session", body).await?;
        if res.status != 200 {
            return Err(refusal(&res, self.now()));
        }
        let g: Grant = parse(&res)?;
        let (Some(id), Some(expires)) = (
            g.session_id,
            g.expires_at.as_deref().and_then(parse_timestamp),
        ) else {
            return Err(Error::Protocol(
                "a session grant without an id or expiry".into(),
            ));
        };
        Ok(self.session.insert(Session {
            id,
            expires,
            scopes: g.scopes.unwrap_or_default(),
        }))
    }

    /// A live session, renewed when it is close to expiry.
    pub async fn session(&mut self) -> Result<Session, Error> {
        match &self.session {
            Some(s) if s.expires - unix_now() > RENEW_BEFORE => Ok(s.clone()),
            _ => self.open_session().await.cloned(),
        }
    }

    /// Forgets the session, so the next call runs the challenge again (after a restart).
    pub fn drop_session(&mut self) {
        self.session = None;
    }

    /// A signed request in a session. A `session_expired` answer (a restart, say) renews the
    /// session and retries once with a new nonce and timestamp.
    pub async fn call(
        &mut self,
        method: &str,
        path: &str,
        query: &str,
        body: Option<&Value>,
    ) -> Result<Response, Error> {
        let body = body
            .map(|b| serde_json::to_vec(b).expect("serialisable"))
            .unwrap_or_default();
        let target = match query {
            "" => path.to_owned(),
            q => format!("{path}?{q}"),
        };
        for retry in [false, true] {
            let s = self.session().await?;
            let headers = self.sign(method, path, query, Some(&s.id), &body);
            let res = self
                .net
                .send(method, &target, &headers, body.clone())
                .await?;
            if (200..300).contains(&res.status) {
                return Ok(res);
            }
            let err = refusal(&res, self.now());
            match &err {
                Error::Refused { code, .. } if code == "session_expired" && !retry => {
                    self.drop_session();
                }
                _ => return Err(err),
            }
        }
        unreachable!("the loop returns on its second pass")
    }

    /// `call`, parsed.
    pub async fn get<T: DeserializeOwned>(&mut self, path: &str, query: &str) -> Result<T, Error> {
        parse(&self.call("GET", path, query, None).await?)
    }

    /// The scopes of the current session, once one is open.
    pub fn scopes(&self) -> &[String] {
        self.session.as_ref().map_or(&[], |s| &s.scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_parse() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_timestamp("2025-10-29T09:26:40.000Z"),
            Some(1_761_730_000)
        );
        assert_eq!(
            parse_timestamp("2024-02-29T23:59:59.999Z"),
            Some(1_709_251_199)
        );
        assert_eq!(parse_timestamp("2024-02-29 23:59:59Z"), None);
    }
}
