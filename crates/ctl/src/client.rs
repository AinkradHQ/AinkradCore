//! A paired device talking to its Core: the identity check before anything is signed, the
//! session challenge-response (spec §6) with transparent renewal, and signed requests (§5).

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Error;
use crate::keystore::Keystore;
use crate::net::{Net, Response};
use crate::proto::{Canonical, b64, fp, nonce, unb64, verify};
use crate::stepup::{self, Passphrase};

/// Renew a session this many seconds before it expires (§6.3: refresh before expiry).
const RENEW_BEFORE: i64 = 60;

/// `GET`/`POST /handshake`, the fields ctl reads; `POST` adds the proof.
#[derive(Debug, Clone, Deserialize)]
pub struct Handshake {
    pub server_version: Option<String>,
    pub api_minor: Option<u32>,
    pub identity_fingerprint: Option<String>,
    #[serde(default)]
    core_spki: Option<String>,
    #[serde(default)]
    core_sig: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub expires: i64,
    pub scopes: Vec<String>,
    /// Until when the Core says this session is elevated (§8), in this process's memory only.
    pub elevated_until: Option<i64>,
}

#[derive(Deserialize)]
struct Grant {
    session_id: Option<String>,
    expires_at: Option<String>,
    scopes: Option<Vec<String>>,
    elevated_until: Option<String>,
}

pub struct Client {
    pub net: Net,
    pub store: Keystore,
    session: Option<Session>,
    /// Seconds added to this machine's clock when signing. Zero but in tests that prove the
    /// Core refuses a skewed clock.
    pub clock_offset: i64,
    /// The step-up key's file (beside the keystore) and where its passphrase comes from.
    pub stepup_file: Option<std::path::PathBuf>,
    pub passphrase: Passphrase,
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

/// A pre-auth `POST`, retried once after `Retry-After` on a 429 (§11: 30 a minute per address,
/// shared by `/handshake` and `/handshake/challenge`).
async fn post_preauth(net: &Net, path: &str, body: Vec<u8>) -> Result<Response, Error> {
    let res = net.send("POST", path, &[], body.clone()).await?;
    if res.status != 429 {
        return Ok(res);
    }
    let wait = res
        .headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .unwrap_or(1)
        .min(60);
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    net.send("POST", path, &[], body).await
}

/// `POST /handshake {nonce}` (spec §4, §13): the Core proves, over a fresh nonce, that it holds
/// the key `pinned` names. Returns what it said and the fingerprint it proved; with no pin yet
/// (a typed code, trust on first use confirmed by the SAS) that is `fp(core_spki)`, still only
/// after the signature verifies. Fails closed: a status other than 200 (a 429 aside, which is
/// the rate), a missing or malformed `core_spki`/`core_sig`, a key that is not the pinned one or
/// a signature that does not verify is `core_identity_mismatch`. Never falls back to `GET`.
pub async fn prove(net: &Net, pinned: Option<&str>) -> Result<(Handshake, String), Error> {
    let nonce = nonce();
    let body = serde_json::to_vec(&serde_json::json!({"nonce": nonce})).expect("serialisable");
    let res = post_preauth(net, "/handshake", body).await?;
    if res.status == 429 {
        return Err(refusal(&res, unix_now()));
    }
    let mismatch = |served: String| Error::Identity {
        pinned: pinned.unwrap_or("(nothing yet)").to_owned(),
        served,
    };
    if res.status != 200 {
        return Err(mismatch(format!(
            "unproven (POST /handshake {})",
            res.status
        )));
    }
    let h: Handshake = serde_json::from_slice(&res.body)
        .map_err(|_| mismatch("unproven (not a handshake)".into()))?;
    let spki = h.core_spki.as_deref().and_then(unb64);
    let sig = h.core_sig.as_deref().and_then(unb64);
    let (Some(spki), Some(sig)) = (spki, sig) else {
        return Err(mismatch("unproven (no core_spki/core_sig)".into()));
    };
    let served = fp(&spki);
    if pinned.is_some_and(|p| p != served) {
        return Err(mismatch(served));
    }
    let message = format!("AINKRAD-CORE-V1\n{}\n{nonce}", net.host);
    if !verify(&spki, message.as_bytes(), &sig) {
        return Err(mismatch(format!("{served} (core_sig does not verify)")));
    }
    Ok((h, served))
}

impl Client {
    pub fn new(net: Net, store: Keystore) -> Self {
        Self {
            net,
            store,
            session: None,
            clock_offset: 0,
            stepup_file: None,
            passphrase: Passphrase::default(),
        }
    }

    pub fn now(&self) -> i64 {
        unix_now() + self.clock_offset
    }

    /// The Core must prove it is the pinned one before anything is signed (§13: native clients
    /// check `POST /handshake`'s `core_sig` at the start of each session).
    pub async fn check_identity(&self) -> Result<Handshake, Error> {
        Ok(prove(&self.net, Some(&self.store.core_fp)).await?.0)
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
        let res = post_preauth(&self.net, "/handshake/challenge", ask).await?;
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
            elevated_until: g.elevated_until.as_deref().and_then(parse_timestamp),
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
    /// session and retries once; a `step_up_required` answer elevates this session once (§8)
    /// and retries once. Each retry is a new nonce and timestamp.
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
        let (mut renewed, mut elevated) = (false, false);
        loop {
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
                Error::Refused { code, .. } if code == "session_expired" && !renewed => {
                    renewed = true;
                    self.drop_session();
                }
                Error::Refused { code, .. } if code == "step_up_required" && !elevated => {
                    elevated = true;
                    self.elevate().await?;
                }
                _ => return Err(err),
            }
        }
    }

    /// Elevates the current session with the step-up key (§8): opens the key (asking for its
    /// passphrase), takes a challenge for this session, signs the step-up message and posts
    /// it. Returns `elevated_until`.
    pub async fn elevate(&mut self) -> Result<i64, Error> {
        let path = self.stepup_file.clone().ok_or_else(|| {
            Error::StepUp("this device has no step-up key, so it cannot elevate".into())
        })?;
        let (device, core_fp) = (self.store.device_id.clone(), self.store.core_fp.clone());
        // The key is opened before anything is sent: no key or a wrong passphrase costs the
        // Core nothing and spends none of this device's step-up budget.
        if !path.exists() {
            return Err(Error::StepUp(stepup::no_key(&path)));
        }
        let pass = self.passphrase.read(false).map_err(Error::StepUp)?;
        let key = stepup::load(&path, &pass, &device, &core_fp).map_err(Error::StepUp)?;
        self.step_up_with(
            |m| key.sign(m),
            |s, c| stepup::message(&core_fp, &device, s, c),
        )
        .await
    }

    /// The step-up exchange with a given signer and message, so a test can prove the Core
    /// refuses a proof made any other way than §8's.
    pub async fn step_up_with(
        &mut self,
        sign: impl Fn(&[u8]) -> Vec<u8>,
        message: impl Fn(&str, &str) -> Vec<u8>,
    ) -> Result<i64, Error> {
        let s = self.session().await?;
        let res = self
            .signed("POST", "/api/v1/auth/step-up/challenge", &s.id, Vec::new())
            .await?;
        let c: Value = parse(&res)?;
        let challenge = c["challenge"]
            .as_str()
            .filter(|c| c.len() == 43)
            .ok_or_else(|| Error::Protocol("a step-up challenge that is not 32 bytes".into()))?;
        let proof = b64(&sign(&message(&s.id, challenge)));
        let body = serde_json::json!({"challenge": challenge, "stepup_sig": proof});
        let res = self
            .signed(
                "POST",
                "/api/v1/auth/step-up",
                &s.id,
                serde_json::to_vec(&body).expect("serialisable"),
            )
            .await?;
        let until = parse::<Value>(&res)?["elevated_until"]
            .as_str()
            .and_then(parse_timestamp)
            .ok_or_else(|| Error::Protocol("a step-up answer without elevated_until".into()))?;
        if let Some(cur) = self.session.as_mut().filter(|cur| cur.id == s.id) {
            cur.elevated_until = Some(until);
        }
        Ok(until)
    }

    /// One signed request in session `session`, no retries; a non-2xx is the refusal.
    async fn signed(
        &self,
        method: &str,
        path: &str,
        session: &str,
        body: Vec<u8>,
    ) -> Result<Response, Error> {
        let headers = self.sign(method, path, "", Some(session), &body);
        let res = self.net.send(method, path, &headers, body).await?;
        match res.status {
            200..300 => Ok(res),
            _ => Err(refusal(&res, self.now())),
        }
    }

    /// The current session, if one is open.
    pub fn current(&self) -> Option<&Session> {
        self.session.as_ref()
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
