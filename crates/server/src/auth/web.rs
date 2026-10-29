//! Passkeys (handshake spec §9, E1-08): the relying party and its ceremonies, on `webauthn-rs`
//! with the system OpenSSL (P1.12 Q2 option 1). Everything here is in memory and per process.
//!
//! - **Relying party:** the RP ID is the Core's hostname (`App::host` without its port), the
//!   origin `https://<host>`; `http://localhost:<port>` only on a loopback listener. An IP
//!   address cannot be an RP ID, so passkeys refuse to start on one.
//! - **ES256 only, attestation `none`, user verification required, resident key preferred.**
//!   webauthn-rs asks for UV and attestation `none` itself; the algorithm list and the
//!   resident-key preference are rewritten in the options sent ([`creation_options`]), and a
//!   registered key that is not EC2 P-256 ES256 is refused ([`p256_spki`]).
//! - **Ceremony state stays server-side** (`danger-allow-state-serialisation` is off), keyed
//!   by what it is bound to: a registration by its pairing (one each, a new one replaces it), a
//!   sign-in by its challenge (with the browser's session key, so the session that comes out of
//!   it signs with that key), a step-up by its session (one each). Every entry is single use and
//!   expires; sign-ins are capped per address and in all, and no address evicts another's. The
//!   host's socket is never refused for a full table.
//! - The sign-in challenge is webauthn-rs's own random one, bound to the session key by the
//!   stored ceremony, not by hashing the key into the challenge (spec §9 step 2): the high-level
//!   API takes no caller-chosen challenge. Same effect: only the ceremony's own key gets the
//!   session.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use webauthn_rs::prelude::*;

use super::budget::LOCAL;
use super::crypto::{b64, spki_of, spki_point};

/// How long a sign-in or step-up ceremony may take.
pub const CEREMONY_SECS: i64 = 60;
/// Live sign-in ceremonies per address; a new one replaces that address's oldest.
pub const SIGNINS_PER_ADDR: usize = 3;
/// Live sign-in ceremonies in all.
pub const SIGNINS_MAX: usize = 10_000;

/// A sign-in in flight: its webauthn-rs state, the browser's session key, who asked.
struct SignIn {
    state: DiscoverableAuthentication,
    key: Vec<u8>,
    addr: String,
    expires: i64,
    order: u64,
}

pub struct Passkeys {
    pub webauthn: Webauthn,
    pub rp_id: String,
    pub origin: String,
    /// pairing id → registration state, until the pairing's expiry.
    registrations: Mutex<HashMap<String, (PasskeyRegistration, i64)>>,
    /// challenge (base64url) → sign-in.
    signins: Mutex<HashMap<String, SignIn>>,
    /// session id → step-up state, its challenge (base64url) and expiry.
    stepups: Mutex<HashMap<String, (PasskeyAuthentication, String, i64)>>,
    order: AtomicU64,
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkeys")
            .field("rp_id", &self.rp_id)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// The name part of a `Host` value (`core.lan`, `localhost:7700`, `[::1]:7700`).
pub fn host_name(host: &str) -> &str {
    if host.starts_with('[') {
        return host.split(']').next().unwrap_or(host);
    }
    host.rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(name, _)| name)
}

/// The origin a browser page served by this Core has: `https://<host>`, or
/// `http://<host>` for `localhost` (a secure context in every browser).
pub fn own_origin(host: &str) -> String {
    if host_name(host).eq_ignore_ascii_case("localhost") {
        format!("http://{host}")
    } else {
        format!("https://{host}")
    }
}

impl Passkeys {
    /// The relying party for `host`. Refused for an IP address or an empty name, and for
    /// `localhost` unless the Core listens on loopback only (`loopback`).
    pub fn new(host: &str, loopback: bool) -> Result<Self, String> {
        let rp_id = host_name(host).to_ascii_lowercase();
        if rp_id.is_empty() || rp_id.starts_with('[') || rp_id.parse::<std::net::IpAddr>().is_ok() {
            return Err(format!(
                "passkeys need a DNS name as the Core host, not {host:?}: set --host"
            ));
        }
        if rp_id == "localhost" && !loopback {
            return Err("passkeys on localhost only with a loopback listener".into());
        }
        let origin = own_origin(&host.to_ascii_lowercase());
        let url = Url::parse(&origin).map_err(|e| format!("origin {origin}: {e}"))?;
        let webauthn = WebauthnBuilder::new(&rp_id, &url)
            .and_then(|b| b.rp_name("Ainkrad Core").build())
            .map_err(|e| format!("passkeys for {rp_id}: {e}"))?;
        Ok(Self {
            webauthn,
            rp_id,
            origin,
            registrations: Mutex::default(),
            signins: Mutex::default(),
            stepups: Mutex::default(),
            order: AtomicU64::new(0),
        })
    }

    /// Registration options for the live passkey pairing `pairing` (expiring at `expires`),
    /// replacing any earlier ceremony of that pairing.
    pub fn start_registration(&self, pairing: &str, name: &str, now: i64, expires: i64) -> Value {
        let user = Uuid::from_bytes(super::crypto::random::<16>());
        let (ccr, state) = self
            .webauthn
            .start_passkey_registration(user, name, name, None)
            .expect("a passkey registration always starts");
        let mut all = self.registrations.lock().unwrap();
        all.retain(|_, (_, exp)| *exp > now);
        all.insert(pairing.to_owned(), (state, expires));
        creation_options(&ccr)
    }

    /// Spends the registration state of `pairing`, if it is live.
    pub fn take_registration(&self, pairing: &str, now: i64) -> Option<PasskeyRegistration> {
        let mut all = self.registrations.lock().unwrap();
        all.remove(pairing)
            .filter(|(_, exp)| *exp > now)
            .map(|(s, _)| s)
    }

    /// Sign-in options for a browser session key `key` (a P-256 SPKI), asked from `addr`.
    /// `None` when the table is full (never for the host's socket).
    pub fn start_signin(&self, key: Vec<u8>, addr: &str, now: i64) -> Option<Value> {
        let (mut rcr, state) = self
            .webauthn
            .start_discoverable_authentication()
            .expect("a discoverable authentication always starts");
        // An explicit sign-in button, not the autofill (conditional) one.
        rcr.mediation = None;
        let challenge = b64(&rcr.public_key.challenge);
        let mut all = self.signins.lock().unwrap();
        all.retain(|_, s| s.expires > now);
        let mut mine: Vec<(u64, String)> = all
            .iter()
            .filter(|(_, s)| s.addr == addr)
            .map(|(k, s)| (s.order, k.clone()))
            .collect();
        if mine.len() >= SIGNINS_PER_ADDR {
            mine.sort();
            for (_, k) in &mine[..=mine.len() - SIGNINS_PER_ADDR] {
                all.remove(k);
            }
        }
        if all.len() >= SIGNINS_MAX && addr != LOCAL {
            return None;
        }
        let order = self.order.fetch_add(1, Ordering::Relaxed);
        let s = SignIn {
            state,
            key,
            addr: addr.to_owned(),
            expires: now + CEREMONY_SECS,
            order,
        };
        all.insert(challenge, s);
        Some(serde_json::to_value(&rcr).expect("options serialise"))
    }

    /// Spends the sign-in whose challenge `cred` answers: its state and session key.
    pub fn take_signin(
        &self,
        cred: &PublicKeyCredential,
        now: i64,
    ) -> Option<(DiscoverableAuthentication, Vec<u8>)> {
        let challenge = challenge_of(&cred.response.client_data_json)?;
        let s = self.signins.lock().unwrap().remove(&challenge)?;
        (s.expires > now).then_some((s.state, s.key))
    }

    /// A step-up ceremony for `session` with its device's `passkey`, replacing the session's
    /// previous one: the challenge (base64url) and the options.
    pub fn start_stepup(&self, session: &str, passkey: &Passkey, now: i64) -> (String, Value) {
        let (rcr, state) = self
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(passkey))
            .expect("a passkey authentication always starts");
        let challenge = b64(&rcr.public_key.challenge);
        let mut all = self.stepups.lock().unwrap();
        all.retain(|_, (_, _, exp)| *exp > now);
        all.insert(
            session.to_owned(),
            (state, challenge.clone(), now + CEREMONY_SECS),
        );
        let options = serde_json::to_value(&rcr).expect("options serialise");
        (challenge, options)
    }

    /// Spends the step-up of `session`, if it is live and `challenge` is its own.
    pub fn take_stepup(
        &self,
        session: &str,
        challenge: &str,
        now: i64,
    ) -> Option<PasskeyAuthentication> {
        let (state, c, exp) = self.stepups.lock().unwrap().remove(session)?;
        (exp > now && c.as_bytes() == challenge.as_bytes()).then_some(state)
    }

    #[cfg(test)]
    fn signins_len(&self) -> usize {
        self.signins.lock().unwrap().len()
    }
}

/// The `challenge` member of a `clientDataJSON`, as sent (base64url).
pub fn challenge_of(client_data: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(client_data).ok()?;
    let c = v.get("challenge")?.as_str()?;
    (c.len() <= 128).then(|| c.to_owned())
}

/// The options webauthn-rs made, held to ES256 and preferring a resident (discoverable) key.
fn creation_options(ccr: &CreationChallengeResponse) -> Value {
    let mut v = serde_json::to_value(ccr).expect("options serialise");
    let pk = &mut v["publicKey"];
    pk["pubKeyCredParams"] = json!([{"type": "public-key", "alg": -7}]);
    pk["authenticatorSelection"]["residentKey"] = json!("preferred");
    pk["authenticatorSelection"]["requireResidentKey"] = json!(false);
    v
}

/// The sign count a stored passkey holds (0 for one that never counts).
pub fn passkey_count(passkey: &Passkey) -> u32 {
    let v = serde_json::to_value(passkey).expect("a passkey serialises");
    v["cred"]["counter"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

/// The credential's public key as a 91-byte P-256 SPKI, when it is ES256 on P-256; `None` for
/// any other algorithm or curve.
pub fn p256_spki(passkey: &Passkey) -> Option<Vec<u8>> {
    let key = passkey.get_public_key();
    if key.type_ != COSEAlgorithm::ES256 {
        return None;
    }
    let COSEKeyType::EC_EC2(ec) = &key.key else {
        return None;
    };
    if ec.curve != ECDSACurve::SECP256R1 || ec.x.len() != 32 || ec.y.len() != 32 {
        return None;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(&ec.x);
    point.extend_from_slice(&ec.y);
    let spki = spki_of(&point);
    spki_point(&spki).is_some().then_some(spki)
}

#[cfg(test)]
mod tests;
