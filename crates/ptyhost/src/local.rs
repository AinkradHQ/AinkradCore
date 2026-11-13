//! The host's side of the local path: who may attach over `<id>.local.sock`.
//!
//! No grant, no attach. A connection must present a grant the Core signed for this terminal,
//! this host's runner and a device, single-use and unexpired, and prove it holds that device's
//! key by signing the host's fresh challenge. The runner tells the host which Core key to trust
//! (`ToHost::Trust`); until it has, every local connection is refused.

use std::collections::HashMap;

use ainkrad_proto::v2::local::{GRANT_VERSION, LocalGrant, attach_message, grant_message};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

/// Clock slack between this Mac and the Core, seconds: a grant issued up to this far ahead of
/// our clock, or expired this long ago, is still taken. It stays single-use either way.
pub const SKEW: i64 = 120;

/// The longest lease a grant may ask for.
pub const MAX_LEASE: u64 = 120;

/// What the runner vouches the host may trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// The Core's identity key (SPKI) the runner proved the connection to.
    pub core_spki: Vec<u8>,
    /// The runner's own device id: a grant for another runner's terminal is refused.
    pub runner: String,
}

/// A grant that passed every check but the proof of possession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub grant: LocalGrant,
    pub device_spki: Vec<u8>,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The runner has not said which Core to trust.
    NoTrust,
    Malformed,
    BadSignature,
    WrongTerminal,
    WrongRunner,
    Expired,
    Replayed,
    /// The proof of possession did not verify, or a renewal named another device.
    BadProof,
}

impl Refusal {
    pub fn why(self) -> &'static str {
        match self {
            Self::NoTrust => "this host does not trust a Core yet",
            Self::Malformed => "the grant is malformed",
            Self::BadSignature => "the grant is not signed by the Core",
            Self::WrongTerminal => "the grant is for another terminal",
            Self::WrongRunner => "the grant is for another runner",
            Self::Expired => "the grant has expired",
            Self::Replayed => "the grant was already used",
            Self::BadProof => "the proof of the device key failed",
        }
    }
}

fn verify_es256(spki: &[u8], message: &[u8], sig: &[u8]) -> bool {
    // The same shape the Core and runner use: a P-256 SPKI of exactly 91 bytes, raw r||s.
    spki.len() == 91
        && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &spki[26..])
            .verify(message, sig)
            .is_ok()
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Checks `text` (`<payload>.<sig>`) against `trust` for `terminal` at unix second `now`. Does
/// not consume the nonce: [`Replay::take`] does, after the proof also passed.
pub fn verify_grant(
    trust: Option<&Trust>,
    terminal: &str,
    text: &str,
    now: i64,
) -> Result<Verified, Refusal> {
    let trust = trust.ok_or(Refusal::NoTrust)?;
    let (payload, sig) = text.split_once('.').ok_or(Refusal::Malformed)?;
    if text.len() > 4096 {
        return Err(Refusal::Malformed);
    }
    let sig = unb64(sig).ok_or(Refusal::Malformed)?;
    if !verify_es256(&trust.core_spki, &grant_message(payload), &sig) {
        return Err(Refusal::BadSignature);
    }
    let grant: LocalGrant = serde_json::from_slice(&unb64(payload).ok_or(Refusal::Malformed)?)
        .map_err(|_| Refusal::Malformed)?;
    if grant.v != GRANT_VERSION {
        return Err(Refusal::Malformed);
    }
    if grant.terminal != terminal {
        return Err(Refusal::WrongTerminal);
    }
    if grant.runner != trust.runner {
        return Err(Refusal::WrongRunner);
    }
    if now > grant.exp.saturating_add(SKEW) || grant.iat > now.saturating_add(SKEW) {
        return Err(Refusal::Expired);
    }
    let device_spki = unb64(&grant.device_spki).ok_or(Refusal::Malformed)?;
    Ok(Verified {
        grant,
        device_spki,
        text: text.to_owned(),
    })
}

/// The proof: the device key signed this connection's `challenge` and this grant.
pub fn verify_proof(v: &Verified, challenge: &str, sig: &str) -> Result<(), Refusal> {
    let sig = unb64(sig).ok_or(Refusal::BadProof)?;
    verify_es256(&v.device_spki, &attach_message(challenge, &v.text), &sig)
        .then_some(())
        .ok_or(Refusal::BadProof)
}

/// Grant nonces seen, until their grant could no longer be presented.
#[derive(Default)]
pub struct Replay(HashMap<String, i64>);

impl Replay {
    /// `true` the first time `nonce` is seen.
    pub fn take(&mut self, nonce: &str, exp: i64, now: i64) -> bool {
        self.0.retain(|_, e| now <= e.saturating_add(SKEW));
        // ponytail: a flood of valid grants grows this until they expire; grants need the
        // Core's signature, and the Core limits them per device.
        self.0.insert(nonce.to_owned(), exp).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    pub struct K(EcdsaKeyPair, pub Vec<u8>);
    pub fn key() -> K {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let spki = [PREFIX.as_slice(), pair.public_key().as_ref()].concat();
        K(pair, spki)
    }
    impl K {
        pub fn sign(&self, m: &[u8]) -> String {
            let s = self.0.sign(&SystemRandom::new(), m).unwrap();
            URL_SAFE_NO_PAD.encode(s.as_ref())
        }
    }
    fn issue(core: &K, device: &K, terminal: &str, runner: &str, iat: i64, exp: i64) -> String {
        let g = LocalGrant {
            v: GRANT_VERSION,
            terminal: terminal.into(),
            runner: runner.into(),
            device: "d_app".into(),
            device_spki: URL_SAFE_NO_PAD.encode(&device.1),
            nonce: "n1".into(),
            iat,
            exp,
            lease: 45,
        };
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&g).unwrap());
        format!("{p}.{}", core.sign(&grant_message(&p)))
    }
    fn trust(core: &K) -> Trust {
        Trust {
            core_spki: core.1.clone(),
            runner: "d_runner".into(),
        }
    }

    #[test]
    fn a_good_grant_and_proof_pass() {
        let (core, dev) = (key(), key());
        let g = issue(&core, &dev, "t_a", "d_runner", 1000, 1060);
        let v = verify_grant(Some(&trust(&core)), "t_a", &g, 1010).unwrap();
        let proof = dev.sign(&attach_message("chal", &g));
        assert!(verify_proof(&v, "chal", &proof).is_ok());
        // The proof is for that challenge only.
        assert_eq!(verify_proof(&v, "other", &proof), Err(Refusal::BadProof));
    }

    #[test]
    fn a_grant_is_refused_when_it_is_not_the_cores_or_not_for_here() {
        let (core, dev, other) = (key(), key(), key());
        let t = trust(&core);
        let g = issue(&core, &dev, "t_a", "d_runner", 1000, 1060);
        assert_eq!(verify_grant(None, "t_a", &g, 1010), Err(Refusal::NoTrust));
        let forged = issue(&other, &dev, "t_a", "d_runner", 1000, 1060);
        assert_eq!(
            verify_grant(Some(&t), "t_a", &forged, 1010),
            Err(Refusal::BadSignature)
        );
        assert_eq!(
            verify_grant(Some(&t), "t_b", &g, 1010),
            Err(Refusal::WrongTerminal)
        );
        let g2 = issue(&core, &dev, "t_a", "d_other", 1000, 1060);
        assert_eq!(
            verify_grant(Some(&t), "t_a", &g2, 1010),
            Err(Refusal::WrongRunner)
        );
        // A tampered payload no longer matches its signature.
        let (p, s) = g.split_once('.').unwrap();
        let mut bytes = unb64(p).unwrap();
        bytes[5] ^= 1;
        let bad = format!("{}.{s}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(
            verify_grant(Some(&t), "t_a", &bad, 1010),
            Err(Refusal::BadSignature)
        );
        assert_eq!(
            verify_grant(Some(&t), "t_a", "junk", 1010),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn a_grant_expires_and_is_not_taken_from_the_future() {
        let (core, dev) = (key(), key());
        let t = trust(&core);
        let g = issue(&core, &dev, "t_a", "d_runner", 1000, 1060);
        assert!(verify_grant(Some(&t), "t_a", &g, 1060 + SKEW).is_ok());
        assert_eq!(
            verify_grant(Some(&t), "t_a", &g, 1061 + SKEW),
            Err(Refusal::Expired)
        );
        assert_eq!(
            verify_grant(Some(&t), "t_a", &g, 1000 - SKEW - 1),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn a_nonce_is_single_use_until_it_could_no_longer_be_presented() {
        let mut r = Replay::default();
        assert!(r.take("n", 100, 90));
        assert!(!r.take("n", 100, 91));
        // Long after, the entry is gone, but the grant itself has expired by then.
        assert!(r.take("n", 100, 100 + SKEW + 1));
    }
}
