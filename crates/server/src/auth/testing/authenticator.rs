//! A software WebAuthn authenticator for tests (`test-support`): an ES256 key that answers the
//! Core's registration and sign-in options exactly as a browser and a platform authenticator
//! would (attestation `none`, the WebAuthn wire formats, a DER signature over
//! `authenticatorData ‖ SHA-256(clientDataJSON)`), with knobs to break each part for the
//! negative tests.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

use crate::auth::crypto::{b64, random, sha256, spki_of};

/// User present, user verified, attested credential data included.
pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
const AT: u8 = 0x40;

pub struct SoftAuthenticator {
    key: EcdsaKeyPair,
    pub cred_id: Vec<u8>,
    /// The signature counter; `None` reports 0 forever (a synced passkey).
    pub counter: Option<u32>,
    /// The user handle the Core gave at registration.
    pub user: Vec<u8>,
    pub rp_id: String,
    pub origin: String,
    /// The flags an assertion carries (`UP | UV` by default).
    pub flags: u8,
}

impl std::fmt::Debug for SoftAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftAuthenticator").finish_non_exhaustive()
    }
}

fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=255 => out.extend([m | 24, n as u8]),
        _ => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
    }
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len(), out);
    out.extend_from_slice(b);
}

fn cbor_text(t: &str, out: &mut Vec<u8>) {
    cbor_head(3, t.len(), out);
    out.extend_from_slice(t.as_bytes());
}

fn field<'a>(options: &'a Value, path: &[&str]) -> &'a str {
    let mut v = &options["publicKey"];
    for p in path {
        v = &v[*p];
    }
    v.as_str().expect("an options field")
}

impl SoftAuthenticator {
    pub fn new(rp_id: &str, origin: &str) -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("key generation");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng)
            .expect("a fresh key");
        Self {
            key,
            cred_id: random::<32>().to_vec(),
            counter: Some(0),
            user: Vec::new(),
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            flags: UP | UV,
        }
    }

    /// The credential's public key as a P-256 SPKI.
    pub fn spki(&self) -> Vec<u8> {
        spki_of(self.key.public_key().as_ref())
    }

    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.public_key().as_ref();
        let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        cbor_bytes(&point[1..33], &mut out);
        out.push(0x22);
        cbor_bytes(&point[33..65], &mut out);
        out
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    fn count(&mut self) -> u32 {
        match &mut self.counter {
            Some(n) => {
                *n += 1;
                *n
            }
            None => 0,
        }
    }

    /// The `RegisterPublicKeyCredential` answering creation `options` (attestation `none`).
    pub fn register(&mut self, options: &Value) -> Value {
        let challenge = field(options, &["challenge"]).to_owned();
        use base64::Engine;
        self.user = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(field(options, &["user", "id"]))
            .expect("a base64url user id");
        let counter = self.count();
        let mut auth = sha256(self.rp_id.as_bytes()).to_vec();
        auth.push(self.flags | AT);
        auth.extend(counter.to_be_bytes());
        auth.extend([0; 16]);
        auth.extend((self.cred_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&self.cred_id);
        auth.extend(self.cose_key());
        let mut att = vec![0xa3];
        cbor_text("fmt", &mut att);
        cbor_text("none", &mut att);
        cbor_text("attStmt", &mut att);
        att.push(0xa0);
        cbor_text("authData", &mut att);
        cbor_bytes(&auth, &mut att);
        let id = b64(&self.cred_id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "attestationObject": b64(&att),
                "clientDataJSON": b64(&self.client_data("webauthn.create", &challenge)),
                "transports": ["internal"],
            },
            "extensions": {},
        })
    }

    /// The `PublicKeyCredential` answering request `options`.
    pub fn assert(&mut self, options: &Value) -> Value {
        let challenge = field(options, &["challenge"]).to_owned();
        self.assert_challenge(&challenge)
    }

    /// An assertion over `challenge` (base64url), as `assert` builds it.
    pub fn assert_challenge(&mut self, challenge: &str) -> Value {
        let counter = self.count();
        let mut auth = sha256(self.rp_id.as_bytes()).to_vec();
        auth.push(self.flags);
        auth.extend(counter.to_be_bytes());
        let client = self.client_data("webauthn.get", challenge);
        let mut signed = auth.clone();
        signed.extend(sha256(&client));
        let sig = self
            .key
            .sign(&SystemRandom::new(), &signed)
            .expect("signing");
        let id = b64(&self.cred_id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth),
                "clientDataJSON": b64(&client),
                "signature": b64(sig.as_ref()),
                "userHandle": b64(&self.user),
            },
            "extensions": {},
        })
    }
}
