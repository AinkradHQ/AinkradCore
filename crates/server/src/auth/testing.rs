//! The reference client for tests (`test-support` feature, never in a release build): a
//! software P-256 key that signs requests exactly as handshake spec §5 says, so every fixture
//! authenticates the way a real client does. Later lanes (pairing, runners) reuse it.

use std::sync::{Arc, Mutex};

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use sqlx::SqlitePool;

use super::crypto::{b64, random, random_id, spki_of};
use super::signed::{self, ALG, Canonical};
use crate::scheduler::Clock;
use crate::store::gov::{self, NewDevice};

pub struct TestDevice {
    /// `d_…`.
    pub id: String,
    key: EcdsaKeyPair,
    /// The routine key's PKCS#8, to rebuild the same device (the golden vector).
    pub pkcs8: Vec<u8>,
    pub spki: Vec<u8>,
    /// The Core this device signs for.
    pub core_fp: String,
    /// The session it signs with, once it has one.
    pub session: Mutex<Option<String>>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl std::fmt::Debug for TestDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDevice")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl TestDevice {
    /// A new key and id for the Core `core_fp`, signing at `clock`'s time.
    pub fn new(core_fp: &str, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("key generation")
                .as_ref()
                .to_vec();
        Self::from_pkcs8(&random_id("d_"), &pkcs8, core_fp, clock)
    }

    pub fn from_pkcs8(
        id: &str,
        pkcs8: &[u8],
        core_fp: &str,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            &SystemRandom::new(),
        )
        .expect("a P-256 PKCS#8 key");
        let spki = spki_of(key.public_key().as_ref());
        Self {
            id: id.to_owned(),
            key,
            pkcs8: pkcs8.to_vec(),
            spki,
            core_fp: core_fp.to_owned(),
            session: Mutex::new(None),
            clock,
        }
    }

    /// A new device enrolled straight into the store as active (fixtures only).
    pub async fn enroll(
        pool: &SqlitePool,
        name: &str,
        kind: &str,
        scopes: &[&str],
        core_fp: &str,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        let d = Self::new(core_fp, clock);
        let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        gov::enroll_for_tests(
            pool,
            &NewDevice {
                id: &d.id,
                kind,
                name,
                routine_spki: &d.spki,
                stepup_spki: None,
                platform: Some("test"),
                key_storage: Some("software"),
                scopes: &scopes,
            },
        )
        .await
        .expect("enrolling a test device");
        d
    }

    /// The `/pair/claim` body for the typed `code` or the QR `secret` (one of them), with this
    /// device's routine key and its proof of possession, as a client builds it (§7.2 step 3).
    pub fn claim_body(&self, code: Option<&str>, secret: Option<&str>) -> serde_json::Value {
        use super::pairing::{code_hash, normal_code, pop_message, secret_hash};
        let hash = match (code, secret) {
            (Some(c), None) => code_hash(&normal_code(c).unwrap_or_default()),
            (None, Some(s)) => secret_hash(&super::crypto::unb64(s, 22).unwrap_or_default()),
            _ => panic!("one of code and secret"),
        };
        let message = pop_message(
            &self.core_fp,
            &hash,
            &super::crypto::fingerprint(&self.spki),
            None,
        );
        serde_json::json!({
            "code": code,
            "secret": secret,
            "routine_spki": b64(&self.spki),
            "platform": "test",
            "key_storage": "software",
            "pop": b64(&self.sign(&message)),
        })
    }

    pub fn set_session(&self, session: Option<String>) {
        *self.session.lock().unwrap() = session;
    }

    /// A raw `r‖s` signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key
            .sign(&SystemRandom::new(), message)
            .expect("signing")
            .as_ref()
            .to_vec()
    }

    /// The six headers for `method` on `uri` (path and optional `?query`) with `body`, at
    /// `timestamp` with `nonce`, under `session` (`None` signs `-` and sends no header).
    pub fn headers_at(
        &self,
        method: &str,
        uri: &str,
        body: &[u8],
        session: Option<&str>,
        timestamp: i64,
        nonce: &str,
    ) -> Vec<(&'static str, String)> {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let canonical = Canonical {
            core_fp: &self.core_fp,
            device: &self.id,
            session,
            method,
            path,
            query,
            timestamp,
            nonce,
            body,
        };
        let mut h = vec![
            (signed::DEVICE, self.id.clone()),
            (signed::ALG_HEADER, ALG.to_owned()),
            (signed::TIMESTAMP, timestamp.to_string()),
            (signed::NONCE, nonce.to_owned()),
            (signed::SIGNATURE, b64(&self.sign(&canonical.bytes()))),
        ];
        if let Some(s) = session {
            h.push((signed::SESSION, s.to_owned()));
        }
        h
    }

    /// `headers_at` now, with a fresh nonce and this device's session.
    pub fn headers(&self, method: &str, uri: &str, body: &[u8]) -> Vec<(&'static str, String)> {
        let session = self.session.lock().unwrap().clone();
        self.headers_session(method, uri, body, session.as_deref())
    }

    /// `headers` with an explicit session (`None` for the session-less calls).
    pub fn headers_session(
        &self,
        method: &str,
        uri: &str,
        body: &[u8],
        session: Option<&str>,
    ) -> Vec<(&'static str, String)> {
        let nonce = b64(&random::<16>());
        self.headers_at(method, uri, body, session, self.clock.unix(), &nonce)
    }
}
