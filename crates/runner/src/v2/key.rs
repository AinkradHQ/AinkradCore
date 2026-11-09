//! The runner's identity (E1-11.3, handshake spec §3, §13): its own P-256 routine key, a
//! PKCS#8 file of mode 0600, and its enrolment: the Core it paired with, its device id there,
//! and the Core identity fingerprint it pinned. On `ring` only, the same primitives the Core
//! uses: raw `r‖s` ES256, SPKI by exact prefix, base64url without padding.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ainkrad_proto::v2::{Rotation, rotation_message};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

/// `SubjectPublicKeyInfo` for `id-ecPublicKey` + `prime256v1`, up to the uncompressed point.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url of exactly `len` characters.
pub fn unb64(text: &str, len: usize) -> Option<Vec<u8>> {
    let bytes = (text.len() == len)
        .then(|| URL_SAFE_NO_PAD.decode(text).ok())
        .flatten()?;
    (b64(&bytes) == text).then_some(bytes)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}

/// `fp(key)`: base64url SHA-256 of the SPKI.
pub fn fingerprint(spki: &[u8]) -> String {
    b64(&sha256(spki))
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    SystemRandom::new()
        .fill(&mut out)
        .expect("the OS random source works");
    out
}

/// ES256 (raw `r‖s`) by the P-256 SPKI `spki` over `message`.
pub fn verify(spki: &[u8], message: &[u8], sig: &[u8]) -> bool {
    spki.len() == 91
        && spki[..26] == SPKI_PREFIX
        && signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &spki[26..])
            .verify(message, sig)
            .is_ok()
}

/// The routine key. No `Debug`: it holds the private half.
pub struct Key {
    pair: EcdsaKeyPair,
    pub spki: Vec<u8>,
}

/// Writes `bytes` to `path` whole, mode 0600: a temp file then a rename.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", b64(&random::<6>())));
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Reads a file only this user may read.
fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} is readable by others (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        )));
    }
    std::fs::read(path)
}

impl Key {
    pub fn from_pkcs8(der: &[u8]) -> std::io::Result<Self> {
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
                .map_err(|_| std::io::Error::other("the runner key is not a P-256 PKCS#8 key"))?;
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        Ok(Self { pair, spki })
    }

    /// A new key, written to `path` (0600); an existing file is never overwritten.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            return Err(std::io::Error::other(format!("{} exists", path.display())));
        }
        let der =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| std::io::Error::other("generating the runner key failed"))?;
        write_private(path, der.as_ref())?;
        Self::from_pkcs8(der.as_ref())
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        Self::from_pkcs8(&read_private(path)?)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .expect("signing with a loaded key")
            .as_ref()
            .to_vec()
    }

    pub fn fp(&self) -> String {
        fingerprint(&self.spki)
    }
}

/// Where a runner's identity lives: `device.p8` and `enrolment.json`, both 0600.
#[derive(Debug, Clone)]
pub struct State(pub PathBuf);

impl State {
    pub fn key(&self) -> PathBuf {
        self.0.join("device.p8")
    }

    pub fn enrolment(&self) -> PathBuf {
        self.0.join("enrolment.json")
    }
}

/// What pairing left: the Core's base URL, this runner's device id there and the pinned Core
/// identity fingerprint, with the last rotation applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// `https://core.example` (or `http://` to a loopback host).
    pub url: String,
    pub device_id: String,
    pub core_fp: String,
    pub rotation_seq: u64,
    /// The key a verified rotation statement announced: accepted beside `core_fp` until the
    /// Core first proves it on a connection, which makes it the pin (security review RH7).
    pub next_fp: Option<String>,
}

impl Enrolment {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let v: Value = serde_json::from_slice(&read_private(path)?)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
        let s = |k: &str| {
            v[k].as_str()
                .map(str::to_owned)
                .ok_or_else(|| std::io::Error::other(format!("{}: no {k}", path.display())))
        };
        Ok(Self {
            url: s("url")?,
            device_id: s("device_id")?,
            core_fp: s("core_fp")?,
            rotation_seq: v["rotation_seq"].as_u64().unwrap_or(0),
            next_fp: v["next_fp"].as_str().map(str::to_owned),
        })
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let v = json!({
            "url": self.url,
            "device_id": self.device_id,
            "core_fp": self.core_fp,
            "rotation_seq": self.rotation_seq,
            "next_fp": self.next_fp,
        });
        write_private(path, (serde_json::to_string_pretty(&v)? + "\n").as_bytes())
    }

    /// Whether `fp` is a Core key this runner accepts: the pin, or the announced next key.
    pub fn accepts(&self, fp: &str) -> bool {
        fp == self.core_fp || self.next_fp.as_deref() == Some(fp)
    }

    /// The Core proved `fp` on a connection: when it is the announced next key, it becomes the
    /// pin and the old one is dropped. `true` when the pin moved.
    pub fn proven(&mut self, fp: &str) -> bool {
        if self.next_fp.as_deref() != Some(fp) {
            return false;
        }
        self.core_fp = fp.to_owned();
        self.next_fp = None;
        true
    }

    /// Applies a rotation statement received on a connection whose Core proved `core_spki`
    /// (handshake spec §13): only from the pinned key, signed by it, and newer than the last.
    /// The pin does not move yet: the new key is accepted beside it, and becomes the pin when
    /// the Core first proves it (`proven`), from `not_before` on. A runner that reconnects
    /// before the Core switches keys still finds the old one (security review RH7). `true`
    /// when the next key was recorded.
    pub fn rotate(&mut self, r: &Rotation, core_spki: &[u8]) -> bool {
        let signed = unb64(&r.sig, 86).is_some_and(|s| verify(core_spki, &rotation_message(r), &s));
        let ok = signed
            && fingerprint(core_spki) == self.core_fp
            && r.old_fp == self.core_fp
            && r.seq > self.rotation_seq
            && r.new_fp.len() == 43;
        if ok {
            self.next_fp = Some(r.new_fp.clone());
            self.rotation_seq = r.seq;
        }
        ok
    }
}
