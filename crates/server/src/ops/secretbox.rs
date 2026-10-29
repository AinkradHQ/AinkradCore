//! `SecretBox` (E1-13.1, threat model T-SEC-1): seals small secrets for the store with the
//! home's master key (`keys/master.key`, 32 random bytes, 0600).
//!
//! Honest scope: the master key is a file on the same host as the database, so it protects only
//! copies of the database that leave the host without it (a disk snapshot, a stray copy). It
//! does nothing against someone who can read the home (A8). An OS keychain is not available on a
//! headless Ubuntu host.
//! ponytail: file key only; add the macOS keychain as a second key source when the Core runs on
//! the Mac as a service.
//!
//! Envelope v1: `0x01 ‖ nonce (12) ‖ AES-256-GCM ciphertext ‖ tag (16)`. The associated data is
//! the version byte and the label, so a sealed value only opens under the label it was sealed
//! for (an ACME key cannot be swapped in as the identity key) and a version byte cannot be
//! changed. Nonces are 96 random bits per seal: safe far beyond the handful of secrets a Core
//! seals with one key (the bound is about 2^32 seals).

use std::fmt;
use std::path::Path;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const V1: u8 = 1;
const TAG_LEN: usize = 16;

pub struct SecretBox {
    key: LessSafeKey,
}

/// Why a sealed value did not open. The cases are kept apart only for the message: none of
/// them says anything about the key.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Not a version this binary knows.
    Version,
    /// Too short to be an envelope.
    Malformed,
    /// Wrong key, wrong label, or changed bytes.
    Rejected,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "sealed secret: unknown envelope version",
            Self::Malformed => "sealed secret: too short",
            Self::Rejected => "sealed secret: wrong key or label, or tampered",
        })
    }
}

impl std::error::Error for OpenError {}

fn aad(label: &str) -> Vec<u8> {
    let mut out = vec![V1];
    out.extend_from_slice(label.as_bytes());
    out
}

impl SecretBox {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = UnboundKey::new(&AES_256_GCM, key).expect("32 bytes is an AES-256 key");
        Self {
            key: LessSafeKey::new(key),
        }
    }

    /// The master key file: exactly 32 bytes.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a 32-byte master key", path.display()),
            )
        })?;
        Ok(Self::new(&key))
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| std::io::Error::other("the OS random source failed"))?;
        let mut body = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(label)),
                &mut body,
            )
            .map_err(|_| std::io::Error::other("sealing failed"))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + body.len());
        out.push(V1);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn open(&self, label: &str, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        let (&version, rest) = sealed.split_first().ok_or(OpenError::Malformed)?;
        if version != V1 {
            return Err(OpenError::Version);
        }
        if rest.len() < NONCE_LEN + TAG_LEN {
            return Err(OpenError::Malformed);
        }
        let (nonce, body) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| OpenError::Malformed)?;
        let mut body = body.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad(label)), &mut body)
            .map_err(|_| OpenError::Rejected)?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_and_refuses_a_change_a_wrong_label_and_a_wrong_key() {
        let boxed = SecretBox::new(&[7; 32]);
        let sealed = boxed.seal("acme.account", b"the account key").unwrap();
        assert_eq!(sealed[0], V1);
        assert_eq!(sealed.len(), 1 + NONCE_LEN + 15 + TAG_LEN);
        assert_eq!(
            boxed.open("acme.account", &sealed).unwrap(),
            b"the account key"
        );
        assert_ne!(
            sealed,
            boxed.seal("acme.account", b"the account key").unwrap(),
            "a fresh nonce per seal"
        );

        for i in [0, 1, 1 + NONCE_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            let want = if i == 0 {
                OpenError::Version
            } else {
                OpenError::Rejected
            };
            assert_eq!(boxed.open("acme.account", &tampered), Err(want), "byte {i}");
        }
        assert_eq!(
            boxed.open("core.identity", &sealed),
            Err(OpenError::Rejected)
        );
        assert_eq!(
            SecretBox::new(&[8; 32]).open("acme.account", &sealed),
            Err(OpenError::Rejected)
        );
        assert_eq!(
            boxed.open("acme.account", &sealed[..20]),
            Err(OpenError::Malformed)
        );
    }
}
