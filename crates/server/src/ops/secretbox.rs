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
//!
//! Each key has a `key_id` (the first 8 bytes of a domain-separated SHA-256 of the key, hex):
//! the secrets broker stores it beside every sealed value, so a value sealed under another
//! master key is named as such instead of failing as tampered, and a rotation can find what it
//! still has to re-seal. Plaintext buffers are wiped on drop (`Zeroizing`).

use std::fmt;
use std::path::Path;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const V1: u8 = 1;
const TAG_LEN: usize = 16;

pub struct SecretBox {
    key: LessSafeKey,
    id: String,
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
        let tagged = Zeroizing::new([b"ainkrad-master-key-id\n".as_slice(), key].concat());
        let id = digest(&SHA256, &tagged).as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let key = UnboundKey::new(&AES_256_GCM, key).expect("32 bytes is an AES-256 key");
        Self {
            key: LessSafeKey::new(key),
            id,
        }
    }

    /// The key's id: 16 hex characters, safe to store and log.
    pub fn key_id(&self) -> &str {
        &self.id
    }

    /// The master key file: exactly 32 bytes.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let bytes = Zeroizing::new(std::fs::read(path)?);
        let key: Zeroizing<[u8; 32]> =
            Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} is not a 32-byte master key", path.display()),
                )
            })?);
        Ok(Self::new(&key))
    }

    /// [`from_file`](Self::from_file), refusing a key file that group or others may read
    /// (review L8): `init` and `restore` write it 0600.
    pub fn from_private_file(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is mode {:o}; a master key must be 0600 (chmod 600 it)",
                    path.display(),
                    mode & 0o777
                ),
            ));
        }
        Self::from_file(path)
    }

    /// The secrets broker's key for `serve`: `None`, with the reason logged, when the file is
    /// missing, malformed or readable by group or others. The broker then answers 503
    /// `secrets_unavailable`; the rest of the Core serves on (review L8).
    pub fn for_serve(path: &Path) -> Option<Self> {
        if !path.exists() {
            tracing::warn!(path = %path.display(), "no master key: the secrets broker is unavailable");
            return None;
        }
        match Self::from_private_file(path) {
            Ok(b) => {
                tracing::info!(key_id = b.key_id(), "secrets broker: master key loaded");
                Some(b)
            }
            Err(e) => {
                tracing::error!(error = %e, "master key not loaded: the secrets broker is unavailable");
                None
            }
        }
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| std::io::Error::other("the OS random source failed"))?;
        // Room for the tag up front: a reallocation would free a plaintext copy unwiped.
        let mut body = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
        body.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(label)),
                &mut *body,
            )
            .map_err(|_| std::io::Error::other("sealing failed"))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + body.len());
        out.push(V1);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The plaintext, wiped when dropped.
    pub fn open(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        let (&version, rest) = sealed.split_first().ok_or(OpenError::Malformed)?;
        if version != V1 {
            return Err(OpenError::Version);
        }
        if rest.len() < NONCE_LEN + TAG_LEN {
            return Err(OpenError::Malformed);
        }
        let (nonce, body) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| OpenError::Malformed)?;
        let mut body = Zeroizing::new(body.to_vec());
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad(label)), &mut body)
            .map_err(|_| OpenError::Rejected)?;
        Ok(Zeroizing::new(plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review L8: a missing, short or group/other-readable key leaves the broker off instead
    /// of failing, and only a 0600 32-byte file loads.
    #[test]
    fn serve_loads_only_a_private_well_formed_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("core-masterkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("master.key");
        let write = |bytes: &[u8], mode: u32| {
            std::fs::write(&key, bytes).unwrap();
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        assert!(SecretBox::for_serve(&key).is_none(), "missing");
        write(&[7; 31], 0o600);
        assert!(SecretBox::for_serve(&key).is_none(), "short");
        write(&[7; 32], 0o644);
        let e = SecretBox::from_private_file(&key).err().unwrap();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(SecretBox::for_serve(&key).is_none(), "world-readable");
        write(&[7; 32], 0o640);
        assert!(SecretBox::for_serve(&key).is_none(), "group-readable");
        write(&[7; 32], 0o600);
        let b = SecretBox::for_serve(&key).expect("0600 and 32 bytes");
        assert_eq!(b.key_id(), SecretBox::new(&[7; 32]).key_id());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn seals_and_opens_and_refuses_a_change_a_wrong_label_and_a_wrong_key() {
        let boxed = SecretBox::new(&[7; 32]);
        let sealed = boxed.seal("acme.account", b"the account key").unwrap();
        assert_eq!(sealed[0], V1);
        assert_eq!(sealed.len(), 1 + NONCE_LEN + 15 + TAG_LEN);
        assert_eq!(
            boxed.open("acme.account", &sealed).unwrap().as_slice(),
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
        assert_eq!(boxed.key_id().len(), 16);
        assert_eq!(boxed.key_id(), SecretBox::new(&[7; 32]).key_id());
        assert_ne!(boxed.key_id(), SecretBox::new(&[8; 32]).key_id());
    }
}
