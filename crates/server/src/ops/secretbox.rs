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
use std::path::{Path, PathBuf};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const V1: u8 = 1;
const TAG_LEN: usize = 16;

pub struct SecretBox {
    key: LessSafeKey,
    id: String,
    /// Older (or about to be current) master keys, for opening values still sealed under them:
    /// a rotation that was interrupted leaves rows under either key. New seals never use these.
    extra: Vec<SecretBox>,
}

/// `master.<16 hex>.key` (a key waiting to become current) or `master.<16 hex>.key.retired`
/// (a former current key, kept for a retention window): the key id and whether it is retired.
/// `master.key` itself, and any other name, is `None`.
pub fn key_file_kind(file_name: &str) -> Option<(String, bool)> {
    let rest = file_name.strip_prefix("master.")?;
    let (id, retired) = match rest.strip_suffix(".key.retired") {
        Some(id) => (id, true),
        None => (rest.strip_suffix(".key")?, false),
    };
    (id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| (id.to_owned(), retired))
}

/// The extra key files in `dir` (`keys/`): `(key id, path, retired)`, by id.
pub fn key_files(dir: &Path) -> std::io::Result<Vec<(String, PathBuf, bool)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if let Some((id, retired)) = entry.file_name().to_str().and_then(key_file_kind) {
            out.push((id, entry.path(), retired));
        }
    }
    out.sort();
    Ok(out)
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
            extra: Vec::new(),
        }
    }

    /// Also opens (never seals) values sealed under `extra`.
    pub fn with_extra(mut self, extra: Vec<SecretBox>) -> Self {
        self.extra = extra;
        self
    }

    /// Whether this box can open a value sealed under key `id`.
    pub fn holds(&self, id: &str) -> bool {
        self.find(id).is_some()
    }

    fn find(&self, id: &str) -> Option<&SecretBox> {
        (self.id == id)
            .then_some(self)
            .or_else(|| self.extra.iter().find(|b| b.id == id))
    }

    /// [`open`](Self::open) with the key named `key_id` (the current one or an extra).
    pub fn open_as(
        &self,
        key_id: &str,
        label: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        self.find(key_id)
            .ok_or(OpenError::Rejected)?
            .open(label, sealed)
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
                let b = b.with_extra(Self::load_extra(path.parent()));
                tracing::info!(
                    key_id = b.key_id(),
                    extra_keys = b.extra.len(),
                    "secrets broker: master key loaded"
                );
                Some(b)
            }
            Err(e) => {
                tracing::error!(error = %e, "master key not loaded: the secrets broker is unavailable");
                None
            }
        }
    }

    /// The retired and pending keys beside the master key, for opening what is still sealed
    /// under them. One that does not load (mode, size, a name that is not its id) is skipped
    /// with a warning: it only matters if a row still names it.
    fn load_extra(keys: Option<&Path>) -> Vec<SecretBox> {
        let Some(keys) = keys else {
            return Vec::new();
        };
        let files = key_files(keys).unwrap_or_default();
        files
            .into_iter()
            .filter_map(|(id, path, _)| match Self::from_private_file(&path) {
                Ok(b) if b.id == id => Some(b),
                _ => {
                    tracing::warn!(path = %path.display(), "a spare master key is not loaded");
                    None
                }
            })
            .collect()
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
    fn spare_key_names_are_exact_and_a_spare_opens_only_what_names_it() {
        let id = "0123456789abcdef";
        assert_eq!(
            key_file_kind(&format!("master.{id}.key")),
            Some((id.into(), false))
        );
        assert_eq!(
            key_file_kind(&format!("master.{id}.key.retired")),
            Some((id.into(), true))
        );
        for bad in [
            "master.key",
            "master..key",
            "master.0123456789abcde.key",
            "master.0123456789ABCDEF.key",
            "master.0123456789abcdefg.key",
            "master.0123456789abcdef.key.old",
            "../master.0123456789abcdef.key",
        ] {
            assert_eq!(key_file_kind(bad), None, "{bad}");
        }
        let (old, new) = (SecretBox::new(&[1; 32]), SecretBox::new(&[2; 32]));
        let sealed = old.seal("l", b"v").unwrap();
        let both = SecretBox::new(&[2; 32]).with_extra(vec![SecretBox::new(&[1; 32])]);
        assert!(both.holds(old.key_id()) && both.holds(new.key_id()));
        assert_eq!(
            both.open_as(old.key_id(), "l", &sealed).unwrap().as_slice(),
            b"v"
        );
        assert!(
            both.open_as(new.key_id(), "l", &sealed).is_err(),
            "named key only"
        );
        assert!(new.open_as(old.key_id(), "l", &sealed).is_err(), "not held");
        // A spare never seals: new values go under the current key.
        assert!(new.open("l", &both.seal("l", b"x").unwrap()).is_ok());
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
