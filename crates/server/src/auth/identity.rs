//! The Core identity key (§3, §13): a P-256 key generated on first start and kept as a PKCS#8
//! file, mode 0600, beside the database. Its fingerprint (`core_fp`) is what `/handshake`
//! shows, and every signed request names it, so a request for one Core is refused by another.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::crypto::{fingerprint, spki_of};

/// The file name beside the database.
pub const FILE: &str = "core-identity.p8";

pub struct Identity {
    key: EcdsaKeyPair,
    /// The public key as a 91-byte SPKI.
    pub spki: Vec<u8>,
    /// `core_fp`: base64url of SHA-256 over the SPKI.
    pub fp: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("fp", &self.fp).finish()
    }
}

impl Identity {
    /// The key in `der` (PKCS#8): the file's contents, or a test vector's.
    pub fn from_pkcs8(der: &[u8]) -> std::io::Result<Self> {
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
                .map_err(|e| {
                std::io::Error::other(format!("the Core identity key is unusable: {e}"))
            })?;
        let spki = spki_of(key.public_key().as_ref());
        let fp = fingerprint(&spki);
        Ok(Self { key, spki, fp })
    }

    fn generate_pkcs8() -> std::io::Result<Vec<u8>> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| std::io::Error::other("generating the Core identity key failed"))
    }

    /// A key that lives only in memory (tests, and a Core without a state directory).
    pub fn ephemeral() -> Self {
        Self::from_pkcs8(&Self::generate_pkcs8().expect("key generation")).expect("fresh key")
    }

    /// The key in `dir`, created (0600, never overwritten) when there is none. A key file that
    /// others may read is refused rather than used.
    pub fn load_or_create(dir: &Path) -> std::io::Result<Self> {
        let path = dir.join(FILE);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                let der = Self::generate_pkcs8()?;
                file.write_all(&der)?;
                file.sync_all()?;
                return Self::from_pkcs8(&der);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let mode = std::fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(std::io::Error::other(format!(
                "{} is readable by others (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            )));
        }
        Self::from_pkcs8(&std::fs::read(&path)?)
    }

    /// A raw `r‖s` signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key
            .sign(&SystemRandom::new(), message)
            .expect("signing with a loaded key")
            .as_ref()
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_0600_and_reloaded() {
        let dir = std::env::temp_dir().join(format!("core-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = Identity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.fp, b.fp, "the same key after a restart");
        assert!(super::super::crypto::verify(&b.spki, b"x", &a.sign(b"x")));
        std::fs::set_permissions(dir.join(FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load_or_create(&dir).is_err(), "world-readable");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
