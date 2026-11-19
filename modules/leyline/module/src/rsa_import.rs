//! RSA import (E0-9, D-23): the Core stores an RSA key in OpenSSH form like every other key, and
//! the runner signs with it (rsa-sha2-256/512, never SHA-1).
//!
//! The Core itself does no RSA arithmetic, so it has no `rsa` crate: `ssh-key` (without its `rsa`
//! feature) parses and writes the OpenSSH form, and `pkcs1` + `pkcs8` read the DER of a PEM key.
//! Like ECDSA (see `keys.rs`), an RSA key is parsed, not validated: a pair that does not match
//! fails safe at use, in the runner's signing.

use pkcs1::RsaPrivateKey as Pkcs1;
use pkcs8::PrivateKeyInfo;
use ssh_key::Mpint;
use ssh_key::PrivateKey;
use ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::RsaPublicKey;
use zeroize::Zeroizing;

/// The `rsaEncryption` algorithm OID of a PKCS#8 key.
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// Keys below this are refused (NIST SP 800-57: 2048 bits is the floor for new keys).
pub(crate) const MIN_BITS: usize = 2048;

/// The bit length of a big-endian unsigned integer.
pub(crate) fn bits(be: &[u8]) -> usize {
    let be = &be[be.iter().take_while(|b| **b == 0).count()..];
    match be.first() {
        None => 0,
        Some(top) => (be.len() - 1) * 8 + (8 - top.leading_zeros() as usize),
    }
}

/// How a PEM RSA key is, before anything is decoded.
pub(crate) enum Pem {
    /// `BEGIN RSA PRIVATE KEY` (PKCS#1) or `BEGIN PRIVATE KEY` (PKCS#8).
    Plain,
    /// A passphrase-protected PEM (legacy `Proc-Type` header, or `BEGIN ENCRYPTED PRIVATE KEY`).
    Encrypted,
    /// Not a PEM kind this module reads.
    Other,
}

pub(crate) fn kind(text: &str) -> Pem {
    let t = text.trim_start();
    if t.contains("ENCRYPTED") {
        Pem::Encrypted
    } else if t.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || t.starts_with("-----BEGIN PRIVATE KEY-----")
    {
        Pem::Plain
    } else {
        Pem::Other
    }
}

/// An unencrypted PKCS#1 or PKCS#8 PEM RSA key, as an `ssh-key` key. `None` is anything else
/// (not RSA, multi-prime, bad DER, an integer that does not fit): the caller refuses it.
pub(crate) fn from_pem(pem: &str) -> Option<PrivateKey> {
    let (label, der) = pem_rfc7468::decode_vec(pem.trim().as_bytes()).ok()?;
    let der = Zeroizing::new(der);
    let key = match label {
        "RSA PRIVATE KEY" => from_pkcs1(&der)?,
        "PRIVATE KEY" => {
            let info = PrivateKeyInfo::try_from(der.as_slice()).ok()?;
            if info.algorithm.oid.to_string() != RSA_ENCRYPTION {
                return None;
            }
            from_pkcs1(info.private_key)?
        }
        _ => return None,
    };
    Some(key)
}

fn from_pkcs1(der: &[u8]) -> Option<PrivateKey> {
    let k = Pkcs1::try_from(der).ok()?;
    if k.other_prime_infos.is_some() {
        return None;
    }
    let mp = |u: pkcs1::UintRef<'_>| Mpint::from_positive_bytes(u.as_bytes()).ok();
    let pair = RsaKeypair {
        public: RsaPublicKey {
            e: mp(k.public_exponent)?,
            n: mp(k.modulus)?,
        },
        private: RsaPrivateKey {
            d: mp(k.private_exponent)?,
            iqmp: mp(k.coefficient)?,
            p: mp(k.prime1)?,
            q: mp(k.prime2)?,
        },
    };
    PrivateKey::new(KeypairData::Rsa(pair), "").ok()
}

/// The modulus size of an RSA key (`None` for any other kind).
pub(crate) fn modulus_bits(public: &ssh_key::PublicKey) -> Option<usize> {
    public
        .key_data()
        .rsa()
        .map(|r| bits(r.n.as_positive_bytes().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_ignores_leading_zeros_and_counts_the_top_byte() {
        assert_eq!(bits(&[]), 0);
        assert_eq!(bits(&[0, 0]), 0);
        assert_eq!(bits(&[1]), 1);
        assert_eq!(bits(&[0, 0x80, 0, 0]), 24);
        let mut n = vec![0xff; 256];
        assert_eq!(bits(&n), 2048);
        n[0] = 0x7f;
        assert_eq!(bits(&n), 2047);
    }

    #[test]
    fn only_unencrypted_rsa_pem_labels_are_read() {
        assert!(matches!(
            kind("-----BEGIN RSA PRIVATE KEY-----\nx"),
            Pem::Plain
        ));
        assert!(matches!(
            kind("  -----BEGIN PRIVATE KEY-----\nx"),
            Pem::Plain
        ));
        assert!(matches!(
            kind("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx"),
            Pem::Encrypted
        ));
        assert!(matches!(
            kind("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Pem::Encrypted
        ));
        assert!(matches!(
            kind("-----BEGIN EC PRIVATE KEY-----\nx"),
            Pem::Other
        ));
        assert!(from_pem("not pem").is_none());
    }
}
