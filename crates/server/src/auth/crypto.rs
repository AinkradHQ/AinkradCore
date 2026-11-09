//! The handshake spec's primitives (§3, §16), on `ring` only: P-256 SPKI by exact prefix
//! compare (no DER parser), fingerprints, ES256 verification of raw `r‖s`, base64url without
//! padding (strict), and random Crockford-base32 ids.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{agreement, digest, signature};

/// `SubjectPublicKeyInfo` for `id-ecPublicKey` + `prime256v1` up to the uncompressed point.
pub const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// A P-256 SPKI with an uncompressed point: the prefix, `04`, X, Y.
pub const SPKI_LEN: usize = 91;

/// The uncompressed point of a P-256 SPKI, when `spki` is exactly that shape and the point is
/// on the curve; `None` for anything else.
pub fn spki_point(spki: &[u8]) -> Option<&[u8]> {
    if spki.len() != SPKI_LEN || spki[..26] != SPKI_PREFIX || spki[26] != 0x04 {
        return None;
    }
    let point = &spki[26..];
    // ECDH against the point fails unless it is a valid point on P-256.
    let rng = SystemRandom::new();
    let mine = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).ok()?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, point);
    agreement::agree_ephemeral(mine, &peer, |_| ()).ok()?;
    Some(point)
}

/// The SPKI of an uncompressed point (65 bytes).
pub fn spki_of(point: &[u8]) -> Vec<u8> {
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point);
    spki
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

/// `fp(key)`: base64url (no padding) of SHA-256 over the SPKI, 43 characters.
pub fn fingerprint(spki: &[u8]) -> String {
    b64(&sha256(spki))
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding: exactly `len` characters that decode to bytes which
/// encode back to the same text (no stray trailing bits).
pub fn unb64(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != len {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (b64(&bytes) == text).then_some(bytes)
}

/// ES256 over `message` (hashed here, message mode) with a raw 64-byte `r‖s` signature.
pub fn verify(spki: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Some(point) = spki.get(26..).filter(|_| spki.len() == SPKI_LEN) else {
        return false;
    };
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(message, sig)
        .is_ok()
}

/// A key nobody holds, verified against when the device is unknown or unusable, so that a
/// refusal costs the same time whatever the reason (§5.3 step 5).
pub fn dummy_verify(message: &[u8], sig: &[u8]) {
    static DUMMY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let spki = DUMMY.get_or_init(|| {
        let rng = SystemRandom::new();
        let doc = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("generating a P-256 key");
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .expect("a fresh key parses");
        use signature::KeyPair;
        spki_of(pair.public_key().as_ref())
    });
    let _ = verify(spki, message, sig);
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    SystemRandom::new()
        .fill(&mut out)
        .expect("the OS random source works");
    out
}

/// Lowercase Crockford base32.
pub const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// `prefix` + 26 lowercase Crockford characters over 128 random bits (`d_`, `s_`, `p_`).
pub fn random_id(prefix: &str) -> String {
    let n = u128::from_be_bytes(random::<16>());
    let body: String = (0..26)
        .rev()
        .map(|i| CROCKFORD[((n >> (i * 5)) & 31) as usize] as char)
        .collect();
    format!("{prefix}{body}")
}

/// Whether `id` is `prefix` + 26 lowercase Crockford characters, the first at most `7` (128
/// bits).
pub fn is_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix).is_some_and(|body| {
        body.len() == 26
            && body.bytes().all(|b| CROCKFORD.contains(&b))
            && body.as_bytes()[0] <= b'7'
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    #[test]
    fn spki_is_exact_and_on_the_curve() {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng).unwrap();
        let spki = spki_of(pair.public_key().as_ref());
        assert_eq!(spki.len(), SPKI_LEN);
        assert!(spki_point(&spki).is_some());
        assert_eq!(fingerprint(&spki).len(), 43);
        let mut off = spki.clone();
        off[90] ^= 1;
        assert!(spki_point(&off).is_none(), "off the curve");
        let mut compressed = spki.clone();
        compressed[26] = 0x02;
        assert!(spki_point(&compressed).is_none());
        assert!(spki_point(&spki[..90]).is_none());
        let mut prefix = spki.clone();
        prefix[3] ^= 1;
        assert!(spki_point(&prefix).is_none());

        let sig = pair.sign(&rng, b"m").unwrap();
        assert!(verify(&spki, b"m", sig.as_ref()));
        assert!(!verify(&spki, b"n", sig.as_ref()));
    }

    #[test]
    fn base64_and_ids_are_strict() {
        assert_eq!(unb64("AAAAAAAAAAAAAAAAAAAAAA", 22).unwrap(), [0; 16]);
        assert!(
            unb64("AAAAAAAAAAAAAAAAAAAAAB", 22).is_none(),
            "trailing bits"
        );
        assert!(unb64("AAAAAAAAAAAAAAAAAAAAA=", 22).is_none());
        assert!(unb64("AAAAAAAAAAAAAAAAAAAA+A", 22).is_none());
        let id = random_id("d_");
        assert!(is_id(&id, "d_"), "{id}");
        assert!(!is_id(&id, "s_"));
        assert!(!is_id(&id.to_uppercase(), "d_"));
        assert!(
            !is_id("d_zzzzzzzzzzzzzzzzzzzzzzzzzz", "d_"),
            "over 128 bits"
        );
        assert_ne!(random_id("s_"), random_id("s_"));
    }
}
