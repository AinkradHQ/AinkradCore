//! The handshake spec's wire primitives, from the spec text alone (§3, §5.2, §7.1, §7.2):
//! base64url, fingerprints, the P-256 key and its raw `r‖s` signatures, the canonical request
//! string, the pairing code fold, the QR payload, the proof of possession and the SAS.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use zeroize::Zeroizing;

/// `Ainkrad-Alg`: the only value in v1.
pub const ALG: &str = "ES256";

/// DER `SubjectPublicKeyInfo` for `id-ecPublicKey` + `prime256v1`, up to the point (§3).
pub const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding: only text that encodes back to itself.
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (b64(&bytes) == text).then_some(bytes)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}

/// `fp(key)` = base64url_nopad(SHA-256(SPKI)), 43 characters.
pub fn fp(spki: &[u8]) -> String {
    b64(&sha256(spki))
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    SystemRandom::new()
        .fill(&mut out)
        .expect("the OS random source works");
    out
}

/// A device's `routine` key: software PKCS#8, as §3 has it for the CLI. Its `Debug` shows the
/// public fingerprint only; the PKCS#8 bytes are wiped when dropped.
pub struct Key {
    pair: EcdsaKeyPair,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", fp(&self.spki()))
    }
}

impl Key {
    /// A new key, made here: the Core never sees the private half.
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generating a P-256 key");
        Self::from_pkcs8(doc.as_ref()).expect("a fresh key parses")
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng).ok()?;
        Some(Self {
            pair,
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The 91-byte SPKI: the fixed prefix, then the uncompressed point.
    pub fn spki(&self) -> Vec<u8> {
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(self.pair.public_key().as_ref());
        spki
    }

    /// ES256 in message mode: raw `r‖s`, 64 bytes, never DER.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .expect("signing with a parsed key")
            .as_ref()
            .to_vec()
    }
}

/// Whether `sig` (raw `r‖s`) is `spki`'s ES256 signature over `message`.
pub fn verify(spki: &[u8], message: &[u8], sig: &[u8]) -> bool {
    spki.len() == 91
        && spki[..26] == SPKI_PREFIX
        && signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &spki[26..])
            .verify(message, sig)
            .is_ok()
}

/// What a request signs (§5.2).
#[derive(Debug, Clone, Copy)]
pub struct Canonical<'a> {
    pub core_fp: &'a str,
    pub device: &'a str,
    /// `None` is signed as `-` (`/handshake/session`, `/pair/status`).
    pub session: Option<&'a str>,
    pub method: &'a str,
    /// The path exactly as sent.
    pub path: &'a str,
    /// The raw query after `?`, or empty.
    pub query: &'a str,
    pub timestamp: u64,
    pub nonce: &'a str,
    pub body: &'a [u8],
}

impl Canonical<'_> {
    /// The 11 fields joined by LF, no trailing newline.
    pub fn bytes(&self) -> Vec<u8> {
        let fields = [
            "AINKRAD-REQ-V1",
            self.core_fp,
            ALG,
            self.device,
            self.session.unwrap_or("-"),
            self.method,
            self.path,
            self.query,
            &self.timestamp.to_string(),
            self.nonce,
            &b64(&sha256(self.body)),
        ];
        fields.join("\n").into_bytes()
    }

    /// The six `Ainkrad-*` headers for this request, signed by `key`. `Ainkrad-Session` is left
    /// out when there is no session: the session-less calls must not carry it.
    pub fn headers(&self, key: &Key) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("ainkrad-device", self.device.to_owned()),
            ("ainkrad-alg", ALG.to_owned()),
            ("ainkrad-timestamp", self.timestamp.to_string()),
            ("ainkrad-nonce", self.nonce.to_owned()),
            ("ainkrad-signature", b64(&key.sign(&self.bytes()))),
        ];
        if let Some(s) = self.session {
            h.push(("ainkrad-session", s.to_owned()));
        }
        h
    }
}

/// A fresh nonce: 16 random bytes, base64url (22 characters).
pub fn nonce() -> String {
    b64(&random::<16>())
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The first `n` upper-case Crockford characters of `bytes`, 5-bit groups, most significant
/// first.
pub fn crockford(bytes: &[u8], n: usize) -> String {
    let bits = |i: usize| (bytes[i / 8] >> (7 - i % 8)) & 1;
    (0..n)
        .map(|c| {
            let v = (0..5).fold(0usize, |acc, b| (acc << 1) | bits(c * 5 + b) as usize);
            CROCKFORD[v] as char
        })
        .collect()
}

/// A typed code, canonical (§7.1): case-insensitive, `I`/`L` → `1`, `O` → `0`, dashes and
/// spaces dropped; `None` unless that leaves 10 Crockford characters.
pub fn normal_code(typed: &str) -> Option<String> {
    let code: String = typed
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect();
    (code.len() == 10 && code.bytes().all(|b| CROCKFORD.contains(&b))).then_some(code)
}

/// The credential hash of a typed code: SHA-256 of its canonical ASCII.
pub fn code_hash(canonical: &str) -> [u8; 32] {
    sha256(canonical.as_bytes())
}

/// The credential hash of a QR secret: SHA-256 of its 16 decoded bytes.
pub fn secret_hash(secret: &[u8]) -> [u8; 32] {
    sha256(secret)
}

/// The string the claimant's keys sign (§7.2 step 3).
pub fn pop_message(core_fp: &str, credential_hash: &[u8], routine_fp: &str) -> String {
    // A step-up key (`fp(stepup)` here) comes with ctl's step-up key (spec Q6).
    format!(
        "AINKRAD-PAIR-V1\n{core_fp}\n{}\n{routine_fp}\n-",
        b64(credential_hash)
    )
}

/// The SAS (§3): 16 Crockford characters of SHA-256("AINKRAD-SAS-V1" ‖ core_spki ‖
/// device_spki ‖ pairing_id), as `XXXX-XXXX-XXXX-XXXX`.
pub fn sas(core_spki: &[u8], device_spki: &[u8], pairing_id: &str) -> String {
    let mut input = b"AINKRAD-SAS-V1".to_vec();
    input.extend_from_slice(core_spki);
    input.extend_from_slice(device_spki);
    input.extend_from_slice(pairing_id.as_bytes());
    let s = crockford(&sha256(&input), 16);
    format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..])
}

/// A scanned QR payload (§7.1): `ainkrad-pair:v1?h=<host>&p=<port>&c=<core_fp>&s=<secret>&e=<unix>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Qr {
    pub host: String,
    pub port: u16,
    pub core_fp: String,
    pub secret: [u8; 16],
    pub expires: i64,
}

impl std::fmt::Debug for Qr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Qr({}:{}, {})", self.host, self.port, self.core_fp)
    }
}

impl Qr {
    /// Every field exactly once, nothing else.
    pub fn parse(text: &str) -> Option<Self> {
        let query = text.strip_prefix("ainkrad-pair:v1?")?;
        let mut fields: [Option<&str>; 5] = [None; 5];
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=')?;
            let i = ["h", "p", "c", "s", "e"].iter().position(|n| *n == k)?;
            if fields[i].replace(v).is_some() {
                return None;
            }
        }
        let [Some(h), Some(p), Some(c), Some(s), Some(e)] = fields else {
            return None;
        };
        let secret = unb64(s)?.try_into().ok()?;
        let fp_ok = c.len() == 43 && unb64(c).is_some();
        (fp_ok && !h.is_empty()).then_some(())?;
        Some(Self {
            host: h.to_owned(),
            port: p.parse().ok()?,
            core_fp: c.to_owned(),
            secret,
            expires: e.parse().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_parses_strictly() {
        let s = b64(&[7; 16]);
        let fp = b64(&[1; 32]);
        let ok = format!("ainkrad-pair:v1?h=core.example&p=443&c={fp}&s={s}&e=9");
        let q = Qr::parse(&ok).unwrap();
        assert_eq!(
            (q.host.as_str(), q.port, q.secret),
            ("core.example", 443, [7; 16])
        );
        assert!(!format!("{q:?}").contains(&s), "Debug hides the secret");
        for bad in [
            ok.replace("v1", "v2"),
            ok.replace("&e=9", ""),
            format!("{ok}&e=9"),
            ok.replace(&s, "short"),
            ok.replace("p=443", "p=x"),
        ] {
            assert!(Qr::parse(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn signatures_are_raw_and_verify() {
        let k = Key::generate();
        let sig = k.sign(b"m");
        assert_eq!(sig.len(), 64);
        assert!(verify(&k.spki(), b"m", &sig));
        assert!(!verify(&k.spki(), b"n", &sig));
        assert!(!format!("{k:?}").contains(&b64(k.pkcs8())));
    }
}
