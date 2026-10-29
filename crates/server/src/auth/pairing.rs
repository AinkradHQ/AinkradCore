//! Pairing's primitives (handshake spec §3, §7.1): the typed code, the QR secret and payload,
//! the proof-of-possession string and the short authentication string (SAS).

use super::crypto::{b64, random, sha256};

/// Upper-case Crockford base32, as codes and the SAS are shown.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `n` Crockford characters from the 5-bit groups of `bytes`, most significant first.
fn crockford(bytes: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n);
    let (mut acc, mut bits) = (0u32, 0);
    for b in bytes {
        if out.len() == n {
            break;
        }
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 && out.len() < n {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    out
}

/// A new typed code: 10 Crockford characters (50 bits). Each character takes 5 whole bits of
/// a random byte stream, so every symbol is equally likely (no modulo skew).
pub fn new_code() -> String {
    crockford(&random::<7>(), 10)
}

/// `ABCDE-FGHJK`.
pub fn show_code(code: &str) -> String {
    format!("{}-{}", &code[..5], &code[5..])
}

/// The code as typed, canonical: case-insensitive, `I`/`L` → `1`, `O` → `0`, dashes and spaces
/// dropped; `None` unless that leaves exactly 10 Crockford characters.
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
    (code.len() == 10 && code.bytes().all(|b| ALPHABET.contains(&b))).then_some(code)
}

/// What the store keeps of the typed code: SHA-256 of its canonical form.
pub fn code_hash(code: &str) -> [u8; 32] {
    sha256(code.as_bytes())
}

/// A new QR secret: 128 random bits, and its base64url text.
pub fn new_secret() -> ([u8; 16], String) {
    let s = random::<16>();
    (s, b64(&s))
}

/// What the store keeps of the QR secret: SHA-256 of its 16 bytes.
pub fn secret_hash(secret: &[u8]) -> [u8; 32] {
    sha256(secret)
}

/// `ainkrad-pair:v1?h=<host>&p=<port>&c=<core_fp>&s=<secret>&e=<expires unix>`. `host` is the
/// Host clients send (`core.example`, or `127.0.0.1:7700` with its port; 443 without one).
pub fn qr(host: &str, core_fp: &str, secret: &str, expires: i64) -> String {
    let (h, p) = match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !h.contains(':') => (h, p),
        _ => (host, "443"),
    };
    format!("ainkrad-pair:v1?h={h}&p={p}&c={core_fp}&s={secret}&e={expires}")
}

/// The string the claimant's keys sign (§7.2 step 3). `credential_hash` is the hash of the
/// code or secret it used, as base64url.
pub fn pop_message(
    core_fp: &str,
    credential_hash: &[u8],
    routine_fp: &str,
    stepup_fp: Option<&str>,
) -> Vec<u8> {
    format!(
        "AINKRAD-PAIR-V1\n{core_fp}\n{}\n{routine_fp}\n{}",
        b64(credential_hash),
        stepup_fp.unwrap_or("-")
    )
    .into_bytes()
}

/// The SAS both screens show: the first 16 Crockford characters of
/// `SHA-256("AINKRAD-SAS-V1" ‖ core_spki ‖ device_spki ‖ pairing_id)`, as `XXXX-XXXX-XXXX-XXXX`.
pub fn sas(core_spki: &[u8], device_spki: &[u8], pairing_id: &str) -> String {
    let mut input = b"AINKRAD-SAS-V1".to_vec();
    input.extend_from_slice(core_spki);
    input.extend_from_slice(device_spki);
    input.extend_from_slice(pairing_id.as_bytes());
    let s = crockford(&sha256(&input), 16);
    format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..])
}

/// Whether two strings are equal, in time that depends on their lengths only.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed pairing vectors (`tests/vectors/pairing-v1.json`), the ones client SDKs
    /// test against, are what this code makes and accepts.
    #[test]
    fn the_pairing_vectors_are_reproduced() {
        use crate::auth::crypto::{fingerprint, unb64, verify};
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/pairing-v1.json")).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_owned();
        let bytes = |k: &str| unb64(&s(k), s(k).len()).unwrap();
        let canonical = normal_code(&s("typed_code")).unwrap();
        assert_eq!(canonical, s("canonical_code"));
        assert_eq!(b64(&code_hash(&canonical)), s("code_hash"));
        assert_eq!(b64(&secret_hash(&bytes("secret"))), s("secret_hash"));
        let (core, device) = (bytes("core_spki"), bytes("device_spki"));
        assert_eq!(fingerprint(&core), s("core_fp"));
        assert_eq!(fingerprint(&device), s("device_fp"));
        for (hash, message, sig) in [
            ("code_hash", "pop_message_code", "pop_code"),
            ("secret_hash", "pop_message_secret", "pop_secret"),
        ] {
            let m = pop_message(&s("core_fp"), &bytes(hash), &s("device_fp"), None);
            assert_eq!(String::from_utf8(m.clone()).unwrap(), s(message));
            assert!(verify(&device, &m, &bytes(sig)), "{sig}");
        }
        assert_eq!(sas(&core, &device, &s("pairing_id")), s("sas"));
    }

    #[test]
    fn codes_are_ten_crockford_characters_and_fold_as_typed() {
        let code = new_code();
        assert_eq!(normal_code(&code).as_deref(), Some(code.as_str()));
        let shown = show_code(&code);
        assert_eq!(shown.len(), 11);
        assert_eq!(
            normal_code(&shown.to_lowercase()).as_deref(),
            Some(code.as_str())
        );
        assert_eq!(normal_code("ilo0O-ABCDE").as_deref(), Some("11000ABCDE"));
        for bad in ["", "ABCDE", "ABCDE-FGHJKX", "ABCDE-FGHJU", "ABCDE_FGHJK"] {
            assert_eq!(normal_code(bad), None, "{bad}");
        }
        // Every symbol shows up: no position is stuck.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..400 {
            seen.extend(new_code().bytes());
        }
        assert_eq!(seen.len(), 32);
    }

    #[test]
    fn sas_qr_pop_and_constant_time_compare() {
        let s = sas(b"core", b"device", "p_x");
        assert_eq!(s.len(), 19);
        assert_eq!(s.matches('-').count(), 3);
        assert_eq!(s, sas(b"core", b"device", "p_x"));
        assert_ne!(s, sas(b"core", b"device", "p_y"), "bound to the pairing");
        assert_ne!(s, sas(b"other", b"device", "p_x"), "bound to the Core key");
        assert_eq!(
            qr("core.example", "fp", "sec", 9),
            "ainkrad-pair:v1?h=core.example&p=443&c=fp&s=sec&e=9"
        );
        assert_eq!(
            qr("127.0.0.1:7700", "fp", "sec", 9),
            "ainkrad-pair:v1?h=127.0.0.1&p=7700&c=fp&s=sec&e=9"
        );
        let m = pop_message("fp", &[0; 32], "rfp", None);
        assert!(String::from_utf8(m).unwrap().ends_with("\nrfp\n-"));
        assert!(ct_eq("ABCD", "ABCD") && !ct_eq("ABCD", "ABCE") && !ct_eq("AB", "ABC"));
    }
}
