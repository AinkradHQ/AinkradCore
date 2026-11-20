//! The installer's way to the app (E3-1, auto-connect): `rendezvous-post` seals the first owner's
//! connect link to the key the app put in the install command and leaves it at the rendezvous
//! (`signin.ainkrad.io`, `/v1/rendezvous/<id>`), where the app is polling for it.
//!
//! THREAT MODEL. The command the app shows carries `<code>.<app public key>` (`AINKRAD_RENDEZVOUS`).
//!  - The rendezvous never sees the link: it is sealed here (X25519 to the app's key, HKDF-SHA256
//!    salted with the code, ChaCha20-Poly1305) and only the app can open it. The rendezvous is
//!    also never told the code, only `id = SHA-256(code)`, so it cannot forge a message either.
//!    A rendezvous that lies can only drop or delay a message; the app then falls back to paste.
//!  - Someone who read the command (code and key) could leave a link for THEIR Core first. The
//!    app shows the Core's FULL fingerprint and waits for the person to press Connect (no Return
//!    shortcut), the installer prints this Core's fingerprint to compare, a code works once and
//!    for 15 minutes, and when the rendezvous answers 409 (someone got there first) this command
//!    exits 4 and the installer says not to press Connect.
//!  - The nonce is fixed (zero) because every message has its own ephemeral key, so a key is never
//!    used twice.

use std::io::Read;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::{aead, agreement, hkdf, rand};
use sha2::{Digest, Sha256};

use crate::cli::Result_;

/// Binds the key and the message to this protocol and version; the app uses the same bytes.
const CONTEXT: &[u8] = b"ainkrad-rendezvous-v1";
const MAX_LINK: usize = 1024;

struct Key32;
impl hkdf::KeyType for Key32 {
    fn len(&self) -> usize {
        32
    }
}

fn derive(shared: &[u8], code: &[u8], epk: &[u8], app_pub: &[u8]) -> [u8; 32] {
    let info: [&[u8]; 3] = [CONTEXT, epk, app_pub];
    let mut key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, code)
        .extract(shared)
        .expand(&info, Key32)
        .expect("32 bytes is within HKDF's limit")
        .fill(&mut key)
        .expect("the output is the length asked for");
    key
}

/// The sealing step alone, from the X25519 shared secret: HKDF (salt = code, info = context || epk || app key), then
/// ChaCha20-Poly1305 with a zero nonce and the context as AAD. Split out so a pinned vector can fix both languages.
pub(crate) fn seal_with(
    shared: &[u8],
    epk: &[u8],
    code: &[u8],
    app_pub: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive(shared, code, epk, app_pub);
    let sealing = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| "cipher")?,
    );
    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key([0u8; 12]),
            aead::Aad::from(CONTEXT),
            &mut buf,
        )
        .map_err(|_| "could not seal")?;
    Ok(buf)
}

/// `(ephemeral public key, ciphertext with its tag)`.
pub(crate) fn seal(
    code: &[u8],
    app_pub: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let rng = rand::SystemRandom::new();
    let eph = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| "no random source")?;
    let epk = eph
        .compute_public_key()
        .map_err(|_| "no public key")?
        .as_ref()
        .to_vec();
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, app_pub);
    // ring refuses a low-order or invalid peer key (all-zero shared secret) as an error here.
    let shared = agreement::agree_ephemeral(eph, &peer, |s| s.to_vec())
        .map_err(|_| "the app's key is not a valid key")?;
    let ct = seal_with(&shared, &epk, code, app_pub, plaintext)?;
    Ok((epk, ct))
}

/// `<code, 16 bytes>.<app public key, 32 bytes>`, both base64url.
fn parse_spec(spec: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let bad = || "the rendezvous is <code>.<app key>, both base64url".to_owned();
    let (c, k) = spec.split_once('.').ok_or_else(bad)?;
    let code = B64.decode(c).map_err(|_| bad())?;
    let key = B64.decode(k).map_err(|_| bad())?;
    if code.len() != 16 || key.len() != 32 {
        return Err(bad());
    }
    Ok((code, key))
}

/// The place a message is left: base64url of SHA-256 of the code.
pub(crate) fn id_of(code: &[u8]) -> String {
    B64.encode(Sha256::digest(code))
}

/// `ainkrad-core-server rendezvous-post <https base url>`, the link on stdin and `<code>.<app key>` in
/// `AINKRAD_RENDEZVOUS` (the environment, not argv, so it is not in the process list). Exits with 4 when the rendezvous
/// says the code was answered already (409): another Core got there first, and the installer says so loudly.
pub async fn post(base: &str) -> Result_ {
    let spec = std::env::var("AINKRAD_RENDEZVOUS").map_err(|_| "AINKRAD_RENDEZVOUS is not set")?;
    let (code, app_pub) = parse_spec(&spec)?;
    if !base.starts_with("https://") {
        return Err("the rendezvous is reached over https only".into());
    }
    let mut link = String::new();
    std::io::stdin()
        .take(MAX_LINK as u64 + 1)
        .read_to_string(&mut link)?;
    let link = link.trim();
    if link.len() > MAX_LINK || !link.starts_with("ainkrad://connect?") {
        return Err("stdin is not an ainkrad://connect link".into());
    }
    let (epk, ct) = seal(&code, &app_pub, link.as_bytes())?;
    let url = format!(
        "{}/v1/rendezvous/{}",
        base.trim_end_matches('/'),
        id_of(&code)
    );
    let res = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .post(url)
        .json(&serde_json::json!({"epk": B64.encode(&epk), "ct": B64.encode(&ct)}))
        .send()
        .await?;
    if res.status().as_u16() == 409 {
        eprintln!("someone else already answered this setup code");
        std::process::exit(4);
    }
    if res.status().as_u16() == 204 {
        Ok(())
    } else {
        Err(format!("the rendezvous answered {}", res.status()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the app does: derive the same key from its private key and the message's `epk`, then open.
    fn open(
        app: agreement::EphemeralPrivateKey,
        app_pub: &[u8],
        code: &[u8],
        epk: &[u8],
        ct: &[u8],
    ) -> Option<Vec<u8>> {
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, epk);
        let key = agreement::agree_ephemeral(app, &peer, |s| derive(s, code, epk, app_pub)).ok()?;
        let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).ok()?);
        let mut buf = ct.to_vec();
        let plain = k
            .open_in_place(
                aead::Nonce::assume_unique_for_key([0u8; 12]),
                aead::Aad::from(CONTEXT),
                &mut buf,
            )
            .ok()?;
        Some(plain.to_vec())
    }

    fn app_key() -> (agreement::EphemeralPrivateKey, Vec<u8>) {
        let rng = rand::SystemRandom::new();
        let k = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let p = k.compute_public_key().unwrap().as_ref().to_vec();
        (k, p)
    }

    #[test]
    fn only_the_app_with_the_code_can_open_the_link() {
        let link = b"ainkrad://connect?host=core.example.com&fp=FP&secret=S";
        let code = [7u8; 16];
        let (app, app_pub) = app_key();
        let (epk, ct) = seal(&code, &app_pub, link).unwrap();
        assert!(!ct.windows(link.len()).any(|w| w == link), "not plaintext");
        assert_eq!(
            open(app, &app_pub, &code, &epk, &ct).as_deref(),
            Some(&link[..])
        );

        // A wrong code, another app's key, or a changed byte all fail to open.
        let (app2, app2_pub) = app_key();
        let (epk2, ct2) = seal(&code, &app_pub, link).unwrap();
        assert!(open(app2, &app2_pub, &code, &epk2, &ct2).is_none());
        let (app3, app3_pub) = app_key();
        let (epk3, ct3) = seal(&code, &app3_pub, link).unwrap();
        assert!(open(app3, &app3_pub, &[8u8; 16], &epk3, &ct3).is_none());
        let (app4, app4_pub) = app_key();
        let (epk4, mut ct4) = seal(&code, &app4_pub, link).unwrap();
        ct4[0] ^= 1;
        assert!(open(app4, &app4_pub, &code, &epk4, &ct4).is_none());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The same vector is opened by `RendezvousTests` in the app: both sides must agree on these bytes.
    #[test]
    fn the_pinned_vector_is_what_the_app_opens() {
        let d = |s: &str| B64.decode(s).unwrap();
        let ct = seal_with(
            &hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
            &d("hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"),
            &[7u8; 16],
            &d("3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"),
            b"ainkrad://connect?host=core.example.com&fp=FP&secret=S",
        )
        .unwrap();
        assert_eq!(
            B64.encode(ct),
            "rBL1S5cKm3hdu54gCEaoH51O343FmiVAKIZp0hurr2NGiMlq9YW-qXbI7lhtVvKrn3askCu1qcmh8FhkA5PS2e4c_rqnPQ"
        );
    }

    #[test]
    fn the_spec_is_checked_and_the_id_is_the_hash_of_the_code() {
        let code = B64.encode([1u8; 16]);
        let key = B64.encode([2u8; 32]);
        assert!(parse_spec(&format!("{code}.{key}")).is_ok());
        assert!(parse_spec(&code).is_err());
        assert!(parse_spec(&format!("{key}.{code}")).is_err());
        assert_eq!(id_of(&[1u8; 16]).len(), 43);
        assert_ne!(id_of(&[1u8; 16]), id_of(&[2u8; 16]));
    }
}
