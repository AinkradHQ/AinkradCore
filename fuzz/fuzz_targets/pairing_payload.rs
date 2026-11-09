//! T-PAIR-1/T-PAIR-2: what a claimant sends at `POST /pair/claim`: the JSON body, the typed code, the QR secret.
//! (The Core only BUILDS the QR payload; a client parses it. `qr` is exercised here for panics.)
#![no_main]
use ainkrad_core_server::api::v1::pair::ClaimBody;
use ainkrad_core_server::auth::crypto::{b64, spki_point, unb64};
use ainkrad_core_server::auth::pairing::{code_hash, normal_code, qr, show_code};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(claim) = serde_json::from_slice::<ClaimBody>(data) {
        for text in [claim.code.as_deref(), claim.secret.as_deref()].into_iter().flatten() {
            let _ = normal_code(text);
            if let Some(bytes) = unb64(text, text.len()) {
                assert_eq!(b64(&bytes), text, "base64url is strict: one text per byte string");
            }
        }
        for key in [Some(claim.routine_spki.as_str()), claim.stepup_spki.as_deref()].into_iter().flatten() {
            if let Some(spki) = unb64(key, key.len()) {
                let _ = spki_point(&spki);
            }
        }
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(code) = normal_code(text) {
        assert_eq!(code.len(), 10);
        assert_eq!(normal_code(&code).as_deref(), Some(code.as_str()), "canonical codes are fixed points");
        assert_eq!(normal_code(&show_code(&code)).as_deref(), Some(code.as_str()));
        assert_eq!(code_hash(&code), code_hash(&normal_code(text).unwrap()));
    }
    let mut parts = text.splitn(4, '\n');
    let (host, fp, secret) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let _ = qr(host, fp, secret, i64::from(data.len() as u32));
});
