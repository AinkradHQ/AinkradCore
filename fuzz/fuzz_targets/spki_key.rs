//! T-PK-5/T-PAIR-2: the SEC1/SPKI public-key parser at enrolment (`spki_point`), and the ES256 verifier on whatever it takes.
#![no_main]
use ainkrad_core_server::auth::crypto::{fingerprint, spki_of, spki_point, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Raw bytes as an SPKI, and the same bytes as an uncompressed point under the right prefix (reaches the curve check).
    for spki in [data.to_vec(), spki_of(data)] {
        if let Some(point) = spki_point(&spki) {
            assert_eq!(point.len(), 65);
            assert_eq!(point[0], 4);
            assert_eq!(fingerprint(&spki).len(), 43);
            // Verifying against any accepted key with junk never panics, and never accepts.
            assert!(!verify(&spki, b"message", &data[..data.len().min(64)]) || data.len() < 64);
        }
        let _ = verify(&spki, data, data);
    }
});
