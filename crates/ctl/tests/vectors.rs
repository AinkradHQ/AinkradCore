//! The committed golden vectors (spec §17.1), reproduced byte for byte by ctl's own code: the
//! same files the server's tests reproduce, so the two implementations meet only here.

use ainkrad_ctl::proto::{
    Canonical, Key, b64, code_hash, fp, normal_code, pop_message, sas, secret_hash, sha256, unb64,
    verify,
};
use serde_json::Value;

fn vector(name: &str) -> Value {
    let path = format!(
        "{}/../server/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

fn bytes(v: &Value, k: &str) -> Vec<u8> {
    unb64(s(v, k)).unwrap_or_else(|| panic!("{k} is strict base64url"))
}

/// A PKCS#8 test key's SPKI, as ctl derives it.
fn spki(v: &Value, k: &str) -> Vec<u8> {
    Key::from_pkcs8(&bytes(v, k)).expect(k).spki()
}

#[test]
fn handshake_v1_canonical_string_and_signature() {
    let v = vector("handshake-v1.json");
    let device = spki(&v, "device_pkcs8");
    assert_eq!(b64(&device), s(&v, "device_spki"));
    assert_eq!(fp(&device), s(&v, "device_fingerprint"));
    assert_eq!(fp(&spki(&v, "core_pkcs8")), s(&v, "core_fp"));
    let body = s(&v, "body").as_bytes();
    assert_eq!(b64(&sha256(body)), s(&v, "body_sha256"));
    let c = Canonical {
        core_fp: s(&v, "core_fp"),
        device: s(&v, "device_id"),
        session: Some(s(&v, "session_id")),
        method: s(&v, "method"),
        path: s(&v, "path"),
        query: s(&v, "query"),
        timestamp: v["timestamp"].as_u64().unwrap(),
        nonce: s(&v, "nonce"),
        body,
    };
    let canonical = c.bytes();
    assert_eq!(canonical, s(&v, "canonical").as_bytes(), "exact bytes");
    assert!(!canonical.ends_with(b"\n"), "no trailing newline");
    assert!(
        verify(&device, &canonical, &bytes(&v, "signature")),
        "the committed signature"
    );
    let mut tampered = canonical.clone();
    tampered[40] ^= 1;
    assert!(!verify(&device, &tampered, &bytes(&v, "signature")));

    // ctl's own signature over the same bytes, through the headers it would send.
    let key = Key::from_pkcs8(&bytes(&v, "device_pkcs8")).unwrap();
    let headers = c.headers(&key);
    let h = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(h("ainkrad-alg"), Some("ES256"));
    assert_eq!(h("ainkrad-device"), Some(s(&v, "device_id")));
    assert_eq!(h("ainkrad-session"), Some(s(&v, "session_id")));
    assert_eq!(h("ainkrad-timestamp"), Some("1761730000"));
    assert_eq!(h("ainkrad-nonce"), Some(s(&v, "nonce")));
    let sig = h("ainkrad-signature").unwrap();
    assert_eq!(sig.len(), 86, "raw r||s, base64url");
    assert!(verify(&device, &canonical, &unb64(sig).unwrap()));

    // Session `-`: the header is absent, the field is `-`.
    let none = Canonical { session: None, ..c };
    let text = String::from_utf8(none.bytes()).unwrap();
    assert_eq!(text.lines().nth(4), Some("-"));
    assert!(
        none.headers(&key)
            .iter()
            .all(|(k, _)| *k != "ainkrad-session")
    );
}

#[test]
fn pairing_v1_code_secret_pop_and_sas() {
    let v = vector("pairing-v1.json");
    let canonical = normal_code(s(&v, "typed_code")).unwrap();
    assert_eq!(canonical, s(&v, "canonical_code"));
    assert_eq!(b64(&code_hash(&canonical)), s(&v, "code_hash"));
    assert_eq!(
        b64(&secret_hash(&bytes(&v, "secret"))),
        s(&v, "secret_hash")
    );
    let (core, device) = (spki(&v, "core_pkcs8"), spki(&v, "device_pkcs8"));
    assert_eq!(b64(&core), s(&v, "core_spki"));
    assert_eq!(b64(&device), s(&v, "device_spki"));
    assert_eq!(fp(&core), s(&v, "core_fp"));
    assert_eq!(fp(&device), s(&v, "device_fp"));
    let key = Key::from_pkcs8(&bytes(&v, "device_pkcs8")).unwrap();
    for (hash, message, sig) in [
        ("code_hash", "pop_message_code", "pop_code"),
        ("secret_hash", "pop_message_secret", "pop_secret"),
    ] {
        let m = pop_message(s(&v, "core_fp"), &bytes(&v, hash), &fp(&device), None);
        assert_eq!(m, s(&v, message));
        assert!(verify(&device, m.as_bytes(), &bytes(&v, sig)), "{sig}");
        assert!(
            verify(&device, m.as_bytes(), &key.sign(m.as_bytes())),
            "ours"
        );
    }
    assert_eq!(sas(&core, &device, s(&v, "pairing_id")), s(&v, "sas"));
}

#[test]
fn codes_fold_as_the_spec_says() {
    assert_eq!(normal_code("ilo0O-abcde").as_deref(), Some("11000ABCDE"));
    assert_eq!(normal_code("4DTTJ F9NW0").as_deref(), Some("4DTTJF9NW0"));
    for bad in ["", "ABCDE", "ABCDE-FGHJKX", "ABCDE-FGHJU", "ABCDE_FGHJK"] {
        assert_eq!(normal_code(bad), None, "{bad}");
    }
}

/// The step-up vector (§8): ctl's message is the vector's byte for byte, its SPKI is the one
/// ctl derives from the test key, the vector's signature verifies over ctl's bytes, and so does
/// ctl's own (signatures are randomised, so they are verified, never compared).
#[test]
fn stepup_v1_message_and_signature() {
    let v = vector("stepup-v1.json");
    let m = ainkrad_ctl::stepup::message(
        s(&v, "core_fp"),
        s(&v, "device_id"),
        s(&v, "session_id"),
        s(&v, "challenge"),
    );
    assert_eq!(m, s(&v, "message").as_bytes());
    let key = Key::from_pkcs8(&bytes(&v, "stepup_pkcs8")).unwrap();
    assert_eq!(b64(&key.spki()), s(&v, "stepup_spki"));
    assert!(verify(&key.spki(), &m, &bytes(&v, "stepup_sig")));
    assert!(verify(&key.spki(), &m, &key.sign(&m)), "ours");
    // The same fields under another prefix are another message.
    let wrong =
        String::from_utf8(m.clone())
            .unwrap()
            .replacen("AINKRAD-STEPUP-V1", "AINKRAD-REQ-V1", 1);
    assert!(!verify(
        &key.spki(),
        wrong.as_bytes(),
        &bytes(&v, "stepup_sig")
    ));
}
