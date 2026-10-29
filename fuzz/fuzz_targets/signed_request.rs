//! T-SIG-2: the signed-request parsing and canonicalisation. Input: one field per line, in this order: device, session,
//! alg, timestamp, nonce, signature, method, path, query, core_fp, then the rest is the body.
#![no_main]
use ainkrad_core_server::auth::signed::{self, Canonical};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut f = data.splitn(11, |b| *b == b'\n');
    let mut next = || f.next().unwrap_or_default();
    let (device, session, alg, ts, nonce, sig) = (next(), next(), next(), next(), next(), next());
    let (method, path, query, core_fp) = (next(), next(), next(), next());
    let body = next();

    let mut headers = HeaderMap::new();
    for (name, value) in [
        (signed::DEVICE, device),
        (signed::SESSION, session),
        (signed::ALG_HEADER, alg),
        (signed::TIMESTAMP, ts),
        (signed::NONCE, nonce),
        (signed::SIGNATURE, sig),
    ] {
        if let Ok(v) = HeaderValue::from_bytes(value) {
            headers.append(HeaderName::from_static(name), v);
        }
    }
    for with_session in [true, false] {
        if let Ok(h) = signed::parse(&headers, with_session) {
            // Whatever parses is exactly in format: a raw 64-byte signature, a 12-digit-at-most timestamp.
            assert_eq!(h.signature.len(), 64);
            assert!((0..1_000_000_000_000).contains(&h.timestamp));
            assert_eq!(h.session.is_some(), with_session);
        }
    }

    let (Ok(path), Ok(query), Ok(method), Ok(core_fp), Ok(device), Ok(nonce)) = (
        std::str::from_utf8(path),
        std::str::from_utf8(query),
        std::str::from_utf8(method),
        std::str::from_utf8(core_fp),
        std::str::from_utf8(device),
        std::str::from_utf8(nonce),
    ) else {
        return;
    };
    let canonical_path = signed::canonical_path(path);
    if canonical_path {
        assert!(!path.contains("..") && !path.contains("//") && !path.contains('\0'));
        assert!(path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic()));
    }
    let bytes = Canonical {
        core_fp,
        device,
        session: std::str::from_utf8(session).ok().filter(|s| !s.is_empty()),
        method,
        path,
        query,
        timestamp: ts.len() as i64,
        nonce,
        body,
    }
    .bytes();
    // Field boundaries cannot move: when no signed text carries a newline, there are exactly 11 fields.
    let text = [path, query, method, core_fp, device, nonce];
    if text.iter().all(|s| !s.contains('\n')) && std::str::from_utf8(session).is_ok_and(|s| !s.contains('\n')) {
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 10);
    }
    // The router and the signer read one path: whatever the URI parser takes as a path, a canonical one is unchanged.
    if canonical_path && let Ok(uri) = path.parse::<axum::http::Uri>() {
        assert_eq!(signed::canonical_path(uri.path()), true, "uri.path() of a canonical path: {path:?} -> {:?}", uri.path());
    }
});
