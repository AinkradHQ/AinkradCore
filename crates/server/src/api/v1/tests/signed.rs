//! Signed requests and sessions, the handshake spec's §17 cases 1 to 10, 22, 23 and 32 (for
//! lockouts), through the router as a client sends them.

use std::time::Instant;

use axum::http::HeaderValue;

use super::*;
use crate::auth::crypto::{b64, random, unb64, verify};
use crate::auth::signed::{self as sig, Canonical};
use crate::scheduler::iso_of_unix;

pub(super) const PATH: &str = "/api/v1/me";

/// `r` with header `name` set to `value`.
fn with(mut r: Request<Body>, name: &'static str, value: &str) -> Request<Body> {
    r.headers_mut()
        .insert(name, HeaderValue::from_str(value).unwrap());
    r
}

/// A request with exactly these headers (no signing).
pub(super) fn raw(
    method: Method,
    uri: &str,
    headers: &[(&'static str, String)],
    body: &[u8],
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST);
    for (n, v) in headers {
        b = b.header(*n, v);
    }
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

pub(super) async fn status_code(app: &App, r: Request<Body>) -> (StatusCode, String) {
    let (status, body) = send(app, r).await;
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

/// §17.1: the committed vector's canonical bytes are what the builder makes, its signature
/// verifies, and the request is accepted end to end by a Core with the vector's identity.
#[tokio::test]
async fn the_golden_vector_is_reproduced_and_accepted() {
    let v: Value =
        serde_json::from_str(include_str!("../../../../tests/vectors/handshake-v1.json")).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_owned();
    let bytes = |k: &str| unb64(&s(k), s(k).len()).unwrap();
    let canonical = Canonical {
        core_fp: &s("core_fp"),
        device: &s("device_id"),
        session: Some(&s("session_id")),
        method: &s("method"),
        path: &s("path"),
        query: &s("query"),
        timestamp: v["timestamp"].as_i64().unwrap(),
        nonce: &s("nonce"),
        body: s("body").as_bytes(),
    }
    .bytes();
    assert_eq!(
        String::from_utf8(canonical.clone()).unwrap(),
        s("canonical")
    );
    assert!(!s("canonical").ends_with('\n'));
    assert!(verify(
        &bytes("device_spki"),
        &canonical,
        &bytes("signature")
    ));
    let core = Identity::from_pkcs8(&bytes("core_pkcs8")).unwrap();
    assert_eq!(core.fp, s("core_fp"));
    let clock = Arc::new(FixedClock(Mutex::new(iso_of_unix(
        v["timestamp"].as_i64().unwrap(),
    ))));
    let dev = TestDevice::from_pkcs8(
        &s("device_id"),
        &bytes("device_pkcs8"),
        &core.fp,
        clock.clone(),
    );
    assert_eq!(b64(&dev.spki), s("device_spki"));
    assert_eq!(
        crate::auth::crypto::fingerprint(&dev.spki),
        s("device_fingerprint")
    );

    let mut fx = fx().await;
    fx.app.auth = Arc::new(crate::auth::Auth::new(Arc::new(core)));
    fx.app.clock = clock;
    let scopes: Vec<String> = vec!["read".to_owned()];
    crate::store::gov::enroll_for_tests(
        &fx.app.pool,
        &crate::store::gov::NewDevice {
            id: &dev.id,
            kind: "device",
            name: "vector",
            routine_spki: &dev.spki,
            stepup_spki: None,
            platform: None,
            key_storage: None,
            scopes: &scopes,
        },
    )
    .await
    .unwrap();
    // The vector's session, as if issued.
    let now = fx.app.clock.unix();
    let issued = fx.app.auth.issue_session(&dev.id, now);
    let headers = [
        (sig::DEVICE, s("device_id")),
        (sig::SESSION, issued.id.clone()),
        (sig::ALG_HEADER, "ES256".to_owned()),
        (sig::TIMESTAMP, v["timestamp"].to_string()),
        (sig::NONCE, s("nonce")),
        (sig::SIGNATURE, s("signature")),
    ];
    // The vector names its own session id, which this Core never issued: re-sign with the
    // session it did issue to prove the rest of the pipeline accepts exactly these bytes.
    let (path, nonce, body) = (s("path"), s("nonce"), s("body"));
    let resigned = Canonical {
        core_fp: &fx.app.auth.identity.fp,
        device: &dev.id,
        session: Some(&issued.id),
        method: "PUT",
        path: &path,
        query: "",
        timestamp: v["timestamp"].as_i64().unwrap(),
        nonce: &nonce,
        body: body.as_bytes(),
    };
    let mut headers = headers.to_vec();
    headers[5].1 = b64(&dev.sign(&resigned.bytes()));
    let r = raw(Method::PUT, &s("path"), &headers, s("body").as_bytes());
    let (status, body) = send(&fx.app, r).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// §17.2: changing any one of the 11 signed fields, or one body byte, is `auth_failed`.
#[tokio::test]
async fn tampering_with_any_field_or_the_body_fails() {
    let fx = fx().await;
    let body = br#"{"token":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}"#;
    let uri = "/api/v1/push-token";
    let session = fx.dev.session.lock().unwrap().clone();
    let good = |f: &dyn Fn(&mut Vec<String>)| {
        let nonce = b64(&random::<16>());
        let ts = fx.clock.unix();
        let mut fields: Vec<String> = String::from_utf8(
            Canonical {
                core_fp: &fx.app.auth.identity.fp,
                device: &fx.dev.id,
                session: session.as_deref(),
                method: "PUT",
                path: uri,
                query: "",
                timestamp: ts,
                nonce: &nonce,
                body,
            }
            .bytes(),
        )
        .unwrap()
        .split('\n')
        .map(str::to_owned)
        .collect();
        assert_eq!(fields.len(), 11);
        f(&mut fields);
        let signature = b64(&fx.dev.sign(fields.join("\n").as_bytes()));
        vec![
            (sig::DEVICE, fx.dev.id.clone()),
            (sig::SESSION, session.clone().unwrap()),
            (sig::ALG_HEADER, "ES256".to_owned()),
            (sig::TIMESTAMP, ts.to_string()),
            (sig::NONCE, nonce),
            (sig::SIGNATURE, signature),
        ]
    };
    let ok = good(&|_| {});
    assert_eq!(
        send(&fx.app, raw(Method::PUT, uri, &ok, body)).await.0,
        StatusCode::OK
    );
    // Each from its own address, so the (address, device) lock (5 failures) never answers
    // instead.
    for i in 0..11 {
        let headers = good(&|f| f[i].push('x'));
        let r = from(
            &format!("10.3.0.{i}"),
            raw(Method::PUT, uri, &headers, body),
        );
        let (status, code) = status_code(&fx.app, r).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::UNAUTHORIZED, "auth_failed"),
            "field {i}"
        );
    }
    // One body byte; another method, path or query than signed.
    let mut flipped = body.to_vec();
    flipped[12] ^= 1;
    let sent = [
        raw(Method::PUT, uri, &good(&|_| {}), &flipped),
        raw(Method::DELETE, uri, &good(&|_| {}), body),
        raw(
            Method::PUT,
            "/api/v1/push-token?limit=1",
            &good(&|_| {}),
            body,
        ),
        raw(Method::PUT, "/api/v1/me", &good(&|_| {}), body),
    ];
    for (n, r) in sent.into_iter().enumerate() {
        let r = from(&format!("10.3.1.{n}"), r);
        let what = format!("{} {}", r.method(), r.uri());
        let (status, code) = status_code(&fx.app, r).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::UNAUTHORIZED, "auth_failed"),
            "{what}"
        );
    }
}

/// §17.3: the same signed request twice is refused the second time.
#[tokio::test]
async fn a_replayed_request_fails() {
    let fx = fx().await;
    let h = fx.dev.headers("GET", PATH, b"");
    assert_eq!(
        send(&fx.app, raw(Method::GET, PATH, &h, b"")).await.0,
        StatusCode::OK
    );
    let (status, code) = status_code(&fx.app, raw(Method::GET, PATH, &h, b"")).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
}

/// §17.4: a request captured before a restart, its clock 59 s ahead, names a dead session;
/// a captured `/handshake/session` names a dead challenge.
#[tokio::test]
async fn a_restart_ends_sessions_and_challenges() {
    let mut fx = fx().await;
    let session = fx.dev.session.lock().unwrap().clone();
    let ahead = fx.clock.unix() + 59;
    let nonce = b64(&random::<16>());
    let captured = fx
        .dev
        .headers_at("GET", PATH, b"", session.as_deref(), ahead, &nonce);

    let (_, got) = send(
        &fx.app,
        req(
            Method::POST,
            "/handshake/challenge",
            None,
            Some(json!({"device_id": fx.dev.id})),
        ),
    )
    .await;
    let body = json!({"challenge": got["challenge"]}).to_string();
    let login = fx
        .dev
        .headers_session("POST", "/handshake/session", body.as_bytes(), None);

    fx.restart();
    let (status, code) = status_code(&fx.app, raw(Method::GET, PATH, &captured, b"")).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "session_expired")
    );
    let r = raw(Method::POST, "/handshake/session", &login, body.as_bytes());
    let (status, code) = status_code(&fx.app, r).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
}

/// §17.5: ±61 s is `clock_skew` with the server's time; ±59 s is accepted.
#[tokio::test]
async fn clock_skew_beyond_sixty_seconds_is_refused() {
    let fx = fx().await;
    let now = fx.clock.unix();
    let session = fx.dev.session.lock().unwrap().clone();
    for (off, want) in [(61, false), (-61, false), (59, true), (-59, true)] {
        let nonce = b64(&random::<16>());
        let h = fx
            .dev
            .headers_at("GET", PATH, b"", session.as_deref(), now + off, &nonce);
        let (status, body) = send(&fx.app, raw(Method::GET, PATH, &h, b"")).await;
        if want {
            assert_eq!(status, StatusCode::OK, "{off}: {body}");
        } else {
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{off}");
            assert_eq!(body["code"], "clock_skew");
            assert_eq!(body["server_time"], now);
        }
    }
}

/// §17.6: a request signed for Core A is refused by Core B, though B has the same device.
#[tokio::test]
async fn a_request_for_another_core_fails() {
    let a = fx().await;
    let b = fx().await;
    let scopes: Vec<String> = vec![];
    crate::store::gov::enroll_for_tests(
        &b.app.pool,
        &crate::store::gov::NewDevice {
            id: &a.dev.id,
            kind: "device",
            name: "same",
            routine_spki: &a.dev.spki,
            stepup_spki: None,
            platform: None,
            key_storage: None,
            scopes: &scopes,
        },
    )
    .await
    .unwrap();
    let s = b.app.auth.issue_session(&a.dev.id, b.clock.unix());
    a.dev.set_session(Some(s.id));
    let (status, code) = status_code(&b.app, req(Method::GET, PATH, Some(&a.dev), None)).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
}

/// A raw `r‖s` signature as DER, the way Security.framework and Android hand it out.
fn der(raw: &[u8]) -> Vec<u8> {
    let int = |b: &[u8]| {
        let b = &b[b.iter().position(|x| *x != 0).unwrap_or(b.len() - 1)..];
        let mut out = vec![0x02];
        let pad = b[0] & 0x80 != 0;
        out.push((b.len() + usize::from(pad)) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(b);
        out
    };
    let body = [int(&raw[..32]), int(&raw[32..])].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

/// §17.7: a DER signature, another `Ainkrad-Alg`, an `Authorization` header and a
/// non-canonical path are each a 400.
#[tokio::test]
async fn der_signatures_other_algs_bearers_and_crooked_paths_are_bad_requests() {
    let fx = fx().await;
    let mut h = fx.dev.headers("GET", PATH, b"");
    let signature = unb64(&h[4].1, 86).unwrap();
    h[4].1 = b64(&der(&signature));
    let (status, code) = status_code(&fx.app, raw(Method::GET, PATH, &h, b"")).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::BAD_REQUEST, "bad_request"),
        "DER"
    );
    for (name, value) in [
        (sig::ALG_HEADER, "ES384"),
        ("authorization", "Bearer cit_device_x"),
    ] {
        let r = with(req(Method::GET, PATH, Some(&fx.dev), None), name, value);
        assert_eq!(send(&fx.app, r).await.0, StatusCode::BAD_REQUEST, "{name}");
    }
    for path in ["/api/v1/../v1/me", "/api//v1/me", "/api/v1/%6de"] {
        let r = req(Method::GET, path, Some(&fx.dev), None);
        assert_eq!(send(&fx.app, r).await.0, StatusCode::BAD_REQUEST, "{path}");
    }
    // Malformed headers: a repeated one, a padded timestamp, a short nonce.
    let mut r = req(Method::GET, PATH, Some(&fx.dev), None);
    r.headers_mut()
        .append(sig::DEVICE, HeaderValue::from_str(&fx.dev.id).unwrap());
    assert_eq!(
        send(&fx.app, r).await.0,
        StatusCode::BAD_REQUEST,
        "repeated"
    );
    let ts = format!("0{}", fx.clock.unix());
    let r = with(
        req(Method::GET, PATH, Some(&fx.dev), None),
        sig::TIMESTAMP,
        &ts,
    );
    assert_eq!(
        send(&fx.app, r).await.0,
        StatusCode::BAD_REQUEST,
        "leading zero"
    );
    let r = with(
        req(Method::GET, PATH, Some(&fx.dev), None),
        sig::NONCE,
        "AAAA",
    );
    assert_eq!(send(&fx.app, r).await.0, StatusCode::BAD_REQUEST, "nonce");
}

/// §17.8: an unknown, a revoked and a wrongly signing device get the identical answer, in
/// about the same time.
#[tokio::test]
async fn unknown_revoked_and_bad_signature_look_alike() {
    let fx = fx().await;
    let revoked = fx.enroll("old", &["read"]).await;
    crate::store::gov::revoke_device(&fx.app.pool, &revoked.id, super::super::BY, None, NOW)
        .await
        .unwrap();
    let liar = fx.enroll("liar", &["read"]).await;
    let other = fx.stranger();
    let unknown = fx.stranger();
    let case = |n: usize, i: usize| {
        let mut h = match n {
            0 => unknown.headers("GET", PATH, b""),
            1 => revoked.headers("GET", PATH, b""),
            _ => liar.headers("GET", PATH, b""),
        };
        if n == 2 {
            // Signed by another key: a well-formed, wrong signature.
            h[4].1 = b64(&other.sign(b"not the canonical string"));
        }
        from(
            &format!("10.9.{}.{}", i / 250, i % 250),
            raw(Method::GET, PATH, &h, b""),
        )
    };
    let mut bodies = Vec::new();
    for n in 0..3 {
        let (status, mut body) = send(&fx.app, case(n, 1000 + n)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        body.as_object_mut().unwrap().remove("error_id");
        bodies.push(body);
    }
    assert!(bodies.iter().all(|b| *b == bodies[0]), "{bodies:?}");
    assert_eq!(bodies[0]["code"], "auth_failed");

    let mut times: [Vec<u128>; 3] = Default::default();
    for i in 0..30 {
        // Rotated, so no case always runs first.
        for k in 0..3 {
            let n = (i + k) % 3;
            let r = case(n, i * 3 + k);
            let t = &mut times[n];
            let start = Instant::now();
            let (status, _) = send(&fx.app, r).await;
            t.push(start.elapsed().as_micros());
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }
    let medians: Vec<u128> = times
        .iter_mut()
        .map(|t| {
            t.sort_unstable();
            t[t.len() / 2]
        })
        .collect();
    let (lo, hi) = (
        *medians.iter().min().unwrap(),
        *medians.iter().max().unwrap(),
    );
    assert!(
        hi * 10 <= lo * 11,
        "median µs unknown/revoked/bad: {medians:?}"
    );
}
