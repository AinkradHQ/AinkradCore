//! The pre-auth surface (E1-06.4, handshake spec §4): unsigned, only `/handshake…`, pairing
//! and `/healthz` answer; every other path and method, in the contract or not, gets the same
//! 401 before routing, and a non-canonical path a 400 before anything. `/handshake` (E1-05.5)
//! answers unsigned and says nothing but the versions and the Core identity fingerprint.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{HOST, from, fx, req, send};
use crate::api::limit::Limiter;
use crate::api::router;
use crate::api::v1::Limits;
use crate::auth::signed::canonical_path;
use crate::gateway::preauth::allowed;

const METHODS: [Method; 5] = [
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::PATCH,
];

/// Paths that are not in the contract: lookalikes, case and slash games, traversal, the ACME
/// path on the main listener, and the bearer-era pairing routes.
const PROBES: [&str; 16] = [
    "/",
    "/nope",
    "/handshakeX",
    "/handshake/../api/v1/me",
    "/API/V1/ME",
    "/api/v1/me/",
    "//api/v1/me",
    "/api/v1",
    "/api/v2/me",
    "/api/v1/devices/pairing",
    "/api/v1/devices/pair",
    "/pairing",
    "/healthzz",
    "/.well-known/acme-challenge/token",
    "/modules/x/v1/y",
    "/api/v1/modules/x/v1/y",
];

/// `{param}` in a contract path, filled with `1`.
fn fill(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some((head, tail)) = rest.split_once('{') {
        out.push_str(head);
        out.push('1');
        rest = tail.split_once('}').map_or("", |(_, t)| t);
    }
    out + rest
}

#[tokio::test]
async fn only_the_allowed_prefixes_answer_unsigned() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut paths: Vec<String> = spec["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(|p| fill(p))
        .collect();
    let in_contract = paths.len();
    paths.extend(PROBES.iter().map(|p| (*p).to_owned()));
    let (mut refused, mut open, mut crooked) = (0, Vec::new(), 0);
    for path in &paths {
        for m in METHODS {
            let (status, body) = send(&fx.app, req(m.clone(), path, None, None)).await;
            if !canonical_path(path) {
                assert_eq!(status, StatusCode::BAD_REQUEST, "{m} {path}: {body}");
                crooked += 1;
                continue;
            }
            if allowed(path) {
                open.push(format!("{m} {path} {}", status.as_u16()));
                continue;
            }
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{m} {path}: {body}");
            assert_eq!(body["code"], "auth_failed", "{m} {path}");
            assert_eq!(body["message"], "authentication failed", "{m} {path}");
            refused += 1;
        }
    }
    assert!(in_contract >= 15, "{in_contract} contract paths");
    // Under the allowed prefixes, only `GET /handshake` succeeds unsigned: the challenge wants
    // a body, the session a signature (and refuses as any route does).
    let ok: Vec<&String> = open.iter().filter(|o| o.ends_with(" 200")).collect();
    assert_eq!(ok, ["GET /handshake 200"], "{open:#?}");
    assert!(
        open.contains(&"POST /handshake/session 401".to_owned()),
        "{open:#?}"
    );
    // `/handshake`, its challenge and session, the passkey sign-in pair, `/pair/claim`, `/pair/status`
    // and the passkey pairing pair.
    assert_eq!(open.len(), 9 * METHODS.len(), "{open:#?}");
    // Unrouted methods under them are a bare 405, which names nothing.
    assert!(open.iter().all(|o| !o.ends_with(" 404")), "{open:#?}");
    assert_eq!(crooked, 2 * METHODS.len(), "the traversal and slash probes");
    assert_eq!(refused + open.len() + crooked, paths.len() * METHODS.len());

    // `/healthz`: `ok`, and nothing about the server.
    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, "/healthz", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(&to_bytes(res.into_body(), 64).await.unwrap()[..], b"ok");

    // A stranger's signature does not open the router either: unknown paths stay 401.
    let stranger = fx.stranger();
    let (status, _) = send(&fx.app, req(Method::GET, "/nope", Some(&stranger), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A live device gets past authentication, but no scope is declared for an unknown path:
    // deny by default.
    let (status, body) = send(&fx.app, req(Method::GET, "/nope", Some(&fx.dev), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
}

#[tokio::test]
async fn pre_auth_routes_keep_the_shared_checks_and_a_small_body() {
    let fx = fx().await;
    let with = |uri: &str, extra: (&str, &str)| {
        Request::builder()
            .uri(uri)
            .header(header::HOST, HOST)
            .header(extra.0, extra.1)
            .body(Body::empty())
            .unwrap()
    };
    let (status, _) = send(
        &fx.app,
        with("/handshake", ("origin", "https://evil.example")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&fx.app, with("/handshake?x=1", ("accept", "*/*"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let wrong_host = Request::builder()
        .uri("/healthz")
        .header(header::HOST, "rebound.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&fx.app, wrong_host).await.0, StatusCode::FORBIDDEN);

    let big = json!({"device_id": "x".repeat(20 * 1024)});
    let (status, body) = send(
        &fx.app,
        req(Method::POST, "/handshake/challenge", None, Some(big)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["code"], "too_large");
    let bearer = with("/handshake", ("authorization", "Bearer cit_device_x"));
    assert_eq!(send(&fx.app, bearer).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_handshake_answers_unsigned_and_leaks_nothing_else() {
    let fx = fx().await;
    let (status, body) = send(&fx.app, req(Method::GET, "/handshake", None, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "api_major",
            "api_minor",
            "git_sha",
            "identity_fingerprint",
            "server_version",
            "supported_minors"
        ]
    );
    assert_eq!(body["server_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["api_major"], "v1");
    assert_eq!(body["api_minor"], super::super::types::API_MINOR);
    assert_eq!(body["supported_minors"][0], 0);
    assert_eq!(
        body["identity_fingerprint"],
        fx.app.auth.identity.fp.as_str(),
        "core_fp, what every request signs"
    );
    assert_eq!(body["identity_fingerprint"].as_str().unwrap().len(), 43);
    // Nothing about devices: the only device's name and id are not in it.
    assert!(!body.to_string().contains("test") && !body.to_string().contains(&fx.dev.id));
}

/// Spec §4, §13 (KAN-251/252): `POST /handshake {nonce}` returns the Core key and its signature
/// over `AINKRAD-CORE-V1` LF host LF nonce; a malformed nonce is a 400.
#[tokio::test]
async fn the_handshake_proves_the_core_key_over_a_nonce() {
    use crate::auth::crypto::{fingerprint, unb64, verify};
    let fx = fx().await;
    let nonce = "BQUFBQUFBQUFBQUFBQUFBQ";
    let (status, body) = send(
        &fx.app,
        req(
            Method::POST,
            "/handshake",
            None,
            Some(json!({"nonce": nonce})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let spki = unb64(body["core_spki"].as_str().unwrap(), 122).unwrap();
    assert_eq!(fingerprint(&spki), fx.app.auth.identity.fp);
    assert_eq!(
        body["identity_fingerprint"],
        fx.app.auth.identity.fp.as_str()
    );
    let sig = unb64(body["core_sig"].as_str().unwrap(), 86).unwrap();
    let message = format!("AINKRAD-CORE-V1\n{HOST}\n{nonce}");
    assert!(verify(&spki, message.as_bytes(), &sig));
    assert!(!verify(
        &spki,
        b"AINKRAD-CORE-V1\nother\nBQUFBQUFBQUFBQUFBQUFBQ",
        &sig
    ));
    for bad in [
        json!({}),
        json!({"nonce": "short"}),
        json!({"nonce": nonce, "x": 1}),
    ] {
        let (status, _) = send(&fx.app, req(Method::POST, "/handshake", None, Some(bad))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // GET is unchanged: no key, no signature.
    let (_, body) = send(&fx.app, req(Method::GET, "/handshake", None, None)).await;
    assert!(body.get("core_sig").is_none() && body.get("core_spki").is_none());
}

/// Review L3: `POST /handshake` signs pre-auth, so it is under the per-address challenge rate,
/// shared with `POST /handshake/challenge`; another address is not affected.
#[tokio::test]
async fn the_handshake_proof_is_under_the_challenge_rate() {
    let fx = fx().await;
    let prove = |peer: &str| {
        let body = json!({"nonce": "BQUFBQUFBQUFBQUFBQUFBQ"});
        from(peer, req(Method::POST, "/handshake", None, Some(body)))
    };
    let mut statuses = Vec::new();
    for _ in 0..40 {
        statuses.push(send(&fx.app, prove("10.60.0.1")).await.0);
    }
    assert!(
        statuses[..30].iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    assert_eq!(statuses[39], StatusCode::TOO_MANY_REQUESTS);
    let ask = req(
        Method::POST,
        "/handshake/challenge",
        None,
        Some(json!({"device_id": fx.dev.id})),
    );
    let (status, _) = send(&fx.app, from("10.60.0.1", ask)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "one shared rate");
    assert_eq!(send(&fx.app, prove("10.60.0.2")).await.0, StatusCode::OK);
}

/// A client lists the minors it was built for; it uses the newest one the server also lists.
fn negotiate(client: &[u32], server: &Value) -> Option<u32> {
    let served: Vec<u32> = serde_json::from_value(server["supported_minors"].clone()).ok()?;
    client.iter().copied().filter(|m| served.contains(m)).max()
}

/// E1-05.5: a client built for N+1 talks to a server at N (it negotiates N, an unknown request
/// field is refused cleanly in the standard error model, never a panic or a 5xx), and a client
/// at N reads an N+1 answer (additive fields) because it reads only the fields it knows.
#[tokio::test]
async fn a_newer_client_talks_to_an_older_server_and_back() {
    let fx = fx().await;
    let n = super::super::types::API_MINOR;
    let (status, body) = send(&fx.app, req(Method::GET, "/handshake", None, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Client at N+1 (also built for every older minor) against server N: the common minor is N.
    let newer: Vec<u32> = (0..=n + 1).collect();
    assert_eq!(negotiate(&newer, &body), Some(n));
    // A client built only for N+1 finds no common minor: it must stop, not guess.
    assert_eq!(negotiate(&[n + 1], &body), None);

    // The N+1 client's POST /handshake carries a field this server does not know: a clean 400.
    let nonce = "BQUFBQUFBQUFBQUFBQUFBQ";
    let newer_body = json!({"nonce": nonce, "client_minor": n + 1});
    let (status, err) = send(
        &fx.app,
        req(Method::POST, "/handshake", None, Some(newer_body)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["code"], "bad_request");
    assert!(err["error_id"].is_string() && err["message"].is_string());
    // The same call without it works.
    let (status, ok) = send(
        &fx.app,
        req(
            Method::POST,
            "/handshake",
            None,
            Some(json!({"nonce": nonce})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ok}");

    // Client at N against server N+1: the answer gains fields; a reader of the known ones is fine.
    let mut future = ok.clone();
    future["supported_minors"] = json!((0..=n + 1).collect::<Vec<u32>>());
    future["a_field_from_the_future"] = json!({"x": 1});
    assert_eq!(negotiate(&(0..=n).collect::<Vec<_>>(), &future), Some(n));
    assert_eq!(future["identity_fingerprint"], ok["identity_fingerprint"]);
}
