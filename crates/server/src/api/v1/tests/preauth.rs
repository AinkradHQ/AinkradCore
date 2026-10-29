//! The pre-auth surface (E1-06.4): without a key, only `/handshake`, pairing and `/healthz`
//! answer; every other path and method, in the contract or not, gets the same 401 before
//! routing. `/handshake` (E1-05.5) answers without a key and says nothing else.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{HOST, fx, req, send};
use crate::api::limit::Limiter;
use crate::api::router;
use crate::api::v1::Limits;
use crate::gateway::preauth::allowed;

const METHODS: [Method; 5] = [
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::PATCH,
];

/// Paths that are not in the contract: lookalikes, case and slash games, traversal, the ACME
/// path on the main listener, and the authenticated `startPairing` next to `pairDevice`.
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
    "/api/v1/devices/pairX",
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
async fn only_the_allowed_prefixes_answer_without_a_key() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(100_000, 1.0),
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
    let (mut refused, mut open) = (0, Vec::new());
    for path in &paths {
        for m in METHODS {
            let (status, body) = send(&fx.app, req(m.clone(), path, None, None)).await;
            if allowed(path) {
                assert_ne!(status, StatusCode::UNAUTHORIZED, "{m} {path}: {body}");
                open.push(format!("{m} {path} {}", status.as_u16()));
                continue;
            }
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{m} {path}: {body}");
            assert_eq!(body["code"], "unauthorized", "{m} {path}");
            assert_eq!(body["message"], "missing device key", "{m} {path}");
            refused += 1;
        }
    }
    assert!(in_contract >= 15, "{in_contract} contract paths");
    // Under the allowed prefixes, only `GET /handshake` succeeds without a key (pairing
    // wants a body); `/handshake/../api/v1/me` is not normalised into the API: a 404.
    let ok: Vec<&String> = open.iter().filter(|o| o.ends_with(" 200")).collect();
    assert_eq!(ok, ["GET /handshake 200"], "{open:#?}");
    assert!(
        open.contains(&"GET /handshake/../api/v1/me 404".to_owned()),
        "{open:#?}"
    );
    assert_eq!(open.len(), 3 * METHODS.len(), "{open:#?}");
    assert_eq!(refused + open.len(), paths.len() * METHODS.len());

    // `/healthz`: `ok`, and nothing about the server.
    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, "/healthz", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(&to_bytes(res.into_body(), 64).await.unwrap()[..], b"ok");

    // A bogus key does not open the router either: unknown paths stay 401, not 404.
    let (status, _) = send(
        &fx.app,
        req(Method::GET, "/nope", Some("cit_device_x"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // With a live key, the client gate is what it was: an unknown path is a 404.
    let (status, _) = send(&fx.app, req(Method::GET, "/nope", Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

    let big = json!({"code": "ABCDEF", "name": "x".repeat(20 * 1024)});
    let (status, body) = send(
        &fx.app,
        req(Method::POST, "/api/v1/devices/pair", None, Some(big)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["code"], "too_large");
}

#[tokio::test]
async fn the_handshake_answers_without_a_key_and_leaks_nothing_else() {
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
        Value::Null,
        "no identity key before E1-07"
    );
    // Nothing about devices: the only device's name and key are not in it.
    assert!(!body.to_string().contains("test") && !body.to_string().contains(&fx.key));
}
