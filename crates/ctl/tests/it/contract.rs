//! Every call ctl makes is in the committed contract (`api/openapi.json`) with the scope ctl
//! expects (`x-ainkrad-scope`; none for the pre-auth routes). There is no generated Rust
//! client: ctl's own types read the contract's fields, and this keeps its routes honest.

const CALLS: &[(&str, &str, Option<&str>)] = &[
    ("post", "/handshake", None),
    ("post", "/handshake/challenge", None),
    ("post", "/handshake/session", None),
    ("post", "/pair/claim", None),
    ("post", "/pair/status", None),
    ("get", "/api/v1/me", Some("read")),
    ("get", "/api/v1/events", Some("read")),
    ("get", "/api/v1/events/ws", Some("read")),
    ("get", "/api/v1/events/latest", Some("read")),
    ("get", "/api/v1/devices", Some("admin")),
    ("delete", "/api/v1/devices/{id}", Some("admin")),
    ("post", "/api/v1/pairings", Some("admin")),
    ("get", "/api/v1/pairings/{id}", Some("admin")),
    ("post", "/api/v1/pairings/{id}/approve", Some("admin")),
    ("post", "/api/v1/pairings/{id}/reject", Some("admin")),
];

#[test]
fn every_call_is_in_the_contract_with_its_scope() {
    let path = format!("{}/../../api/openapi.json", env!("CARGO_MANIFEST_DIR"));
    let api: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for (method, route, scope) in CALLS {
        let op = &api["paths"][route][method];
        assert!(op.is_object(), "{method} {route} is not in the contract");
        assert_eq!(op["x-ainkrad-scope"].as_str(), *scope, "{method} {route}");
    }
    // The fields ctl reads off the answers.
    let schema = |name: &str| api["components"]["schemas"][name]["properties"].clone();
    for (name, fields) in [
        (
            "HandshakeProof",
            &[
                "identity_fingerprint",
                "server_version",
                "api_minor",
                "core_spki",
                "core_sig",
            ][..],
        ),
        ("Challenge", &["challenge"]),
        ("SessionGrant", &["session_id", "expires_at", "scopes"]),
        ("Claimed", &["device_id", "core_spki", "pairing_id", "sas"]),
        ("PairStatus", &["status"]),
        (
            "PairingCreated",
            &["pairing_id", "code", "qr", "expires_at"],
        ),
        ("PastRetention", &["floor"]),
        ("ErrorBody", &["code", "message", "server_time"]),
    ] {
        for f in fields {
            assert!(
                schema(name)[f].is_object(),
                "{name}.{f} is not in the contract"
            );
        }
    }
}
