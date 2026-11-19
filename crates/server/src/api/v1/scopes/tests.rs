use super::*;

#[test]
fn templates_match_whole_segments_only() {
    let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
    assert_eq!(required(&m("GET"), "/api/v1/me", &[]), Some("read"));
    assert_eq!(
        required(&m("DELETE"), "/api/v1/devices/d_x", &[]),
        Some("admin")
    );
    assert_eq!(
        required(&m("PUT"), "/api/v1/settings/server/k", &[]),
        Some("admin")
    );
    assert_eq!(
        required(&m("GET"), "/api/v1/settings/server/k", &[]),
        Some("read")
    );
    for (method, path) in [
        ("POST", "/api/v1/me"),
        ("GET", "/api/v1/devices/"),
        ("GET", "/api/v1/devices/d_x/extra"),
        ("GET", "/api/v1/nope"),
        ("GET", "/modules/x/v1/y"),
    ] {
        assert_eq!(required(&m(method), path, &[]), None, "{method} {path}");
    }
    assert!(destructive(&m("DELETE"), "/api/v1/devices/d_x", &[]));
    assert!(!destructive(&m("GET"), "/api/v1/devices/d_x", &[]));
    assert!(!destructive(&m("DELETE"), "/api/v1/devices/d_x/y", &[]));
}

/// D-4: the danger list is exactly this, and nothing else asks Touch ID per action. A route
/// added to `DESTRUCTIVE` fails here until the decision is made again on purpose.
#[test]
fn the_danger_list_is_the_d4_list() {
    let mut have: Vec<_> = DESTRUCTIVE.to_vec();
    have.sort();
    let mut want = vec![
        ("DELETE", "/api/v1/devices/{id}"),
        ("PATCH", "/api/v1/devices/{id}"),
        ("PUT", "/api/v1/devices/{id}/scopes"),
        ("POST", "/api/v1/pairings"),
        ("POST", "/api/v1/pairings/invites"),
        ("POST", "/api/v1/pairings/{id}/approve"),
        ("POST", "/api/v1/pairings/{id}/reject"),
        ("POST", "/api/v1/auth/lockouts/clear"),
        ("POST", "/api/v1/system/restart"),
        ("GET", "/api/v1/system/logs/runner"),
        ("GET", "/api/v1/system/logs/backup"),
        ("POST", "/api/v1/secrets/{id}/reveal"),
        ("POST", "/api/v1/secrets/{id}/leases"),
        ("POST", "/api/v1/secret-groups/{id}/leases"),
    ];
    want.sort();
    assert_eq!(have, want);
    let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
    // A normal write now: an account, a project, a setting that is not a security one.
    for (method, path) in [
        ("POST", "/api/v1/accounts"),
        ("POST", "/api/v1/projects"),
        ("PUT", "/api/v1/settings/server/api.request_burst"),
    ] {
        assert!(!destructive(&m(method), path, &[]), "{method} {path}");
    }
    // A security setting is danger: it would weaken the list itself.
    assert!(destructive(
        &m("PUT"),
        "/api/v1/settings/server/auth.step_up_secs",
        &[]
    ));
    assert!(destructive(
        &m("DELETE"),
        "/api/v1/settings/server/auth.passkey_admin",
        &[]
    ));
}

/// E1-2: the routes that run code on a runner need the app unlock, not a per-action prompt; they
/// are declared routes and never also danger.
#[test]
fn code_running_routes_need_the_unlock_and_are_not_danger() {
    for (m, t) in UNLOCKED {
        assert!(declared(m, t).is_some(), "{m} {t} is not in ROUTES");
        assert!(!declared_destructive(m, t), "{m} {t} is both");
    }
    let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
    assert!(needs_unlock(&m("POST"), "/api/v1/terminals", &[]));
    assert!(needs_unlock(&m("POST"), "/api/v1/agent-sessions", &[]));
    assert!(!needs_unlock(&m("GET"), "/api/v1/terminals", &[]));
    assert!(!needs_unlock(&m("POST"), "/api/v1/accounts", &[]));
}

/// Review S5 (KAN-298): the refusal throttle keys on the template, so varying an id adds no key.
#[test]
fn a_destructive_route_is_keyed_by_its_template() {
    let m = Method::DELETE;
    for id in ["d_a", "d_b", "d_c"] {
        assert_eq!(
            destructive_template(&m, &format!("/api/v1/devices/{id}"), &[]).as_deref(),
            Some("/api/v1/devices/{id}")
        );
    }
    assert_eq!(
        destructive_template(&Method::GET, "/api/v1/devices/d_a", &[]),
        None
    );
    assert_eq!(destructive_template(&m, "/api/v1/nope/x", &[]), None);
}

#[test]
fn every_destructive_route_is_a_declared_route() {
    for (m, t) in DESTRUCTIVE {
        assert!(
            declared(m, t).is_some(),
            "{m} {t} is destructive but not in ROUTES"
        );
    }
}
