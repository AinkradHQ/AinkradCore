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

/// Review S3: independent of `DESTRUCTIVE`. Every state-changing route whose scope is not
/// `read` or `runner` is destructive, unless it is named here with the reason. The list is
/// inverted on purpose: a new scope is covered without anyone remembering to add it here.
#[test]
fn every_state_changing_privileged_route_is_destructive_or_excepted() {
    const EXCEPTED: &[(&str, &str)] = &[
        // Fixed op, no input, changes nothing on the runner (see `DESTRUCTIVE`).
        ("POST", "/api/v1/runners/{id}/noop"),
        // One fixed, free request to the host the key was bound to when it was stored, through
        // a runner in the key's scope (design 2026-11-04 section 5.2 says it is not
        // destructive); its only effect is the account's last-test record.
        ("POST", "/api/v1/accounts/{id}/test"),
        // The caller's own sign-in: a cancel grants nothing, a code acts once on one a step-up began.
        ("DELETE", "/api/v1/accounts/logins/{id}"),
        ("POST", "/api/v1/accounts/logins/{id}/code"),
        // One fixed request with the connection's own credential; its only effect is the test
        // record and the health it decides (like an account's test).
        ("POST", "/api/v1/connections/{id}/test"),
        // The caller's own sign-in, which a step-up began: a cancel grants nothing, the redirect
        // and the site choice finish that one flow (state-checked, once), as a login code does.
        ("DELETE", "/api/v1/connections/flows/{id}"),
        ("POST", "/api/v1/connections/flows/{id}/callback"),
        ("POST", "/api/v1/connections/flows/{id}/choose"),
    ];
    for (m, t, scope) in ROUTES {
        let privileged = !matches!(*scope, "read" | "runner");
        let writes = *m != "GET";
        // A terminal socket is a GET but is a live shell.
        let shell = t.ends_with("/terminals/{id}/ws");
        if !(privileged && (writes || shell)) {
            continue;
        }
        assert!(
            declared_destructive(m, t) || EXCEPTED.contains(&(*m, *t)),
            "{m} {t} ({scope}) changes state but is neither destructive nor excepted"
        );
    }
    for e in EXCEPTED {
        assert!(
            !declared_destructive(e.0, e.1),
            "{e:?} is excepted but listed"
        );
    }
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
