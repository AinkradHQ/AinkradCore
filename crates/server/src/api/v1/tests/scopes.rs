//! Scopes over the whole contract (handshake spec §8, §17.11, E1-09.1/.2): every authenticated
//! operation declares one, a `read` device and a `runner` device get 403 on every `admin`
//! operation, a runner on every operation, and the admin device on none.

use super::*;

/// Every authenticated operation of the contract: method, a concrete path, its scope.
fn operations() -> Vec<(Method, String, String)> {
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut ops = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if op["security"] == json!([{}]) {
                continue;
            }
            let scope = op["x-ainkrad-scope"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} declares no x-ainkrad-scope"))
                .to_owned();
            assert!(
                crate::store::gov::SCOPES.contains(&scope.as_str()),
                "{scope}"
            );
            let uri = path
                .replace("{id}", "d_00000000000000000000000000")
                .replace("{scope}", "server")
                .replace("{key}", "api.request_burst");
            ops.push((method.to_uppercase().parse().unwrap(), uri, scope));
        }
    }
    ops
}

#[test]
fn every_authenticated_operation_declares_a_scope() {
    let ops = operations();
    assert!(ops.len() >= 15, "{} operations", ops.len());
    assert!(ops.iter().any(|o| o.2 == "admin") && ops.iter().any(|o| o.2 == "read"));
}

#[tokio::test]
async fn read_and_runner_devices_are_refused_what_their_scopes_do_not_allow() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    let reader = fx.enroll("phone", &["read", "approve"]).await;
    let runner = TestDevice::enroll(
        &fx.app.pool,
        "runner",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let s = fx.app.auth.issue_session(&runner.id, fx.clock.unix());
    runner.set_session(Some(s.id));
    let body =
        |m: &Method| (*m == Method::PUT).then(|| json!({"value": 120, "token": "0a".repeat(32)}));
    let (mut admin_ops, mut checked) = (0, 0);
    for (m, uri, scope) in operations() {
        let as_ = |dev| req(m.clone(), &uri, Some(dev), body(&m));
        let refused = |r: (StatusCode, Value)| {
            r.0 == StatusCode::FORBIDDEN && r.1["code"] == "forbidden_scope"
        };
        let r = send(&fx.app, as_(&runner)).await;
        assert!(refused(r.clone()), "runner {m} {uri}: {r:?}");
        let r = send(&fx.app, as_(&reader)).await;
        assert_eq!(
            refused(r.clone()),
            scope == "admin",
            "read {m} {uri}: {r:?}"
        );
        let r = send(&fx.app, as_(&fx.dev)).await;
        assert!(!refused(r.clone()), "admin {m} {uri}: {r:?}");
        admin_ops += usize::from(scope == "admin");
        checked += 1;
    }
    assert!(
        admin_ops >= 5 && checked >= 15,
        "{admin_ops} admin of {checked}"
    );
    // The runner cannot read the event stream or the audit log, nor revoke anyone.
    for uri in ["/api/v1/events", "/api/v1/audit", "/api/v1/events/latest"] {
        let (s, _) = send(&fx.app, req(Method::GET, uri, Some(&runner), None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{uri}");
    }
    let uri = format!("/api/v1/devices/{}", fx.dev.id);
    let (s, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&runner), None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&reader), None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        fx.ok("/api/v1/me").await["device"]["id"],
        fx.dev.id.as_str(),
        "still active"
    );
}
