//! Scopes (handshake spec §8, E1-09.1/.2): every authenticated route declares the one scope a
//! device needs to call it, here, and the gate refuses anything else with 403
//! `forbidden_scope` right after authentication. Deny by default: a method and path with no
//! entry (an unknown path included) is refused, so a route added without a scope cannot be
//! called, and the contract test fails on its missing `x-ainkrad-scope`.
//!
//! - `read`: what the device itself shows (its own identity and push token, events, settings).
//! - `admin`: devices, pairing, setting changes, the audit log.
//! - A module's routes need the module's own `Module::scope` (`admin` unless it says otherwise).
//! - A `runner` device holds only `runner`, which no `/api/v1` route takes: it can call nothing
//!   here (the runner hub is E1-11).
//!
//! **Destructive routes** (spec §8, E1-09.6) are listed in [`DESTRUCTIVE`] (a module's in
//! `Module::destructive`): on top of its scope, such a route needs a session elevated by a
//! step-up (`auth::stepup`), else 403 `step_up_required`. The contract marks each with
//! `x-ainkrad-destructive: true`. Reads never need it; the host socket's `bootstrap` and
//! `recover` are not routes and never need it.

use std::sync::Arc;

use axum::http::Method;

use crate::module::Module;

/// `(method, path template, scope)`; a `{…}` segment matches any one segment. The templates are
/// the contract's own paths.
pub const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/me", "read"),
    ("PUT", "/api/v1/push-token", "read"),
    ("DELETE", "/api/v1/push-token", "read"),
    ("GET", "/api/v1/events", "read"),
    ("GET", "/api/v1/events/ws", "read"),
    ("GET", "/api/v1/events/latest", "read"),
    ("GET", "/api/v1/settings", "read"),
    ("GET", "/api/v1/settings/{scope}", "read"),
    ("GET", "/api/v1/settings/{scope}/{key}", "read"),
    ("GET", "/api/v1/settings/{scope}/{key}/history", "read"),
    ("PUT", "/api/v1/settings/{scope}/{key}", "admin"),
    ("DELETE", "/api/v1/settings/{scope}/{key}", "admin"),
    ("GET", "/api/v1/devices", "admin"),
    ("DELETE", "/api/v1/devices/{id}", "admin"),
    ("GET", "/api/v1/audit", "admin"),
    ("POST", "/api/v1/pairings", "admin"),
    ("GET", "/api/v1/pairings/{id}", "admin"),
    ("POST", "/api/v1/pairings/{id}/approve", "admin"),
    ("POST", "/api/v1/pairings/{id}/reject", "admin"),
    ("POST", "/api/v1/auth/step-up/challenge", "read"),
    ("POST", "/api/v1/auth/step-up", "read"),
    ("GET", "/api/v1/devices/{id}", "admin"),
    ("PATCH", "/api/v1/devices/{id}", "admin"),
    ("PUT", "/api/v1/devices/{id}/scopes", "admin"),
    ("GET", "/api/v1/auth/lockouts", "admin"),
    ("POST", "/api/v1/auth/lockouts/clear", "admin"),
];

/// `(method, path template)` of every route that needs a live elevation (spec §8): device
/// admin (pairing create, approve and reject; revoke, rename, scope change; clearing a lockout)
/// and every setting write (one flag per route, and some settings weaken security, the step-up
/// window itself among them). Each must also be in [`ROUTES`] (a test checks).
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/api/v1/devices/{id}"),
    ("PATCH", "/api/v1/devices/{id}"),
    ("PUT", "/api/v1/devices/{id}/scopes"),
    ("POST", "/api/v1/pairings"),
    ("POST", "/api/v1/pairings/{id}/approve"),
    ("POST", "/api/v1/pairings/{id}/reject"),
    ("PUT", "/api/v1/settings/{scope}/{key}"),
    ("DELETE", "/api/v1/settings/{scope}/{key}"),
    ("POST", "/api/v1/auth/lockouts/clear"),
];

/// Whether `path` fits `template` segment by segment.
pub(super) fn fits(template: &str, path: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(t, p)| (t.starts_with('{') && t.ends_with('}') && !p.is_empty()) || t == p)
}

/// The scope `method` on `template` declares, by the contract's own path template.
pub fn declared(method: &str, template: &str) -> Option<&'static str> {
    ROUTES
        .iter()
        .find(|(m, t, _)| m.eq_ignore_ascii_case(method) && *t == template)
        .map(|r| r.2)
}

/// Whether `method` on `template` is declared destructive, by the contract's own path template.
pub fn declared_destructive(method: &str, template: &str) -> bool {
    DESTRUCTIVE
        .iter()
        .any(|(m, t)| m.eq_ignore_ascii_case(method) && *t == template)
}

/// Whether a request needs a live elevation: its route is in [`DESTRUCTIVE`], or in its
/// module's `Module::destructive` (relative to `/modules/<id>/v1`).
pub fn destructive(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> bool {
    if let Some(rest) = path.strip_prefix("/modules/") {
        let id = rest.split('/').next().unwrap_or_default();
        let Some(sub) = rest.strip_prefix(id).and_then(|r| r.strip_prefix("/v1")) else {
            return false;
        };
        return modules.iter().filter(|m| m.id() == id).any(|m| {
            m.destructive()
                .iter()
                .any(|(mm, t)| *mm == method.as_str() && fits(t, sub))
        });
    }
    DESTRUCTIVE
        .iter()
        .any(|(m, t)| *m == method.as_str() && fits(t, path))
}

/// The scope a request needs; `None` when nothing declares one (refused).
pub fn required(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> Option<&'static str> {
    if let Some(rest) = path.strip_prefix("/modules/") {
        let id = rest.split('/').next().unwrap_or_default();
        let under = rest.strip_prefix(id).is_some_and(|r| r.starts_with("/v1/"));
        return modules
            .iter()
            .find(|m| m.id() == id && under)
            .map(|m| m.scope());
    }
    // A WebSocket upgrade is a GET.
    ROUTES
        .iter()
        .find(|(m, t, _)| *m == method.as_str() && fits(t, path))
        .map(|r| r.2)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn every_destructive_route_is_a_declared_route() {
        for (m, t) in DESTRUCTIVE {
            assert!(
                declared(m, t).is_some(),
                "{m} {t} is destructive but not in ROUTES"
            );
        }
    }
}
