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
//! Step-up (`approve`/`terminal`/`agent` routes and elevation) is E1-09.3+.

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
];

/// Whether `path` fits `template` segment by segment.
fn fits(template: &str, path: &str) -> bool {
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
    }
}
