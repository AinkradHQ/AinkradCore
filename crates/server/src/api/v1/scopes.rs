//! Scopes (handshake spec §8, E1-09.1/.2): every authenticated route declares the one scope a
//! device needs to call it, here, and the gate refuses anything else with 403
//! `forbidden_scope` right after authentication. Deny by default: a method and path with no
//! entry (an unknown path included) is refused, so a route added without a scope cannot be
//! called, and the contract test fails on its missing `x-ainkrad-scope`.
//!
//! - `read`: what the device itself shows (its own identity and push token, events, settings).
//! - `admin`: devices, pairing, setting changes, the audit log.
//! - `agent`: sending a runner a command (`POST /api/v1/runners/{id}/noop`).
//! - A module's routes need the module's own `Module::scope` (`admin` unless it says otherwise),
//!   or the scope its `Module::route_scopes` declares for that route (`module_scope`).
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
    ("POST", "/api/v1/ws-ticket", "read"),
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
    ("GET", "/api/v1/runners", "read"),
    ("GET", "/api/v1/runners/{id}", "read"),
    ("POST", "/api/v1/runners/{id}/noop", "agent"),
];

/// `(method, path template)` of every route that needs a live elevation (spec §8): device
/// admin (pairing create, approve and reject; revoke, rename, scope change; clearing a lockout)
/// and every setting write (one flag per route, and some settings weaken security, the step-up
/// window itself among them). Each must also be in [`ROUTES`] (a test checks).
///
/// `POST /api/v1/runners/{id}/noop` is not here: it runs one fixed op that takes no input,
/// reads nothing and changes nothing on the runner (it proves the path), so it needs `agent`
/// but no elevation. A route that runs caller-chosen commands on a runner (`exec.run`, E2) is
/// arbitrary code execution there and must be listed.
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

/// `("citadel", "/companies/x")` of `/modules/citadel/v1/companies/x`; `None` for a path that
/// is not under a module's `/v1/` (the module's id is the segment right after `/modules/`).
fn module_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/modules/")?;
    let (id, sub) = rest.split_once('/')?;
    let sub = sub.strip_prefix("v1")?;
    (sub.starts_with('/')).then_some((id, sub))
}

/// Whether every name of `query` is allowed on a module route: a platform name
/// (`super::QUERY`) or one the path's module declares in `Module::query_names`. Never true for
/// a path outside `/modules/<id>/v1`, nor for another module's names.
pub fn module_query_ok(modules: &[Arc<dyn Module>], path: &str, query: &str) -> bool {
    let Some((id, _)) = module_path(path) else {
        return false;
    };
    let Some(m) = modules.iter().find(|m| m.id() == id) else {
        return false;
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split('=').next().unwrap_or(pair))
        .all(|n| super::QUERY.contains(&n) || m.query_names().contains(&n))
}

/// The segments of `template` that are not `{…}`: how specific it is.
fn literals(template: &str) -> usize {
    template.split('/').filter(|s| !s.starts_with('{')).count()
}

/// The scope `m` needs for `method` on `sub` (relative to its prefix; a contract template or a
/// real path): its own `route_scopes` entry that fits, the most specific, else `Module::scope`.
/// A tie between two different templates, or an entry whose scope is not allowed on a module
/// route, is not guessed: the first falls back to the module-wide scope, the second to `admin`.
pub fn module_scope(m: &dyn Module, method: &str, sub: &str) -> &'static str {
    let mut best: Option<(usize, &'static str, bool)> = None;
    for (mm, t, scope) in m.route_scopes() {
        if !mm.eq_ignore_ascii_case(method) || !fits(t, sub) {
            continue;
        }
        let n = literals(t);
        let scope = if crate::module::route_scope_ok(scope) {
            *scope
        } else {
            "admin"
        };
        best = match best {
            Some((b, _, _)) if b > n => best,
            Some((b, s, _)) if b == n => Some((b, s, true)),
            _ => Some((n, scope, false)),
        };
    }
    match best {
        Some((_, scope, false)) => scope,
        _ => m.scope(),
    }
}

/// Whether `m` declares `method` on `sub` destructive (`Module::destructive`).
pub fn module_destructive(m: &dyn Module, method: &str, sub: &str) -> bool {
    m.destructive()
        .iter()
        .any(|(mm, t)| mm.eq_ignore_ascii_case(method) && fits(t, sub))
}

/// Whether a request needs a live elevation: its route is in [`DESTRUCTIVE`], or in its
/// module's `Module::destructive` (relative to `/modules/<id>/v1`).
pub fn destructive(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> bool {
    if path.starts_with("/modules/") {
        let Some((id, sub)) = module_path(path) else {
            return false;
        };
        return modules
            .iter()
            .filter(|m| m.id() == id)
            .any(|m| module_destructive(m.as_ref(), method.as_str(), sub));
    }
    DESTRUCTIVE
        .iter()
        .any(|(m, t)| *m == method.as_str() && fits(t, path))
}

/// The scope a request needs; `None` when nothing declares one (refused).
pub fn required(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> Option<&'static str> {
    if path.starts_with("/modules/") {
        let (id, sub) = module_path(path)?;
        return modules
            .iter()
            .find(|m| m.id() == id)
            .map(|m| module_scope(m.as_ref(), method.as_str(), sub));
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
