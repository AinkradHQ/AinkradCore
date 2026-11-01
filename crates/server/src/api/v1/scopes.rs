//! Scopes (handshake spec §8, E1-09.1/.2): every authenticated route declares the one scope a
//! device needs to call it, here, and the gate refuses anything else with 403
//! `forbidden_scope` right after authentication. Deny by default: a method and path with no
//! entry (an unknown path included) is refused, so a route added without a scope cannot be
//! called, and the contract test fails on its missing `x-ainkrad-scope`.
//!
//! - `read`: what the device itself shows (its own identity and push token, events, settings).
//! - `admin`: devices, pairing, setting changes, the audit log, the metrics.
//! - `agent`: sending a runner a command (`POST /api/v1/runners/{id}/noop`).
//! - Agent sessions (E2-08): `agent`; deciding a tool call `approve`.
//! - Secrets (E2-07): managing them and granting a lease is `admin` (and destructive); the one
//!   route a `runner` device may call is redeeming a lease granted to it.
//! - `terminal`: opening, attaching, signalling and closing a terminal (listing is `read`).
//! - A module's routes need the module's own `Module::scope` (`admin` unless it says otherwise),
//!   or the scope its `Module::route_scopes` declares for that route (`module_scope`).
//! - A `runner` device holds only `runner`, which only `POST /api/v1/secret-leases/redeem`
//!   takes: it can call nothing else here (the runner hub is E1-11).
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
    ("GET", "/api/v1/push-token/kinds", "read"),
    ("PUT", "/api/v1/push-token/kinds", "read"),
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
    ("GET", "/api/v1/metrics", "admin"),
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
    ("GET", "/api/v1/secrets", "admin"),
    ("POST", "/api/v1/secrets", "admin"),
    ("PUT", "/api/v1/secrets/{id}", "admin"),
    ("DELETE", "/api/v1/secrets/{id}", "admin"),
    ("POST", "/api/v1/secrets/{id}/leases", "admin"),
    ("POST", "/api/v1/secret-leases/redeem", "runner"),
    ("GET", "/api/v1/terminals", "read"),
    ("GET", "/api/v1/terminals/{id}", "read"),
    ("POST", "/api/v1/terminals", "terminal"),
    ("GET", "/api/v1/terminals/{id}/ws", "terminal"),
    ("POST", "/api/v1/terminals/{id}/signal", "terminal"),
    ("DELETE", "/api/v1/terminals/{id}", "terminal"),
    ("GET", "/api/v1/agent-sessions", "agent"),
    ("POST", "/api/v1/agent-sessions", "agent"),
    ("GET", "/api/v1/agent-sessions/{id}", "agent"),
    ("GET", "/api/v1/agent-sessions/{id}/transcript", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/messages", "agent"),
    (
        "POST",
        "/api/v1/agent-sessions/{id}/approvals/{request}",
        "approve",
    ),
    ("POST", "/api/v1/agent-sessions/{id}/cancel", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/kill", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/resume", "agent"),
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
    // Secrets (E2-07): every write, and a lease, the only way a value leaves the Core.
    ("POST", "/api/v1/secrets"),
    ("PUT", "/api/v1/secrets/{id}"),
    ("DELETE", "/api/v1/secrets/{id}"),
    ("POST", "/api/v1/secrets/{id}/leases"),
    // Opening or attaching a terminal is a shell on the runner (spec §8, E2-01).
    ("POST", "/api/v1/terminals"),
    ("GET", "/api/v1/terminals/{id}/ws"),
    // Signalling or closing one acts on a live shell, so it needs the same step-up.
    ("POST", "/api/v1/terminals/{id}/signal"),
    ("DELETE", "/api/v1/terminals/{id}"),
    // Agent sessions (E2-08): starting one, telling it what to do and resuming it run code on
    // a runner and lease it secrets; cancelling and killing stop someone's work.
    ("POST", "/api/v1/agent-sessions"),
    ("POST", "/api/v1/agent-sessions/{id}/messages"),
    ("POST", "/api/v1/agent-sessions/{id}/cancel"),
    ("POST", "/api/v1/agent-sessions/{id}/kill"),
    ("POST", "/api/v1/agent-sessions/{id}/resume"),
    // Approval can execute a tool; a live step-up is required even for the approve scope.
    ("POST", "/api/v1/agent-sessions/{id}/approvals/{request}"),
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

/// How strict a scope is, for resolving a tie: `read` < the others < `admin`.
fn rank(scope: &str) -> u8 {
    match scope {
        "read" => 0,
        "admin" => 2,
        _ => 1,
    }
}

/// The stricter of two scopes; two different ones of the same rank (`approve` and `agent`) are
/// not comparable, so they become `admin`.
fn stricter(a: &'static str, b: &'static str) -> &'static str {
    match (a == b, rank(a).cmp(&rank(b))) {
        (true, _) => a,
        (_, std::cmp::Ordering::Greater) => a,
        (_, std::cmp::Ordering::Less) => b,
        _ => "admin",
    }
}

/// A module's request method as its tables see it: `HEAD` is the `GET` it is served by, so it
/// needs that route's scope and step-up. `None` for a method no module route takes.
fn module_method(method: &str) -> Option<&str> {
    match method {
        m if m.eq_ignore_ascii_case("HEAD") => Some("GET"),
        m if ["GET", "POST", "PUT", "PATCH", "DELETE"]
            .iter()
            .any(|k| k.eq_ignore_ascii_case(m)) =>
        {
            Some(m)
        }
        _ => None,
    }
}

/// The scope `m` needs for `method` on `sub` (relative to its prefix; a contract template or a
/// real path): its own `route_scopes` entry that fits, the most specific, else `Module::scope`.
/// Two equally specific templates that disagree resolve to the stricter scope; an entry whose
/// scope is not allowed on a module route is `admin`. `HEAD` is `GET`; a method no module route
/// takes (`OPTIONS`, `TRACE`) needs `admin`.
pub fn module_scope(m: &dyn Module, method: &str, sub: &str) -> &'static str {
    let Some(method) = module_method(method) else {
        return "admin";
    };
    let mut best: Option<(usize, &'static str)> = None;
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
            Some((b, _)) if b > n => best,
            Some((b, s)) if b == n => Some((b, stricter(s, scope))),
            _ => Some((n, scope)),
        };
    }
    best.map_or_else(|| m.scope(), |(_, scope)| scope)
}

/// Whether `m` declares `method` on `sub` destructive (`Module::destructive`); `HEAD` is `GET`,
/// and a method no module route takes counts as destructive (it needs `admin` anyway).
pub fn module_destructive(m: &dyn Module, method: &str, sub: &str) -> bool {
    let Some(method) = module_method(method) else {
        return true;
    };
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

    /// Review S3: independent of `DESTRUCTIVE`. Every state-changing route that needs `admin`,
    /// `terminal`, `agent` or `approve` is destructive, unless it is named here with the reason.
    /// A new such route nobody flags fails this test.
    #[test]
    fn every_state_changing_privileged_route_is_destructive_or_excepted() {
        const EXCEPTED: &[(&str, &str)] = &[
            // Fixed op, no input, changes nothing on the runner (see `DESTRUCTIVE`).
            ("POST", "/api/v1/runners/{id}/noop"),
        ];
        for (m, t, scope) in ROUTES {
            let privileged = matches!(*scope, "admin" | "terminal" | "agent" | "approve");
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
