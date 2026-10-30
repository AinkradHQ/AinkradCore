//! The seam between the platform and the modules built on it (E1-02.2): Citadel is the first,
//! `ops` (the no-op command) the second. A module is a backend crate that depends on the
//! platform; the platform never depends on a module.
//!
//! A module's routes live under `/modules/<id>/v1` and are mounted **inside** the client API's
//! gate, so a module never does its own authentication: by the time a handler runs, host,
//! origin, rate limits and the device key have been checked, and `Device` and `Client` are in
//! the request extensions.
//!
//! A module's migrations run in their own namespace, after the platform's, and may touch only
//! its own `<id>_` tables (`crate::store::migrate`).
//!
//! A module declares the event kinds it emits and the audit actions it records
//! (`crate::store::kinds`, E1-04.2, E1-10.2): each starts with `<id>.`. `migrate_modules`
//! registers them; an event or audit row of an undeclared name is refused at append.
//!
//! A module's routes need its `scope` (`admin` unless it declares another), or the narrower
//! per-route scope it declares in `route_scopes` (a phone that only reads may call the routes
//! that declare `read`); the ones that need a step-up are its `destructive` routes. A route's
//! scope is looked up in the module's own table only, relative to its own prefix, so a module
//! cannot declare scopes for another module's or the platform's routes, and a route it does not
//! list keeps the module-wide scope (deny by default).
//! Its OpenAPI paths (`openapi`) are merged into the Core contract under `/modules/<id>/v1`, and
//! its tunables (`settings`) live in the Core's settings store under its own namespace.
//! Its scheduler jobs (E2-11) are `Module::jobs`: appended to the trait, so a module written
//! before it keeps compiling.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Router;

use crate::api::App;
use crate::store::Migration;

/// One tunable a module declares (`Module::settings`): an integer with a default and bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleSetting {
    /// Lowercase letters, digits, `_` and `.`, starting with a letter.
    pub name: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    pub description: &'static str,
}

/// A backend module mounted on the Core.
pub trait Module: Send + Sync + 'static {
    /// Stable lowercase id: the route prefix `/modules/<id>/v1`, the migration namespace and
    /// the table prefix `<id>_`. Letters, digits and `_`, starting with a letter.
    fn id(&self) -> &'static str;

    /// The module's routes, relative to its prefix.
    fn routes(&self) -> Router<App>;

    /// The module's migrations, oldest first (`crate::store::migrate::migrate_modules`).
    /// `serve --enable-module <id>` (`cli`) runs `migrate_modules` before `mount`, so a refused
    /// migration or id stops the start.
    fn migrations(&self) -> &'static [Migration] {
        &[]
    }

    /// The event kinds the module emits, each `<id>.<…>` (`crate::store::kinds`).
    fn event_kinds(&self) -> &'static [&'static str] {
        &[]
    }

    /// The scope a device needs to see the module's event `kind` in its stream
    /// (`store::events::view`): one of `read`, `approve`, `terminal`, `agent`, `admin`. The
    /// module's route scope unless it says otherwise.
    fn event_scope(&self, _kind: &str) -> &'static str {
        self.scope()
    }

    /// The audit actions the module records, each `<id>.<…>`.
    fn audit_actions(&self) -> &'static [&'static str] {
        &[]
    }

    /// The scope a device needs for any of the module's routes (`api::v1::scopes`).
    fn scope(&self) -> &'static str {
        "admin"
    }

    /// Per-route scopes: `(method, path template, scope)`, templates relative to
    /// `/modules/<id>/v1` as in `destructive`. A route listed here needs that scope instead of
    /// [`scope`](Self::scope); one that is not listed keeps `scope()`. When several templates fit
    /// a path the one with the most literal segments wins, and two equally specific templates that disagree resolve to the stricter scope. `HEAD` takes its `GET`'s scope and step-up.
    /// `runner` is never allowed on a module route (the runner hub is not a module route): a
    /// route that declares it needs `admin`. Checked by `valid_route_scopes` at `mount`.
    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        &[]
    }

    /// Query parameter names the module's routes take besides the platform's (`api::v1::QUERY`:
    /// paging and filters). Any other name is a 400 at the gate, so a key never ends up in a URL.
    /// Names that carry a secret (`token`, `key`, ...) are refused at `mount`.
    fn query_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// The module's OpenAPI document (utoipa's `OpenApi::openapi()` as JSON) with paths relative
    /// to `/modules/<id>/v1`, or `null` for none. The Core merges its paths and schemas into the
    /// contract: every `x-ainkrad-scope` / `x-ainkrad-destructive` is set by the Core from
    /// `route_scopes` / `scope` / `destructive` (any the module wrote is dropped), `security` is
    /// forced to the platform's, operation ids and schema names must be unique across the
    /// contract (a clash stops the contract, never merges silently).
    fn openapi(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// The tunables the module owns (`store::modsettings`), stored in the platform's settings
    /// table as `module.<id>.<name>` and readable by the module only by the names it declares.
    fn settings(&self) -> &'static [ModuleSetting] {
        &[]
    }

    /// `(method, path template)` of the module's routes that need a live step-up elevation
    /// (`api::v1::scopes::destructive`), relative to `/modules/<id>/v1`, e.g.
    /// `("POST", "/runs/{id}/kill")`. None by default.
    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// The scheduler jobs the module declares (E2-11), recorded at start by `jobs::register`
    /// and run by the `jobs::Engine`. None by default. A job's name is unique within the module.
    fn jobs(&self) -> Vec<crate::jobs::Job> {
        Vec::new()
    }
}

/// Whether `id` is a legal module id.
pub(crate) fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `scope` may be declared for a module route: a device scope, but never `runner`.
pub(crate) fn route_scope_ok(scope: &str) -> bool {
    scope != "runner" && crate::store::gov::SCOPES.contains(&scope)
}

/// Whether `template` is a legal module route template: absolute, no `..`/`.`/empty segments,
/// no query, fragment or backslash, and `{name}` only as a whole segment.
fn legal_template(template: &str) -> bool {
    template.starts_with('/')
        && !template.contains(['?', '#', '\\'])
        && template.split('/').skip(1).all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && (!s.contains(['{', '}']) || (s.starts_with('{') && s.ends_with('}')))
        })
}

/// Refuses (panics on) a module whose declared scopes, routes or settings are malformed. A
/// declaration error must stop the server at start, not weaken a gate at the first request.
pub(crate) fn validate(m: &dyn Module) {
    let id = m.id();
    assert!(
        route_scope_ok(m.scope()),
        "module {id}: scope {:?}",
        m.scope()
    );
    let mut seen = HashSet::new();
    for (method, template, scope) in m.route_scopes() {
        assert!(
            matches!(*method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE"),
            "module {id}: bad method {method:?}"
        );
        assert!(
            legal_template(template),
            "module {id}: bad route template {template:?}"
        );
        assert!(
            route_scope_ok(scope),
            "module {id}: route {method} {template} declares scope {scope:?}"
        );
        assert!(
            seen.insert((*method, *template)),
            "module {id}: route {method} {template} declared twice"
        );
    }
    for q in m.query_names() {
        let secret = [
            "token",
            "key",
            "secret",
            "password",
            "signature",
            "auth",
            "credential",
        ];
        assert!(
            valid_id(q) && !secret.iter().any(|w| q.contains(w)),
            "module {id}: query name {q:?} is not allowed"
        );
    }
    let mut step_up = HashSet::new();
    for (method, template) in m.destructive() {
        assert!(
            matches!(*method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE"),
            "module {id}: bad destructive method {method:?}"
        );
        assert!(
            legal_template(template),
            "module {id}: bad destructive template {template:?}"
        );
        assert!(
            step_up.insert((*method, *template)),
            "module {id}: destructive {method} {template} declared twice"
        );
    }
    // Against the module's real routes: a typo must stop the server at start, never silently
    // leave a route without its step-up (or a scope entry dead). Checked when the module
    // documents its routes (`openapi`).
    let doc = m.openapi();
    if let Some(paths) = doc["paths"].as_object() {
        let has = |method: &str, template: &str| {
            paths.get(template).is_some_and(|item| {
                item.as_object()
                    .is_some_and(|o| o.keys().any(|k| k.eq_ignore_ascii_case(method)))
            })
        };
        for (method, template) in m.destructive() {
            assert!(
                has(method, template),
                "module {id}: destructive {method} {template} matches no documented route"
            );
        }
        for (method, template, _) in m.route_scopes() {
            assert!(
                has(method, template),
                "module {id}: route scope {method} {template} matches no documented route"
            );
        }
    }
    let mut names = HashSet::new();
    for s in m.settings() {
        let legal = valid_id(s.name.replace('.', "_").as_str());
        assert!(
            legal && s.min <= s.default && s.default <= s.max,
            "module {id}: bad setting {:?}",
            s.name
        );
        assert!(
            names.insert(s.name),
            "module {id}: setting {:?} declared twice",
            s.name
        );
    }
}

/// Every module's routes, each nested under `/modules/<id>/v1`.
///
/// # Panics
///
/// On an illegal or duplicate id: that is a programming error, and it must stop the server at
/// start, not at the first request.
pub fn mount(modules: &[Arc<dyn Module>]) -> Router<App> {
    let mut seen = HashSet::new();
    modules.iter().fold(Router::new(), |router, module| {
        let id = module.id();
        assert!(valid_id(id), "illegal module id {id:?}");
        assert!(seen.insert(id), "duplicate module id {id:?}");
        validate(module.as_ref());
        router.nest(&format!("/modules/{id}/v1"), module.routes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Named(&'static str);

    impl Module for Named {
        fn id(&self) -> &'static str {
            self.0
        }

        fn routes(&self) -> Router<App> {
            Router::new()
        }
    }

    fn mounted(ids: &[&'static str]) {
        let modules: Vec<Arc<dyn Module>> = ids.iter().map(|id| Arc::new(Named(id)) as _).collect();
        let _router = mount(&modules);
    }

    #[test]
    fn legal_ids_mount() {
        mounted(&["ops", "citadel", "mail_2"]);
    }

    #[test]
    fn illegal_ids_are_refused() {
        for id in ["", "Ops", "2ops", "ops-x", "ops/x", "ö"] {
            assert!(
                std::panic::catch_unwind(|| mounted(&[id])).is_err(),
                "{id:?} must be refused"
            );
        }
    }

    #[test]
    #[should_panic(expected = "duplicate module id")]
    fn duplicate_ids_are_refused() {
        mounted(&["ops", "ops"]);
    }
}
