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

use std::any::Any;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::routing::MethodRouter;
pub use zeroize::Zeroizing;

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

/// A boxed future, so the hooks below stay object-safe.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One route a module lets a bearer token reach **without a device signature**
/// (`Module::token_routes`). It is served at `/token/<module id>/v1<template>` by its own gate
/// (`gateway::token`); nothing in the signed gate's scope tables is involved or loosened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRoute {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// Absolute, relative to `/token/<id>/v1`; `{name}` only as a whole segment.
    pub template: &'static str,
    /// The most body bytes the route reads, `1..=MAX_TOKEN_BODY`; a larger one is a 413.
    pub max_body: usize,
}

/// The largest `TokenRoute::max_body`.
pub const MAX_TOKEN_BODY: usize = 1024 * 1024;

/// Who a verified bearer token is, as the module understands it: handed to the handler as an
/// extension (`TokenPrincipal`), and keyed in the per-principal rate limit by `key`.
#[derive(Clone)]
pub struct TokenGrant {
    /// What the module's handlers read back with `downcast_ref`.
    pub principal: Arc<dyn Any + Send + Sync>,
    /// A short stable name of the principal for the rate limit (`run:12`); never the token.
    pub key: String,
}

/// The verified principal of a token request (`Module::verify_token`), in the request's extensions.
#[derive(Clone)]
pub struct TokenPrincipal(pub Arc<dyn Any + Send + Sync>);

/// A value a module hands a session's runner at launch (`Module::credentials`): delivered like a
/// broker lease, held in the Core's memory only until redeemed, never stored or logged.
pub struct Credential {
    /// The variable name the runner delivers it under (`secrets::valid_var`).
    pub var: String,
    pub value: Zeroizing<String>,
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

    /// The module's writes (POST, PUT, PATCH, DELETE) that deliberately need no step-up. `None`
    /// (the default) leaves the classification unchecked. `Some(list)` makes `mount` refuse the
    /// module unless every documented write is in `destructive` XOR this list, so a new write
    /// cannot default silently to "no step-up".
    fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
        None
    }

    /// The scheduler jobs the module declares (E2-11), recorded at start by `jobs::register`
    /// and run by the `jobs::Engine`. None by default. A job's name is unique within the module.
    fn jobs(&self) -> Vec<crate::jobs::Job> {
        Vec::new()
    }

    /// The routes a bearer token reaches without a device signature, listed (deny by default:
    /// none). The Core builds the module's token router from this list and `token_handler`, so
    /// the list is the whole unsigned surface of the module; `mount` validates it.
    fn token_routes(&self) -> &'static [TokenRoute] {
        &[]
    }

    /// The handler of a declared token route (`None` for a route it did not declare).
    fn token_handler(&self, _method: &str, _template: &str) -> Option<MethodRouter<App>> {
        None
    }

    /// Checks `token` (a bearer as sent; never logged) for a request on one of the module's
    /// token routes. `None` refuses it, whatever the reason: the caller answers one identical 401.
    fn verify_token<'a>(
        &'a self,
        _app: &'a App,
        _token: &'a str,
    ) -> BoxFut<'a, Option<TokenGrant>> {
        Box::pin(async { None })
    }

    /// Credentials for the agent session `session` this module owns, minted fresh at every
    /// launch (start and resume). `Err` fails the launch with that reason (never a value).
    fn credentials<'a>(
        &'a self,
        _app: &'a App,
        _session: &'a crate::store::agents::Session,
    ) -> BoxFut<'a, Result<Vec<Credential>, String>> {
        Box::pin(async { Ok(Vec::new()) })
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
        if let Some(plain) = m.non_destructive() {
            let listed = |list: &[(&str, &str)], method: &str, template: &str| {
                list.iter()
                    .any(|(m2, t2)| m2.eq_ignore_ascii_case(method) && *t2 == template)
            };
            for (method, template) in plain {
                assert!(
                    has(method, template),
                    "module {id}: non-destructive {method} {template} matches no documented route"
                );
                assert!(
                    !listed(m.destructive(), method, template),
                    "module {id}: {method} {template} is both destructive and non-destructive"
                );
            }
            for (template, item) in paths {
                for method in item.as_object().into_iter().flat_map(|o| o.keys()) {
                    let write = ["post", "put", "patch", "delete"]
                        .iter()
                        .any(|w| method.eq_ignore_ascii_case(w));
                    assert!(
                        !write
                            || listed(m.destructive(), method, template)
                            || listed(plain, method, template),
                        "module {id}: write {method} {template} is not classified: add it to \
                         destructive or non_destructive"
                    );
                }
            }
        }
    }
    let mut token = HashSet::new();
    for r in m.token_routes() {
        assert!(
            matches!(r.method, "GET" | "POST"),
            "module {id}: bad token route method {:?}",
            r.method
        );
        assert!(
            legal_template(r.template),
            "module {id}: bad token route template {:?}",
            r.template
        );
        assert!(
            (1..=MAX_TOKEN_BODY).contains(&r.max_body),
            "module {id}: token route {} body cap {}",
            r.template,
            r.max_body
        );
        assert!(
            token.insert((r.method, r.template)),
            "module {id}: token route {} {} declared twice",
            r.method,
            r.template
        );
        assert!(
            m.token_handler(r.method, r.template).is_some(),
            "module {id}: token route {} {} has no handler",
            r.method,
            r.template
        );
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

/// Every module's token routes, each at `/token/<id>/v1<template>`, built from the declared list
/// only (`Module::token_routes`): a handler the module does not declare is never mounted. They
/// are reached only through the token gate (`gateway::token`), which checks the declaration again.
pub fn mount_token(modules: &[Arc<dyn Module>]) -> Router<App> {
    modules.iter().fold(Router::new(), |router, module| {
        let id = module.id();
        module.token_routes().iter().fold(router, |router, r| {
            match module.token_handler(r.method, r.template) {
                Some(handler) => router.route(&format!("/token/{id}/v1{}", r.template), handler),
                None => router,
            }
        })
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

    /// A module that documents one POST and classifies `listed`.
    struct Writes {
        listed: &'static [(&'static str, &'static str)],
        step_up: &'static [(&'static str, &'static str)],
    }

    impl Module for Writes {
        fn id(&self) -> &'static str {
            "writes"
        }

        fn routes(&self) -> Router<App> {
            Router::new()
        }

        fn openapi(&self) -> serde_json::Value {
            serde_json::json!({"paths": {"/a": {"post": {}, "get": {}}}})
        }

        fn destructive(&self) -> &'static [(&'static str, &'static str)] {
            self.step_up
        }

        fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
            Some(self.listed)
        }
    }

    #[test]
    fn a_classified_write_mounts() {
        validate(&Writes {
            listed: &[("POST", "/a")],
            step_up: &[],
        });
        validate(&Writes {
            listed: &[],
            step_up: &[("POST", "/a")],
        });
    }

    #[test]
    #[should_panic(expected = "is not classified")]
    fn an_unclassified_write_is_refused() {
        validate(&Writes {
            listed: &[],
            step_up: &[],
        });
    }

    #[test]
    #[should_panic(expected = "both destructive and non-destructive")]
    fn a_write_cannot_be_both() {
        validate(&Writes {
            listed: &[("POST", "/a")],
            step_up: &[("POST", "/a")],
        });
    }

    #[test]
    #[should_panic(expected = "matches no documented route")]
    fn a_dead_non_destructive_entry_is_refused() {
        validate(&Writes {
            listed: &[("POST", "/a"), ("PUT", "/b")],
            step_up: &[],
        });
    }
}
