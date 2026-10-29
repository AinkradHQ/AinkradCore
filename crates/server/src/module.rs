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
//! A module's routes need its one `scope` (`admin` unless it declares another; per-route scopes
//! come when a module needs them); the ones that need a step-up are its `destructive` routes.
//! Scheduler jobs (E2-11) are not here yet.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Router;

use crate::api::App;
use crate::store::Migration;

/// A backend module mounted on the Core.
pub trait Module: Send + Sync + 'static {
    /// Stable lowercase id: the route prefix `/modules/<id>/v1`, the migration namespace and
    /// the table prefix `<id>_`. Letters, digits and `_`, starting with a letter.
    fn id(&self) -> &'static str;

    /// The module's routes, relative to its prefix.
    fn routes(&self) -> Router<App>;

    /// The module's migrations, oldest first (`crate::store::migrate::migrate_modules`).
    /// `serve` mounts no module yet; whoever mounts the first must run `migrate_modules`
    /// before `mount`, so a refused migration or id stops the start.
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

    /// `(method, path template)` of the module's routes that need a live step-up elevation
    /// (`api::v1::scopes::destructive`), relative to `/modules/<id>/v1`, e.g.
    /// `("POST", "/runs/{id}/kill")`. None by default.
    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }
}

/// Whether `id` is a legal module id.
pub(crate) fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
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
