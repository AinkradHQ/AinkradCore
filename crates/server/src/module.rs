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
//! Deliberately not here yet: event kinds (E1-04.2), scopes (E1-09.1) and scheduler jobs
//! (E2-11). Each lands on this trait with its own
//! consumer; guessing their shape now would be speculation.

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
    fn migrations(&self) -> &'static [Migration] {
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
