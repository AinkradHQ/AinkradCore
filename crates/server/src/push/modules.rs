//! A module's pushes (E2-12 hook): the module declares the notification kinds it may raise
//! (`Module::notification_kinds`) and classifies its own events (`Module::classify`); this is
//! the only place that output reaches the pusher, so the Core, not the module, decides what
//! may leave. A module's push is confined to its declared kind (`<id>.<name>`, never a platform
//! kind nor another module's), carries the scope its declaration fixes (the module cannot widen
//! it at run time), and cannot merge into another kind's bursts. It then goes through the
//! same `policy::clean` and per-token scope check as every platform push.

use std::collections::HashSet;
use std::sync::Arc;

use super::{Classifier, Notification, Platform};
use crate::module::{Module, route_scope_ok, valid_id};
use crate::store::events::StoredEvent;

/// Panics on a malformed declaration (a typo must stop the server at start): each kind is
/// `<id>.<name>`, once, with a device scope that is not `runner`; each admin command is a name.
pub(crate) fn validate(m: &dyn Module) {
    let id = m.id();
    let mut seen = HashSet::new();
    for (kind, scope) in m.notification_kinds() {
        let name = kind.strip_prefix(id).and_then(|k| k.strip_prefix('.'));
        assert!(
            name.is_some_and(|n| valid_id(&n.replace('.', "_"))),
            "module {id}: notification kind {kind:?} must be {id}.<name>"
        );
        assert!(
            route_scope_ok(scope),
            "module {id}: notification kind {kind} declares scope {scope:?}"
        );
        assert!(
            seen.insert(*kind),
            "module {id}: notification kind {kind} declared twice"
        );
    }
    let mut commands = HashSet::new();
    for name in m.admin_commands() {
        assert!(
            valid_id(name) && commands.insert(*name),
            "module {id}: admin command {name:?} is illegal or declared twice"
        );
    }
}

/// Whether `e` is one of `id`'s own events: its kind is `<id>.…`, or it is the audit row of an
/// `<id>.…` action. A module never sees (so never classifies) another's or the platform's.
fn owns(id: &str, e: &StoredEvent) -> bool {
    let of = |s: &str| s.strip_prefix(id).is_some_and(|r| r.starts_with('.'));
    of(&e.kind) || (e.kind == "audit" && e.payload.0["action"].as_str().is_some_and(of))
}

/// `n` as the module's declaration allows it, or `None` for a kind it did not declare.
fn confine(m: &dyn Module, mut n: Notification) -> Option<Notification> {
    let (_, scope) = m.notification_kinds().iter().find(|(k, _)| *k == n.kind)?;
    n.scope = scope;
    n.collapse = n.collapse.map(|c| format!("{}:{c}", n.kind));
    Some(n)
}

/// The platform's rules, then each mounted module's for its own events.
pub struct Modules(pub Arc<[Arc<dyn Module>]>);

impl Classifier for Modules {
    fn notification(&self, e: &StoredEvent) -> Option<Notification> {
        if let Some(n) = Platform.notification(e) {
            return Some(n);
        }
        self.0.iter().find_map(|m| {
            if !owns(m.id(), e) {
                return None;
            }
            let n = m.classify(e)?;
            let kind = n.kind;
            let n = confine(m.as_ref(), n);
            if n.is_none() {
                tracing::warn!(
                    module = m.id(),
                    kind,
                    "undeclared notification kind: dropped"
                );
            }
            n
        })
    }
}
