//! The ambient origin of an audit row (E1): what started the work being done, carried by a task
//! local so no write path can forget it and no caller has to pass it down. The request gate
//! scopes a person's request, the job engine a scheduled run, a module (Brain) narrows it, and
//! work with no scope is the Core's own (`system`). Task locals do not cross `tokio::spawn`: a
//! spawn that outlives its request re-scopes with [`scope`] or its rows read `system`.

use std::future::Future;

use ainkrad_core::audit::{AuditOrigin, OriginKind};

tokio::task_local! {
    static CURRENT: AuditOrigin;
}

/// The origin now in force: the scoped one, else `system`.
pub fn current() -> AuditOrigin {
    CURRENT
        .try_with(Clone::clone)
        .unwrap_or_else(|_| AuditOrigin::new(OriginKind::System, None))
}

/// Runs `fut` with `origin` in force.
pub fn scope<F: Future>(origin: AuditOrigin, fut: F) -> impl Future<Output = F::Output> {
    CURRENT.scope(origin, fut)
}

/// `kind` carried on from the origin now in force, keeping its root.
pub fn derived(kind: OriginKind, reference: Option<String>) -> AuditOrigin {
    match CURRENT.try_with(|o| o.then(kind, reference.clone())) {
        Ok(o) => o,
        Err(_) => AuditOrigin::new(kind, reference),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unscoped_is_system_and_a_derived_link_keeps_the_root() {
        assert_eq!(current().kind, OriginKind::System);
        let p = AuditOrigin::new(OriginKind::Person, Some("d_1".into()));
        scope(p, async {
            let d = derived(OriginKind::BrainImport, None);
            assert_eq!(d.kind, OriginKind::BrainImport);
            assert_eq!(d.root_kind, OriginKind::Person);
            assert_eq!(d.root_reference.as_deref(), Some("d_1"));
        })
        .await;
        // Nothing to carry on from: the new link is its own root.
        assert_eq!(
            derived(OriginKind::BrainDistil, None).root_kind,
            OriginKind::BrainDistil
        );
    }
}
