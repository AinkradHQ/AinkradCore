//! Sync leases and what the hub keeps for them (E15-2, spec 7).

use std::collections::HashMap;
use std::sync::Mutex;

struct Lease {
    device: String,
    project: i64,
    scope: String,
    expires: i64,
}

/// The sync leases a Core process has handed out.
#[derive(Default)]
pub struct Leases(Mutex<HashMap<String, Lease>>);

impl Leases {
    /// A new lease `l_…` for `device` to work on `project` for `scope` (a job or session id),
    /// valid `ttl` seconds from `now`.
    pub fn issue(&self, device: &str, project: i64, scope: &str, ttl: i64, now: i64) -> String {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).expect("the system random source");
        let id = format!(
            "l_{}",
            raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let mut all = self.0.lock().unwrap();
        all.retain(|_, l| l.expires > now);
        all.insert(
            id.clone(),
            Lease {
                device: device.to_owned(),
                project,
                scope: scope.to_owned(),
                expires: now + ttl,
            },
        );
        id
    }

    /// The scope of `lease` when it is live and belongs to exactly this device and project; any
    /// other case is `None`, and the caller answers the same 404 whatever the reason.
    pub fn check(&self, lease: &str, device: &str, project: i64, now: i64) -> Option<String> {
        let all = self.0.lock().unwrap();
        let l = all.get(lease)?;
        (l.device == device && l.project == project && l.expires > now).then(|| l.scope.clone())
    }

    /// Ends every lease of `scope` (a job or session ended).
    pub fn revoke_scope(&self, scope: &str) {
        self.0.lock().unwrap().retain(|_, l| l.scope != scope);
    }
}

/// What the hub keeps for workspace sync: the leases and the live session watches.
#[derive(Default)]
pub struct Registry {
    pub leases: Leases,
    pub watches: super::watch::Watches,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_serves_only_its_device_project_and_time() {
        let l = Leases::default();
        let id = l.issue("d1", 7, "j_1", 60, 100);
        assert!(id.starts_with("l_") && id.len() == 34);
        assert_eq!(l.check(&id, "d1", 7, 150).as_deref(), Some("j_1"));
        assert_eq!(l.check(&id, "d2", 7, 150), None, "another device");
        assert_eq!(l.check(&id, "d1", 8, 150), None, "another project");
        assert_eq!(l.check(&id, "d1", 7, 161), None, "expired");
        assert_eq!(l.check("l_nope", "d1", 7, 150), None);
        l.revoke_scope("j_1");
        assert_eq!(l.check(&id, "d1", 7, 150), None, "revoked");
    }
}
