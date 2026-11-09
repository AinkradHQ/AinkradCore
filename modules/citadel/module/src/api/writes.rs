//! The writes that deliberately need no step-up. Every write (POST, PUT, PATCH, DELETE) of the
//! module is either in a slice's `DESTRUCTIVE` list or here: the Core refuses to mount the module
//! otherwise (`Module::non_destructive`, checked by `module::validate`), so a new write cannot
//! default silently to "admin without step-up".
//!
//! A write belongs here only when it cannot widen what an agent may do, change a model, price,
//! budget or project policy, or start runs in bulk (see `api::DESTRUCTIVE_AUDIT`).

/// `(method, template)`, relative to `/modules/citadel/v1`, grouped by why it is safe.
pub const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    // Display only.
    ("PUT", "/agents/{id}/appearance"),
    ("DELETE", "/agents/{id}/avatar"),
    ("DELETE", "/companies/{id}/logo"),
    // Org structure: names and seats, no permissions.
    ("POST", "/companies"),
    ("PUT", "/companies/{id}"),
    ("POST", "/companies/{id}/departments"),
    ("PATCH", "/departments/{id}"),
    ("PUT", "/departments/{id}"),
    ("POST", "/departments/{id}/teams"),
    ("PATCH", "/teams/{id}"),
    ("PUT", "/teams/{id}"),
    ("DELETE", "/teams/{id}/members/{agent_id}"),
    ("PUT", "/teams/{id}/members/{agent_id}"),
    // A hire proposal is pending: approving it is `decide-forge`, which is step-up (F-01).
    ("POST", "/companies/{id}/agents"),
    // `decide` refuses the approval of every kind but a budget overrun (see `approvals::check_kind`);
    // a rejection only stops work.
    ("POST", "/approvals/{id}/decide"),
    // Work items. These queue wake requests (F-03): spend is bounded by the budgets, `mcp.max_calls_per_run`,
    // the loop breaker and the engine switch (`POST /engine`, step-up); the bulk starts (sprint commit,
    // requirement resume) are step-up.
    ("PATCH", "/issues/{id}"),
    ("POST", "/projects/{id}/issues"),
    ("POST", "/issues/{id}/comments"),
    ("POST", "/issues/{id}/move"),
    ("POST", "/issues/{id}/transition"),
    ("POST", "/issues/{id}/sprint"),
    ("POST", "/requirements/{id}/thread"),
    ("POST", "/sprints/{id}/close"),
    ("PUT", "/requirements/{id}"),
    ("POST", "/requirements/{id}/done"),
    ("POST", "/requirements/{id}/pause"),
    // Planning data that starts nothing.
    ("PATCH", "/epics/{id}"),
    ("POST", "/projects/{id}/epics"),
    ("POST", "/issues/{id}/epic"),
    ("POST", "/issues/{id}/estimate"),
    ("POST", "/projects/{id}/sprints"),
    ("POST", "/projects/{id}/labels"),
    ("PUT", "/projects/{id}/labels/{label_id}"),
    ("PUT", "/issues/{id}/labels/{label_id}"),
    ("DELETE", "/issues/{id}/labels/{label_id}"),
    ("PUT", "/issues/{id}/blockers/{blocker_id}"),
    ("DELETE", "/issues/{id}/blockers/{blocker_id}"),
    // Parallelism is capped by the project's `max_parallel_runs`, which is step-up.
    ("PUT", "/projects/{id}/capacity/{agent_id}"),
    ("POST", "/projects/{id}/wip"),
    // Which repo, in which order: the repos themselves (commands, forge URL) are step-up.
    ("PUT", "/issues/{id}/repos"),
    ("PUT", "/projects/{id}/repo-order"),
    ("POST", "/repos/{id}/primary"),
    // Knowledge a proposal only suggests: accepting is step-up.
    ("POST", "/knowledge/{id}/reject"),
    ("POST", "/knowledge/{id}/retire"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::DESTRUCTIVE;

    /// Every write of the contract is classified exactly once: step-up or listed here.
    #[test]
    fn every_write_in_the_contract_is_classified_once() {
        let doc = crate::api::spec::document();
        let mut writes = vec![];
        for (path, item) in doc["paths"].as_object().unwrap() {
            for method in item.as_object().unwrap().keys() {
                let m = method.to_ascii_uppercase();
                if ["POST", "PUT", "PATCH", "DELETE"].contains(&m.as_str()) {
                    writes.push((m, path.clone()));
                }
            }
        }
        assert!(writes.len() > 90, "{} writes", writes.len());
        for (m, p) in &writes {
            let d = DESTRUCTIVE.iter().any(|(dm, dp)| dm == m && dp == p);
            let n = NON_DESTRUCTIVE.iter().any(|(nm, np)| nm == m && np == p);
            assert!(
                d ^ n,
                "{m} {p}: step-up={d}, non-destructive={n}; classify it once"
            );
        }
        for (m, p) in NON_DESTRUCTIVE {
            assert!(
                writes.iter().any(|(wm, wp)| wm == m && wp == p),
                "{m} {p} is no write route"
            );
        }
    }

    /// Each F-01..F-04 write is step-up, so dropping one from `DESTRUCTIVE_AUDIT` fails here.
    #[test]
    fn the_audited_writes_need_a_step_up() {
        for (m, p) in [
            ("PATCH", "/agents/{id}"),
            ("POST", "/prices"),
            ("PUT", "/projects/{id}"),
            ("PUT", "/agents/{id}/chain"),
            ("POST", "/sprints/{id}/commit"),
            ("POST", "/approvals/{id}/decide-forge"),
        ] {
            assert!(DESTRUCTIVE.contains(&(m, p)), "{m} {p}");
        }
    }
}
