//! E1-2: every Core path that writes an audit row, and how its origin gets set. The origin is
//! ambient (`store::audit::origin`): a request's person comes from the client gate, a job's
//! schedule from the job engine, and anything else reads `system`. This list is the review
//! point: a new write path fails the test until it is added here and its class decided.

use std::path::Path;

#[derive(Debug)]
enum How {
    /// Runs inside a signed client request: the gate scopes its person.
    Request,
    /// A store function its callers reach from a request, a job or a session: ambient.
    Ambient,
    /// Sets its origin itself (`append_as`).
    Explicit,
    /// Narrows the ambient origin to the session it is about.
    Session,
    /// Runs with no request or job in force: the Core on its own (`system`).
    Background,
}

const PATHS: &[(&str, How)] = &[
    ("api/v1/devices.rs", How::Request),
    ("api/v1/gate.rs", How::Request),
    ("api/v1/runner_control.rs", How::Request),
    ("api/v1/runners.rs", How::Request),
    ("api/v1/secrets.rs", How::Request),
    ("api/v1/stepup.rs", How::Request),
    ("api/v1/system.rs", How::Request),
    ("api/v1/terminals.rs", How::Request),
    ("api/v1/trace.rs", How::Request),
    ("auth/identity.rs", How::Background),
    ("cli/admin/bootstrap.rs", How::Background),
    ("health.rs", How::Background),
    ("hub/connect.rs", How::Background),
    ("jobs/store.rs", How::Explicit),
    ("push.rs", How::Background),
    ("store/accounts.rs", How::Ambient),
    ("store/agents.rs", How::Session),
    ("store/budgets.rs", How::Ambient),
    ("store/budgets/write.rs", How::Ambient),
    ("store/chains.rs", How::Ambient),
    ("store/connections.rs", How::Ambient),
    ("store/connections/access.rs", How::Ambient),
    ("store/connections/apps.rs", How::Ambient),
    ("store/connections/resolve.rs", How::Session),
    ("store/events.rs", How::Ambient),
    ("store/failover/notice.rs", How::Ambient),
    ("store/gateway/signals.rs", How::Ambient),
    ("store/gov/devices.rs", How::Ambient),
    ("store/gov/limits.rs", How::Ambient),
    ("store/gov/pairing.rs", How::Ambient),
    ("store/health/recover.rs", How::Ambient),
    ("store/logins.rs", How::Ambient),
    ("store/modsettings.rs", How::Ambient),
    ("store/placement.rs", How::Ambient),
    ("store/pools.rs", How::Ambient),
    ("store/prices.rs", How::Ambient),
    ("store/providers.rs", How::Ambient),
    ("store/secret_groups.rs", How::Ambient),
    ("store/secrets.rs", How::Ambient),
    ("store/settings.rs", How::Ambient),
    ("store/usage.rs", How::Ambient),
];

/// The files that append audit rows, under `dir`, relative to `src`.
fn writers(dir: &Path, src: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            if name != "tests" {
                writers(&p, src, out);
            }
        } else if name.ends_with(".rs")
            && !name.starts_with("tests")
            && !name.contains("fixture")
            && !p.starts_with(src.join("store/audit"))
        {
            let text = std::fs::read_to_string(&p).unwrap();
            // Only code above the file's test module counts.
            let code = text.split("#[cfg(test)]").next().unwrap();
            if code.contains("NewAuditEvent {") || code.contains("audit::append") {
                out.push(p.strip_prefix(src).unwrap().to_string_lossy().into_owned());
            }
        }
    }
}

#[test]
fn every_audit_write_path_is_listed_with_how_it_sets_its_origin() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    writers(&src, &src, &mut found);
    found.sort();
    let listed: Vec<&str> = PATHS.iter().map(|(f, _)| *f).collect();
    let missing: Vec<&String> = found
        .iter()
        .filter(|f| !listed.contains(&f.as_str()))
        .collect();
    let gone: Vec<&&str> = listed
        .iter()
        .filter(|f| !found.iter().any(|x| x == **f))
        .collect();
    assert!(
        missing.is_empty() && gone.is_empty(),
        "audit write paths changed. Add each new one to PATHS with its origin class; drop the \
         ones that are gone.\nnot listed: {missing:?}\nlisted but gone: {gone:?}"
    );
    // The classes are documentation the compiler checks is used.
    assert!(
        PATHS
            .iter()
            .any(|(_, h)| matches!(h, How::Explicit | How::Session))
    );
}
