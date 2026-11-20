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

/// Review M4, independent of the tables: every state-changing route whose scope is not `read` or
/// `runner` is in `DESTRUCTIVE` (fresh step-up), `UNLOCKED` (app unlock) or the explicit plain
/// list below with its reason. A route added to `ROUTES` fails here until someone classifies it.
#[test]
fn every_privileged_write_is_danger_unlocked_or_plain_with_a_reason() {
    const PLAIN: &[(&str, &str, &str)] = &[
        (
            "PUT",
            "/api/v1/core/prefs",
            "the update schedule and notice prefs only; installing an update is its own danger route",
        ),
        (
            "POST",
            "/api/v1/accounts/logins/{id}/input",
            "a menu number or a code typed into one sign-in; free text is refused, and the login stays on its runner",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/models/{model}",
            "switches one model on or off for one account: a limit, never a grant",
        ),
        (
            "POST",
            "/api/v1/accounts/{id}/restore",
            "brings a deleted account back within its window; nothing new is granted",
        ),
        (
            "PUT",
            "/api/v1/ai-order",
            "the order accounts are tried in: a preference, not a grant",
        ),
        (
            "PUT",
            "/api/v1/ai-order/agents/{agent}",
            "one agent's order of accounts: a preference, not a grant",
        ),
        (
            "DELETE",
            "/api/v1/ai-order/agents/{agent}",
            "drops one agent's own order: a preference, not a grant",
        ),
        (
            "PUT",
            "/api/v1/projects/defaults",
            "limits for new projects (CPU, memory, idle stop): a normal project setting",
        ),
        (
            "POST",
            "/api/v1/system/backup",
            "starts the unit the backup timer starts, with no input; audited and held back for a minute",
        ),
        (
            "POST",
            "/api/v1/core/update/check",
            "asks the release feed whether a newer version exists and changes nothing",
        ),
        (
            "PUT",
            "/api/v1/settings/{scope}/{key}",
            "a setting that is not `auth.*` (those are danger by key, in the handler)",
        ),
        (
            "DELETE",
            "/api/v1/settings/{scope}/{key}",
            "a setting that is not `auth.*` (those are danger by key, in the handler)",
        ),
        (
            "POST",
            "/api/v1/runners/{id}/noop",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/accounts/logins",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/accounts/logins/{id}/code",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "DELETE",
            "/api/v1/accounts/logins/{id}",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/accounts",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/secret",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/state",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/cap",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/session-limits",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/accounts/{id}/test",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/accounts/{id}/check",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "DELETE",
            "/api/v1/accounts/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/accounts/providers",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/providers/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/accounts/providers/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/pools",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/pools/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/pools/{id}/members/{account}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/pools/{id}/members/{account}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/pools/{id}/default",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/bindings",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/bindings/{agent}/{provider}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/chains",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/chains/bindings/{agent}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/chains/bindings/{agent}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/chains/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/chains/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/chains/{id}/default",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/connections",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/connections/start",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/connections/flows/{id}",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/connections/flows/{id}/callback",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/connections/flows/{id}/choose",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "PATCH",
            "/api/v1/connections/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/connections/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/connections/{id}/credential",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/connections/{id}/test",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "PUT",
            "/api/v1/connections/{id}/grants",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/connections/{id}/grants/{grantee_kind}/{grantee}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/connection-defaults/{kind}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/connection-defaults/{kind}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/connection-apps/{kind}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/accounts/{id}/limits",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/budgets",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/budgets/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/budgets/{id}/raise",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/prices",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/from-github",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PATCH",
            "/api/v1/projects/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/archive",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/unarchive",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/run-configs",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PATCH",
            "/api/v1/projects/{id}/run-configs/{config}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/projects/{id}/run-configs/{config}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/run-configs/{config}/duplicate",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/run-configs/{config}/env/{env}/import",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/run-envs",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/projects/{id}/run-envs/{name}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/repos",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/projects/{id}/repos/{repo}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/repos/{repo}/primary",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/projects/{id}/secrets/{name}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/projects/{id}/secrets/{name}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/projects/{id}/repos/{repo}/fetch",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "POST",
            "/api/v1/secrets",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/secrets/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/secrets/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "POST",
            "/api/v1/secret-groups",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "PUT",
            "/api/v1/secret-groups/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/secret-groups/{id}",
            "D-4: a normal write; only the danger list asks Touch ID, only code-running routes need the unlock",
        ),
        (
            "DELETE",
            "/api/v1/terminals/{id}/local",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
        (
            "PATCH",
            "/api/v1/agent-sessions/{id}",
            "fixed or caller-owned effect, not a grant (see 0.9 notes)",
        ),
    ];
    let in_plain = |m: &str, t: &str| PLAIN.iter().any(|(pm, pt, _)| *pm == m && *pt == t);
    for (m, t, scope) in ROUTES {
        let privileged = !matches!(*scope, "read" | "runner");
        // A terminal socket is a GET but is a live shell.
        let shell = t.ends_with("/terminals/{id}/ws");
        if !(privileged && (*m != "GET" || shell)) {
            continue;
        }
        let tiers = declared_destructive(m, t) as u8
            + UNLOCKED.iter().any(|(um, ut)| um == m && ut == t) as u8
            + in_plain(m, t) as u8;
        assert_eq!(tiers, 1, "{m} {t} ({scope}) must be in exactly one tier");
    }
    for (m, t, why) in PLAIN {
        assert!(
            declared(m, t).is_some(),
            "{m} {t} is plain but not in ROUTES"
        );
        assert!(!why.is_empty());
    }
}

/// D-4: the danger list is exactly this, and nothing else asks Touch ID per action. A route
/// added to `DESTRUCTIVE` fails here until the decision is made again on purpose.
#[test]
fn the_danger_list_is_the_d4_list() {
    let mut have: Vec<_> = DESTRUCTIVE.to_vec();
    have.sort();
    let mut want = vec![
        ("DELETE", "/api/v1/devices/{id}"),
        ("PATCH", "/api/v1/devices/{id}"),
        ("PUT", "/api/v1/devices/{id}/scopes"),
        ("POST", "/api/v1/pairings"),
        ("POST", "/api/v1/pairings/invites"),
        ("POST", "/api/v1/pairings/{id}/approve"),
        ("POST", "/api/v1/pairings/{id}/reject"),
        ("POST", "/api/v1/auth/lockouts/clear"),
        ("POST", "/api/v1/system/restart"),
        ("GET", "/api/v1/system/logs/runner"),
        ("GET", "/api/v1/system/logs/backup"),
        ("POST", "/api/v1/secrets/{id}/reveal"),
        ("POST", "/api/v1/secrets/{id}/leases"),
        ("POST", "/api/v1/secret-groups/{id}/leases"),
        // E6: only the Mac app that enrolled a runner may call it the bundled one, which alone can
        // be given a real shell; a live step-up keeps a stolen routine key from claiming it.
        ("POST", "/api/v1/runners/{id}/bundled"),
        // E7/E8/E12: the retention write, a Core update, a runner update and an export of secret values.
        ("PUT", "/api/v1/system/backups/retention"),
        ("POST", "/api/v1/system/update"),
        ("POST", "/api/v1/runners/{id}/update"),
        ("POST", "/api/v1/secrets/export"),
    ];
    want.sort();
    assert_eq!(have, want);
    let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
    // A normal write now: an account, a project, a setting that is not a security one.
    for (method, path) in [
        ("POST", "/api/v1/accounts"),
        ("POST", "/api/v1/projects"),
        ("PUT", "/api/v1/settings/server/api.request_burst"),
    ] {
        assert!(!destructive(&m(method), path, &[]), "{method} {path}");
    }
    // A security setting is danger: it would weaken the list itself.
    assert!(destructive(
        &m("PUT"),
        "/api/v1/settings/server/auth.step_up_secs",
        &[]
    ));
    assert!(destructive(
        &m("DELETE"),
        "/api/v1/settings/server/auth.passkey_admin",
        &[]
    ));
}

/// E1-2: the routes that run code on a runner need the app unlock, not a per-action prompt; they
/// are declared routes and never also danger.
#[test]
fn code_running_routes_need_the_unlock_and_are_not_danger() {
    for (m, t) in UNLOCKED {
        assert!(declared(m, t).is_some(), "{m} {t} is not in ROUTES");
        assert!(!declared_destructive(m, t), "{m} {t} is both");
    }
    let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
    assert!(needs_unlock(&m("POST"), "/api/v1/terminals", &[]));
    assert!(needs_unlock(&m("POST"), "/api/v1/agent-sessions", &[]));
    assert!(!needs_unlock(&m("GET"), "/api/v1/terminals", &[]));
    assert!(!needs_unlock(&m("POST"), "/api/v1/accounts", &[]));
}

/// Review S5 (KAN-298): the refusal throttle keys on the template, so varying an id adds no key.
#[test]
fn a_destructive_route_is_keyed_by_its_template() {
    let m = Method::DELETE;
    for id in ["d_a", "d_b", "d_c"] {
        assert_eq!(
            destructive_template(&m, &format!("/api/v1/devices/{id}"), &[]).as_deref(),
            Some("/api/v1/devices/{id}")
        );
    }
    assert_eq!(
        destructive_template(&Method::GET, "/api/v1/devices/d_a", &[]),
        None
    );
    assert_eq!(destructive_template(&m, "/api/v1/nope/x", &[]), None);
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

#[test]
fn no_route_is_listed_twice() {
    for (i, r) in ROUTES.iter().enumerate() {
        assert!(
            !ROUTES[..i].iter().any(|o| (o.0, o.1) == (r.0, r.1)),
            "{} {} is listed twice",
            r.0,
            r.1
        );
    }
}
