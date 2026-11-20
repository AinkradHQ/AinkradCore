//! Scopes (handshake spec §8, E1-09.1/.2): every authenticated route declares the one scope a
//! device needs to call it, here, and the gate refuses anything else with 403
//! `forbidden_scope` right after authentication. Deny by default: a method and path with no
//! entry (an unknown path included) is refused, so a route added without a scope cannot be
//! called, and the contract test fails on its missing `x-ainkrad-scope`.
//!
//! - `read`: what the device itself shows (its own identity and push token, events, settings).
//! - `admin`: devices, pairing, setting changes, the audit log, the metrics.
//! - `agent`: sending a runner a command (`POST /api/v1/runners/{id}/noop`).
//! - Agent sessions (E2-08): `agent`; deciding a tool call `approve`.
//! - Projects (P1-02): reading is `read`; every write is `admin` and destructive.
//! - Secrets (E2-07): managing them and granting a lease is `admin` (and destructive); the one
//!   route a `runner` device may call is redeeming a lease granted to it.
//! - Fallback chains and their bindings (S7): every route is `admin`; every write is destructive.
//! - Accounts, pools, bindings and provider definitions (KAN-432): reading is `read`; every write is
//!   `admin` and destructive.
//! - The cost ledger, prices and account usage (KAN-449): the price list is `read`; the cost ledger and the
//!   account usage report (who spent what, in which company) are `admin` without a step-up; a price or an
//!   account's limit is `admin` and destructive. No route writes the ledger.
//! - Budgets (KAN-448): reading is `read`; setting, deleting or raising one is `admin` and destructive.
//! - Connections (C5): reading the kinds and the connections is `read` (a non-admin device sees only the
//!   connections granted to it); every other route is `admin`, every write destructive.
//! - `terminal`: opening, attaching, signalling and closing a terminal (listing is `read`).
//! - A module's routes need the module's own `Module::scope` (`admin` unless it says otherwise),
//!   or the scope its `Module::route_scopes` declares for that route (`module_scope`).
//! - A `runner` device holds only `runner`, which only `POST /api/v1/secret-leases/redeem` and
//!   the read side of the Core's repo copies (`/api/v1/mirrors/{repo}/…`, P3-01) take: it can call
//!   nothing else here (the runner hub is E1-11).
//!
//! **Danger routes** (spec §8, E1-09.6, D-4; still named "destructive" in the contract) are
//! listed in [`DESTRUCTIVE`] (a module's in `Module::destructive`): on top of its scope, such a
//! route needs a session elevated by a fresh step-up (`auth::stepup`), else 403
//! `step_up_required`. The list is short on purpose: every other write is a normal write. A
//! module route in `Module::needs_unlock` needs the app unlock instead (`unlock_required`). The contract marks each with
//! `x-ainkrad-destructive: true`. Reads never need it; the host socket's `bootstrap` and
//! `recover` are not routes and never need it.

use std::sync::Arc;

use axum::http::Method;

use crate::module::Module;

/// `(method, path template, scope)`; a `{…}` segment matches any one segment. The templates are
/// the contract's own paths.
pub const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/me", "read"),
    ("PUT", "/api/v1/push-token", "read"),
    ("DELETE", "/api/v1/push-token", "read"),
    ("GET", "/api/v1/push-token/kinds", "read"),
    ("PUT", "/api/v1/push-token/kinds", "read"),
    ("GET", "/api/v1/events", "read"),
    ("GET", "/api/v1/events/ws", "read"),
    ("GET", "/api/v1/events/latest", "read"),
    ("POST", "/api/v1/ws-ticket", "read"),
    ("GET", "/api/v1/settings", "read"),
    ("GET", "/api/v1/settings/{scope}", "read"),
    ("GET", "/api/v1/settings/{scope}/{key}", "read"),
    ("GET", "/api/v1/settings/{scope}/{key}/history", "read"),
    ("PUT", "/api/v1/settings/{scope}/{key}", "admin"),
    ("DELETE", "/api/v1/settings/{scope}/{key}", "admin"),
    ("GET", "/api/v1/devices", "admin"),
    ("DELETE", "/api/v1/devices/{id}", "admin"),
    ("GET", "/api/v1/audit", "admin"),
    ("GET", "/api/v1/audit/stats", "admin"),
    ("GET", "/api/v1/ops/history", "admin"),
    // The Core machine (host-helper plan §4): all `admin`; see DESTRUCTIVE for the step-up ones.
    ("GET", "/api/v1/system/host", "admin"),
    ("GET", "/api/v1/core/health", "read"),
    ("GET", "/api/v1/core/prefs", "read"),
    ("PUT", "/api/v1/core/prefs", "admin"),
    ("GET", "/api/v1/core/storage", "admin"),
    ("POST", "/api/v1/core/update/check", "admin"),
    ("POST", "/api/v1/system/restart", "admin"),
    // A backup now and the backup schedule (E2-6): `admin`; a start is no danger, it is the unit the timer starts.
    ("POST", "/api/v1/system/backup", "admin"),
    ("GET", "/api/v1/system/backups", "admin"),
    // How many local backups are kept: reading is `admin`; the write is in DESTRUCTIVE (D-4).
    ("GET", "/api/v1/system/backups/retention", "admin"),
    ("PUT", "/api/v1/system/backups/retention", "admin"),
    ("GET", "/api/v1/system/update", "admin"),
    ("POST", "/api/v1/system/update", "admin"),
    ("GET", "/api/v1/system/logs/core", "admin"),
    ("GET", "/api/v1/system/logs/helper", "admin"),
    ("GET", "/api/v1/system/logs/runner", "admin"),
    ("GET", "/api/v1/system/logs/backup", "admin"),
    ("GET", "/api/v1/metrics", "admin"),
    ("POST", "/api/v1/pairings", "admin"),
    ("POST", "/api/v1/pairings/invites", "admin"),
    ("POST", "/api/v1/runners/{id}/bundled", "admin"),
    ("GET", "/api/v1/pairings/{id}", "admin"),
    ("POST", "/api/v1/pairings/{id}/approve", "admin"),
    ("POST", "/api/v1/pairings/{id}/reject", "admin"),
    ("POST", "/api/v1/auth/step-up/challenge", "read"),
    ("POST", "/api/v1/auth/step-up", "read"),
    ("POST", "/api/v1/auth/unlock/beat", "read"),
    ("POST", "/api/v1/auth/unlock/end", "read"),
    ("GET", "/api/v1/devices/{id}", "admin"),
    ("PATCH", "/api/v1/devices/{id}", "admin"),
    ("PUT", "/api/v1/devices/{id}/scopes", "admin"),
    ("GET", "/api/v1/auth/lockouts", "admin"),
    ("POST", "/api/v1/auth/lockouts/clear", "admin"),
    ("GET", "/api/v1/runners", "read"),
    ("GET", "/api/v1/runners/{id}", "read"),
    ("POST", "/api/v1/runners/{id}/noop", "agent"),
    ("PUT", "/api/v1/runners/{id}/policy", "admin"),
    ("POST", "/api/v1/runners/{id}/tools", "admin"),
    ("POST", "/api/v1/runners/{id}/update", "admin"),
    ("GET", "/api/v1/runners/{id}/tools/operations/{op}", "read"),
    ("GET", "/api/v1/accounts", "read"),
    // Before `/accounts/{id}`: the first template that fits a path decides, and `usage` fits `{id}`.
    ("GET", "/api/v1/accounts/usage", "admin"),
    ("POST", "/api/v1/accounts/logins", "admin"),
    ("GET", "/api/v1/accounts/logins/{id}", "admin"),
    ("POST", "/api/v1/accounts/logins/{id}/code", "admin"),
    ("POST", "/api/v1/accounts/logins/{id}/input", "admin"),
    ("GET", "/api/v1/accounts/logins/{id}/screen", "admin"),
    ("DELETE", "/api/v1/accounts/logins/{id}", "admin"),
    ("GET", "/api/v1/accounts/{id}", "read"),
    ("GET", "/api/v1/accounts/{id}/models", "read"),
    ("PUT", "/api/v1/accounts/{id}/models/{model}", "admin"),
    ("GET", "/api/v1/accounts/providers", "read"),
    ("POST", "/api/v1/accounts", "admin"),
    ("PUT", "/api/v1/accounts/{id}/secret", "admin"),
    ("PUT", "/api/v1/accounts/{id}/state", "admin"),
    ("PUT", "/api/v1/accounts/{id}/cap", "admin"),
    ("PUT", "/api/v1/accounts/{id}/session-limits", "admin"),
    ("POST", "/api/v1/accounts/{id}/test", "admin"),
    ("POST", "/api/v1/accounts/{id}/check", "admin"),
    ("DELETE", "/api/v1/accounts/{id}", "admin"),
    ("POST", "/api/v1/accounts/{id}/restore", "admin"),
    ("POST", "/api/v1/accounts/providers", "admin"),
    ("PUT", "/api/v1/accounts/providers/{id}", "admin"),
    ("DELETE", "/api/v1/accounts/providers/{id}", "admin"),
    ("GET", "/api/v1/pools", "read"),
    ("POST", "/api/v1/pools", "admin"),
    ("DELETE", "/api/v1/pools/{id}", "admin"),
    ("PUT", "/api/v1/pools/{id}/members/{account}", "admin"),
    ("DELETE", "/api/v1/pools/{id}/members/{account}", "admin"),
    ("PUT", "/api/v1/pools/{id}/default", "admin"),
    ("GET", "/api/v1/bindings", "read"),
    ("PUT", "/api/v1/bindings", "admin"),
    ("DELETE", "/api/v1/bindings/{agent}/{provider}", "admin"),
    // The AI order (E7-1): reading says which accounts a run may walk, so it is `admin` too.
    ("GET", "/api/v1/ai-order", "admin"),
    ("PUT", "/api/v1/ai-order", "admin"),
    ("PUT", "/api/v1/ai-order/agents/{agent}", "admin"),
    ("DELETE", "/api/v1/ai-order/agents/{agent}", "admin"),
    // Fallback chains (S7): reading says which accounts a run may walk, so it is `admin` too.
    ("GET", "/api/v1/chains", "admin"),
    ("POST", "/api/v1/chains", "admin"),
    ("GET", "/api/v1/chains/bindings", "admin"),
    ("PUT", "/api/v1/chains/bindings/{agent}", "admin"),
    ("DELETE", "/api/v1/chains/bindings/{agent}", "admin"),
    ("GET", "/api/v1/chains/{id}", "admin"),
    ("PUT", "/api/v1/chains/{id}", "admin"),
    ("DELETE", "/api/v1/chains/{id}", "admin"),
    ("PUT", "/api/v1/chains/{id}/default", "admin"),
    // Connections (C5). The flow templates come before `/connections/{id}/...`: the first that fits wins.
    ("GET", "/api/v1/connection-kinds", "read"),
    ("GET", "/api/v1/connections", "read"),
    ("POST", "/api/v1/connections", "admin"),
    ("POST", "/api/v1/connections/start", "admin"),
    ("GET", "/api/v1/connections/flows/{id}", "admin"),
    ("DELETE", "/api/v1/connections/flows/{id}", "admin"),
    ("POST", "/api/v1/connections/flows/{id}/callback", "admin"),
    ("POST", "/api/v1/connections/flows/{id}/choose", "admin"),
    ("GET", "/api/v1/connections/{id}", "read"),
    ("PATCH", "/api/v1/connections/{id}", "admin"),
    ("DELETE", "/api/v1/connections/{id}", "admin"),
    ("PUT", "/api/v1/connections/{id}/credential", "admin"),
    ("POST", "/api/v1/connections/{id}/test", "admin"),
    ("GET", "/api/v1/connections/{id}/activity", "admin"),
    ("GET", "/api/v1/connections/{id}/resources", "admin"),
    ("GET", "/api/v1/connections/{id}/grants", "admin"),
    ("PUT", "/api/v1/connections/{id}/grants", "admin"),
    (
        "DELETE",
        "/api/v1/connections/{id}/grants/{grantee_kind}/{grantee}",
        "admin",
    ),
    ("GET", "/api/v1/connection-defaults", "admin"),
    ("PUT", "/api/v1/connection-defaults/{kind}", "admin"),
    ("DELETE", "/api/v1/connection-defaults/{kind}", "admin"),
    ("GET", "/api/v1/connection-apps/{kind}", "admin"),
    ("PUT", "/api/v1/connection-apps/{kind}", "admin"),
    ("GET", "/api/v1/costs", "admin"),
    ("GET", "/api/v1/costs/series", "admin"),
    ("GET", "/api/v1/prices", "read"),
    ("GET", "/api/v1/budgets", "read"),
    ("PUT", "/api/v1/budgets", "admin"),
    ("DELETE", "/api/v1/budgets/{id}", "admin"),
    ("POST", "/api/v1/budgets/{id}/raise", "admin"),
    ("PUT", "/api/v1/prices", "admin"),
    ("GET", "/api/v1/projects", "read"),
    ("POST", "/api/v1/projects", "admin"),
    // It reads private repo names with the connection's token.
    ("GET", "/api/v1/projects/github/repos", "admin"),
    ("POST", "/api/v1/projects/from-github", "admin"),
    ("GET", "/api/v1/projects/{id}", "read"),
    ("PATCH", "/api/v1/projects/{id}", "admin"),
    ("POST", "/api/v1/projects/{id}/archive", "admin"),
    ("POST", "/api/v1/projects/{id}/unarchive", "admin"),
    ("GET", "/api/v1/projects/defaults", "read"),
    ("PUT", "/api/v1/projects/defaults", "admin"),
    ("POST", "/api/v1/projects/{id}/repos", "admin"),
    ("DELETE", "/api/v1/projects/{id}/repos/{repo}", "admin"),
    (
        "POST",
        "/api/v1/projects/{id}/repos/{repo}/primary",
        "admin",
    ),
    ("GET", "/api/v1/projects/{id}/spec", "read"),
    ("PUT", "/api/v1/projects/{id}/spec", "admin"),
    ("POST", "/api/v1/projects/{id}/run/spec/draft", "admin"),
    ("GET", "/api/v1/projects/{id}/spec/versions", "read"),
    (
        "GET",
        "/api/v1/projects/{id}/spec/versions/{version}",
        "read",
    ),
    ("GET", "/api/v1/projects/{id}/secrets", "admin"),
    ("PUT", "/api/v1/projects/{id}/secrets/{name}", "admin"),
    ("DELETE", "/api/v1/projects/{id}/secrets/{name}", "admin"),
    ("POST", "/api/v1/projects/{id}/repos/{repo}/fetch", "admin"),
    // The Core's repo copies, to runners: upload side only; receive-pack answers 403 `read_only`.
    ("GET", "/api/v1/mirrors/{repo}/info/refs", "runner"),
    ("POST", "/api/v1/mirrors/{repo}/git-upload-pack", "runner"),
    ("POST", "/api/v1/mirrors/{repo}/git-receive-pack", "runner"),
    ("GET", "/api/v1/projects/{id}/run", "read"),
    ("POST", "/api/v1/projects/{id}/run/start", "admin"),
    ("POST", "/api/v1/projects/{id}/run/stop", "admin"),
    ("POST", "/api/v1/projects/{id}/run/restart", "admin"),
    ("POST", "/api/v1/projects/{id}/run/activity", "read"),
    // Run configurations and environments (Core 0.10, E11-3): values never leave except `value`.
    ("GET", "/api/v1/projects/{id}/runs", "read"),
    ("POST", "/api/v1/projects/{id}/runs/{run}/stop", "admin"),
    ("GET", "/api/v1/projects/{id}/code", "read"),
    ("GET", "/api/v1/projects/{id}/usage", "read"),
    ("GET", "/api/v1/projects/{id}/changes", "read"),
    ("GET", "/api/v1/projects/{id}/run-configs", "read"),
    ("POST", "/api/v1/projects/{id}/run-configs", "admin"),
    ("GET", "/api/v1/projects/{id}/run-configs/{config}", "read"),
    (
        "PATCH",
        "/api/v1/projects/{id}/run-configs/{config}",
        "admin",
    ),
    (
        "DELETE",
        "/api/v1/projects/{id}/run-configs/{config}",
        "admin",
    ),
    (
        "POST",
        "/api/v1/projects/{id}/run-configs/{config}/duplicate",
        "admin",
    ),
    (
        "POST",
        "/api/v1/projects/{id}/run-configs/{config}/run",
        "admin",
    ),
    (
        "GET",
        "/api/v1/projects/{id}/run-configs/{config}/env-diff",
        "read",
    ),
    (
        "GET",
        "/api/v1/projects/{id}/run-configs/{config}/env/{env}",
        "read",
    ),
    (
        "POST",
        "/api/v1/projects/{id}/run-configs/{config}/env/{env}/import",
        "admin",
    ),
    (
        "PUT",
        "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
        "admin",
    ),
    (
        "DELETE",
        "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
        "admin",
    ),
    (
        "GET",
        "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}/value",
        "admin",
    ),
    ("GET", "/api/v1/projects/{id}/run-envs", "read"),
    ("POST", "/api/v1/projects/{id}/run-envs", "admin"),
    ("DELETE", "/api/v1/projects/{id}/run-envs/{name}", "admin"),
    ("GET", "/api/v1/projects/{id}/run/services", "read"),
    // Logs are what the project's code printed (redacted, but still its own words): admin.
    ("GET", "/api/v1/projects/{id}/run/logs", "admin"),
    ("GET", "/api/v1/projects/{id}/run/logs/ws", "admin"),
    ("GET", "/api/v1/secrets", "admin"),
    ("POST", "/api/v1/secrets", "admin"),
    ("PUT", "/api/v1/secrets/{id}", "admin"),
    ("DELETE", "/api/v1/secrets/{id}", "admin"),
    ("POST", "/api/v1/secrets/{id}/leases", "admin"),
    ("POST", "/api/v1/secrets/{id}/reveal", "admin"),
    // Exporting every value (D-4): `admin`, destructive (a live step-up).
    ("POST", "/api/v1/secrets/export", "admin"),
    ("POST", "/api/v1/secret-leases/redeem", "runner"),
    ("GET", "/api/v1/secret-groups", "admin"),
    ("POST", "/api/v1/secret-groups", "admin"),
    ("PUT", "/api/v1/secret-groups/{id}", "admin"),
    ("DELETE", "/api/v1/secret-groups/{id}", "admin"),
    ("POST", "/api/v1/secret-groups/{id}/leases", "admin"),
    ("GET", "/api/v1/terminals", "read"),
    ("GET", "/api/v1/terminals/{id}", "read"),
    ("POST", "/api/v1/terminals", "terminal"),
    ("GET", "/api/v1/terminals/{id}/ws", "terminal"),
    ("POST", "/api/v1/terminals/{id}/local", "terminal"),
    ("DELETE", "/api/v1/terminals/{id}/local", "terminal"),
    ("POST", "/api/v1/terminals/{id}/signal", "terminal"),
    // A preview of a sandbox terminal's last screen rows: the terminal scope and the caller's own
    // terminal, no per-action step-up (it attaches nothing). At integration it joins E1's
    // `UNLOCKED` gate, so a locked Core answers `unlock_required`.
    ("GET", "/api/v1/terminals/{id}/tail", "terminal"),
    ("DELETE", "/api/v1/terminals/{id}", "terminal"),
    ("GET", "/api/v1/agent-sessions", "agent"),
    ("POST", "/api/v1/agent-sessions", "agent"),
    ("GET", "/api/v1/agent-sessions/{id}", "agent"),
    ("GET", "/api/v1/agent-sessions/{id}/transcript", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/messages", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/attachments", "agent"),
    ("GET", "/api/v1/agent-sessions/{id}/approvals", "agent"),
    (
        "POST",
        "/api/v1/agent-sessions/{id}/approvals/{request}",
        "approve",
    ),
    ("PATCH", "/api/v1/agent-sessions/{id}", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/interrupt", "agent"),
    (
        "POST",
        "/api/v1/agent-sessions/{id}/subagents/{tool_use_id}/stop",
        "agent",
    ),
    ("POST", "/api/v1/agent-sessions/{id}/mode", "agent"),
    // A session's folder (E14): the listing is read like the transcript; a revert and a write
    // change files on the runner.
    ("GET", "/api/v1/agent-sessions/{id}/files", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/files/revert", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/files/write", "agent"),
    // "Always for this project" rules (E14).
    ("GET", "/api/v1/projects/{id}/approval-rules", "agent"),
    (
        "DELETE",
        "/api/v1/projects/{id}/approval-rules/{rule}",
        "approve",
    ),
    ("POST", "/api/v1/agent-sessions/{id}/cancel", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/kill", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/resume", "agent"),
    ("POST", "/api/v1/agent-sessions/{id}/wake", "agent"),
];

/// `(method, path template)` of every route that needs a **fresh** step-up (spec §8, E1-2, D-4):
/// the danger list, and nothing else. Touch ID per action, only for: devices and their access
/// (pairing, revoking, rescoping, clearing a lockout), a secret leaving the Core (a lease, the
/// runner and backup logs) and the Core machine (restart). Deleting the Core's data, a backup
/// key or restore, and an update have no route here yet; they join this list when they get one.
/// Security settings (`auth.*`) are danger too, matched by key in [`destructive`]. Every other
/// write is a normal write (a module's own `needs_unlock` routes aside). Each must also be in
/// [`ROUTES`] (a test checks).
///
/// `POST /api/v1/runners/{id}/noop` is not here: it runs one fixed op that takes no input,
/// reads nothing and changes nothing on the runner (it proves the path).
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/api/v1/devices/{id}"),
    ("PATCH", "/api/v1/devices/{id}"),
    ("PUT", "/api/v1/devices/{id}/scopes"),
    ("POST", "/api/v1/pairings"),
    // It hands out a credential that enrols a device with no second approval.
    ("POST", "/api/v1/pairings/invites"),
    ("POST", "/api/v1/runners/{id}/bundled"),
    ("POST", "/api/v1/pairings/{id}/approve"),
    ("POST", "/api/v1/pairings/{id}/reject"),
    ("POST", "/api/v1/auth/lockouts/clear"),
    // The Core machine: a restart drops every session, and the runner and backup logs can hold
    // values no redactor recognises (D4). The Core and helper logs are not here.
    ("POST", "/api/v1/system/restart"),
    // Retention decides how much history survives a loss (D-4): it writes the Core's config.
    ("PUT", "/api/v1/system/backups/retention"),
    // Replaces the Core's own programs (signed releases only) and restarts it: a step-up, like a restart.
    ("POST", "/api/v1/system/update"),
    // Replaces the programs a runner runs on its host (signed releases only), like a tool install.
    ("POST", "/api/v1/runners/{id}/update"),
    ("GET", "/api/v1/system/logs/runner"),
    ("GET", "/api/v1/system/logs/backup"),
    // A lease or a reveal is how a secret's value leaves the Core.
    ("POST", "/api/v1/secrets/{id}/reveal"),
    ("POST", "/api/v1/secrets/{id}/leases"),
    // An exported value leaves the Core to a file (D-4).
    ("POST", "/api/v1/secrets/export"),
    ("POST", "/api/v1/secret-groups/{id}/leases"),
];

/// `(method, path template)` of the routes that need the **app unlock** and no per-action prompt
/// (E1-2, D-5): the ones that run code on a runner, the capability `hub::Elevated` stands for. A
/// device unlocks once (`POST /api/v1/auth/step-up` with `purpose: session`) and holds it by
/// heartbeat until the client ends it, so these cost the app nothing after the first Touch ID,
/// while a device that never unlocked (a stolen routine key, a script) still cannot open a
/// shell or start an AI session. Each must also be in [`ROUTES`] (a test checks).
pub const UNLOCKED: &[(&str, &str)] = &[
    ("POST", "/api/v1/terminals"),
    ("GET", "/api/v1/terminals/{id}/ws"),
    // The last lines of a terminal's screen are the terminal's output: it reads like an attach (E6).
    ("GET", "/api/v1/terminals/{id}/tail"),
    ("POST", "/api/v1/terminals/{id}/local"),
    // The gate lets INT, TSTP and CONT through (Ctrl-C, Ctrl-Z, fg: `gate::plain_signal`).
    ("POST", "/api/v1/terminals/{id}/signal"),
    ("DELETE", "/api/v1/terminals/{id}"),
    ("POST", "/api/v1/agent-sessions"),
    ("POST", "/api/v1/agent-sessions/{id}/messages"),
    ("POST", "/api/v1/agent-sessions/{id}/attachments"),
    ("POST", "/api/v1/agent-sessions/{id}/interrupt"),
    (
        "POST",
        "/api/v1/agent-sessions/{id}/subagents/{tool_use_id}/stop",
    ),
    ("POST", "/api/v1/agent-sessions/{id}/mode"),
    // They change files on the runner, as a message could.
    ("POST", "/api/v1/agent-sessions/{id}/files/revert"),
    ("POST", "/api/v1/agent-sessions/{id}/files/write"),
    // Removing a rule makes later calls ask again; it is a deletion like any other.
    ("DELETE", "/api/v1/projects/{id}/approval-rules/{rule}"),
    ("POST", "/api/v1/agent-sessions/{id}/cancel"),
    ("POST", "/api/v1/agent-sessions/{id}/kill"),
    ("POST", "/api/v1/agent-sessions/{id}/resume"),
    ("POST", "/api/v1/agent-sessions/{id}/wake"),
    ("POST", "/api/v1/agent-sessions/{id}/approvals/{request}"),
    ("PUT", "/api/v1/runners/{id}/policy"),
    ("POST", "/api/v1/runners/{id}/tools"),
    ("PUT", "/api/v1/projects/{id}/spec"),
    ("POST", "/api/v1/projects/{id}/run/spec/draft"),
    ("POST", "/api/v1/projects/{id}/run/start"),
    ("POST", "/api/v1/projects/{id}/run/stop"),
    ("POST", "/api/v1/projects/{id}/run/restart"),
    // A run configuration starts a container on a runner, as the project run does (E11-3).
    ("POST", "/api/v1/projects/{id}/run-configs/{config}/run"),
    ("POST", "/api/v1/projects/{id}/runs/{run}/stop"),
];

/// Whether `path` fits `template` segment by segment.
pub(super) fn fits(template: &str, path: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(t, p)| (t.starts_with('{') && t.ends_with('}') && !p.is_empty()) || t == p)
}

/// The scope `method` on `template` declares, by the contract's own path template.
pub fn declared(method: &str, template: &str) -> Option<&'static str> {
    ROUTES
        .iter()
        .find(|(m, t, _)| m.eq_ignore_ascii_case(method) && *t == template)
        .map(|r| r.2)
}

/// Whether `method` on `template` is declared destructive, by the contract's own path template.
pub fn declared_destructive(method: &str, template: &str) -> bool {
    DESTRUCTIVE
        .iter()
        .any(|(m, t)| m.eq_ignore_ascii_case(method) && *t == template)
}

/// `("citadel", "/companies/x")` of `/modules/citadel/v1/companies/x`; `None` for a path that
/// is not under a module's `/v1/` (the module's id is the segment right after `/modules/`).
fn module_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/modules/")?;
    let (id, sub) = rest.split_once('/')?;
    let sub = sub.strip_prefix("v1")?;
    (sub.starts_with('/')).then_some((id, sub))
}

/// The body cap a module route declared (`Module::body_limits`), clamped to the platform maximum.
pub fn module_body_limit(
    modules: &[Arc<dyn Module>],
    method: &Method,
    path: &str,
) -> Option<usize> {
    let (id, sub) = module_path(path)?;
    let m = modules.iter().find(|m| m.id() == id)?;
    m.body_limits()
        .iter()
        .find(|(mm, t, _)| mm.eq_ignore_ascii_case(method.as_str()) && fits(t, sub))
        .map(|(_, _, n)| (*n).min(crate::module::MAX_MODULE_BODY))
}

/// Whether every name of `query` is allowed on a module route: a platform name
/// (`super::QUERY`) or one the path's module declares in `Module::query_names`. Never true for
/// a path outside `/modules/<id>/v1`, nor for another module's names.
pub fn module_query_ok(modules: &[Arc<dyn Module>], path: &str, query: &str) -> bool {
    let Some((id, _)) = module_path(path) else {
        return false;
    };
    let Some(m) = modules.iter().find(|m| m.id() == id) else {
        return false;
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split('=').next().unwrap_or(pair))
        .all(|n| super::QUERY.contains(&n) || m.query_names().contains(&n))
}

/// The segments of `template` that are not `{…}`: how specific it is.
fn literals(template: &str) -> usize {
    template.split('/').filter(|s| !s.starts_with('{')).count()
}

/// How strict a scope is, for resolving a tie: `read` < the others < `admin`.
fn rank(scope: &str) -> u8 {
    match scope {
        "read" => 0,
        "admin" => 2,
        _ => 1,
    }
}

/// The stricter of two scopes; two different ones of the same rank (`approve` and `agent`) are
/// not comparable, so they become `admin`.
fn stricter(a: &'static str, b: &'static str) -> &'static str {
    match (a == b, rank(a).cmp(&rank(b))) {
        (true, _) => a,
        (_, std::cmp::Ordering::Greater) => a,
        (_, std::cmp::Ordering::Less) => b,
        _ => "admin",
    }
}

/// A module's request method as its tables see it: `HEAD` is the `GET` it is served by, so it
/// needs that route's scope and step-up. `None` for a method no module route takes.
fn module_method(method: &str) -> Option<&str> {
    match method {
        m if m.eq_ignore_ascii_case("HEAD") => Some("GET"),
        m if ["GET", "POST", "PUT", "PATCH", "DELETE"]
            .iter()
            .any(|k| k.eq_ignore_ascii_case(m)) =>
        {
            Some(m)
        }
        _ => None,
    }
}

/// The scope `m` needs for `method` on `sub` (relative to its prefix; a contract template or a
/// real path): its own `route_scopes` entry that fits, the most specific, else `Module::scope`.
/// Two equally specific templates that disagree resolve to the stricter scope; an entry whose
/// scope is not allowed on a module route is `admin`. `HEAD` is `GET`; a method no module route
/// takes (`OPTIONS`, `TRACE`) needs `admin`.
pub fn module_scope(m: &dyn Module, method: &str, sub: &str) -> &'static str {
    let Some(method) = module_method(method) else {
        return "admin";
    };
    let mut best: Option<(usize, &'static str)> = None;
    for (mm, t, scope) in m.route_scopes() {
        if !mm.eq_ignore_ascii_case(method) || !fits(t, sub) {
            continue;
        }
        let n = literals(t);
        let scope = if crate::module::route_scope_ok(scope) {
            *scope
        } else {
            "admin"
        };
        best = match best {
            Some((b, _)) if b > n => best,
            Some((b, s)) if b == n => Some((b, stricter(s, scope))),
            _ => Some((n, scope)),
        };
    }
    best.map_or_else(|| m.scope(), |(_, scope)| scope)
}

/// Whether `m` declares `method` on `sub` destructive (`Module::destructive`); `HEAD` is `GET`,
/// and a method no module route takes counts as destructive (it needs `admin` anyway).
pub fn module_destructive(m: &dyn Module, method: &str, sub: &str) -> bool {
    let Some(method) = module_method(method) else {
        return true;
    };
    m.destructive()
        .iter()
        .any(|(mm, t)| mm.eq_ignore_ascii_case(method) && fits(t, sub))
}

/// Whether a module route decides its own approvals (`Module::self_approved`) and is not
/// destructive: Code Mode then leaves the asking to it. Platform routes never are.
pub fn self_approved(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> bool {
    let Some((id, sub)) = module_path(path) else {
        return false;
    };
    let Some(m) = modules.iter().find(|m| m.id() == id) else {
        return false;
    };
    let Some(method) = module_method(method.as_str()) else {
        return false;
    };
    !module_destructive(m.as_ref(), method, sub)
        && m.self_approved()
            .iter()
            .any(|(mm, t)| mm.eq_ignore_ascii_case(method) && fits(t, sub))
}

/// Whether a request needs a live elevation: its route is in [`DESTRUCTIVE`], or in its
/// module's `Module::destructive` (relative to `/modules/<id>/v1`).
pub fn destructive(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> bool {
    if path.starts_with("/modules/") {
        let Some((id, sub)) = module_path(path) else {
            return false;
        };
        return modules
            .iter()
            .filter(|m| m.id() == id)
            .any(|m| module_destructive(m.as_ref(), method.as_str(), sub));
    }
    security_setting(method, path)
        || DESTRUCTIVE
            .iter()
            .any(|(m, t)| *m == method.as_str() && fits(t, path))
}

/// A write to a security setting (`auth.*`: the step-up window, passkey admin): changing one
/// weakens the danger list itself, so it is danger too.
fn security_setting(method: &Method, path: &str) -> bool {
    (*method == Method::PUT || *method == Method::DELETE)
        && path
            .strip_prefix("/api/v1/settings/")
            .and_then(|rest| rest.split_once('/'))
            // Fail closed: a `%` could spell `auth.` after decoding, so it is danger here; the
            // handler decides from the parsed key (`settings::guard`).
            .is_some_and(|(_, key)| key.starts_with("auth.") || key.contains('%'))
}

/// Whether a request needs the app unlock (E1-2, E1-3, D-6): a route in [`UNLOCKED`], or in its
/// module's `Module::needs_unlock`. The unlock is the app's one Touch ID at open; no per-action prompt.
pub fn needs_unlock(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> bool {
    let Some((id, sub)) = module_path(path) else {
        return UNLOCKED
            .iter()
            .any(|(m, t)| *m == method.as_str() && fits(t, path));
    };
    let Some(method) = module_method(method.as_str()) else {
        return false;
    };
    modules
        .iter()
        .filter(|m| m.id() == id)
        .flat_map(|m| m.needs_unlock())
        .any(|(mm, t)| mm.eq_ignore_ascii_case(method) && fits(t, sub))
}

/// The declared template of the destructive route `method path` is (a module's with its
/// `/modules/<id>/v1` prefix), so a per-route key stays bounded however many ids a caller varies.
/// `None` when no template matches.
pub fn destructive_template(
    method: &Method,
    path: &str,
    modules: &[Arc<dyn Module>],
) -> Option<String> {
    if path.starts_with("/modules/") {
        let (id, sub) = module_path(path)?;
        let method = module_method(method.as_str())?;
        return modules
            .iter()
            .filter(|m| m.id() == id)
            .flat_map(|m| m.destructive())
            .find(|(mm, t)| mm.eq_ignore_ascii_case(method) && fits(t, sub))
            .map(|(_, t)| format!("/modules/{id}/v1{t}"));
    }
    DESTRUCTIVE
        .iter()
        .find(|(m, t)| *m == method.as_str() && fits(t, path))
        .map(|(_, t)| (*t).to_owned())
}

/// The scope a request needs; `None` when nothing declares one (refused).
pub fn required(method: &Method, path: &str, modules: &[Arc<dyn Module>]) -> Option<&'static str> {
    if path.starts_with("/modules/") {
        let (id, sub) = module_path(path)?;
        return modules
            .iter()
            .find(|m| m.id() == id)
            .map(|m| module_scope(m.as_ref(), method.as_str(), sub));
    }
    // A WebSocket upgrade is a GET.
    ROUTES
        .iter()
        .find(|(m, t, _)| *m == method.as_str() && fits(t, path))
        .map(|r| r.2)
}

#[cfg(test)]
mod tests;
