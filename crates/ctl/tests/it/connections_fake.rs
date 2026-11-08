//! The fake Core of the connection CLI tests: the contract's shapes (C5, `api/openapi.json`) for
//! connections, grants, defaults, apps and sign-in flows, with the refusals the real Core gives.
//! Flows are scripted per name (the `name` of the start request), polled in order.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

use crate::common::*;
use crate::scheduler_fake::{body_json, core, prelude, refusal};

pub const CONN: &str = r#"{"id":3,"kind":"github","name":"work","label":"","auth_method":"token","status":"active","disabled":false,"is_default":true,"identity":"octocat","created_at":"T","updated_at":"T","last_tested_at":"2026-11-07T00:00:00.000Z","grant_count":2}"#;
pub const JIRA: &str = r#"{"id":4,"kind":"jira","name":"acme","label":"team","auth_method":"oauth","status":"auth_suspected","state_reason":"auth_suspected","state_until":"2026-11-07T01:00:00.000Z","disabled":true,"is_default":false,"identity":null,"created_at":"T","updated_at":"T","grant_count":0}"#;
pub const KINDS: &str = r#"[{"kind":"github","title":"GitHub","summary":"s","configured":true,"auth_methods":[{"id":"oauth","title":"Sign in","help":"h","steps":[],"advanced":false,"available":true},{"id":"token","title":"Token","help":"h","steps":[],"advanced":true,"available":true},{"id":"app_install","title":"App","help":"h","steps":[],"advanced":true,"available":false}],"capabilities":[{"name":"read_repo","title":"Read repositories","class":"read","write":false},{"name":"issues_write","title":"Change issues","class":"issues","write":true}],"limits":[{"key":"repos","title":"Repositories","help":"owner/name list"}]},{"kind":"jira","title":"Jira","summary":"s","configured":false,"auth_methods":[],"capabilities":[],"limits":[]}]"#;
pub const GRANT: &str = r#"{"grantee_kind":"agent","grantee":"bot","capabilities":["read_repo","issues_write"],"limits":{"repos":["a/b","c/d"]},"created_at":"T","updated_at":"T"}"#;
pub const APP: &str = r#"{"kind":"github","configured":true,"app_install_configured":false,"redirect_uri":"http://127.0.0.1:47613/callback","fields":[{"name":"client_id","title":"Client id","secret":false,"set":true,"value":"abc"},{"name":"client_secret","title":"Client secret","secret":true,"set":true,"value":null}]}"#;

/// Which flow views have been served: `(flow id) -> polls`.
fn polls() -> &'static Mutex<HashMap<String, usize>> {
    static P: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

pub static ELEVATED: AtomicBool = AtomicBool::new(false);

fn view(id: &str, step: &str, extra: Value) -> String {
    let mut v = json!({"id": id, "kind": "x", "step": step, "expires_in_secs": 300, "sites": []});
    for (k, e) in extra.as_object().into_iter().flatten() {
        v[k] = e.clone();
    }
    v.to_string()
}

const SITES: &str = r#"[{"id":"cloud-1","name":"Acme","url":"https://acme.atlassian.example"},{"id":"cloud-2","name":"Beta","url":"https://beta.atlassian.example"}]"#;

/// The flow `id` (`cf_<name>`) at its n-th poll.
fn flow_view(id: &str) -> String {
    let n = {
        let mut p = polls().lock().unwrap();
        let n = p.entry(id.to_owned()).or_insert(0);
        *n += 1;
        *n
    };
    // `name_suffix` runs the scenario `name` again under its own flow id.
    let name = id.trim_start_matches("cf_").split('_').next().unwrap_or("");
    match (name, n) {
        ("devok", 1) => view(id, "waiting", json!({"interval": 0})),
        ("devok", 2) => view(id, "approved", json!({"interval": 0})),
        ("devok", _) => view(
            id,
            "connected",
            json!({"identity": "octocat", "connection": 5}),
        ),
        ("devdenied", _) => view(id, "denied", json!({})),
        ("devexpired", _) => view(id, "expired", json!({})),
        ("devfailed", _) => view(
            id,
            "failed",
            json!({"error_code": "scope_missing", "error_message": "GitHub did not grant repo access: sign in again and allow it"}),
        ),
        ("jiraok", 1) => view(id, "approved", json!({"interval": 0})),
        ("jiraok", _) => view(
            id,
            "connected",
            json!({"identity": "me@acme", "connection": 6}),
        ),
        // Waits for ever (until cancelled).
        _ => view(id, "waiting", json!({"interval": 1})),
    }
}

fn start(body: &Value) -> (u16, String) {
    let full = body["name"].as_str().unwrap_or("devok");
    let name = full.split('_').next().unwrap_or(full);
    let id = format!("cf_{full}");
    polls().lock().unwrap().remove(&id);
    if name.starts_with("jira") || name == "canceljira" {
        return (
            200,
            view(
                &id,
                "waiting",
                json!({"authorize_url": "https://auth.atlassian.example/authorize?x=1", "state": "st1", "interval": 0}),
            ),
        );
    }
    (
        200,
        view(
            &id,
            "waiting",
            json!({"user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device", "interval": if name.starts_with("cancel") { 1 } else { 0 }}),
        ),
    )
}

/// Every route of the connections surface; a write goes through unless the test needs a
/// refusal.
pub fn conns(method: &str, path: &str, body: &str) -> (u16, String) {
    if (method, path) == ("POST", "/api/v1/auth/step-up") {
        ELEVATED.store(true, Ordering::SeqCst);
    }
    if let Some(a) = prelude(method, path, body) {
        return a;
    }
    let b = body_json(body);
    let token = b["token"].as_str().unwrap_or("");
    match (method, path) {
        ("GET", "/api/v1/connection-kinds") => (200, KINDS.into()),
        ("GET", "/api/v1/connections") => (200, format!("[{CONN},{JIRA}]")),
        ("GET", "/api/v1/connections/3") => (200, CONN.into()),
        ("GET", "/api/v1/connections/4") => (200, JIRA.into()),
        ("GET" | "POST" | "PATCH" | "PUT", "/api/v1/connections/404") | ("POST", "/api/v1/connections/404/test") => {
            refusal(404, "not_found", "no such connection")
        }
        ("POST", "/api/v1/connections") if token.starts_with("REJECT") => {
            refusal(400, "credential_rejected", "the service refused that credential")
        }
        ("POST" | "PUT", "/api/v1/connections" | "/api/v1/connections/3/credential") if token.starts_with("ECHO") => {
            refusal(400, "bad_request", &format!("odd token {token}"))
        }
        ("POST", "/api/v1/connections") => (200, CONN.into()),
        ("PUT", "/api/v1/connections/3/credential") => (200, CONN.into()),
        ("POST", "/api/v1/connections/3/test") => (200, CONN.into()),
        ("POST", "/api/v1/connections/4/test") => (200, JIRA.into()),
        ("POST", "/api/v1/connections/6/test") => refusal(429, "rate_limited", "too many requests; retry later"),
        ("PATCH", "/api/v1/connections/3") => {
            let mut v: Value = serde_json::from_str(CONN).unwrap();
            if let Some(n) = b["name"].as_str() {
                v["name"] = json!(n);
            }
            if let Some(d) = b["disabled"].as_bool() {
                v["disabled"] = json!(d);
            }
            (200, v.to_string())
        }
        ("DELETE", "/api/v1/connections/3") => refusal(409, "conflict", "connection 3 is its kind's default"),
        ("DELETE", "/api/v1/connections/4") => (200, r#"{"deleted":true}"#.into()),
        ("GET", "/api/v1/connections/3/grants") => (200, format!("[{GRANT}]")),
        ("PUT", "/api/v1/connections/3/grants") => (200, GRANT.into()),
        ("PUT", "/api/v1/connections/404/grants") => refusal(404, "not_found", "no such connection"),
        ("DELETE", "/api/v1/connections/3/grants/agent/bot") => (200, r#"{"deleted":true}"#.into()),
        ("GET", "/api/v1/connections/3/activity") => (
            200,
            r#"[{"seq":9,"at":"2026-11-07T00:00:00.000Z","kind":"call","action":"issues.create","result":"ok","agent":"bot","session":"as_1"},{"seq":8,"at":"2026-11-06T00:00:00.000Z","kind":"test"}]"#.into(),
        ),
        ("GET", "/api/v1/connection-defaults") => (200, r#"[{"kind":"github","connection":3}]"#.into()),
        ("PUT", "/api/v1/connection-defaults/github") => (200, r#"{"kind":"github","connection":3}"#.into()),
        ("DELETE", "/api/v1/connection-defaults/github") => (200, r#"{"deleted":true}"#.into()),
        ("GET", "/api/v1/connection-apps/github") => (200, APP.into()),
        ("PUT", "/api/v1/connection-apps/github") => (200, APP.into()),
        ("GET", "/api/v1/connection-apps/jira") => (
            200,
            r#"{"kind":"jira","configured":false,"app_install_configured":false,"fields":[]}"#.into(),
        ),
        ("PUT", "/api/v1/connection-apps/jira") => {
            refusal(403, "forbidden_scope", "only the Core's owner changes Ainkrad's sign-in apps")
        }
        ("POST", "/api/v1/connections/start") => start(&b),
        ("GET", p) if p.starts_with("/api/v1/connections/flows/") => {
            (200, flow_view(p.trim_start_matches("/api/v1/connections/flows/")))
        }
        ("DELETE", p) if p.starts_with("/api/v1/connections/flows/") => (200, r#"{"deleted":true}"#.into()),
        ("POST", p) if p.ends_with("/callback") => {
            let id = p.trim_start_matches("/api/v1/connections/flows/").trim_end_matches("/callback");
            if b["state"] != "st1" {
                return refusal(400, "bad_state", "that redirect is not for this sign-in");
            }
            (200, view(id, "choose_site", json!({"sites": serde_json::from_str::<Value>(SITES).unwrap()})))
        }
        ("POST", p) if p.ends_with("/choose") => {
            let id = p.trim_start_matches("/api/v1/connections/flows/").trim_end_matches("/choose");
            match b["site"].as_str() {
                Some("cloud-2") => (200, view(id, "approved", json!({"interval": 0}))),
                _ => refusal(400, "bad_site", "that site is not in the list"),
            }
        }
        _ => core(method, path, body),
    }
}

/// A Core that wants a step-up for `POST /connections` until the device has elevated.
pub fn gated(method: &str, path: &str, body: &str) -> (u16, String) {
    if (method, path) == ("POST", "/api/v1/connections") && !ELEVATED.load(Ordering::SeqCst) {
        return refusal(403, "step_up_required", "elevate first");
    }
    conns(method, path, body)
}

/// The recorded requests whose request line starts with `line` (lower-cased).
pub fn matching(fake: &crate::fake::Fake, line: &str) -> Vec<String> {
    fake.requests()
        .into_iter()
        .filter(|r| r.starts_with(line))
        .collect()
}

/// The JSON body of a recorded request (what follows its last header line).
pub fn body_of(request: &str) -> Value {
    body_json(request.rsplit("\r\n").next().unwrap_or_default())
}

/// Reads stdout and stderr and the status of a finished run.
pub fn text(o: &std::process::Output) -> (String, String) {
    (stdout(o), String::from_utf8_lossy(&o.stderr).into_owned())
}
