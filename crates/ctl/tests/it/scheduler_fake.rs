//! The fake Core of the scheduler CLI tests: the contract's answers (S7, `api/openapi.json`)
//! for chains, sessions, accounts and settings, a Core that wants a step-up, and a device paired
//! to it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ainkrad_ctl::keystore::Keystore;
use ainkrad_ctl::proto::Key;
use ainkrad_ctl::stepup;
use serde_json::{Value, json};

use crate::common::*;
use crate::fake::{Answer, Fake, PINNED, proof, test_core};

pub const DEVICE: &str = "d_00000000000000000000000000";
pub const SESSION: &str = "as_0000000000000000000000000a";
pub const CHAIN: &str = r#"{"id":1,"name":"main","is_default":true,"created_at":"2026-11-06T00:00:00.000Z","updated_at":"2026-11-06T01:00:00.000Z","entries":[{"pool":2,"provider":"anthropic","harness":"claude","model":"sonnet-x"},{"pool":5,"provider":"openai","harness":"codex","model":null}]}"#;

pub fn refusal(status: u16, code: &str, message: &str) -> (u16, String) {
    (
        status,
        json!({"error": code, "code": code, "message": message}).to_string(),
    )
}

/// The handshake and session every request opens with.
pub fn prelude(method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    let ch = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    Some(match (method, path) {
        ("POST", "/handshake") => proof(test_core(), body),
        ("POST", "/handshake/challenge" | "/api/v1/auth/step-up/challenge") => {
            (200, format!(r#"{{"challenge":"{ch}","expires_in":60}}"#))
        }
        ("POST", "/handshake/session") => (
            200,
            r#"{"session_id":"s_00000000000000000000000000","expires_at":"2099-01-01T00:00:00.000Z","scopes":["admin"]}"#.into(),
        ),
        ("POST", "/api/v1/auth/step-up") => {
            ELEVATED.store(true, Ordering::SeqCst);
            (200, r#"{"elevated_until":"2099-01-01T00:05:00.000Z"}"#.into())
        }
        _ => return None,
    })
}

pub fn body_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_default()
}

/// The Core of every test but the step-up ones: every write goes through.
pub fn core(method: &str, path: &str, body: &str) -> (u16, String) {
    if let Some(a) = prelude(method, path, body) {
        return a;
    }
    let b = body_json(body);
    match (method, path) {
        ("GET", "/api/v1/chains") => (200, format!("[{CHAIN}]")),
        ("GET", "/api/v1/chains/1") | ("PUT", "/api/v1/chains/1/default") => (200, CHAIN.into()),
        ("GET" | "DELETE" | "PUT", "/api/v1/chains/404")
        | ("PUT", "/api/v1/chains/404/default") => refusal(404, "not_found", "no such chain"),
        ("POST", "/api/v1/chains") => match b["name"].as_str() {
            Some("dup") => refusal(409, "conflict", "a chain of that name exists"),
            Some("bad") => refusal(400, "bad_request", "a pool is in the chain twice"),
            Some("ghost") => refusal(404, "not_found", ""),
            _ => (200, CHAIN.into()),
        },
        ("PUT", "/api/v1/chains/1") => (200, CHAIN.into()),
        ("DELETE", "/api/v1/chains/1") => (200, r#"{"deleted":true}"#.into()),
        ("DELETE", "/api/v1/chains/2") => {
            refusal(409, "conflict", "1 live session(s) walk the chain")
        }
        ("GET", "/api/v1/chains/bindings") => (200, r#"[{"agent":"bot","chain":1}]"#.into()),
        ("PUT", "/api/v1/chains/bindings/bot") => (200, r#"{"agent":"bot","chain":1}"#.into()),
        ("DELETE", "/api/v1/chains/bindings/bot") => (200, r#"{"deleted":true}"#.into()),
        ("DELETE", "/api/v1/chains/bindings/none") => {
            refusal(404, "not_found", "that agent has no binding")
        }
        ("GET", "/api/v1/accounts") => (200, format!("[{ACCOUNT},{PLAIN}]")),
        ("GET", "/api/v1/accounts/7") => (200, ACCOUNT.into()),
        ("GET", "/api/v1/settings") => (200, format!("[{HOPS},{WAIT},{BURST}]")),
        ("GET" | "PUT", "/api/v1/settings/server/scheduler.max_hops") => {
            match b["value"].as_i64() {
                Some(n) if n > 8 => refusal(400, "out_of_bounds", "scheduler.max_hops is 0 to 8"),
                _ => (200, HOPS.into()),
            }
        }
        ("DELETE", "/api/v1/settings/server/scheduler.max_hops") => (200, HOPS.into()),
        ("GET" | "PUT", "/api/v1/settings/server/nope") => {
            refusal(404, "not_found", "no such setting")
        }
        ("GET", "/api/v1/agent-sessions") => (200, format!("[{SESSION_JSON}]")),
        ("POST", p) if p == format!("/api/v1/agent-sessions/{SESSION}/wake") => (
            200,
            format!(r#"{{"session":"{SESSION}","key":"k1","queued":true}}"#),
        ),
        ("POST", "/api/v1/agent-sessions/as_000000000000000000000000p0/wake") => refusal(
            409,
            "failed_over",
            "the session was replaced: wake as_0000000000000000000000000b",
        ),
        ("POST", "/api/v1/agent-sessions") => (200, session_for(&b)),
        ("GET", p) if p == format!("/api/v1/agent-sessions/{SESSION}") => {
            (200, SESSION_JSON.into())
        }
        ("GET", p) if p == format!("/api/v1/agent-sessions/{SESSION}/transcript") => (
            200,
            r#"{"state":"starting","entries":[{"seq":1,"body":"hello"}]}"#.into(),
        ),
        _ => (500, "{}".into()),
    }
}

pub const ACCOUNT: &str = r#"{"id":7,"provider":"anthropic","label":"work","masked_tail":"abcd","base_url":"https://x","state":"cooling","state_reason":"rate_limited","state_until":"2026-11-06T02:00:00.000Z","cap":3,"live":2,"created_at":"T","updated_at":"T","health":{"fail_streak":1,"auth_streak":0,"last_success_at":"2026-11-06T01:30:00.000Z","upstream_class":"rate_limited","plan_limit":{"status":"allowed_warning","at":"2026-11-06T01:31:00.000Z","windows":[{"name":"five_hour","utilization":0.834,"resets_at":"2026-11-06T05:00:00.000Z"},{"name":"seven_day","utilization":0.2}]}}}"#;
pub const PLAIN: &str = r#"{"id":8,"provider":"openai","label":"home","masked_tail":"wxyz","base_url":"https://y","state":"active","cap":0,"live":0,"created_at":"T","updated_at":"T","health":{"fail_streak":0,"auth_streak":0}}"#;
pub const HOPS: &str = r#"{"key":"scheduler.max_hops","description":"d","unit":"count","default":3,"min":0,"max":8,"scopes":["server"],"value":3}"#;
pub const WAIT: &str = r#"{"key":"scheduler.wait_max_secs","description":"d","unit":"seconds","default":900,"min":1,"max":86400,"scopes":["server"],"value":600,"source":"server"}"#;
pub const BURST: &str = r#"{"key":"api.request_burst","description":"d","unit":"count","default":60,"min":1,"max":1000,"scopes":["server"],"value":60}"#;
pub const SESSION_JSON: &str = r#"{"id":"as_0000000000000000000000000a","runner":"d_00000000000000000000000000","harness":"claude","state":"starting","last_seq":1,"created_by":"d","created_at":"2026-11-06T00:00:00.000Z","updated_at":"T","usage":{"input":0,"output":0},"agent":"bot","chain_id":1,"chain_pos":1,"account":9,"repicked":1,"upstream_class":"rate_limited","run":"as_00000000000000000000000000","attempt":1,"failover_of":"as_000000000000000000000000p0","failed_over_to":null,"failover_class":"quota","skip_pools":[2],"waiting":{"until":"2026-11-06T00:10:00.000Z","since":"2026-11-06T00:00:00.000Z","why":"every account is cooling"},"chain":[{"pool":2,"provider":"anthropic","harness":"claude","model":"sonnet-x"},{"pool":5,"provider":"openai","harness":"codex","model":null}]}"#;

/// A created session echoing the request's runner and harness, as the Core does.
pub fn session_for(b: &Value) -> String {
    json!({"id": SESSION, "runner": b["runner"], "harness": b["harness"], "state": "starting",
        "last_seq": 0, "created_by": "d", "created_at": "T", "updated_at": "T",
        "usage": {"input": 0, "output": 0}})
    .to_string()
}

pub static ELEVATED: AtomicBool = AtomicBool::new(false);
pub static GATED: AtomicUsize = AtomicUsize::new(0);

/// A Core that wants a step-up for `POST /chains` until the device has elevated.
pub fn gated(method: &str, path: &str, body: &str) -> (u16, String) {
    if (method, path) == ("POST", "/api/v1/chains") {
        GATED.fetch_add(1, Ordering::SeqCst);
        if !ELEVATED.load(Ordering::SeqCst) {
            return refusal(403, "step_up_required", "elevate first");
        }
    }
    core(method, path, body)
}

/// A fake Core running `answer`, and a device paired to it (with a step-up key when `stepup`).
pub fn device(name: &str, answer: Answer, stepup: bool) -> (Fake, String) {
    let dir = std::env::temp_dir().join(format!("ctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fake = Fake::start(dir.join("f.sock"), answer);
    let ks = dir.join("ks").join("keystore.json");
    Keystore {
        device_id: DEVICE.into(),
        core_fp: PINNED.into(),
        endpoint: format!("unix:{}", fake.sock.display()),
        host: None,
        key: Key::generate(),
    }
    .save(&ks)
    .unwrap();
    if stepup {
        let path = stepup::path_for(&ks);
        stepup::save(
            &path,
            &Key::generate(),
            PASSPHRASE.as_bytes(),
            DEVICE,
            PINNED,
        )
        .unwrap();
    }
    (fake, ks.display().to_string())
}
