//! The fake Core of the account CLI tests: the contract's shapes (`api/openapi.json`) for
//! accounts, sign-ins, pools, budgets, usage and costs, with the refusals the real Core gives.
//! A sign-in is scripted by its label (the id is `al_<label>`) and polled in order.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

use crate::scheduler_fake::{body_json, core, prelude, refusal};

/// Set by the step-up route; the tests of the step-up reset it.
pub static ELEVATED: AtomicBool = AtomicBool::new(false);

pub const ACCT: &str = r#"{"id":9,"provider":"anthropic","label":"work","masked_tail":"wxyz","base_url":"https://api.example","state":"active","cap":4,"live":0,"created_at":"T","updated_at":"T","health":{"fail_streak":0,"auth_streak":0}}"#;
pub const ACCT_ROW: &str = "9\tanthropic\twork\tactive\tlive 0/4\tfail 0 auth 0\n";
const POOLS: &str = r#"[{"id":2,"name":"main","provider":"anthropic","is_default":true,"members":[7,9],"created_at":"T","updated_at":"T"},{"id":3,"name":"subs","provider":"claude-sub","is_default":false,"members":[],"created_at":"T","updated_at":"T"}]"#;
const BUDGET: &str = r#"{"id":4,"kind":"account","subject":"9","period":"month","token_cap":1000000,"spent":250,"usd_spent":1500,"usd_cap_micros":5000000,"warn_at_percent":80,"hard_stop":true,"exhausted":false,"period_key":"2026-11","raised":0,"raised_usd":0,"held":0,"held_usd":0,"created_at":"T","updated_at":"T"}"#;
const USAGE: &str = r#"[{"account_id":7,"five_hours":{"input_tokens":1,"output_tokens":2,"cache_tokens":3,"total_tokens":1200,"messages":3,"cost_usd_micros":15000},"seven_days":{"input_tokens":1,"output_tokens":2,"cache_tokens":3,"total_tokens":9000,"messages":30,"cost_usd_micros":150000},"limits":[{"unit":"tokens","window_secs":18000,"cap":100000,"used":1200,"warn_percent":80,"exhausted":false}],"max_utilisation_bps":8340,"recent_drops":1,"by_company":[]}]"#;
const COSTS: &str = r#"[{"id":9,"session":"as_1","epoch":2,"provider":"anthropic","harness":"claude","model":"sonnet-x","input_tokens":10,"output_tokens":20,"cache_tokens":30,"basis":"list_price","approximate":false,"cost_usd_micros":1234,"account_id":7,"occurred_at":"2026-11-07T00:00:00.000Z"},{"id":8,"session":"as_1","epoch":1,"provider":"anthropic","harness":"claude","model":"sonnet-x","input_tokens":1,"output_tokens":2,"cache_tokens":3,"basis":"unpriced","approximate":true,"account_id":null,"occurred_at":"2026-11-06T00:00:00.000Z"}]"#;
const PROVIDERS: &str = r#"[{"id":"anthropic","name":"Anthropic","harness":"claude","auth_var":"X","base_url":"https://api.example","usage_parser":"p","delivery":["env","gateway"],"login_methods":["paste"],"models":[],"builtin":true},{"id":"claude-sub","name":"Claude subscription","harness":"claude","auth_var":"X","base_url":"https://claude.example","usage_parser":"p","delivery":["env"],"login_methods":["browser"],"models":[],"builtin":true}]"#;

/// Per sign-in: `(code sent, polls since the code)`.
fn logins() -> &'static Mutex<HashMap<String, (bool, usize)>> {
    static L: OnceLock<Mutex<HashMap<String, (bool, usize)>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

fn account_with(patch: Value) -> String {
    let mut v: Value = serde_json::from_str(ACCT).unwrap();
    for (k, e) in patch.as_object().into_iter().flatten() {
        v[k] = e.clone();
    }
    v.to_string()
}

fn pool_with(patch: Value) -> String {
    let mut v: Value = serde_json::from_str(&POOLS[1..POOLS.find("},{").unwrap() + 1]).unwrap();
    for (k, e) in patch.as_object().into_iter().flatten() {
        v[k] = e.clone();
    }
    v.to_string()
}

fn login_view(id: &str, state: &str, extra: Value) -> String {
    let mut v = json!({"id": id, "provider": "claude-sub", "label": id.trim_start_matches("al_"), "runner": "d_runner1",
        "state": state, "created_at": "T", "updated_at": "T", "expires_at": "T"});
    for (k, e) in extra.as_object().into_iter().flatten() {
        v[k] = e.clone();
    }
    v.to_string()
}

const URL: &str = "https://claude.example/oauth/authorize?x=1";

/// The sign-in `id` polled: `open_url` until the code is sent, then `storing`, then its end.
fn poll(id: &str) -> String {
    let (sent, n) = {
        let mut l = logins().lock().unwrap();
        let e = l.entry(id.to_owned()).or_insert((false, 0));
        if e.0 {
            e.1 += 1;
        }
        *e
    };
    let label = id.trim_start_matches("al_");
    match (label.split('_').next().unwrap_or(""), sent, n) {
        ("cored", ..) => login_view(id, "cancelled", json!({"reason": "cancelled"})),
        (_, false, _) => login_view(id, "open_url", json!({"url": URL})),
        ("failed", true, _) => login_view(
            id,
            "failed",
            json!({"reason": "the provider refused the code"}),
        ),
        (_, true, 1) => login_view(id, "storing", json!({})),
        _ => login_view(id, "done", json!({"account_id": 11})),
    }
}

pub fn accounts(method: &str, path: &str, body: &str) -> (u16, String) {
    // The step-up is this Core's own: the shared prelude would raise the other fakes' flag too,
    // and their step-up tests (running beside these) would see a device already elevated.
    if (method, path) == ("POST", "/api/v1/auth/step-up") {
        ELEVATED.store(true, Ordering::SeqCst);
        return (
            200,
            r#"{"elevated_until":"2099-01-01T00:05:00.000Z"}"#.into(),
        );
    }
    if let Some(a) = prelude(method, path, body) {
        return a;
    }
    let b = body_json(body);
    let text = |k: &str| b[k].as_str().unwrap_or("").to_owned();
    match (method, path) {
        ("POST", "/api/v1/accounts") => {
            let v = text("value");
            match (text("label").as_str(), v.as_str()) {
                (_, v) if v.starts_with("REJECT") => refusal(400, "bad_request", "that key is not shaped like an anthropic key"),
                (_, v) if v.starts_with("ECHO") => refusal(400, "bad_request", &format!("odd key {v}")),
                ("dup", _) => refusal(409, "conflict", "an account labelled dup exists"),
                ("full", _) => refusal(409, "limit_reached", "the account limit is reached"),
                _ => (
                    200,
                    format!(
                        r#"{{"account":{},"runners":{}}}"#,
                        account_with(json!({"provider": b["provider"], "label": b["label"], "cap": b["cap"].as_i64().unwrap_or(4)})),
                        b["runners"].as_array().map_or("[]".into(), |_| b["runners"].to_string())
                    ),
                ),
            }
        }
        ("GET", "/api/v1/accounts/providers") => (200, PROVIDERS.into()),
        ("GET", "/api/v1/accounts/usage") => (200, USAGE.into()),
        ("GET", "/api/v1/costs") => (200, COSTS.into()),
        ("POST", "/api/v1/accounts/logins") => match text("label").as_str() {
            "norunner" => refusal(409, "no_runner", "no runner is ready with the claude harness and sign-in support"),
            l => {
                logins().lock().unwrap().remove(&format!("al_{l}"));
                (200, login_view(&format!("al_{l}"), "starting", json!({})))
            }
        },
        ("GET", p) if p.starts_with("/api/v1/accounts/logins/") => (200, poll(p.trim_start_matches("/api/v1/accounts/logins/"))),
        ("DELETE", p) if p.starts_with("/api/v1/accounts/logins/") => {
            let id = p.trim_start_matches("/api/v1/accounts/logins/");
            (200, login_view(id, "cancelled", json!({"reason": "cancelled"})))
        }
        ("POST", p) if p.starts_with("/api/v1/accounts/logins/") && p.ends_with("/code") => {
            let id = p.trim_start_matches("/api/v1/accounts/logins/").trim_end_matches("/code");
            if text("code").starts_with("WRONG") {
                return refusal(400, "bad_request", &format!("the provider refused {}", text("code")));
            }
            logins().lock().unwrap().insert(id.to_owned(), (true, 0));
            (200, login_view(id, "waiting_code", json!({"url": URL})))
        }
        ("PUT", "/api/v1/accounts/9/state") => match text("state").as_str() {
            "bogus" => refusal(400, "bad_request", "no such state"),
            st => (200, account_with(json!({"state": st, "state_reason": b["reason"], "state_until": b["until"]}))),
        },
        ("PUT", "/api/v1/accounts/9/cap") => match b["cap"].as_i64() {
            Some(n) if n > 64 => refusal(400, "bad_request", "the cap is 0 to 64"),
            n => (200, account_with(json!({"cap": n}))),
        },
        ("PUT", "/api/v1/accounts/9/limits") => (200, json!({"account_id": 9, "unit": b["unit"], "window_secs": b["window_secs"], "cap": b["cap"], "warn_percent": b["warn_percent"]}).to_string()),
        ("DELETE", "/api/v1/accounts/9/limits/tokens/18000") => (200, r#"{"cleared":true}"#.into()),
        ("DELETE", "/api/v1/accounts/9/limits/messages/60") => (200, r#"{"cleared":false}"#.into()),
        ("PUT", "/api/v1/accounts/9/session-limits") => (200, account_with(json!({"session_limits": b}))),
        ("PUT", "/api/v1/accounts/9/secret") if text("value").starts_with("ECHO") => {
            refusal(400, "bad_request", &format!("odd key {}", text("value")))
        }
        ("PUT", "/api/v1/accounts/9/secret") => (200, format!(r#"{{"account":{ACCT},"runners":["d_runner1"]}}"#)),
        ("POST", "/api/v1/accounts/9/test") => (200, r#"{"result":"ok","latency_ms":123,"runner":"d_runner1"}"#.into()),
        ("POST", "/api/v1/accounts/10/test") => (200, r#"{"result":"inconclusive","latency_ms":0,"runner":""}"#.into()),
        ("POST", "/api/v1/accounts/11/test") => refusal(429, "rate_limited", "tested within a minute"),
        ("POST", "/api/v1/accounts/12/test") => refusal(409, "no_runner", "no runner is online in the key's scope"),
        ("DELETE", "/api/v1/accounts/9") => (200, r#"{"deleted":true}"#.into()),
        (_, p) if p.starts_with("/api/v1/accounts/404") => refusal(404, "not_found", "no such account"),
        ("GET", "/api/v1/pools") => (200, POOLS.into()),
        ("POST", "/api/v1/pools") => match text("name").as_str() {
            "dup" => refusal(409, "conflict", "a pool named dup exists"),
            n => (200, pool_with(json!({"id": 6, "name": n, "provider": b["provider"], "is_default": false, "members": []}))),
        },
        ("PUT", "/api/v1/pools/2/members/8") => refusal(400, "bad_request", "account 8 is an openai account, pool 2 is anthropic's"),
        ("PUT", "/api/v1/pools/3/members/10") => refusal(409, "conflict", "a subscription account is always alone in its pool: pool 3 already has one"),
        ("PUT", "/api/v1/pools/2/members/5") => (200, pool_with(json!({"members": [7, 9, 5]}))),
        ("DELETE", "/api/v1/pools/2/members/9") => (200, pool_with(json!({"members": [7]}))),
        ("PUT", "/api/v1/pools/3/default") => (200, pool_with(json!({"id": 3, "name": "subs", "provider": "claude-sub", "is_default": true, "members": []}))),
        ("DELETE", "/api/v1/pools/2") => refusal(409, "conflict", "pool 2 is used by chain 1"),
        ("DELETE", "/api/v1/pools/3") => (200, r#"{"deleted":true}"#.into()),
        (_, p) if p.starts_with("/api/v1/pools/404") => refusal(404, "not_found", "no such pool"),
        ("GET", "/api/v1/budgets") => (200, format!("[{BUDGET}]")),
        ("PUT", "/api/v1/budgets") if text("kind") == "bogus" => refusal(400, "bad_request", "no such kind"),
        ("PUT", "/api/v1/budgets") => {
            let mut v: Value = serde_json::from_str(BUDGET).unwrap();
            for (k, f) in [("token_cap", "token_cap"), ("usd_cap_micros", "usd_cap_micros"), ("warn_at_percent", "warn_at_percent"), ("hard_stop", "hard_stop"), ("period", "period")] {
                if !b[f].is_null() {
                    v[k] = b[f].clone();
                }
            }
            (200, v.to_string())
        }
        ("POST", "/api/v1/budgets/4/raise") => (200, BUDGET.into()),
        ("DELETE", "/api/v1/budgets/4") => (200, r#"{"deleted":true}"#.into()),
        ("DELETE", "/api/v1/budgets/5") => (200, r#"{"deleted":false}"#.into()),
        _ => core(method, path, body),
    }
}

/// A Core that wants a step-up for the writes of accounts until the device has elevated.
pub fn gated(method: &str, path: &str, body: &str) -> (u16, String) {
    if (method, path) == ("POST", "/api/v1/accounts") && !ELEVATED.load(Ordering::SeqCst) {
        return refusal(403, "step_up_required", "elevate first");
    }
    accounts(method, path, body)
}
