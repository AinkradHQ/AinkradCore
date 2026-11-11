use super::*;

/// E1-04.2: a module's kinds and actions are listed next to the platform's.
#[test]
fn the_contract_lists_registered_kinds_and_actions() {
    struct Toy;
    impl Module for Toy {
        fn id(&self) -> &'static str {
            "toy"
        }
        fn routes(&self) -> axum::Router<crate::api::App> {
            axum::Router::new()
        }
        fn event_kinds(&self) -> &'static [&'static str] {
            &["toy.line"]
        }
        fn audit_actions(&self) -> &'static [&'static str] {
            &["toy.made"]
        }
    }
    let spec: Value = serde_json::from_str(&json_for(&[Arc::new(Toy)])).unwrap();
    let s = &spec["components"]["schemas"];
    assert_eq!(
        s["Event"]["x-event-kinds"],
        json!([
            "account.budget",
            "account.expired",
            "account.failover",
            "account.health",
            "account.limited",
            "account.login.done",
            "account.login.failed",
            "account.login.started",
            "account.login.url",
            "agent.approval_decided",
            "agent.approval_requested",
            "agent.created",
            "agent.ended",
            "agent.message",
            "agent.state",
            "agent.transcript",
            "alarm.cleared",
            "alarm.raised",
            "audit",
            "connection.health",
            "notify.delivery",
            "runner.connected",
            "runner.degraded",
            "runner.disconnected",
            "runner.policy",
            "runner.tool_install",
            "terminal.attached",
            "terminal.closed",
            "terminal.detached",
            "terminal.exited",
            "terminal.opened",
            "terminal.reap_warning",
            "toy.line"
        ])
    );
    // A module's kinds default to its route scope (`admin`); runner presence is `read`.
    assert_eq!(
        s["Event"]["x-event-scopes"],
        json!({"account.budget": "admin", "account.expired": "admin", "account.failover": "admin",
            "account.health": "admin", "account.limited": "admin",
            "account.login.done": "admin", "account.login.failed": "admin",
            "account.login.started": "admin", "account.login.url": "admin",
            "agent.approval_decided": "approve", "agent.approval_requested": "approve",
            "agent.created": "agent", "agent.ended": "agent", "agent.message": "agent",
            "agent.state": "agent", "agent.transcript": "agent",
            "alarm.cleared": "admin", "alarm.raised": "admin", "audit": "admin", "connection.health": "admin", "notify.delivery": "admin", "runner.connected": "read",
            "runner.degraded": "read", "runner.disconnected": "read",
            "runner.policy": "read", "runner.tool_install": "read",
            "terminal.attached": "terminal", "terminal.closed": "terminal",
            "terminal.detached": "terminal", "terminal.exited": "terminal",
            "terminal.opened": "terminal", "terminal.reap_warning": "terminal",
            "toy.line": "admin"})
    );
    let actions = s["AuditEntry"]["x-audit-actions"].as_array().unwrap();
    assert!(actions.contains(&json!("toy.made")) && actions.contains(&json!("setting.set")));
    let plain: Value = serde_json::from_str(&json()).unwrap();
    assert_eq!(
        plain["components"]["schemas"]["Event"]["x-event-kinds"],
        json!([
            "account.budget",
            "account.expired",
            "account.failover",
            "account.health",
            "account.limited",
            "account.login.done",
            "account.login.failed",
            "account.login.started",
            "account.login.url",
            "agent.approval_decided",
            "agent.approval_requested",
            "agent.created",
            "agent.ended",
            "agent.message",
            "agent.state",
            "agent.transcript",
            "alarm.cleared",
            "alarm.raised",
            "audit",
            "connection.health",
            "notify.delivery",
            "runner.connected",
            "runner.degraded",
            "runner.disconnected",
            "runner.policy",
            "runner.tool_install",
            "terminal.attached",
            "terminal.closed",
            "terminal.detached",
            "terminal.exited",
            "terminal.opened",
            "terminal.reap_warning"
        ])
    );
}

#[test]
fn rewrites_nullable_ref_tagged_union_inlined_generic_and_enums() {
    let mut spec = json!({
        "paths": {},
        "components": { "schemas": {
            "Issue": { "type": "object", "properties": {
                "next": { "oneOf": [{ "$ref": "#/components/schemas/Actor" }, { "type": "null" }] }
            }},
            "Actor": { "oneOf": [
                { "type": "object", "properties": { "kind": { "type": "string", "enum": ["agent"] } } },
                { "type": "object", "properties": { "kind": { "type": "string", "enum": ["human"] }, "user_id": { "type": "string" } } }
            ]},
            "Page_Issue": { "type": "object", "properties": { "items": { "type": "array", "items":
                { "type": "object", "properties": { "next": { "oneOf": [{ "$ref": "#/components/schemas/Actor" }, { "type": "null" }] } } }
            }}},
            "State": { "type": "string", "enum": ["open", "done"] }
        }}
    });
    normalise(&mut spec);
    let s = &spec["components"]["schemas"];
    assert_eq!(
        s["Issue"]["properties"]["next"],
        json!({ "$ref": "#/components/schemas/Actor" })
    );
    assert_eq!(
        s["Actor"]["discriminator"]["mapping"]["human"],
        "#/components/schemas/ActorHuman"
    );
    assert_eq!(
        s["ActorAgent"]["properties"]["kind"]["enum"],
        json!(["agent"])
    );
    assert_eq!(
        s["Page_Issue"]["properties"]["items"]["items"],
        json!({ "$ref": "#/components/schemas/Issue" })
    );
    assert_eq!(s["State"]["anyOf"][1], json!({"type": "string"}));
    assert_eq!(s["State"]["anyOf"][0]["enum"], json!(["open", "done"]));
}

/// The committed contract is what the code generates. On failure: `make contract`, and
/// review the diff like code — a client is generated from it.
#[test]
fn the_committed_contract_is_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../api/openapi.json");
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    let current = json();
    assert!(
        committed == current,
        "api/openapi.json is stale: run `make contract` and commit it"
    );
    let spec: Value = serde_json::from_str(&current).unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    let text = current.as_str();
    assert!(
        !text.contains("\"type\": \"null\""),
        "a null branch survived"
    );
    for op in spec["paths"].as_object().unwrap().values() {
        for (method, op) in op.as_object().unwrap() {
            assert!(op["operationId"].is_string(), "{method}: no operationId");
            for (status, r) in op["responses"].as_object().unwrap() {
                let named = r["$ref"].is_string();
                assert!(
                    named || r["description"].is_string(),
                    "{status}: no description"
                );
            }
        }
    }
}
