//! The client contract (E10.1): utoipa's OpenAPI 3.1 for `/api/v1`, normalised into shapes
//! Apple's swift-openapi-generator (1.14.2) takes without a warning (E0.4 spike, ported).
//! `ainkrad-core-server openapi` prints it; `make contract` writes `api/openapi.json`; a test
//! fails while the committed file differs. Every rewrite keeps the wire format; only the
//! schema text changes:
//!
//! 1. `oneOf: [X, {type: null}]` (utoipa's `Option<Ref>`) → `X`, still not `required`. The
//!    generator otherwise drops the whole property, silently.
//! 2. Internally tagged enums (`#[serde(tag = "kind")]`, struct variants) are a `oneOf` of
//!    anonymous objects: each variant is hoisted to a named component (`Actor` + `agent` →
//!    `ActorAgent`) and a `discriminator` with a `mapping` is added, so clients get named
//!    cases instead of `case1`/`case2`.
//! 3. utoipa inlines generic arguments (`Page<Run>` copies `Run`): an inline schema equal to
//!    a component becomes a `$ref` to it.
//! 4. Every string enum component becomes open, `anyOf: [the enum, any string]`, which the
//!    generator turns into a known case or the raw string: an older client survives a value
//!    added later (the versioning rule in `types`).
//! 5. The signed-request scheme (handshake spec §5), required everywhere, and the shared
//!    error answers on every operation, each an `ErrorBody`.
//!
//! After normalising, the registered names (`store::kinds`, E1-04.2, E1-10.2) are listed as
//! extensions: `Event` carries `x-event-kinds`, `AuditEntry` `x-audit-actions`, the platform's
//! and those of the modules given to [`json_for`]. Extensions, not enums: `kind` stays an open
//! string, so a client keeps decoding an event of a kind it was not built with.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use utoipa::OpenApi;

use crate::module::Module;
use crate::store::kinds::{PLATFORM_AUDIT_ACTIONS, PLATFORM_EVENT_KINDS};

use super::{
    audit, devices, events, handshake, lockouts, me, pair, pairing, passkey, runners, session,
    settings, stepup, ticket, types, websession,
};

#[derive(OpenApi)]
#[openapi(
    info(title = "Ainkrad Core", version = "1.0.0"),
    paths(
        devices::list,
        devices::revoke,
        devices::get,
        devices::rename,
        devices::set_scopes,
        devices::set_push,
        devices::clear_push,
        events::replay,
        events::ws,
        events::latest,
        ticket::issue,
        handshake::handshake,
        handshake::prove,
        websession::options,
        websession::session,
        session::challenge,
        session::session,
        pair::claim,
        pair::status,
        passkey::options_route,
        passkey::claim_route,
        pairing::create,
        pairing::get,
        pairing::approve,
        pairing::reject,
        me::me,
        audit::list,
        runners::list,
        runners::get,
        runners::noop,
        settings::list_server,
        settings::list,
        settings::get,
        settings::set,
        settings::reset,
        settings::history,
        stepup::challenge,
        stepup::step_up,
        lockouts::list,
        lockouts::clear,
    ),
    components(schemas(types::ErrorBody, events::Event))
)]
struct ApiDoc;

const DESCRIPTION: &str = "The Ainkrad Core client API, for the Ainkrad app. Every request \
is signed by the device's own P-256 key (ES256, raw r||s): the headers Ainkrad-Device, \
Ainkrad-Session, Ainkrad-Alg (ES256), Ainkrad-Timestamp, Ainkrad-Nonce and Ainkrad-Signature \
cover an exact canonical string of the Core identity fingerprint, the method, path, query, \
time, nonce and the body's SHA-256 (handshake spec §5). A session comes from \
POST /handshake/challenge then POST /handshake/session and lasts 15 minutes; there is no bearer \
secret, and an Authorization header is refused. A signed body is at most 1 MiB: a larger one \
is answered 401 auth_failed and counted as a failure against the address, so keep uploads below \
it. Before trusting a Core, POST /handshake with a fresh nonce and check that core_sig verifies \
under core_spki and that its fingerprint is the pinned one. Requests carry the server's own Host and no \
Origin, or the Core's own origin from its web client. A web client signs in with a passkey \
(POST /handshake/passkey/options, then POST /handshake/passkey/session) and signs every request \
with a non-extractable WebCrypto P-256 session key in the same way; its event socket takes a \
one-time ticket (POST /api/v1/ws-ticket) in Sec-WebSocket-Protocol. Times are RFC 3339 UTC with milliseconds. Versioning: within /api/v1, enum values, \
union variants, optional fields and operations may be added; a client must keep an unknown enum \
value (every enum is open) and skip an event or union variant it cannot decode. Anything \
removed or renamed is a new /api/v2. `info.version` is `1.<minor>.0`; the minor \
(`GET /api/v1/me`, `versions.api.minor`) is bumped on every addition.";

/// The normalised spec, as committed: pretty JSON with sorted keys and a final newline. Lists
/// the platform's event kinds and audit actions; `serve` mounts no module yet.
pub fn json() -> String {
    json_for(&[])
}

/// The platform's names and `modules`', sorted: event kinds, then audit actions.
pub fn registered(modules: &[Arc<dyn Module>]) -> [Vec<&'static str>; 2] {
    let mut kinds = PLATFORM_EVENT_KINDS.to_vec();
    let mut actions = PLATFORM_AUDIT_ACTIONS.to_vec();
    for m in modules {
        kinds.extend(m.event_kinds());
        actions.extend(m.audit_actions());
    }
    kinds.sort_unstable();
    actions.sort_unstable();
    [kinds, actions]
}

/// Each registered event kind and the scope a device needs to see it (E1-04.3).
pub fn event_scopes(
    modules: &[Arc<dyn Module>],
) -> std::collections::BTreeMap<&'static str, &'static str> {
    let platform = PLATFORM_EVENT_KINDS
        .iter()
        .map(|k| (*k, crate::store::kinds::platform_scope(k)));
    let theirs = modules
        .iter()
        .flat_map(|m| m.event_kinds().iter().map(|k| (*k, m.event_scope(k))));
    platform.chain(theirs).collect()
}

/// [`json`] with `modules`' event kinds and audit actions listed too.
pub fn json_for(modules: &[Arc<dyn Module>]) -> String {
    let mut spec = serde_json::to_value(ApiDoc::openapi()).expect("spec serialises");
    normalise(&mut spec);
    let [kinds, actions] = registered(modules);
    spec["components"]["schemas"]["Event"]["x-event-kinds"] = json!(kinds);
    spec["components"]["schemas"]["Event"]["x-event-scopes"] = json!(event_scopes(modules));
    spec["components"]["schemas"]["AuditEntry"]["x-audit-actions"] = json!(actions);
    spec["info"]["description"] = json!(DESCRIPTION);
    spec["info"]["version"] = json!(format!("1.{}.0", types::API_MINOR));
    let mut text = serde_json::to_string_pretty(&spec).expect("spec serialises");
    text.push('\n');
    text
}

pub fn normalise(spec: &mut Value) {
    strip_null_branches(spec);
    hoist_tagged_unions(spec);
    let components = spec["components"]["schemas"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (name, schema) in spec["components"]["schemas"]
        .as_object_mut()
        .into_iter()
        .flatten()
    {
        dedupe(schema, &components, name, true);
    }
    for path in spec["paths"].as_object_mut().into_iter().flatten() {
        dedupe(path.1, &components, "", true);
    }
    open_enums(spec);
    security_and_errors(spec);
    // OpenAPI cannot describe a socket's frames; this names their schema for any client.
    if let Some(op) = spec
        .pointer_mut("/paths/~1api~1v1~1events~1ws/get")
        .filter(|op| op.is_object())
    {
        op["x-citadel-frame"] = json!("#/components/schemas/Event");
    }
}

fn strip_null_branches(v: &mut Value) {
    if let Some(obj) = v.as_object_mut() {
        if let Some(Value::Array(one_of)) = obj.get("oneOf")
            && one_of.len() == 2
            && let Some(i) = one_of.iter().position(|s| s == &json!({"type": "null"}))
        {
            let keep = one_of[1 - i].clone();
            obj.remove("oneOf");
            if let Value::Object(k) = keep {
                obj.extend(k);
            }
        }
        obj.values_mut().for_each(strip_null_branches);
    } else if let Some(arr) = v.as_array_mut() {
        arr.iter_mut().for_each(strip_null_branches);
    }
}

/// The tag property shared by every `oneOf` child, with each child's single tag value.
fn tag_of(one_of: &[Value]) -> Option<(String, Vec<String>)> {
    let mut tag: Option<String> = None;
    let mut values = Vec::new();
    for child in one_of {
        let props = child.get("properties")?.as_object()?;
        let (name, value) = props.iter().find_map(|(k, p)| {
            let e = p.get("enum")?.as_array()?;
            let value = e
                .first()?
                .as_str()
                .filter(|_| e.len() == 1 && p["type"] == "string")?;
            Some((k.clone(), value.to_owned()))
        })?;
        if tag.get_or_insert_with(|| name.clone()) != &name {
            return None;
        }
        values.push(value);
    }
    tag.map(|t| (t, values))
}

fn pascal(s: &str) -> String {
    s.split('_')
        .filter(|w| !w.is_empty())
        .map(|w| w[..1].to_uppercase() + &w[1..])
        .collect()
}

fn hoist_tagged_unions(spec: &mut Value) {
    let Some(schemas) = spec["components"]["schemas"].as_object_mut() else {
        return;
    };
    let mut hoisted = Map::new();
    for (name, schema) in schemas.iter_mut() {
        let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) else {
            continue;
        };
        let Some((tag, values)) = tag_of(one_of) else {
            continue;
        };
        let mut refs = Vec::new();
        let mut mapping = Map::new();
        for (child, value) in one_of.iter().zip(&values) {
            let target = format!("#/components/schemas/{name}{}", pascal(value));
            hoisted.insert(format!("{name}{}", pascal(value)), child.clone());
            refs.push(json!({ "$ref": target }));
            mapping.insert(value.clone(), json!(target));
        }
        schema["oneOf"] = Value::Array(refs);
        schema["discriminator"] = json!({ "propertyName": tag, "mapping": mapping });
    }
    schemas.extend(hoisted);
}

fn dedupe(v: &mut Value, components: &Map<String, Value>, own: &str, root: bool) {
    if !root
        && v.get("properties").is_some()
        && let Some(name) = components
            .iter()
            .find(|(n, s)| *n != own && *s == v)
            .map(|(n, _)| n)
    {
        *v = json!({ "$ref": format!("#/components/schemas/{name}") });
        return;
    }
    match v {
        Value::Object(o) => o
            .values_mut()
            .for_each(|c| dedupe(c, components, own, false)),
        Value::Array(a) => a.iter_mut().for_each(|c| dedupe(c, components, own, false)),
        _ => {}
    }
}

fn open_enums(spec: &mut Value) {
    for schema in spec["components"]["schemas"]
        .as_object_mut()
        .into_iter()
        .flat_map(|s| s.values_mut())
    {
        if schema["type"] == "string" && schema.get("enum").is_some() {
            let known = schema.clone();
            *schema = json!({"anyOf": [known, {"type": "string"}]});
        }
    }
}

/// The shared answers every operation may give besides its own, by name in
/// `components.responses`.
const ERRORS: [(&str, &str, &str); 7] = [
    (
        "400",
        "BadRequest",
        "Bad request, or a query parameter that is not allowed",
    ),
    (
        "401",
        "Unauthorized",
        "auth_failed (any signature or device failure, alike whatever the reason), clock_skew \
         (with server_time), or session_expired",
    ),
    (
        "403",
        "Forbidden",
        "Wrong Host (unknown_host), an Origin header (origin_refused), a scope the device \
         lacks (forbidden_scope; see each operation's x-ainkrad-scope), or an operation marked \
         x-ainkrad-destructive without a live step-up elevation (step_up_required)",
    ),
    ("404", "NotFound", "No such resource"),
    ("409", "Conflict", "Conflicts with the current state"),
    ("429", "TooManyRequests", "Rate limited; see Retry-After"),
    ("500", "InternalError", "Internal error"),
];

fn security_and_errors(spec: &mut Value) {
    spec["components"]["securitySchemes"] = json!({"device_signature": {
        "type": "apiKey", "in": "header", "name": "Ainkrad-Signature",
        "description": "ES256 over the canonical request string, with Ainkrad-Device, \
            Ainkrad-Session, Ainkrad-Alg, Ainkrad-Timestamp and Ainkrad-Nonce alongside \
            (handshake spec §5)"}});
    spec["security"] = json!([{"device_signature": []}]);
    // The scope each authenticated operation needs (`scopes::ROUTES`); the pre-auth ones have
    // `security: [{}]` and none.
    for (path, item) in spec["paths"].as_object_mut().into_iter().flatten() {
        for (method, op) in item.as_object_mut().into_iter().flatten() {
            if let Some(scope) = super::scopes::declared(method, path) {
                op["x-ainkrad-scope"] = json!(scope);
            }
            if super::scopes::declared_destructive(method, path) {
                op["x-ainkrad-destructive"] = json!(true);
            }
        }
    }
    let error = json!({"application/json": {"schema": {"$ref": "#/components/schemas/ErrorBody"}}});
    for (_, name, description) in ERRORS {
        spec["components"]["responses"][name] =
            json!({"description": description, "content": error});
    }
    for item in spec["paths"]
        .as_object_mut()
        .into_iter()
        .flat_map(|p| p.values_mut())
    {
        for op in item
            .as_object_mut()
            .into_iter()
            .flat_map(|o| o.values_mut())
        {
            let Some(responses) = op.get_mut("responses").and_then(Value::as_object_mut) else {
                continue;
            };
            for (status, name, _) in ERRORS {
                responses
                    .entry(status)
                    .or_insert_with(|| json!({"$ref": format!("#/components/responses/{name}")}));
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
                "audit",
                "notify.delivery",
                "runner.connected",
                "runner.degraded",
                "runner.disconnected",
                "toy.line"
            ])
        );
        // A module's kinds default to its route scope (`admin`); runner presence is `read`.
        assert_eq!(
            s["Event"]["x-event-scopes"],
            json!({"audit": "admin", "notify.delivery": "admin", "runner.connected": "read", "runner.degraded": "read",
                "runner.disconnected": "read", "toy.line": "admin"})
        );
        let actions = s["AuditEntry"]["x-audit-actions"].as_array().unwrap();
        assert!(actions.contains(&json!("toy.made")) && actions.contains(&json!("setting.set")));
        let plain: Value = serde_json::from_str(&json()).unwrap();
        assert_eq!(
            plain["components"]["schemas"]["Event"]["x-event-kinds"],
            json!([
                "audit",
                "notify.delivery",
                "runner.connected",
                "runner.degraded",
                "runner.disconnected"
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
}
