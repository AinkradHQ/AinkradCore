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
//! 5. The bearer scheme, required everywhere, and the shared error answers on every
//!    operation, each an `ErrorBody`.

use serde_json::{Map, Value, json};
use utoipa::OpenApi;

use super::{
    account_usage, accounts, agent_stats, agents, artifacts, audit, avatars, chains, companies,
    controls, devices, disk, events, fallbacks, gov, hire, hub, issues, library, me, model, money,
    notifications, org, pairing, profile, project_charts, project_logo, projects, quest, reads,
    repos, requirements, roles, routing, runners, runs, settings, structure, stuck, types,
};

#[derive(OpenApi)]
#[openapi(
    info(title = "Citadel", version = "1.0.0"),
    paths(
        accounts::list,
        accounts::create,
        accounts::assign,
        accounts::unassign,
        accounts::delete,
        accounts::set_status,
        accounts::set_plan,
        account_usage::set_limit,
        account_usage::clear_limit,
        account_usage::usage,
        account_usage::company_usage,
        devices::list,
        devices::create,
        devices::revoke,
        devices::set_push,
        devices::clear_push,
        events::replay,
        events::ws,
        events::latest,
        me::me,
        companies::list,
        companies::create,
        companies::update,
        companies::get_logo,
        companies::upload_logo,
        companies::reset_logo,
        org::org_chart,
        org::list_agents,
        org::get_agent,
        hire::apply_template,
        hire::propose_agent,
        structure::create_department,
        structure::update_department,
        structure::delete_department,
        structure::create_team,
        structure::update_team,
        structure::delete_team,
        structure::seat,
        structure::unseat,
        agents::update,
        agents::wake,
        agents::terminate,
        avatars::palettes,
        avatars::set_appearance,
        avatars::get,
        avatars::upload,
        avatars::reset,
        fallbacks::list,
        fallbacks::set,
        routing::list_tiers,
        routing::set_tiers,
        routing::get_rules,
        routing::set_rules,
        routing::task_costs,
        runners::list,
        runners::register,
        runners::drain_runner,
        runners::undrain_runner,
        runners::remove,
        runners::logs,
        runners::probe,
        runners::set_power_nap,
        disk::get_disk,
        org::list_stuck,
        org::submit_request,
        runs::list_agent_runs,
        reads::agent_skills,
        reads::company_runs,
        reads::open_questions,
        reads::spend_series,
        reads::spend_breakdown,
        reads::issue_diff,
        reads::issue_prs,
        audit::list,
        controls::pause_agent,
        controls::resume_agent,
        controls::pause_company,
        controls::resume_company,
        controls::stop_run,
        controls::message_run,
        controls::wake_runner,
        controls::nudge_issue,
        controls::move_to_backlog,
        money::list_prices,
        money::set_price,
        money::set_budget,
        money::create_budget,
        money::delete_budget,
        money::price_history,
        money::list_unpriced,
        chains::list,
        chains::create,
        chains::update,
        chains::delete,
        chains::set_chain,
        pairing::start,
        pairing::pair,
        notifications::get,
        notifications::set,
        notifications::test,
        agent_stats::get,
        roles::list,
        roles::create,
        roles::update,
        roles::delete,
        stuck::release_checkout,
        stuck::retry_run,
        stuck::bump_issue,
        controls::reassign_issue,
        controls::allow_for_issue,
        runs::get_run,
        runs::transcript,
        runs::timing,
        gov::list_approvals,
        gov::decide,
        gov::company_costs,
        gov::sprint_costs,
        projects::list_projects,
        projects::create_project,
        projects::get_project,
        quest::update_project,
        quest::list_labels,
        quest::add_label,
        quest::rename_label,
        quest::delete_label,
        quest::label_issue,
        quest::unlabel_issue,
        quest::capacity,
        quest::set_capacity,
        quest::project_flow,
        quest::issue_flow,
        quest::commit_sprint,
        quest::sprint_review,
        profile::get,
        profile::update,
        profile::history,
        profile::decide,
        repos::list,
        repos::add,
        repos::probe,
        repos::update,
        repos::remove,
        repos::primary,
        repos::order,
        repos::get_issue_repos,
        repos::set_issue_repos,
        projects::list_issues,
        project_charts::cfd,
        project_charts::preview,
        project_logo::get,
        project_logo::upload,
        project_logo::reset,
        projects::backlog,
        projects::list_epics,
        projects::create_epic,
        projects::update_epic,
        projects::list_sprints,
        projects::plan_sprint,
        projects::close_sprint,
        projects::delete_sprint,
        projects::sprint_report,
        projects::velocity,
        projects::wip_limits,
        projects::set_wip_limit,
        issues::get_issue,
        issues::update_issue,
        issues::activity,
        issues::create_issue,
        issues::transition,
        issues::move_issue,
        issues::estimate,
        issues::set_epic,
        issues::set_sprint,
        issues::list_comments,
        issues::post_comment,
        issues::list_blockers,
        issues::link_blocker,
        issues::unlink_blocker,
        settings::list_server,
        settings::list,
        settings::get,
        settings::set,
        settings::reset,
        settings::history,
        settings::overridden,
        requirements::list,
        requirements::rename,
        requirements::cancel,
        requirements::pause,
        requirements::resume,
        requirements::finish,
        hub::attach,
        requirements::get,
        requirements::tree,
        hub::get,
        hub::post,
        artifacts::list,
        artifacts::get,
        artifacts::download,
        artifacts::preview,
        artifacts::usage,
        library::get_policy,
        library::set_policy,
        library::list_skills,
        library::publish_skill,
        library::list_knowledge,
        library::accept,
        library::reject,
        library::retire,
        library::supersede,
    ),
    components(schemas(types::ErrorBody, model::Issue, events::Event))
)]
struct ApiDoc;

const DESCRIPTION: &str = "The Citadel client API, for the Ainkrad app. Every request carries \
a device key as `Authorization: Bearer` (never in the URL) and the server's own `Host`, and \
no `Origin`. A client working in one company sends its id as `X-Citadel-Company`: every \
route then answers 404 for another company's data, and lists that span companies keep to it. \
Times are RFC 3339 UTC with milliseconds. Versioning: within /api/v1, enum \
values, union variants, optional fields and operations may be added; a client must keep an \
unknown enum value (every enum is open) and skip an event or union variant it cannot decode. \
Anything removed or renamed is a new /api/v2. `info.version` is `1.<minor>.0`; the minor \
(`GET /api/v1/me`, `versions.api.minor`) is bumped on every addition.";

/// The normalised spec, as committed: pretty JSON with sorted keys and a final newline.
pub fn json() -> String {
    let mut spec = serde_json::to_value(ApiDoc::openapi()).expect("spec serialises");
    normalise(&mut spec);
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
        "Missing, invalid or revoked device key",
    ),
    ("403", "Forbidden", "Wrong Host, or an Origin header"),
    ("404", "NotFound", "No such resource"),
    (
        "409",
        "Conflict",
        "Refused by the engine's rules (state, WIP, sprint, approval)",
    ),
    ("429", "TooManyRequests", "Rate limited; see Retry-After"),
    ("500", "InternalError", "Internal error"),
];

fn security_and_errors(spec: &mut Value) {
    spec["components"]["securitySchemes"] =
        json!({"device_key": {"type": "http", "scheme": "bearer"}});
    spec["security"] = json!([{"device_key": []}]);
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
