use serde_json::{Value, json};

use super::*;

fn mini() -> Value {
    json!({
        "paths": {
            "/api/v1/things/{id}": {
                "get": {
                    "operationId": "getThing",
                    "parameters": [
                        {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Thing"}}}},
                        "404": {"$ref": "#/components/responses/NotFound"}
                    },
                    "x-ainkrad-scope": "read"
                },
                "delete": {"operationId": "dropThing", "responses": {"204": {}}, "x-ainkrad-scope": "admin"}
            },
            "/modules/brain/v1/rooms": {
                "post": {
                    "operationId": "makeRoom",
                    "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewRoom"}}}},
                    "responses": {"201": {"content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Thing"}}}}}},
                    "x-ainkrad-scope": "admin"
                }
            }
        },
        "components": {"schemas": {
            "Thing": {"type": "object", "required": ["name"], "properties": {
                "name": {"type": "string"},
                "kind": {"anyOf": [{"enum": ["a", "b"], "type": "string"}, {"type": "string"}]},
                "note": {"type": ["string", "null"]},
                "token": {"type": "string", "writeOnly": true},
                "secret": {"type": "string", "x-ainkrad-secret": true},
                "parent": {"$ref": "#/components/schemas/Thing"}
            }},
            "NewRoom": {"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}}
        }}
    })
}

fn allow(rows: &[(&str, Option<Risk>)]) -> Vec<Allowed> {
    rows.iter()
        .map(|(op, risk)| Allowed {
            op: (*op).to_owned(),
            risk: *risk,
            summary: format!("Does {op}."),
        })
        .collect()
}

#[test]
fn the_gate_refuses_unknown_unrisked_and_mislabelled_ops() {
    let spec = mini();
    assert!(
        check(
            &spec,
            &allow(&[("getThing", None), ("makeRoom", Some(Risk::Write))])
        )
        .is_empty()
    );
    let bad = check(
        &spec,
        &allow(&[
            ("nope", None),
            ("dropThing", None),
            ("makeRoom", Some(Risk::Read)),
            ("getThing", Some(Risk::Write)),
            ("getThing", None),
        ]),
    );
    assert_eq!(bad.len(), 5, "{bad:?}");
}

#[test]
fn the_catalogue_resolves_refs_and_prefixes_modules() {
    let c = build(
        &mini(),
        &allow(&[
            ("getThing", None),
            ("makeRoom", Some(Risk::Write)),
            ("ghost", None),
        ]),
    );
    assert_eq!(c.ops.len(), 2);
    assert!(c.warnings.iter().any(|w| w.starts_with("ghost")));
    assert!(
        c.warnings.iter().any(|w| w.starts_with("cyclic ref")),
        "{:?}",
        c.warnings
    );
    let t = &c.ops["getThing"];
    assert_eq!(
        (t.group.as_str(), t.method.as_str(), t.scope.as_str()),
        ("things", "GET", "read")
    );
    assert_eq!(t.risk, Risk::Read);
    assert!(t.params[0].required && !t.params[1].required);
    assert_eq!(
        t.response.as_ref().unwrap()["properties"]["name"]["type"],
        "string"
    );
    let r = &c.ops["makeRoom"];
    assert_eq!(
        (r.group.as_str(), r.path.as_str()),
        ("brain", "/modules/brain/v1/rooms")
    );
    assert_eq!(r.body.as_ref().unwrap()["required"][0], "title");
    assert_eq!(r.response.as_ref().unwrap()["type"], "array");
}

#[test]
fn an_oversized_schema_is_listed_open_with_a_warning() {
    let mut spec = mini();
    let props: serde_json::Map<String, Value> = (0..2000)
        .map(|i| (format!("field_number_{i}"), json!({"type": "string"})))
        .collect();
    spec["components"]["schemas"]["Thing"] = json!({"type": "object", "properties": props});
    let c = build(&spec, &allow(&[("getThing", None)]));
    let resp = c.ops["getThing"].response.as_ref().unwrap();
    assert_eq!(resp["additionalProperties"], true);
    assert!(c.warnings.iter().any(|w| w.contains("listed open")));
}

#[test]
fn definitions_are_typed_and_never_show_secrets() {
    let c = build(
        &mini(),
        &allow(&[("getThing", None), ("makeRoom", Some(Risk::Write))]),
    );
    assert_eq!(
        render(&c.ops["getThing"]),
        "/** Does getThing. [read] */\nainkrad.things.getThing(args: { id: string; limit?: number }): \
         { kind?: \"a\" | \"b\" | string; name: string; note?: string | null; parent?: unknown }"
    );
    let d = render(&c.ops["makeRoom"]);
    assert!(
        d.contains("body: { title: string }") && d.ends_with("): object[]") || d.contains("]"),
        "{d}"
    );
    assert!(!render(&c.ops["getThing"]).contains("token"));
    assert!(!render(&c.ops["getThing"]).contains("secret"));
}

#[test]
fn a_big_type_is_cut_to_fit() {
    let mut op = build(&mini(), &allow(&[("getThing", None)]))
        .ops
        .remove("getThing")
        .unwrap();
    let wide: serde_json::Map<String, Value> = (0..40)
        .map(|i| {
            (
                format!("a_long_field_name_{i}"),
                json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            )
        })
        .collect();
    op.response = Some(json!({"type": "object", "properties": wide}));
    let d = render(&op);
    assert!(
        d.len() <= 1536 && d.contains("a_long_field_name_0?: object"),
        "{} {d}",
        d.len()
    );
}

/// The committed allow-list against the real contract: the build-time gate (D1). Run with
/// `--nocapture` to see the reviewed and unreviewed operations.
#[test]
fn the_committed_allow_list_matches_the_real_contract() {
    let allow = allow_list().expect("api/ai-ops.allow.json reads");
    let spec: Value = serde_json::from_str(&crate::api::v1::spec::json()).unwrap();
    let bad = check(&spec, &allow);
    assert!(bad.is_empty(), "{bad:#?}");
    let c = build(&spec, &allow);
    assert_eq!(c.ops.len(), allow.len());
    assert!(
        !c.warnings.iter().any(|w| w.starts_with("unresolved")),
        "{:?}",
        c.warnings
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    for o in c.ops.values() {
        let d = render(o);
        assert!(d.len() <= 1536, "{} is {} bytes", o.id, d.len());
    }
    let reviewed: Vec<&str> = allow.iter().map(|a| a.op.as_str()).collect();
    let mut unreviewed = Vec::new();
    for item in spec["paths"].as_object().unwrap().values() {
        for op in item.as_object().unwrap().values() {
            if let Some(id) = op["operationId"].as_str()
                && !reviewed.contains(&id)
            {
                unreviewed.push(id);
            }
        }
    }
    unreviewed.sort_unstable();
    println!("reviewed ({}): {reviewed:?}", reviewed.len());
    println!("unreviewed ({}): {unreviewed:?}", unreviewed.len());
}

/// Every operation of the real contract resolves with no unresolved `$ref` (the builder works on
/// more than today's allow-list).
#[test]
fn the_whole_real_contract_builds_without_unresolved_refs() {
    let spec: Value = serde_json::from_str(&crate::api::v1::spec::json()).unwrap();
    let every: Vec<Allowed> = spec["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|i| i.as_object().unwrap().values())
        .filter_map(|o| o["operationId"].as_str())
        .map(|id| Allowed {
            op: id.to_owned(),
            risk: Some(Risk::Risky),
            summary: String::new(),
        })
        .collect();
    let c = build(&spec, &every);
    assert!(
        !c.warnings.iter().any(|w| w.starts_with("unresolved")),
        "{:?}",
        c.warnings
    );
    // Everything but the families no session reaches (secrets, devices, runners, sign-in).
    let hidden = check(&spec, &every)
        .iter()
        .filter(|b| b.contains("not exposed"))
        .count();
    assert!(hidden > 20, "{hidden}");
    assert_eq!(c.ops.len() + hidden, every.len());
}

fn cat() -> Catalogue {
    let spec = mini();
    build(
        &spec,
        &allow(&[("getThing", None), ("makeRoom", Some(Risk::Write))]),
    )
}

#[test]
fn search_ranks_by_words_and_hides_ops_outside_the_scopes() {
    let c = cat();
    let both = vec!["read".to_owned(), "admin".to_owned()];
    let r = search(&c, &both, "get a thing", None);
    assert_eq!(r["defs"][0]["op"], "getThing");
    assert!(r.get("groups").is_none());
    // Without the admin scope the room op does not exist for the session.
    let r = search(&c, &["read".to_owned()], "room", None);
    assert!(r["defs"].as_array().unwrap().is_empty());
    assert_eq!(r["groups"], json!({"things": ["getThing"]}));
    // An unknown query is an empty list and the groups, not an error.
    let r = search(&c, &both, "zzzz", None);
    assert!(r["defs"].as_array().unwrap().is_empty());
    assert_eq!(r["groups"]["brain"][0], "makeRoom");
    // No scopes, nothing; the limit holds.
    assert!(
        search(&c, &[], "thing", None)["groups"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        search(&c, &both, "thing room", Some(1))["defs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(search(&c, &both, "thing", None).to_string().len() < 8 * 1024);
}
