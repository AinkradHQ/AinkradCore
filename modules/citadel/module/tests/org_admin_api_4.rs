//! Several organisations (ported from the monolith's `api/v1/tests/companies.rs`, E15.14): companies,
//! own or client, are listed, added and changed with a profile; working in one
//! (`X-Citadel-Company`), the org_admin operations refuse the other's data, and the company list
//! shows only its own. `scope.rs` walks every operation of the contract for the header's shape;
//! the walk here is over this slice's routes, with another company's real resources.
#![allow(dead_code, unused_imports)]

mod common;

use ainkrad_core_server::api::v1::BY;
use axum::http::{Method, StatusCode};
use citadel_module::domain::ops::{NewChainPreset, NewRole};
use citadel_module::domain::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::store::org;
use common::*;
use serde_json::{Value, json};

async fn api(fx: &Fx, m: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), m, path, body).await
}

async fn get(fx: &Fx, path: &str) -> (StatusCode, Value) {
    api(fx, Method::GET, path, None).await
}

async fn post(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    api(fx, Method::POST, path, Some(body)).await
}

async fn ok(fx: &Fx, path: &str) -> Value {
    let (status, body) = get(fx, path).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

async fn ok_post(fx: &Fx, path: &str, body: Value) -> Value {
    let (status, got) = post(fx, path, body).await;
    assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
    got
}

async fn company(fx: &Fx, name: &str) -> CompanyId {
    org::create_company(&fx.app.pool, name).await.unwrap().id
}

async fn agent(fx: &Fx, company: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id: company,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    org::create_agent(&fx.app.pool, &a).await.unwrap().id
}

#[tokio::test]
async fn companies_are_listed_added_and_changed() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    // Adapted: the accounts half (`account_ids` of an assigned account) is S9's; the list
    // carries an empty `account_ids` until then.
    let own = ok_post(&fx, "/companies", json!({"name": "Ainkrad", "kind": "own"})).await;
    assert_eq!(
        (own["kind"].clone(), own["account_ids"].clone()),
        (json!("own"), json!([]))
    );
    let (status, _) = post(&fx, "/companies", json!({"name": " ", "kind": "own"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let all = ok(&fx, "/companies").await;
    assert_eq!(all[0]["kind"], "client", "existing companies are clients");
    assert_eq!(all[0]["account_ids"], json!([]));
    let uri = format!("/companies/{}", a.0);
    let (status, changed) = api(&fx, Method::PUT, &uri, Some(json!({"kind": "own"}))).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(
        (changed["name"].clone(), changed["kind"].clone()),
        (json!("A"), json!("own"))
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE action IN ('citadel.company.created', 'citadel.company.updated')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);
    let (status, _) = call_in(
        &fx,
        Some(&fx.dev),
        Some("999"),
        Method::GET,
        "/companies",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such company to work in");
}

#[tokio::test]
async fn a_company_lists_its_pool_accounts() {
    let fx = fx().await;
    let a = company(&fx, "A").await;
    let new = json!({"harness": "claude", "label": "claude-a"});
    let account = ok_post(&fx, "/accounts", new).await["id"].as_i64().unwrap();
    let assign = format!("/accounts/{account}/companies/{}", a.0);
    api(&fx, Method::PUT, &assign, None).await;
    let all = ok(&fx, "/companies").await;
    assert_eq!(all[0]["account_ids"], json!([account]));
}

#[tokio::test]
async fn every_org_admin_operation_refuses_another_companys_data() {
    let fx = fx().await;
    let pool = fx.app.pool.clone();
    let a = company(&fx, "A").await;
    let b = company(&fx, "B").await;
    let b_agent = agent(&fx, b, "B dev").await.0;
    let department = org::add_department(&pool, b, "Ops", BY).await.unwrap();
    let team = org::add_team(&pool, department.id, "Run", BY)
        .await
        .unwrap();
    let preset = org::create_preset(
        &pool,
        b,
        &NewChainPreset {
            name: "Theirs".to_owned(),
            color: None,
            description: String::new(),
            is_default: false,
            entries: vec![],
        },
        BY,
    )
    .await
    .unwrap()
    .id;
    let role = org::create_role(
        &pool,
        b,
        &NewRole {
            name: "Theirs".to_owned(),
            purpose: String::new(),
            icon: String::new(),
            harness: None,
            model: None,
            budget_tokens: None,
            skills: vec![],
            instructions: String::new(),
        },
        BY,
    )
    .await
    .unwrap()
    .id;
    let project: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_projects (company_id, name, key, mode, sprint_approval) \
         VALUES (?, 'P', 'BBB', 'kanban', 'owner') RETURNING id",
    )
    .bind(b.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (bc, ag, dp, tm) = (b.0, b_agent, department.id.0, team.id.0);
    let ops: Vec<(Method, String, Option<Value>)> = vec![
        (Method::GET, format!("/companies/{bc}/org"), None),
        (Method::DELETE, format!("/companies/{bc}/logo"), None),
        (Method::GET, format!("/companies/{bc}/chain-presets"), None),
        (
            Method::POST,
            format!("/companies/{bc}/chain-presets"),
            Some(json!({})),
        ),
        (Method::GET, format!("/companies/{bc}/roles"), None),
        (
            Method::POST,
            format!("/companies/{bc}/roles"),
            Some(json!({})),
        ),
        (
            Method::POST,
            format!("/companies/{bc}/agents"),
            Some(json!({})),
        ),
        (
            Method::POST,
            format!("/companies/{bc}/templates/engineering"),
            Some(json!({})),
        ),
        (Method::PATCH, format!("/agents/{ag}"), Some(json!({}))),
        (
            Method::PUT,
            format!("/agents/{ag}/appearance"),
            Some(json!({})),
        ),
        (Method::DELETE, format!("/agents/{ag}/avatar"), None),
        (Method::GET, format!("/agents/{ag}/fallbacks"), None),
        (
            Method::PUT,
            format!("/agents/{ag}/fallbacks"),
            Some(json!([])),
        ),
        (Method::GET, format!("/agents/{ag}/tiers"), None),
        (Method::PUT, format!("/agents/{ag}/tiers"), Some(json!([]))),
        (Method::PUT, format!("/agents/{ag}/chain"), Some(json!({}))),
        (Method::GET, format!("/projects/{project}/tier-rules"), None),
        (
            Method::PUT,
            format!("/projects/{project}/tier-rules"),
            Some(json!([])),
        ),
        (
            Method::PUT,
            format!("/chain-presets/{preset}"),
            Some(json!({})),
        ),
        (Method::DELETE, format!("/chain-presets/{preset}"), None),
        (Method::PUT, format!("/roles/{role}"), Some(json!({}))),
        (Method::DELETE, format!("/roles/{role}"), None),
        (Method::PATCH, format!("/departments/{dp}"), Some(json!({}))),
        (Method::PATCH, format!("/teams/{tm}"), Some(json!({}))),
        (
            Method::PUT,
            format!("/teams/{tm}/members/{ag}"),
            Some(json!({})),
        ),
        (Method::DELETE, format!("/teams/{tm}/members/{ag}"), None),
    ];
    let a_id = a.0.to_string();
    for (m, uri, body) in &ops {
        let (status, got) = call_in(
            &fx,
            Some(&fx.dev),
            Some(&a_id),
            m.clone(),
            uri,
            body.clone(),
        )
        .await;
        let msg = got["message"].as_str().unwrap_or_default();
        let refused =
            status == StatusCode::NOT_FOUND && msg.contains(&format!("in company {}", a.0));
        assert!(refused, "{m} {uri} as company A: {status} {got}");
        if *m == Method::GET {
            let (status, got) = call_in(
                &fx,
                Some(&fx.dev),
                Some(&b.0.to_string()),
                m.clone(),
                uri,
                None,
            )
            .await;
            assert!(
                !got.to_string().contains("in company"),
                "{m} {uri} as B: {status} {got}"
            );
        }
    }
    // Nothing was written as A.
    let writes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.%' \
         AND action NOT IN ('citadel.department.added', 'citadel.team.added', \
         'citadel.chain_preset.created', 'citadel.role.created')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(writes, 0);

    // The company list keeps to the acting one.
    let (_, list) = call_in(
        &fx,
        Some(&fx.dev),
        Some(&a_id),
        Method::GET,
        "/companies",
        None,
    )
    .await;
    let ids: Vec<i64> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [a.0]);
    assert_eq!(ok(&fx, "/companies").await.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_company_profile_is_set_checked_changed_and_cleared() {
    let fx = fx().await;
    let new = json!({"name": "Acme", "kind": "client", "color": "#2563eb",
        "description": "Builds rockets.", "industries": ["Software", "Research"],
        "website": "https://acme.example", "timezone": "Europe/Berlin",
        "work_start": 540, "work_end": 1080, "work_days": 31});
    let c = ok_post(&fx, "/companies", new.clone()).await;
    for k in [
        "color",
        "description",
        "industries",
        "website",
        "timezone",
        "work_start",
        "work_end",
        "work_days",
    ] {
        assert_eq!(c[k], new[k], "{k}");
    }
    assert!(c["logo_url"].is_null());
    let bad = [
        json!({"color": "blue"}),
        json!({"timezone": "not a zone"}),
        json!({"website": "ftp://x"}),
        json!({"work_start": 1441}),
        json!({"work_days": 128}),
        json!({"industries": [""]}),
    ];
    for b in &bad {
        let mut body = json!({"name": "X", "kind": "own"});
        body.as_object_mut()
            .unwrap()
            .extend(b.as_object().unwrap().clone());
        let (status, got) = post(&fx, "/companies", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{b}: {got}");
    }

    let uri = format!("/companies/{}", c["id"]);
    let put = |body: Value| api(&fx, Method::PUT, &uri, Some(body));
    let (status, got) = put(json!({"color": "#10b981", "website": null, "work_days": null})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["color"], "#10b981");
    assert!(
        got["website"].is_null() && got["work_days"].is_null(),
        "null clears"
    );
    assert_eq!(got["timezone"], "Europe/Berlin", "absent stays");
    assert_eq!(got["name"], "Acme");
    let (status, _) = put(json!({"timezone": "Europe//Berlin"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.company.updated' \
         ORDER BY seq DESC",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["color"], "#10b981", "audited with its profile");
}
