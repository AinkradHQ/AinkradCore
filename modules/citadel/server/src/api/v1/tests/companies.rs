//! Several organisations (E15.14, pain #12): companies, own or client, are listed, added and
//! changed; working in one (`X-Citadel-Company`), every operation of the contract refuses the
//! other's data, and lists that span companies show only its own.

use citadel_core::gov::{ApprovalKind, NewApproval};
use citadel_core::work::{NewSprint, ProjectMode, SprintState};
use serde_json::json;

use super::*;
use crate::api::v1::scope::{COMPANY_HEADER, params};
use crate::store::gov::open_approval;
use crate::store::work::{Commands, Repo, add_repo, plan_sprint, submit_intake};

/// Paths that name nothing a company owns: the admin's own (the account pool, devices,
/// runners, the server's settings), the company switcher, and the lists that keep to the
/// acting company (checked below). A new route must be scoped, or added here on purpose.
const GLOBAL: &[&str] = &[
    "/api/v1/accounts",
    "/api/v1/accounts/usage",
    "/api/v1/accounts/{id}",
    "/api/v1/accounts/{id}/status",
    "/api/v1/accounts/{id}/limits",
    "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
    "/api/v1/companies",
    "/api/v1/devices",
    "/api/v1/devices/{id}",
    "/api/v1/devices/pairing",
    "/api/v1/devices/pair",
    "/api/v1/push-token",
    "/api/v1/events",
    "/api/v1/events/ws",
    "/api/v1/events/latest",
    "/api/v1/audit",
    "/api/v1/me",
    "/api/v1/runners",
    "/api/v1/runners/{id}/disk",
    "/api/v1/runners/{id}/wake",
    "/api/v1/runners/{id}/probe",
    "/api/v1/runners/{id}",
    "/api/v1/runners/{id}/drain",
    "/api/v1/runners/{id}/logs",
    "/api/v1/runners/{id}/power-nap",
    "/api/v1/accounts/{id}/plan",
    "/api/v1/prices",
    "/api/v1/prices/history",
    "/api/v1/settings",
    "/api/v1/stuck",
    "/api/v1/requirements",
    "/api/v1/artifacts",
    "/api/v1/avatars/palettes",
];

/// What a company owns, by the path segment naming it.
const OWNED: &[&str] = &[
    "companies",
    "projects",
    "issues",
    "epics",
    "sprints",
    "repos",
    "agents",
    "departments",
    "teams",
    "runs",
    "approvals",
    "settings",
    "requirements",
    "artifacts",
    "budgets",
    "knowledge",
    "chain-presets",
    "roles",
];

pub(super) fn with(company: CompanyId, mut r: Request<Body>) -> Request<Body> {
    let v = company.0.to_string().parse().unwrap();
    r.headers_mut().insert(COMPANY_HEADER, v);
    r
}

#[tokio::test]
async fn companies_are_listed_added_and_changed_with_their_accounts() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let new = json!({"harness": "claude", "label": "claude-a"});
    let account = fx.ok_post("/api/v1/accounts", new).await["id"]
        .as_i64()
        .unwrap();
    let assign = format!("/api/v1/accounts/{account}/companies/{}", a.company.0);
    send(&fx.app, req(Method::PUT, &assign, Some(&fx.key), None)).await;

    let own = fx
        .ok_post(
            "/api/v1/companies",
            json!({"name": "Ainkrad", "kind": "own"}),
        )
        .await;
    assert_eq!(
        (own["kind"].clone(), own["account_ids"].clone()),
        (json!("own"), json!([]))
    );
    let (status, _) = fx
        .post("/api/v1/companies", json!({"name": " ", "kind": "own"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let all = fx.ok("/api/v1/companies").await;
    assert_eq!(all[0]["kind"], "client", "existing companies are clients");
    assert_eq!(all[0]["account_ids"], json!([account]));
    let uri = format!("/api/v1/companies/{}", a.company.0);
    let (status, changed) = send(
        &fx.app,
        req(
            Method::PUT,
            &uri,
            Some(&fx.key),
            Some(json!({"kind": "own"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(
        (changed["name"].clone(), changed["kind"].clone()),
        (json!("A"), json!("own"))
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('company.created', 'company.updated')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);
    let (status, _) = send(
        &fx.app,
        with(
            CompanyId(999),
            req(Method::GET, "/api/v1/companies", Some(&fx.key), None),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such company to work in");
}

#[tokio::test]
async fn every_operation_refuses_another_companys_data() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(1000, 1.0),
        requests: Limiter::new(1000, 1.0),
    });
    let pool = fx.app.pool.clone();
    let a = seed(&pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&pool, "B", "BBB", ProjectMode::Scrum).await;
    let epic = crate::store::work::create_epic(&pool, b.project, "Theirs")
        .await
        .unwrap()
        .id
        .0;
    let sprint = NewSprint {
        project_id: b.project,
        name: "S1".to_owned(),
        goal: String::new(),
        state: SprintState::Planned,
        starts_on: Some("2026-10-22".to_owned()),
        ends_on: Some("2026-11-04".to_owned()),
    };
    let sprint = plan_sprint(&pool, &sprint, super::super::BY)
        .await
        .unwrap()
        .id
        .0;
    let ask = NewApproval {
        company_id: b.company,
        kind: ApprovalKind::BudgetOverrun,
        issue_id: Some(b.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: b.agent,
        payload: "{}".to_owned(),
    };
    let approval = open_approval(&pool, &ask, NOW).await.unwrap().id.0;
    let repo = Repo {
        id: 0,
        project_id: b.project,
        name: "core".to_owned(),
        url: "/srv/core.git".to_owned(),
        default_branch: "main".to_owned(),
        position: 0,
        primary: false,
        forge: None,
        commands: Commands::default(),
    };
    let repo = add_repo(&pool, &repo, super::super::BY)
        .await
        .unwrap()
        .unwrap()
        .id;
    let asked = submit_intake(&pool, b.company, "Theirs", "", super::super::BY)
        .await
        .unwrap();
    let requirement = asked.requirement_id.unwrap().0;
    let theirs = crate::store::artifacts::NewArtifact {
        company: b.company,
        issue: Some(b.issue),
        requirement: None,
        run: None,
        agent: None,
        name: "b.md".to_owned(),
        kind: citadel_core::gov::ArtifactKind::Report,
        user: None,
    };
    let artifact = crate::store::artifacts::publish_artifact(
        &pool,
        &fx.app.artifacts,
        &theirs,
        b"b",
        &Default::default(),
    )
    .await
    .unwrap()
    .id
    .0;
    let cap = citadel_core::gov::NewBudget {
        scope: citadel_core::gov::BudgetScope::Company(b.company),
        period: citadel_core::gov::BudgetPeriod::Month,
        token_cap: 1000,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let budget = crate::store::gov::set_budget(&pool, &cap, super::super::BY)
        .await
        .unwrap()
        .id
        .0;
    let entry = crate::store::gov::add_knowledge(
        &pool,
        b.project,
        citadel_core::gov::KnowledgeKind::Decision,
        "Theirs",
        "b",
        citadel_core::work::UserId(1),
    )
    .await
    .unwrap()
    .id
    .0;
    let department = crate::store::org::add_department(&pool, b.company, "Ops", super::super::BY)
        .await
        .unwrap();
    let team = crate::store::org::add_team(&pool, department.id, "Run", super::super::BY)
        .await
        .unwrap();
    let preset = crate::store::org::create_preset(
        &pool,
        b.company,
        &citadel_core::ops::NewChainPreset {
            name: "Theirs".to_owned(),
            color: None,
            description: String::new(),
            is_default: false,
            entries: vec![],
        },
        super::super::BY,
    )
    .await
    .unwrap()
    .id;
    let role = crate::store::org::create_role(
        &pool,
        b.company,
        &citadel_core::ops::NewRole {
            name: "Theirs".to_owned(),
            purpose: String::new(),
            icon: String::new(),
            harness: None,
            model: None,
            budget_tokens: None,
            skills: vec![],
            instructions: String::new(),
        },
        super::super::BY,
    )
    .await
    .unwrap()
    .id;
    let value = |segment: &str, param: &str| -> String {
        match (segment, param) {
            ("companies", "{id}") | (_, "{company_id}") => b.company.0.to_string(),
            ("projects", _) => b.project.0.to_string(),
            ("issues", _) => b.issue.0.to_string(),
            ("epics", _) => epic.to_string(),
            ("sprints", _) => sprint.to_string(),
            ("repos", _) => repo.to_string(),
            ("agents", _) => b.agent.0.to_string(),
            ("departments", _) => department.id.0.to_string(),
            ("teams", _) => team.id.0.to_string(),
            ("runs", _) => b.run.id.0.to_string(),
            ("approvals", _) => approval.to_string(),
            ("requirements", _) => requirement.to_string(),
            ("artifacts", _) => artifact.to_string(),
            ("budgets", _) => budget.to_string(),
            ("knowledge", _) => entry.to_string(),
            ("chain-presets", _) => preset.to_string(),
            ("roles", _) => role.to_string(),
            ("runners", _) => b.runner.0.to_string(),
            ("settings", "{scope}") => format!("company:{}", b.company.0),
            (_, "{key}") => "run.token_cap".to_owned(),
            (_, "{unit}") => "tokens".to_owned(),
            (_, "{window_secs}") => "3600".to_owned(),
            _ => "1".to_owned(),
        }
    };

    let spec: Value = serde_json::from_str(&crate::api::v1::spec::json()).unwrap();
    let (mut scoped, mut global) = (0, 0);
    for (path, item) in spec["paths"].as_object().unwrap() {
        let pairs = params(path, path);
        let mut uri = path.clone();
        for (segment, param) in &pairs {
            uri = uri.replacen(param, &value(segment, param), 1);
        }
        let owned = pairs
            .iter()
            .any(|(s, p)| OWNED.contains(s) || *p == "{company_id}");
        if !owned {
            assert!(
                GLOBAL.contains(&path.as_str()),
                "{path} names no company: scope it"
            );
            global += 1;
            continue;
        }
        for method in item.as_object().unwrap().keys() {
            let m: Method = method.to_uppercase().parse().unwrap();
            let body = (m != Method::GET && m != Method::DELETE).then(|| json!({}));
            let r = with(a.company, req(m.clone(), &uri, Some(&fx.key), body));
            let (status, got) = send(&fx.app, r).await;
            let msg = got["message"].as_str().unwrap_or_default();
            let refused = status == StatusCode::NOT_FOUND
                && msg.contains(&format!("in company {}", a.company.0));
            assert!(refused, "{m} {uri} as company A: {status} {got}");
            if m == Method::GET {
                let r = with(b.company, req(m.clone(), &uri, Some(&fx.key), None));
                let (status, got) = send(&fx.app, r).await;
                assert!(
                    !got.to_string().contains("in company"),
                    "{m} {uri} as B: {status} {got}"
                );
            }
            scoped += 1;
        }
    }
    assert!(
        scoped >= 40 && global == GLOBAL.len(),
        "{scoped} scoped, {global} global"
    );

    // The lists that span companies keep to the acting one.
    let as_a = |uri: &str| {
        send(
            &fx.app,
            with(a.company, req(Method::GET, uri, Some(&fx.key), None)),
        )
    };
    let (_, events) = as_a("/api/v1/events").await;
    let items = events["items"].as_array().unwrap();
    assert!(!items.is_empty());
    for e in items {
        let p = &e["payload"];
        assert!(
            p["company_id"].is_null() || p["company_id"] == a.company.0,
            "{e}"
        );
        assert!(
            p["run_id"] != b.run.id.0 && p["agent_id"] != b.agent.0,
            "{e}"
        );
    }
    let (_, everything) = send(
        &fx.app,
        req(Method::GET, "/api/v1/events", Some(&fx.key), None),
    )
    .await;
    assert!(
        everything
            .to_string()
            .contains(&format!("\"company_id\":{}", b.company.0))
    );
    let (_, theirs) = as_a("/api/v1/requirements").await;
    assert_eq!(theirs, json!([]), "B's requirement is not A's");
    let (_, theirs) = as_a("/api/v1/artifacts").await;
    assert_eq!(theirs["items"], json!([]), "B's artifact is not A's");
    let (_, stuck) = as_a("/api/v1/stuck").await;
    assert!(
        stuck
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["issue_id"] != b.issue.0),
        "{stuck}"
    );
    let new = json!({"harness": "claude", "label": "claude-b"});
    let account = fx.ok_post("/api/v1/accounts", new).await["id"]
        .as_i64()
        .unwrap();
    let assign = format!("/api/v1/accounts/{account}/companies/{}", b.company.0);
    send(&fx.app, req(Method::PUT, &assign, Some(&fx.key), None)).await;
    assert_eq!(as_a("/api/v1/accounts").await.1, json!([]));
    assert_eq!(
        as_a("/api/v1/accounts/usage").await.0,
        StatusCode::NOT_FOUND
    );
    let (_, all) = send(
        &fx.app,
        req(Method::GET, "/api/v1/accounts", Some(&fx.key), None),
    )
    .await;
    assert_eq!(all.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_company_profile_is_set_checked_changed_and_cleared() {
    let fx = fx().await;
    let new = json!({"name": "Acme", "kind": "client", "color": "#2563eb",
        "description": "Builds rockets.", "industries": ["Software", "Research"],
        "website": "https://acme.example", "timezone": "Europe/Berlin",
        "work_start": 540, "work_end": 1080, "work_days": 31});
    let c = fx.ok_post("/api/v1/companies", new.clone()).await;
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
        let (status, got) = fx.post("/api/v1/companies", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{b}: {got}");
    }

    let uri = format!("/api/v1/companies/{}", c["id"]);
    let put = |body: Value| send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(body)));
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
        "SELECT details FROM audit_events WHERE action = 'company.updated' ORDER BY seq DESC",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["color"], "#10b981", "audited with its profile");
}
