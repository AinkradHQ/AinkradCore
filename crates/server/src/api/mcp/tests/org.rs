//! The org tools: any agent of the company reads its org chart, and only its own company's;
//! only the CEO routes an intake request, to new or existing projects.

use serde_json::json;

use super::plan::{ok, planning_team, refused};
use super::*;
use crate::store::org::get_team;
use crate::store::work::{get_issue, submit_intake};

#[tokio::test]
async fn any_agent_reads_its_own_companys_org_chart() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let (_, team, dev) = planning_team(pool, &a).await;

    let chart = ok(&fx, &a, "org_chart", json!({})).await;
    assert_eq!(chart["company"]["name"], "A");
    let agents: Vec<i64> = chart["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_i64().unwrap())
        .collect();
    assert_eq!(agents, [a.agent.0, dev.0]);
    let t = &chart["departments"][0]["teams"][0];
    assert_eq!(t["id"], team.0);
    assert_eq!(t["members"][0]["team_role"], "product_owner");
    assert_eq!(t["members"][1]["agent_id"], dev.0);
    // Its projects, so the CEO can route to one; never another company's.
    assert_eq!(
        chart["projects"],
        json!([{"id": get_issue(pool, a.issue).await.unwrap().unwrap().project_id.0,
                "key": "AAA", "name": "A project", "team_id": team.0}])
    );

    let theirs = ok(&fx, &b, "org_chart", json!({})).await;
    assert_eq!(theirs["projects"][0]["key"], "BBB");
    assert_eq!(theirs["projects"].as_array().unwrap().len(), 1);
    assert_eq!(theirs["company"]["name"], "B");
    assert_eq!(theirs["agents"].as_array().unwrap().len(), 1);
    assert!(theirs["departments"].as_array().unwrap().is_empty());
}

/// The company's CEO.
async fn ceo(pool: &SqlitePool, a: &Company) -> AgentId {
    let ceo = NewAgent {
        company_id: a.company,
        name: "Ceo".to_owned(),
        role: "CEO".to_owned(),
        org_role: OrgRole::Ceo,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &ceo).await.unwrap().id
}

/// A request from the admin to the company, waiting on its CEO.
async fn intake(pool: &SqlitePool, a: &Company, title: &str) -> ainkrad_core::work::Issue {
    let admin = AuditActor::User(ainkrad_core::work::UserId(1));
    submit_intake(pool, a.company, title, "Go", admin)
        .await
        .unwrap()
}

/// The CEO's run on the request, woken by it.
async fn ceo_run(fx: &Fx, a: &Company, ceo: AgentId, req: IssueId) -> Company {
    let pool = &fx.app.pool;
    let runner = NewRunner {
        name: "ceo-runner".to_owned(),
        tags: vec![],
    };
    let (runner, _) = register_runner(pool, &runner).await.unwrap();
    let run = dispatch_next(pool, runner.id, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .expect("the CEO is woken");
    assert_eq!((run.agent_id, run.issue_id), (ceo, Some(req)));
    let (run, token) = start_run(pool, run.id, AuditActor::Runner(runner.id), None, NOW)
        .await
        .unwrap();
    Company {
        company: a.company,
        agent: ceo,
        issue: req,
        run,
        token,
    }
}

/// The CEO's run on an intake request routes it to a department; no other agent may.
#[tokio::test]
async fn the_ceo_routes_an_intake_request() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let (_, team, _) = planning_team(pool, &a).await;
    let dept = get_team(pool, team).await.unwrap().unwrap().department_id;
    let ceo = ceo(pool, &a).await;
    let req = intake(pool, &a, "Launch").await;
    let route = |key: &str| {
        json!({"routes": [{"department_id": dept.0, "name": "Launch",
                                               "key": key}], "issue_id": req.id.0})
    };
    let why = refused(&fx, &a, "route_intake", route("LCH")).await;
    assert!(why.contains("only the CEO"), "{why}");
    let c = ceo_run(&fx, &a, ceo, req.id).await;
    let bad = refused(&fx, &c, "route_intake", route("lch")).await;
    assert!(bad.contains("capital letters"), "{bad}");
    assert!(!bad.contains("constraint"), "{bad}");
    let taken = refused(&fx, &c, "route_intake", route("AAA")).await;
    assert!(taken.contains("key `AAA` already"), "{taken}");
    let v = ok(&fx, &c, "route_intake", route("LCH")).await;
    assert_eq!(v["status"], "routed");
    let p = &v["projects"][0];
    assert_eq!(
        (p["key"].as_str(), p["team_id"].as_i64()),
        (Some("LCH"), Some(team.0))
    );
    assert_eq!(p["product_owner"], a.agent.0);
    let again = refused(&fx, &c, "route_intake", route("LC2")).await;
    assert!(again.contains("closed"), "{again}");
}

/// A product owner asks for a hire, which waits on a human; a developer may not ask, and the
/// generic request_approval no longer takes hires.
#[tokio::test]
async fn a_product_owner_requests_a_hire() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let hire = json!({"name": "Dev 3", "role": "Developer", "harness": "codex",
                      "model": "gpt-5", "runner_tags": ["macos"],
                      "justification": "two stories are waiting"});
    let why = refused(&fx, &a, "request_hire", hire.clone()).await;
    assert!(why.contains("product owner"), "{why}");

    planning_team(pool, &a).await;
    let v = ok(&fx, &a, "request_hire", hire).await;
    assert_eq!(v["status"], "pending_approval");
    let agent = crate::store::org::get_agent(pool, AgentId(v["agent_id"].as_i64().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (agent.status, agent.runner_tags, agent.harness),
        (
            AgentStatus::PendingApproval,
            vec!["macos".to_owned()],
            Harness::Codex
        )
    );
    let approval = crate::store::gov::get_approval(
        pool,
        ainkrad_core::gov::ApprovalId(v["approval_id"].as_i64().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (approval.requested_by, approval.agent_id),
        (a.agent, Some(agent.id))
    );

    let bad = json!({"name": "X", "role": "Dev", "harness": "gemini", "justification": "j"});
    let e = super::super::tools::call(
        &fx.app,
        a.scope(),
        &Default::default(),
        "request_hire",
        &bad.as_object().unwrap().clone(),
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("harness must be"), "{e}");
    let old = json!({"kind": "hire_agent", "summary": "hire"});
    let e = super::super::tools::call(
        &fx.app,
        a.scope(),
        &Default::default(),
        "request_approval",
        &old.as_object().unwrap().clone(),
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("request_hire"), "{e}");
}

/// The CEO routes a request to an existing project of its company (and a new one alongside);
/// another company's project, the intake project, or a mixed-up route is refused.
#[tokio::test]
async fn the_ceo_routes_a_request_to_an_existing_project() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let (aaa, team, _) = planning_team(pool, &a).await;
    let dept = get_team(pool, team).await.unwrap().unwrap().department_id;
    let bbb = get_issue(pool, b.issue).await.unwrap().unwrap().project_id;
    let ceo = ceo(pool, &a).await;
    let req = intake(pool, &a, "Invoices").await;
    let c = ceo_run(&fx, &a, ceo, req.id).await;
    let to = |routes: Value| json!({"routes": routes});
    for p in [bbb, req.project_id] {
        let why = refused(&fx, &c, "route_intake", to(json!([{"project_id": p.0}]))).await;
        assert!(why.contains(&format!("project {} is not", p.0)), "{why}");
    }
    let mixed = to(json!([{"project_id": aaa.0, "key": "X"}]));
    let why = refused(&fx, &c, "route_intake", mixed).await;
    assert!(why.contains("only project_id"), "{why}");

    let both = to(json!([{"project_id": aaa.0},
                         {"department_id": dept.0, "name": "Billing", "key": "BIL"}]));
    let v = ok(&fx, &c, "route_intake", both).await;
    let p = &v["projects"];
    assert_eq!(
        (&p[0]["project_id"], &p[0]["key"], &p[0]["created"]),
        (&json!(aaa.0), &json!("AAA"), &json!(false))
    );
    assert_eq!(
        (&p[1]["key"], &p[1]["created"]),
        (&json!("BIL"), &json!(true))
    );
    assert_eq!(p[0]["product_owner"], a.agent.0);
    let kickoff = IssueId(p[0]["kickoff_issue_id"].as_i64().unwrap());
    let kickoff = get_issue(pool, kickoff).await.unwrap().unwrap();
    assert_eq!(
        (kickoff.project_id, kickoff.requirement_id),
        (aaa, req.requirement_id)
    );
}
