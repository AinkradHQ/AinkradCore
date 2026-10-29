//! Role-scoped tools (E15.18 step 1): each role's list, `search_tools` and `describe_tool` for
//! the rest, and calls outside the list still decided by each tool's own permission check.

use serde_json::json;

use super::super::roles::listed;
use super::plan::{ok, planning_team, refused};
use super::*;

async fn names(fx: &Fx, a: &Company) -> Vec<String> {
    listed(&fx.app, a.scope())
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect()
}

async fn sql(fx: &Fx, q: &'static str, id: i64) {
    sqlx::query(q).bind(id).execute(&fx.app.pool).await.unwrap();
}

/// Each role's list holds its tools and not the others'; everyone has the common ones and
/// the two discovery tools.
#[tokio::test]
async fn each_role_lists_its_own_tools() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let has = |list: &[String], tools: &[&str], yes: bool| {
        for t in tools {
            assert_eq!(list.iter().any(|n| n == t), yes, "{t} in {list:?}");
        }
    };
    let common = [
        "get_issue",
        "comment",
        "transition",
        "search_tools",
        "describe_tool",
    ];

    let dev = names(&fx, &a).await;
    has(&dev, &common, true);
    has(&dev, &["open_pr", "request_repo"], true);
    has(
        &dev,
        &["qa_verdict", "plan_sprint", "apply_plan", "route_intake"],
        false,
    );

    sql(&fx, "UPDATE agents SET role = 'QA' WHERE id = ?", a.agent.0).await;
    let qa = names(&fx, &a).await;
    has(&qa, &["qa_verdict"], true);
    has(&qa, &["open_pr", "plan_sprint"], false);

    sql(&fx, "UPDATE agents SET role = 'PO' WHERE id = ?", a.agent.0).await;
    planning_team(&fx.app.pool, &a).await;
    let po = names(&fx, &a).await;
    has(&po, &common, true);
    has(
        &po,
        &["apply_plan", "plan_sprint", "set_repos", "org_chart"],
        true,
    );
    has(
        &po,
        &["decide_repo", "open_pr", "qa_verdict", "route_intake"],
        false,
    );

    let lead = "UPDATE team_memberships SET team_role = 'team_lead' WHERE agent_id = ?";
    sql(&fx, lead, a.agent.0).await;
    let lead = names(&fx, &a).await;
    has(
        &lead,
        &["decide_repo", "review_knowledge", "apply_plan"],
        true,
    );
    has(&lead, &["open_pr", "route_intake"], false);

    sql(
        &fx,
        "DELETE FROM team_memberships WHERE agent_id = ?",
        a.agent.0,
    )
    .await;
    sql(
        &fx,
        "UPDATE agents SET org_role = 'ceo' WHERE id = ?",
        a.agent.0,
    )
    .await;
    let ceo = names(&fx, &a).await;
    has(&ceo, &["route_intake", "apply_plan", "org_chart"], true);
    has(&ceo, &["open_pr", "plan_sprint", "decide_repo"], false);

    sql(
        &fx,
        "UPDATE agents SET org_role = 'cto' WHERE id = ?",
        a.agent.0,
    )
    .await;
    let cto = names(&fx, &a).await;
    has(&cto, &["plan_sprint", "apply_plan", "request_hire"], true);
    has(&cto, &["route_intake", "open_pr", "qa_verdict"], false);
    assert!(cto.len() < super::super::defs::list().len());
}

/// A developer finds the tools it was not given, reads one, and may call any; each still
/// decides by its own rules: the org chart is anyone's, sprint planning a planner's.
#[tokio::test]
async fn other_tools_are_found_described_and_still_permission_checked() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;

    let found = ok(&fx, &a, "search_tools", json!({"query": "plan a sprint"})).await;
    let tools = found["tools"].as_array().unwrap();
    let sprint = tools.iter().find(|t| t["name"] == "plan_sprint").unwrap();
    assert_eq!(sprint["listed"], false, "{found}");
    assert!(
        sprint["summary"]
            .as_str()
            .unwrap()
            .starts_with("Plan a sprint")
    );
    assert!(tools.len() <= 10);

    let d = ok(&fx, &a, "describe_tool", json!({"name": "plan_sprint"})).await;
    assert_eq!(d["listed"], false);
    assert_eq!(
        d["input_schema"]["required"],
        json!(["name", "starts_on", "ends_on"])
    );
    let mine = ok(&fx, &a, "describe_tool", json!({"name": "open_pr"})).await;
    assert_eq!(mine["listed"], true);
    let why = refused(&fx, &a, "describe_tool", json!({"name": "rm_rf"})).await;
    assert!(why.contains("no tool"), "{why}");

    // Outside its list: allowed when the tool allows it, refused when it does not.
    let chart = ok(&fx, &a, "org_chart", json!({})).await;
    assert!(chart["agents"].is_array(), "{chart}");
    let (starts_on, ends_on) = super::plan::DATES;
    let plan = json!({"name": "S1", "starts_on": starts_on, "ends_on": ends_on});
    let why = refused(&fx, &a, "plan_sprint", plan).await;
    assert!(why.contains("product owner or team lead"), "{why}");
}

/// `mcp.role_scoped_tools`: off for the company lists everything, back on for one project,
/// and only 0 or 1.
#[tokio::test]
async fn scoping_is_a_setting_a_project_overrides() {
    use ainkrad_core::settings::{Key, Scope};
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let by = AuditActor::User(ainkrad_core::work::UserId(1));
    let set = |at, v: &'static str| {
        crate::store::settings::set(&fx.app.pool, Key::McpRoleScopedTools, at, v, by, NOW)
    };
    let all = super::super::defs::list().len();
    let scoped = names(&fx, &a).await.len();
    assert!(scoped < all);
    set(Scope::Company(a.company), "0").await.unwrap();
    assert_eq!(names(&fx, &a).await.len(), all);
    let project = crate::store::work::get_issue(&fx.app.pool, a.issue)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    set(Scope::Project(project), "1").await.unwrap();
    assert_eq!(names(&fx, &a).await.len(), scoped);
    assert!(set(Scope::Project(project), "2").await.is_err());
}
