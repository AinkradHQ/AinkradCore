//! `apply_plan` (E15.18 step 2): a whole plan in one call, all or nothing with every problem
//! listed, audited per item, and idempotent by its key.

use serde_json::{Value, json};

use super::plan::{DATES, ok, planning_team, refused};
use super::*;
use crate::store::work::{Commands, Repo, add_repo};

/// Requirement 7 on `a`'s project, which gets repos `api` and `web`.
async fn requirement(fx: &Fx, a: &Company) {
    let pool = &fx.app.pool;
    sqlx::query(
        "INSERT INTO requirements (id, company_id, number, title, requested_by_user_id) \
         VALUES (7, ?, 3, 'Phone alerts', 1)",
    )
    .bind(a.company.0)
    .execute(pool)
    .await
    .unwrap();
    for sql in [
        "UPDATE issues SET requirement_id = 7 WHERE id = ?",
        "UPDATE projects SET requirement_id = 7 WHERE id = \
         (SELECT project_id FROM issues WHERE id = ?)",
    ] {
        sqlx::query(sql)
            .bind(a.issue.0)
            .execute(pool)
            .await
            .unwrap();
    }
    let project = crate::store::work::get_issue(pool, a.issue)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    for name in ["api", "web"] {
        let r = Repo {
            id: 0,
            project_id: project,
            name: name.to_owned(),
            url: format!("https://git.example/acme/{name}.git"),
            default_branch: "main".to_owned(),
            position: 0,
            primary: false,
            forge: None,
            commands: Commands::default(),
        };
        let by = AuditActor::User(citadel_core::work::UserId(1));
        add_repo(pool, &r, by).await.unwrap().unwrap();
    }
}

/// How many rows each table holds, and how often each audited action happened.
async fn counts(fx: &Fx) -> Value {
    let one = |q: &'static str| async move {
        sqlx::query_scalar::<_, i64>(q)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap()
    };
    let mut out = json!({
        "epics": one("SELECT count(*) FROM epics").await,
        "issues": one("SELECT count(*) FROM issues").await,
        "sprints": one("SELECT count(*) FROM sprints").await,
        "repos": one("SELECT count(*) FROM issue_repos").await,
    });
    let audited: Vec<(String, i64)> = sqlx::query_as(
        "SELECT action, count(*) FROM audit_events WHERE action IN ('epic.created', \
         'issue.created', 'issue.repos_set', 'sprint.planned', 'issue.sprint_set', \
         'plan.applied') GROUP BY action",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    for (action, n) in audited {
        out[action] = json!(n);
    }
    out
}

fn plan(assignee: i64, key: &str) -> Value {
    let task = |title: &str, repo: &str| {
        json!({"title": title, "body": "b", "points": 3, "assignee_agent_id": assignee,
               "repos": [repo]})
    };
    json!({"idempotency_key": key, "submit": true,
    "sprint": {"name": "S1", "goal": "alerts", "starts_on": DATES.0, "ends_on": DATES.1},
    "epics": [
        {"title": "Sender", "tasks": [task("Queue", "api"), task("Push", "api")]},
        {"title": "Screen", "tasks": [task("List", "web"),
            json!({"title": "Later", "points": 1, "assignee_agent_id": assignee,
                   "sprint": false})]},
    ]})
}

#[tokio::test]
async fn a_whole_plan_in_one_call_all_or_nothing_audited_and_idempotent() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    requirement(&fx, &a).await;

    // Not a planner yet: refused as a whole.
    let why = refused(&fx, &a, "apply_plan", plan(1, "k1")).await;
    assert!(why.contains("product owner or team lead"), "{why}");
    let (_, _, dev) = planning_team(&fx.app.pool, &a).await;
    let before = counts(&fx).await;

    // Bad items: every one is named, and nothing at all is filed.
    let mut bad = plan(dev.0, "k1");
    bad["epics"][0]["tasks"][1]["assignee_agent_id"] = json!(999);
    bad["epics"][1]["epic_id"] = json!(999);
    let why = refused(&fx, &a, "apply_plan", bad).await;
    assert!(why.contains("nothing was filed; 3 problem(s)"), "{why}");
    assert!(why.contains("epics[0].tasks[1]: no agent 999"), "{why}");
    assert!(
        why.contains("epics[1].tasks[1]: epic 999 is not one of"),
        "{why}"
    );
    let mut bad = plan(dev.0, "k1");
    bad["epics"][1]["tasks"][0]["repos"] = json!(["nope"]);
    bad["sprint"]["ends_on"] = json!("2026-01-01");
    let why = refused(&fx, &a, "apply_plan", bad).await;
    assert!(why.contains("sprint: bad sprint dates"), "{why}");
    assert!(
        why.contains("epics[1].tasks[0].repos: the project has no repo"),
        "{why}"
    );
    assert_eq!(counts(&fx).await, before, "all or nothing");

    // The whole plan: 2 epics, 4 tasks (3 in the new sprint), repos, submitted for approval.
    let out = ok(&fx, &a, "apply_plan", plan(dev.0, "k1")).await;
    assert_eq!(out["problems"], json!([]), "{out}");
    assert_eq!(out["submitted"]["status"], "pending_approval", "{out}");
    assert_eq!(out["state"], "plan_review");
    let tasks = out["tasks"].as_array().unwrap().clone();
    assert_eq!(
        (out["epics"].as_array().unwrap().len(), tasks.len()),
        (2, 4)
    );
    let sprint = out["sprint_id"].as_i64().unwrap();
    // The new ids come back: each task as {id, key, ...}, and the sprint.
    let ids: Vec<&Value> = out["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["id"])
        .collect();
    assert_eq!(ids, tasks.iter().collect::<Vec<_>>(), "{out}");
    assert!(
        out["issues"][0]["key"]
            .as_str()
            .unwrap()
            .starts_with("AAA-"),
        "{out}"
    );
    assert_eq!(out["sprint"]["sprint_id"], sprint);
    assert_eq!(out["sprint"]["name"], "S1");
    let in_sprint: i64 = sqlx::query_scalar("SELECT count(*) FROM issues WHERE sprint_id = ?")
        .bind(sprint)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(in_sprint, 3);
    let after = counts(&fx).await;
    // Audited item by item, and the whole once.
    assert_eq!(after["epic.created"], 2);
    assert_eq!(
        after["issue.created"].as_i64().unwrap(),
        4 + before["issue.created"].as_i64().unwrap_or(0)
    );
    assert_eq!(after["issue.repos_set"], 3);
    assert_eq!(after["sprint.planned"], 1);
    assert_eq!(after["issue.sprint_set"], 3);
    assert_eq!(after["plan.applied"], 1);

    // The same key again: the first result, nothing filed twice.
    let again = ok(&fx, &a, "apply_plan", plan(dev.0, "k1")).await;
    assert_eq!(again["replayed"], true);
    assert_eq!(again["tasks"], json!(tasks));
    assert_eq!(again["issues"], out["issues"]);
    assert_eq!(counts(&fx).await, after);
}

#[tokio::test]
async fn plans_for_one_project_fill_its_one_planned_sprint() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    requirement(&fx, &a).await;
    let (_, _, dev) = planning_team(&fx.app.pool, &a).await;

    // Two plans, each asking for a new "S1": the second joins the first's sprint.
    let mut sprints = vec![];
    for key in ["k1", "k2"] {
        let mut p = plan(dev.0, key);
        p["submit"] = json!(false);
        let out = ok(&fx, &a, "apply_plan", p).await;
        sprints.push(out["sprint_id"].as_i64().unwrap());
    }
    assert_eq!(sprints[0], sprints[1]);
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sprints")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(names, ["S1"]);
    let in_sprint: i64 = sqlx::query_scalar("SELECT count(*) FROM issues WHERE sprint_id = ?")
        .bind(sprints[0])
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(in_sprint, 6, "3 tasks of each plan");
}

#[tokio::test]
async fn a_deleted_planned_sprint_is_not_reused_by_the_next_plan() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    requirement(&fx, &a).await;
    let (project, _, dev) = planning_team(pool, &a).await;
    // The empty planned sprint a past bug left behind (a reuse would keep its name).
    let left: i64 = sqlx::query_scalar(
        "INSERT INTO sprints (project_id, name, state) VALUES (?, 'Left', 'planned') \
         RETURNING id",
    )
    .bind(project.0)
    .fetch_one(pool)
    .await
    .unwrap();
    let by = AuditActor::User(citadel_core::work::UserId(1));
    crate::store::work::delete_empty_sprint(pool, citadel_core::work::SprintId(left), by)
        .await
        .unwrap();

    let mut p = plan(dev.0, "k1");
    p["submit"] = json!(false);
    let out = ok(&fx, &a, "apply_plan", p).await;
    let fresh = out["sprint_id"].as_i64().unwrap();
    let names: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM sprints")
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(names, [(fresh, "S1".to_owned())]);
}
