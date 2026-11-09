//! The planning commands of `citadel-server`, on a scratch database: plan, fill and estimate a
//! sprint, decide its commit, report and close it, and set a WIP limit; and the org commands
//! (departments, teams, seats), as the admin. Knowledge commands in `knowledge`.

mod pm_cli {
    mod accounts;
    mod avatars;
    mod forge;
    mod knowledge;
    mod linear;
    mod profile;
    mod repos;
    mod settings;
}

use std::path::PathBuf;
use std::process::Command;

/// A scratch database path in its own temp dir, removed on drop.
struct Db(PathBuf);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn db(name: &str) -> Db {
    let dir = std::env::temp_dir().join(format!("citadel-pm-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Db(dir.join("citadel.db"))
}

/// `citadel-server <verb> <noun> <db> <rest…>`: its trimmed stdout, or its stderr on failure.
fn cli(db: &Db, args: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(&args[..2])
        .arg(&db.0)
        .args(&args[2..])
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

fn ok(db: &Db, args: &[&str]) -> String {
    cli(db, args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

/// The product owner's commit (through the library: agents commit over MCP) waits on the
/// owner: `approval reject` returns it, `approval approve` starts it.
#[tokio::test]
async fn plans_commits_through_the_owner_reports_and_closes_a_sprint() {
    use citadel_core::org::{AgentId, TeamMembership, TeamRole};
    use citadel_core::work::{ProjectId, SprintId};
    use citadel_server::store::{self, org, work};

    let db = db("sprint");
    let c = ok(&db, &["company", "add", "A"]);
    let po = ok(&db, &["agent", "add", &c, "PO", "--harness", "claude"]);
    let hire = ok(&db, &["approval", "list", &c]);
    ok(
        &db,
        &["approval", "approve", hire.split('\t').next().unwrap()],
    );
    let p = ok(&db, &["project", "add", &c, "PRJ", "P", "--mode", "scrum"]);
    let i = ok(&db, &["issue", "add", &p, "a"]);
    ok(&db, &["project", "spec", &p, "Build the thing."]);
    let s = ok(
        &db,
        &[
            "sprint",
            "plan",
            &p,
            "S1",
            "--start",
            "2026-10-21",
            "--end",
            "2026-11-03",
        ],
    );
    ok(&db, &["sprint", "add", &s, &i]);
    ok(&db, &["issue", "estimate", &i, "5"]);
    assert!(
        cli(&db, &["sprint", "start", &s]).is_err(),
        "no start without the gate"
    );

    let pool = store::connect(&db.0).await.unwrap();
    let company = citadel_core::org::CompanyId(c.parse().unwrap());
    let dept = org::create_department(&pool, company, "Eng").await.unwrap();
    let team = org::create_team(&pool, dept.id, "Core").await.unwrap();
    let mut project = work::get_project(&pool, ProjectId(p.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    project.team_id = Some(team.id);
    assert!(work::update_project(&pool, &project).await.unwrap());
    let po = AgentId(po.parse().unwrap());
    let m = TeamMembership {
        team_id: team.id,
        agent_id: po,
        team_role: TeamRole::ProductOwner,
    };
    org::create_membership(&pool, &m).await.unwrap();
    let sprint = SprintId(s.parse().unwrap());
    let commit = || work::commit_sprint(&pool, sprint, po, None, None, "2026-10-22T10:00:00.000Z");
    assert!(matches!(commit().await, Ok(work::Commit::Pending(_))));

    let listed = ok(&db, &["approval", "list", &c]);
    assert!(listed.contains("sprint_commit\tpending"), "{listed}");
    let commit_line = listed
        .lines()
        .find(|l| l.contains("sprint_commit"))
        .unwrap();
    let first = commit_line.split('\t').next().unwrap().to_owned();
    ok(&db, &["approval", "reject", &first, "--reply", "trim it"]);
    let report = |db: &Db| -> serde_json::Value {
        serde_json::from_str(&ok(db, &["sprint", "report", &s])).unwrap()
    };
    assert_eq!(report(&db)["state"], "planned");
    assert!(ok(&db, &["approval", "list", &c]).contains("rejected\tsprint"));

    let Ok(work::Commit::Pending(again)) = commit().await else {
        panic!("pending again");
    };
    ok(&db, &["approval", "approve", &again.id.0.to_string()]);
    let r = report(&db);
    assert_eq!(
        (r["state"].as_str(), r["committed"].as_u64()),
        (Some("active"), Some(5))
    );
    ok(&db, &["sprint", "close", &s]);
    let r = report(&db);
    assert_eq!(
        (r["state"].as_str(), r["completed"].as_u64()),
        (Some("closed"), Some(0))
    );
    let usage = cli(&db, &["sprint", "close", &s, "--carry-to"]).unwrap_err();
    assert!(usage.contains("usage"), "{usage}");
    let why = cli(&db, &["sprint", "delete", &s]).unwrap_err();
    assert!(why.contains("closed sprint"), "{why}");
    let dates = ["--start", "2026-11-04", "--end", "2026-11-17"];
    let empty = ok(&db, &[&["sprint", "plan", &p, "S2"][..], &dates].concat());
    assert_eq!(ok(&db, &["sprint", "delete", &empty]), empty);
    pool.close().await;
}

#[test]
fn sets_and_clears_a_wip_limit() {
    let db = db("wip");
    let c = ok(&db, &["company", "add", "A"]);
    let kanban = ok(&db, &["project", "add", &c, "FLO", "Flow"]);
    let scrum = ok(
        &db,
        &["project", "add", &c, "SCR", "Scrum", "--mode", "scrum"],
    );
    ok(&db, &["wip", "set", &kanban, "in_progress", "2"]);
    ok(&db, &["wip", "set", &kanban, "in_progress", "none"]);
    let refused = cli(&db, &["wip", "set", &scrum, "in_progress", "2"]).unwrap_err();
    assert!(refused.contains("kanban"), "{refused}");
    assert!(cli(&db, &["wip", "set", &kanban, "done", "1"]).is_err());
}

/// Departments, teams and seats from a shell: an agent of another company gets no seat.
#[test]
fn adds_departments_teams_and_seats() {
    let db = db("org");
    let c = ok(&db, &["company", "add", "A"]);
    let other = ok(&db, &["company", "add", "B"]);
    let po = ok(&db, &["agent", "add", &c, "PO", "--harness", "claude"]);
    let outsider = ok(&db, &["agent", "add", &other, "X", "--harness", "claude"]);
    let eng = ok(&db, &["department", "add", &c, "Engineering"]);
    ok(&db, &["department", "add", &c, "Marketing"]);
    assert_eq!(
        ok(&db, &["department", "list", &c]),
        format!(
            "{eng}\tEngineering\n{}\tMarketing",
            eng.parse::<i64>().unwrap() + 1
        )
    );
    let team = ok(&db, &["team", "add", &eng, "Core"]);
    let seat = [
        "member",
        "add",
        &team,
        &po,
        "--role",
        "product_owner",
        "--capacity",
        "8",
    ];
    ok(&db, &seat);
    assert_eq!(
        ok(&db, &["team", "list", &eng]),
        format!("{team}\tCore\t{po}:product_owner")
    );
    let refused = cli(
        &db,
        &["member", "add", &team, &outsider, "--role", "member"],
    )
    .unwrap_err();
    assert!(refused.contains("different companies"), "{refused}");
    ok(&db, &["member", "remove", &team, &po]);
    assert!(cli(&db, &["member", "remove", &team, &po]).is_err());
    assert_eq!(
        ok(&db, &["team", "list", &eng]),
        format!("{team}\tCore"),
        "trimmed"
    );
}

/// With no CEO the admin routes an intake request from a shell; once there is one, the
/// request is the CEO's to route.
#[test]
fn files_and_routes_intake_requests() {
    let db = db("intake");
    let c = ok(&db, &["company", "add", "A"]);
    let po = ok(&db, &["agent", "add", &c, "PO", "--harness", "claude"]);
    let mkt = ok(&db, &["department", "add", &c, "Marketing"]);
    let team = ok(&db, &["team", "add", &mkt, "Brand"]);
    ok(
        &db,
        &["member", "add", &team, &po, "--role", "product_owner"],
    );
    let req = ok(
        &db,
        &["intake", "add", &c, "Launch", "--body", "v1 campaign"],
    );
    let route = format!("{mkt}:MKT:Campaign");
    let project = ok(&db, &["intake", "route", &req, &route]);
    assert!(project.parse::<i64>().is_ok(), "{project}");
    assert!(
        cli(&db, &["intake", "route", &req, &route]).is_err(),
        "routed once"
    );
    // A later request about that project goes to it: no new project, a kickoff there.
    let more = ok(&db, &["intake", "add", &c, "Launch v2"]);
    let bad = cli(&db, &["intake", "route", &more, "project:999"]).unwrap_err();
    assert!(bad.contains("is not a project"), "{bad}");
    let routed = ok(
        &db,
        &["intake", "route", &more, &format!("project:{project}")],
    );
    assert_eq!(routed, project);

    ok(
        &db,
        &[
            "agent",
            "add",
            &c,
            "Ceo",
            "--harness",
            "claude",
            "--org-role",
            "ceo",
            "--active",
        ],
    );
    let theirs = ok(&db, &["intake", "add", &c, "Next"]);
    let e = cli(
        &db,
        &["intake", "route", &theirs, &format!("{mkt}:NXT:Next")],
    )
    .unwrap_err();
    assert!(e.contains("next actor"), "{e}");
}

/// `agent add` hires: the agent waits on its approval, which activates it; only a company's
/// first CEO starts active.
#[tokio::test]
async fn agents_are_hired_through_an_approval() {
    use citadel_core::org::{AgentId, AgentStatus};
    use citadel_server::store::{self, org};

    let db = db("hire");
    let c = ok(&db, &["company", "add", "A"]);
    let dev = ok(&db, &["agent", "add", &c, "Dev", "--harness", "codex"]);
    let listed = ok(&db, &["approval", "list", &c]);
    assert!(listed.contains("hire_agent\tpending"), "{listed}");
    let early = cli(
        &db,
        &["agent", "add", &c, "X", "--harness", "codex", "--active"],
    );
    assert!(early.unwrap_err().contains("first CEO"));
    let boot = [
        "agent",
        "add",
        &c,
        "Ceo",
        "--harness",
        "claude",
        "--org-role",
        "ceo",
        "--active",
    ];
    ok(&db, &boot);
    let again = [
        "agent",
        "add",
        &c,
        "Ceo2",
        "--harness",
        "claude",
        "--org-role",
        "cto",
        "--active",
    ];
    assert!(cli(&db, &again).is_err(), "a CTO is hired");

    let pool = store::connect(&db.0).await.unwrap();
    let status = |id: &str| {
        let pool = pool.clone();
        let id = AgentId(id.parse().unwrap());
        async move { org::get_agent(&pool, id).await.unwrap().unwrap().status }
    };
    assert_eq!(status(&dev).await, AgentStatus::PendingApproval);
    ok(
        &db,
        &["approval", "approve", listed.split('\t').next().unwrap()],
    );
    assert_eq!(status(&dev).await, AgentStatus::Active);

    // A deadline for hires: the next one expires an hour after it opens; decided ones drop
    // out of the pending list.
    ok(&db, &["approval", "deadline", "hire_agent", "3600"]);
    assert!(cli(&db, &["approval", "deadline", "hire_agent", "-5"]).is_err());
    ok(&db, &["agent", "add", &c, "Qa", "--harness", "codex"]);
    let pending = ok(&db, &["approval", "list", &c, "--pending"]);
    let rows: Vec<&str> = pending.lines().collect();
    assert_eq!(rows.len(), 1, "{pending}");
    assert!(rows[0].contains("hire_agent\tpending\tagent"), "{pending}");
    assert!(!rows[0].ends_with("\t-"), "it has a deadline: {pending}");
    pool.close().await;
}

/// The Engineering template from a shell, twice: one team, seven hires waiting on approval.
#[test]
fn applies_the_engineering_template_once() {
    let db = db("template");
    let c = ok(&db, &["company", "add", "A"]);
    let team = ok(&db, &["template", "apply", "engineering", &c]);
    assert_eq!(ok(&db, &["template", "apply", "engineering", &c]), team);
    let hires = ok(&db, &["approval", "list", &c]);
    assert_eq!(hires.matches("hire_agent\tpending").count(), 7, "{hires}");
    let dept = ok(&db, &["department", "list", &c]);
    assert!(dept.ends_with("\tEngineering"), "{dept}");
}

/// Budgets from a shell: set (and change) one, list it with its spend, recount the spend.
#[test]
fn sets_lists_and_recomputes_budgets() {
    let db = db("budget");
    let c = ok(&db, &["company", "add", "A"]);
    let set = [
        "budget", "set", "company", &c, "week", "5000", "--warn", "90",
    ];
    let b = ok(&db, &set);
    assert_eq!(
        ok(&db, &set),
        b,
        "the same scope and period is changed, not added"
    );
    let soft = [
        "budget", "set", "company", &c, "total", "100", "--soft", "yes",
    ];
    ok(&db, &soft);
    assert!(cli(&db, &["budget", "set", "galaxy", &c, "week", "1"]).is_err());
    assert!(
        cli(
            &db,
            &["budget", "set", "company", &c, "week", "1", "--warn", "0"]
        )
        .is_err()
    );
    let listed = ok(&db, &["budget", "list", &c]);
    let rows: Vec<Vec<&str>> = listed.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(rows.len(), 2, "{listed}");
    assert_eq!(
        (
            rows[0][1],
            rows[0][3],
            rows[0][5],
            rows[0][7],
            rows[0][8],
            rows[0][9],
            rows[0][10]
        ),
        ("company", "week", "5000", "0", "5000", "90", "hard")
    );
    assert_eq!((rows[1][4], rows[1][10]), ("total", "soft"));
    assert_eq!(ok(&db, &["budget", "recompute"]), "0");
}

/// Prices, billing and the cost report from a shell: a price is dollars per million tokens,
/// versioned; an empty company reports nothing spent and nothing unpriced.
#[test]
fn sets_prices_and_billing_and_reports_cost() {
    let db = db("cost");
    let c = ok(&db, &["company", "add", "A"]);
    ok(
        &db,
        &["price", "set", "codex", "gpt-5", "1.25", "10", "0.125"],
    );
    ok(
        &db,
        &["price", "set", "codex", "gpt-5", "2.5", "10", "0.125"],
    );
    assert!(cli(&db, &["price", "set", "codex", "gpt-5", "-1", "1", "1"]).is_err());
    assert!(cli(&db, &["price", "set", "vim", "x", "1", "1", "1"]).is_err());
    assert_eq!(
        ok(&db, &["price", "list"]),
        "codex\tgpt-5\tv2\t2500000\t10000000\t125000"
    );
    ok(&db, &["billing", "set", "claude", "subscription"]);
    assert!(cli(&db, &["billing", "set", "claude", "free"]).is_err());
    let report: serde_json::Value =
        serde_json::from_str(&ok(&db, &["cost", "report", &c])).unwrap();
    assert_eq!(
        (
            report["runs"].as_i64(),
            report["cost_usd"].as_str(),
            report["unpriced"].as_str()
        ),
        (Some(0), Some("0.000000"), Some("0 runs"))
    );
}
