//! Reads for the home, agent and run screens: an agent's skills and caps, a company's runs,
//! open questions and hourly spend, an issue's diff per repo; and the per-issue token cap.

use ainkrad_core::exec::{RunEvent, Usage};
use ainkrad_core::gov::SkillAttach;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::ProjectMode;
use ainkrad_proto::runner::{RepoDiff, TokenCaps};
use serde_json::json;

use super::*;
use crate::store::exec::{
    get_run, record_progress, record_run_usage, run_token_cap, run_token_caps, transition_run,
};
use crate::store::gov::publish_skill;
use crate::store::work::ask_human;

#[tokio::test]
async fn an_agent_shows_its_skills_hire_date_and_caps() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let by = super::super::BY;
    let skill = |name: &'static str, attach: SkillAttach| async move {
        publish_skill(pool, a.company, name, "body", &attach, by)
            .await
            .unwrap()
    };
    skill("conventions", SkillAttach::Company).await;
    skill("conventions", SkillAttach::Company).await;
    skill("rust", SkillAttach::Role("Developer".to_owned())).await;
    skill("design", SkillAttach::Role("Designer".to_owned())).await;
    let got = fx.ok(&format!("/api/v1/agents/{}/skills", a.agent.0)).await;
    let names: Vec<_> = got
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap(), s["version"].as_i64().unwrap()))
        .collect();
    assert_eq!(
        names,
        [("conventions", 2), ("rust", 1)],
        "not another role's"
    );
    assert_eq!(got[1]["attached_role"], "Developer");
    assert_eq!(
        fx.get("/api/v1/agents/99/skills").await.0,
        StatusCode::NOT_FOUND
    );

    let set = |key: Key, value: &'static str| async move {
        let at = Scope::Company(a.company);
        crate::store::settings::set(pool, key, at, value, by, NOW)
            .await
            .unwrap();
    };
    set(Key::IssueTokenCap, "600000").await;
    let agent = fx.ok(&format!("/api/v1/agents/{}", a.agent.0)).await;
    assert!(agent["hired_at"].is_string());
    assert_eq!(
        (&agent["run_token_cap"], &agent["issue_token_cap"]),
        (&json!(2_000_000), &json!(600_000))
    );
}

#[tokio::test]
async fn the_issue_cap_caps_a_run_at_what_its_other_runs_left() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let run = get_run(pool, a.run.id).await.unwrap().unwrap();
    assert_eq!(
        run_token_cap(pool, &run, 50_000, NOW).await.unwrap(),
        50_000,
        "no cap"
    );
    let at = Scope::Project(a.project);
    let by = super::super::BY;
    crate::store::settings::set(pool, Key::IssueTokenCap, at, "30000", by, NOW)
        .await
        .unwrap();
    assert_eq!(
        run_token_cap(pool, &run, 50_000, NOW).await.unwrap(),
        30_000
    );
    // Its own tokens do not count against it; an earlier run's do.
    let used = Usage {
        input_tokens: 9_000,
        output_tokens: 1_000,
        cache_tokens: 0,
        cost_usd_micros: None,
    };
    record_run_usage(pool, &run, 1, &used, NOW).await.unwrap();
    let run = get_run(pool, a.run.id).await.unwrap().unwrap();
    assert_eq!(
        run_token_cap(pool, &run, 50_000, NOW).await.unwrap(),
        30_000
    );
    let by = AuditActor::Runner(a.runner);
    transition_run(pool, run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let mut next = run.clone();
    next.id = ainkrad_core::exec::RunId(run.id.0 + 1);
    assert_eq!(
        run_token_cap(pool, &next, 50_000, NOW).await.unwrap(),
        20_000
    );
}

#[tokio::test]
async fn a_company_lists_its_runs_questions_spend_and_diffs() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let c = format!("/api/v1/companies/{}", a.company.0);

    // Runs: filtered and paged.
    let all = fx.ok(&format!("{c}/runs")).await;
    assert_eq!(all["items"][0]["id"], a.run.id.0);
    let live = fx
        .ok(&format!("{c}/runs?live=true&agent={}", a.agent.0))
        .await;
    assert_eq!(live["items"].as_array().unwrap().len(), 1);
    let ended = fx.ok(&format!("{c}/runs?live=false")).await;
    assert_eq!(ended["items"], json!([]));
    let running = fx
        .ok(&format!("{c}/runs?state=running&issue={}", a.issue.0))
        .await;
    assert_eq!(running["items"].as_array().unwrap().len(), 1);
    let older = fx.ok(&format!("{c}/runs?after={}", a.run.id.0)).await;
    assert_eq!(older["items"], json!([]));
    assert_eq!(
        fx.get(&format!("{c}/runs?state=lost")).await.0,
        StatusCode::BAD_REQUEST
    );

    // Open questions across requirements.
    let asked = ask_human(pool, a.agent, Some(a.run.id), a.issue, "Which port?", &[])
        .await
        .unwrap();
    let questions = fx.ok(&format!("{c}/questions")).await;
    assert_eq!(questions[0]["id"], asked.id.0);
    assert_eq!(questions[0]["issue_key"], "AAA-1");

    // Spend by the hour: a day of hours, the last one holding the run's tokens.
    let run = get_run(pool, a.run.id).await.unwrap().unwrap();
    let used = Usage {
        input_tokens: 1_000,
        output_tokens: 200,
        cache_tokens: 0,
        cost_usd_micros: Some(50_000),
    };
    record_run_usage(pool, &run, 1, &used, NOW).await.unwrap();
    let series = fx.ok(&format!("{c}/spend")).await;
    let hours = series.as_array().unwrap();
    assert_eq!(hours.len(), 25, "a day of hours: {series}");
    assert_eq!(hours[24]["start"], "2026-10-22T10:00:00.000Z");
    assert_eq!(
        hours[24]["spend"],
        json!({"cost_usd_micros": 50_000, "priced_tokens": 1_200, "unpriced_tokens": 0,
               "unpriced_runs": 0, "subscription_tokens": 0, "subscription_runs": 0})
    );
    assert_eq!(hours[0]["spend"]["priced_tokens"], 0);
    let short = fx
        .ok(&format!("{c}/spend?since=2026-10-22T08:30:00.000Z"))
        .await;
    assert_eq!(short.as_array().unwrap().len(), 3);
    let days = fx.ok(&format!("{c}/spend?bucket=day")).await;
    let days = days.as_array().unwrap();
    assert_eq!(days.len(), 31, "30 days back, by the day");
    assert_eq!(days[30]["start"], "2026-10-22T00:00:00.000Z");
    assert_eq!(days[30]["spend"]["cost_usd_micros"], 50_000);
    for bad in [
        "since=soon",
        "since=2026-10-01T00:00:00.000Z",
        "bucket=week",
        "bucket=day&since=2026-10-23T00:00:00.000Z",
    ] {
        let uri = format!("{c}/spend?{bad}");
        assert_eq!(fx.get(&uri).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    // By agent and by department: the idle agent is there at zero, in no department.
    let b = fx.ok(&format!("{c}/costs/breakdown")).await;
    assert_eq!(b["agents"][0]["agent_id"], a.agent.0);
    assert_eq!(b["agents"][0]["spend"]["cost_usd_micros"], 50_000);
    assert_eq!(b["departments"][0]["department_id"], Value::Null);
    assert_eq!(b["departments"][0]["spend"]["priced_tokens"], 1_200);
    let later = fx
        .ok(&format!(
            "{c}/costs/breakdown?since=2026-10-22T11:00:00.000Z&until=2026-10-22T12:00:00.000Z"
        ))
        .await;
    assert_eq!(later["agents"][0]["spend"]["priced_tokens"], 0);

    // An issue's diff per repo, from the run that measured it.
    let uri = format!("/api/v1/issues/{}/diff", a.issue.0);
    let none = fx.ok(&uri).await;
    assert!(none["run_id"].is_null() && none["repos"] == json!([]));
    let repos = [RepoDiff {
        repo: "core".to_owned(),
        files: 2,
        insertions: 38,
        deletions: 6,
    }];
    record_progress(pool, a.run.id, a.runner, Some(2), &repos, NOW)
        .await
        .unwrap();
    let diff = fx.ok(&uri).await;
    assert_eq!(diff["run_id"], a.run.id.0);
    let run = fx.ok(&format!("/api/v1/runs/{}", a.run.id.0)).await;
    assert_eq!(run["diff_repos"][0]["insertions"], 38, "on the run too");
    assert_eq!(
        diff["repos"],
        json!([{"repo": "core", "files": 2, "insertions": 38, "deletions": 6}])
    );
}

/// Every stuck item says since when (the Why-stuck screen's age).
#[tokio::test]
async fn a_stuck_issue_says_since_when() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let by = AuditActor::Runner(a.runner);
    transition_run(pool, a.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    sqlx::query("UPDATE wake_requests SET status = 'dropped', dropped_reason = 'test'")
        .execute(pool)
        .await
        .unwrap();
    let later = "2027-01-01T00:00:00.000Z";
    *fx.clock.0.lock().unwrap() = later.to_owned();
    let stuck = fx.ok("/api/v1/stuck").await;
    let item = stuck
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["issue_id"] == a.issue.0)
        .unwrap_or_else(|| panic!("{stuck}"));
    let since = item["stuck_since"].as_str().unwrap();
    assert!(since.len() == 24 && since < later, "{since}");
}

#[tokio::test]
async fn the_issue_cap_stays_exact_while_the_run_cap_is_weighted() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let run = get_run(pool, a.run.id).await.unwrap().unwrap();
    let caps = run_token_caps(pool, &run, 50_000, 10, NOW).await.unwrap();
    assert_eq!(
        caps,
        TokenCaps {
            exact: None,
            run: 50_000,
            cache_weight_divisor: 10,
        },
        "no budget or issue cap: only the run's"
    );
    let at = Scope::Project(a.project);
    let by = super::super::BY;
    crate::store::settings::set(pool, Key::IssueTokenCap, at, "30000", by, NOW)
        .await
        .unwrap();
    let caps = run_token_caps(pool, &run, 50_000, 10, NOW).await.unwrap();
    assert_eq!(caps.exact, Some(30_000), "the issue cap counts in full");
    assert_eq!(caps.run, 50_000);
    assert_eq!(caps.cache_weight_divisor, 10);
    assert_eq!(caps.least(), 30_000);
    assert_eq!(
        run_token_cap(pool, &run, 50_000, NOW).await.unwrap(),
        caps.least(),
        "the token_cap an older runner counts is the least"
    );
}
