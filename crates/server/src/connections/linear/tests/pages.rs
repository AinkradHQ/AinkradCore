//! A list that was cut says so, the most requests a call makes is the number the hourly budget
//! counts, and Linear's reported budget reaches the broker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::linear::{Limit, MAX_REQUESTS_PER_CALL};

fn any() -> Limit {
    Limit::any()
}

#[tokio::test]
async fn list_teams_follows_pages_up_to_a_bound_and_says_when_it_was_cut() {
    let f = fx(false).await;
    let c = f.key().await;
    // Linear always has one more page: five are read, and the answer says it is cut.
    let n = Arc::new(AtomicUsize::new(0));
    let k = n.clone();
    f.fake.on("GQL Teams", move |_| {
        let i = k.fetch_add(1, Ordering::SeqCst) + 1;
        let node = json!({"id": TEAM_ENG, "key": format!("T{i}"), "name": "t"});
        Reply::data(json!({"teams": {"nodes": [node],
            "pageInfo": {"hasNextPage": true, "endCursor": format!("c{i}")}}}))
    });
    let v = run(&f, &c, &any(), "linear.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(
        (v["count"].as_u64(), &v["truncated"]),
        (Some(5), &json!(true)),
        "{v}"
    );
    assert_eq!(f.fake.count("GQL Teams"), 5);
    let afters: Vec<Value> = f
        .fake
        .seen()
        .iter()
        .filter(|s| s.op == "Teams")
        .map(|s| s.body["after"].clone())
        .collect();
    assert_eq!(
        afters,
        [
            json!(null),
            json!("c1"),
            json!("c2"),
            json!("c3"),
            json!("c4")
        ]
    );
    // Two pages and the end: nothing was cut.
    let m = Arc::new(AtomicUsize::new(0));
    f.fake.on("GQL Teams", move |_| {
        let i = m.fetch_add(1, Ordering::SeqCst) + 1;
        let node = json!({"id": TEAM_ENG, "key": format!("U{i}"), "name": "t"});
        let page = json!({"hasNextPage": i < 2, "endCursor": format!("d{i}")});
        Reply::data(json!({"teams": {"nodes": [node], "pageInfo": page}}))
    });
    let v = run(&f, &c, &any(), "linear.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(
        (v["count"].as_u64(), &v["truncated"]),
        (Some(2), &json!(false)),
        "{v}"
    );
    // More pages but no cursor to follow: cut, and no loop.
    f.fake.data(
        "Teams",
        json!({"teams": {"nodes": [], "pageInfo": {"hasNextPage": true, "endCursor": null}}}),
    );
    let before = f.fake.count("GQL Teams");
    let v = run(&f, &c, &any(), "linear.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(v["truncated"], true);
    assert_eq!(f.fake.count("GQL Teams"), before + 1);
}

#[tokio::test]
async fn the_other_lists_say_when_they_were_cut_and_never_for_a_team_that_was_cut_away() {
    let f = fx(false).await;
    let c = f.key().await;
    let state = json!({"id": STATE_ID, "name": "Todo", "team": {"key": "ENG"}});
    f.fake.data(
        "States",
        json!({"workflowStates": {"nodes": [state], "pageInfo": {"hasNextPage": true}}}),
    );
    let args = json!({"team": "ENG"});
    let v = run(&f, &c, &any(), "linear.list_workflow_states", args)
        .await
        .unwrap();
    assert_eq!(v["truncated"], true);
    let proj = |id: &str, more: bool| {
        json!({"nodes": [{"id": id, "name": "P"}],
        "pageInfo": {"hasNextPage": more}})
    };
    let teams = |eng: bool, ops: bool, more_teams: bool| {
        json!({"teams": {"nodes": [{"key": "ENG", "projects": proj("p1", eng)},
            {"key": "OPS", "projects": proj("p2", ops)}],
            "pageInfo": {"hasNextPage": more_teams}}})
    };
    f.fake.data("Projects", teams(false, false, false));
    let v = run(&f, &c, &any(), "linear.list_projects", json!({}))
        .await
        .unwrap();
    assert_eq!(
        (v["count"].as_u64(), &v["truncated"]),
        (Some(2), &json!(false)),
        "{v}"
    );
    // One team shown has more projects; or Linear has more teams.
    f.fake.data("Projects", teams(true, false, false));
    let v = run(&f, &c, &any(), "linear.list_projects", json!({}))
        .await
        .unwrap();
    assert_eq!(v["truncated"], true);
    f.fake.data("Projects", teams(false, false, true));
    let v = run(&f, &c, &any(), "linear.list_projects", json!({}))
        .await
        .unwrap();
    assert_eq!(v["truncated"], true);
    // Under a limit to ENG, OPS having more projects is not said.
    let l = Limit::only(&["ENG".to_owned()]);
    f.fake.data("Projects", teams(false, true, false));
    let v = run(&f, &c, &l, "linear.list_projects", json!({}))
        .await
        .unwrap();
    assert_eq!(
        (v["count"].as_u64(), &v["truncated"]),
        (Some(1), &json!(false)),
        "{v}"
    );
}

#[tokio::test]
async fn no_call_makes_more_requests_than_the_hourly_budget_counts() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = Limit::only(&["ENG".to_owned()]);
    f.fake.data("IssueRef", issue_ref("ENG-1", "ENG"));
    f.fake.data(
        "StateRef",
        json!({"workflowState": {"id": STATE_ID, "team": {"key": "ENG"}}}),
    );
    f.fake.data(
        "IssueUpdate",
        json!({"issueUpdate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "ENG-1", "team": {"key": "ENG"}}}}),
    );
    f.fake.data(
        "CommentCreate",
        json!({"commentCreate": {"success": true, "comment": {"id": "c1", "url": "u",
            "issue": {"identifier": "ENG-1", "team": {"key": "ENG"}}}}}),
    );
    f.fake.data(
        "TeamRef",
        json!({"teams": {"nodes": [{"id": TEAM_ENG, "key": "ENG"}]}}),
    );
    f.fake.data(
        "IssueCreate",
        json!({"issueCreate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "ENG-2", "team": {"key": "ENG"}}}}),
    );
    f.fake
        .data("Issue", json!({"issue": issue("ENG-1", "ENG")}));
    f.fake
        .data("Issues", json!({"issues": {"nodes": [], "pageInfo": {}}}));
    f.fake.data(
        "States",
        json!({"workflowStates": {"nodes": [], "pageInfo": {}}}),
    );
    f.fake
        .data("Projects", json!({"teams": {"nodes": [], "pageInfo": {}}}));
    f.fake.on("GQL Teams", |_| {
        let page = json!({"hasNextPage": true, "endCursor": "c"});
        Reply::data(json!({"teams": {"nodes": [], "pageInfo": page}}))
    });
    let calls = [
        ("linear.get_issue", json!({"id": "ENG-1"})),
        ("linear.search_issues", json!({})),
        ("linear.list_teams", json!({})),
        ("linear.list_workflow_states", json!({"team": "ENG"})),
        ("linear.list_projects", json!({})),
        ("linear.create_issue", json!({"team": "ENG", "title": "t"})),
        (
            "linear.update_issue",
            json!({"id": "ENG-1", "title": "t", "state_id": STATE_ID}),
        ),
        ("linear.add_comment", json!({"id": "ENG-1", "body": "b"})),
    ];
    let mut worst = 0;
    for (op, args) in calls {
        let before = f.fake.seen().len();
        let r = run(&f, &c, &l, op, args).await;
        assert!(r.is_ok(), "{op}: {r:?}");
        let used = f.fake.seen().len() - before;
        worst = worst.max(used);
        assert!(
            used <= MAX_REQUESTS_PER_CALL as usize,
            "{op} made {used} requests"
        );
    }
    assert_eq!(
        worst, MAX_REQUESTS_PER_CALL as usize,
        "the constant is the real worst case"
    );
}

#[tokio::test]
async fn what_linear_says_about_its_budget_is_kept_for_the_broker_once() {
    let f = fx(false).await;
    let c = f.key().await;
    let reset_ms = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600)
        * 1000;
    let ok = Reply::data(json!({"issue": issue("ENG-1", "ENG")}))
        .header("x-ratelimit-requests-remaining", "7")
        .header("x-ratelimit-requests-reset", &reset_ms.to_string());
    f.fake.on("GQL Issue", move |_| ok.clone());
    run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-1"}))
        .await
        .unwrap();
    let (remaining, reset, wait) = f.linear.quota(c.id).unwrap();
    assert_eq!(remaining, Some(7));
    assert_eq!(reset, i64::try_from(reset_ms / 1000).ok());
    // An ordinary answer never carries a wait: it would block the connection after every call.
    assert_eq!(wait, None);
    assert_eq!(f.linear.quota(c.id), None, "it is taken once");
    // A rate limit carries the wait.
    let slow = Reply::error(429, "RATELIMITED").header("retry-after", "30");
    f.fake.on("GQL Issue", move |_| slow.clone());
    let r = run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-1"})).await;
    assert!(r.is_err());
    assert_eq!(f.linear.quota(c.id), Some((None, None, Some(30))));
    // Nothing said, nothing kept.
    f.fake
        .data("Issue", json!({"issue": issue("ENG-1", "ENG")}));
    run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-1"}))
        .await
        .unwrap();
    assert_eq!(f.linear.quota(c.id), None);
}
