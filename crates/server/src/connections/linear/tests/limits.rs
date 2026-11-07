//! What a limited connection (a grant with `teams`) may reach: on the request, and again on the
//! answer, because an identifier's prefix is only the team an issue WAS in.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::linear::answer::OUTSIDE;
use crate::connections::linear::{CallError, Limit};

fn limited(keys: &[&str]) -> Limit {
    Limit::only(&keys.iter().map(|k| (*k).to_owned()).collect::<Vec<_>>())
}

fn refused(r: &Result<Value, CallError>) -> bool {
    matches!(r, Err(CallError::Refused(_)))
}

/// A refusal says nothing about which team lies outside.
fn says_nothing_of(r: &Result<Value, CallError>, team: &str) {
    let Err(CallError::Refused(why)) = r else {
        panic!("not refused: {r:?}")
    };
    assert!(!why.contains(team), "{why}");
}

#[test]
fn the_limit_comes_from_the_teams_key_and_drops_what_is_not_a_team_key() {
    let grant = |v: &[&str]| {
        let list = v.iter().map(|s| (*s).to_owned()).collect();
        BTreeMap::from([("teams".to_owned(), list)])
    };
    assert_eq!(Limit::from_grant(&BTreeMap::new()), Limit::any());
    assert_eq!(Limit::from_grant(&grant(&["ENG"])), limited(&["ENG"]));
    // `*`, a lowercase key and a path are no team key: they only shrink what is allowed.
    let l = Limit::from_grant(&grant(&["*", "eng", "ENG/../OPS", "OPS"]));
    assert_eq!(l, limited(&["OPS"]));
    // Another limit key is not the teams limit.
    let other = BTreeMap::from([("projects".to_owned(), vec!["ENG".to_owned()])]);
    assert_eq!(Limit::from_grant(&other), Limit::any());
}

#[tokio::test]
async fn a_request_outside_the_limit_is_refused_before_any_call() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    let cases = [
        ("linear.get_issue", json!({"id": "OPS-1"})),
        ("linear.update_issue", json!({"id": "OPS-1", "title": "x"})),
        ("linear.add_comment", json!({"id": "OPS-1", "body": "x"})),
        ("linear.create_issue", json!({"team": "OPS", "title": "x"})),
        ("linear.list_workflow_states", json!({"team": "OPS"})),
        ("linear.search_issues", json!({"team": "OPS"})),
        ("linear.list_projects", json!({"team": "OPS"})),
    ];
    for (op, args) in cases {
        let r = run(&f, &c, &l, op, args).await;
        assert!(refused(&r), "{op}: {r:?}");
        says_nothing_of(&r, "OPS");
    }
    assert!(f.fake.seen().is_empty());
    // A limit with no usable team reaches nothing, in the operations that scope themselves too.
    let none = Limit::only(&["*".to_owned()]);
    for (op, args) in [
        ("linear.search_issues", json!({})),
        ("linear.list_teams", json!({})),
        ("linear.list_projects", json!({})),
        ("linear.get_issue", json!({"id": "ENG-1"})),
    ] {
        let r = run(&f, &c, &none, op, args).await;
        assert!(refused(&r), "{op}: {r:?}");
    }
    assert!(f.fake.seen().is_empty());
}

#[tokio::test]
async fn an_answer_in_another_team_is_refused_whatever_the_identifier_said() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    // ENG-1 was moved: Linear answers it with its NEW identifier and team.
    f.fake
        .data("Issue", json!({"issue": issue("OPS-9", "OPS")}));
    let r = run(&f, &c, &l, "linear.get_issue", json!({"id": "ENG-1"})).await;
    assert_eq!(r, Err(CallError::Refused(OUTSIDE.to_owned())));
    says_nothing_of(&r, "OPS");
    // The team says ENG but the identifier is another team's.
    f.fake
        .data("Issue", json!({"issue": issue("OPS-9", "ENG")}));
    let r = run(&f, &c, &l, "linear.get_issue", json!({"id": "ENG-1"})).await;
    assert!(refused(&r), "{r:?}");
    // No team at all cannot be checked, so it is refused rather than passed.
    let mut no_team = issue("ENG-1", "ENG");
    no_team["team"] = Value::Null;
    f.fake.data("Issue", json!({"issue": no_team}));
    let r = run(&f, &c, &l, "linear.get_issue", json!({"id": "ENG-1"})).await;
    assert!(refused(&r), "{r:?}");
    // A team that is not even text.
    let mut odd = issue("ENG-1", "ENG");
    odd["team"] = json!({"key": 5});
    f.fake.data("Issue", json!({"issue": odd}));
    assert!(refused(
        &run(&f, &c, &l, "linear.get_issue", json!({"id": "ENG-1"})).await
    ));
    // The same issue in the limit passes.
    f.fake
        .data("Issue", json!({"issue": issue("ENG-1", "ENG")}));
    let r = run(&f, &c, &l, "linear.get_issue", json!({"id": "ENG-1"})).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn a_search_carries_the_team_filter_and_one_stray_issue_refuses_the_page() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG", "WEB"]);
    let page = |issues: Vec<Value>| json!({"issues": {"nodes": issues, "pageInfo": {}}});
    f.fake.data(
        "Issues",
        page(vec![issue("ENG-1", "ENG"), issue("WEB-2", "WEB")]),
    );
    let r = run(&f, &c, &l, "linear.search_issues", json!({"text": "x"})).await;
    assert!(r.is_ok(), "{r:?}");
    let vars = f.fake.last("GQL Issues").unwrap().body;
    let parts = vars["filter"]["and"].as_array().unwrap();
    assert_eq!(parts[0], json!({"team": {"key": {"in": ["ENG", "WEB"]}}}));
    // The caller's own text is a separate AND part: it can not sit beside the team as an `or`.
    assert!(parts[1].get("or").is_some() && parts.len() == 2);
    // A team given narrows to that one team.
    run(&f, &c, &l, "linear.search_issues", json!({"team": "WEB"}))
        .await
        .unwrap();
    let vars = f.fake.last("GQL Issues").unwrap().body;
    assert_eq!(
        vars["filter"]["and"][0],
        json!({"team": {"key": {"eq": "WEB"}}})
    );
    // Linear ignores the filter (or one issue slipped through): the whole page is refused.
    f.fake.data(
        "Issues",
        page(vec![issue("ENG-1", "ENG"), issue("OPS-7", "OPS")]),
    );
    let r = run(&f, &c, &l, "linear.search_issues", json!({})).await;
    assert!(refused(&r), "{r:?}");
    says_nothing_of(&r, "OPS");
    // A page that cannot be read cannot be checked.
    f.fake.data("Issues", json!({"issues": {"nodes": "many"}}));
    assert!(refused(
        &run(&f, &c, &l, "linear.search_issues", json!({})).await
    ));
    f.fake.data("Issues", json!({"issues": null}));
    assert!(
        run(&f, &c, &l, "linear.search_issues", json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_change_is_checked_against_the_team_the_issue_is_in_now() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    // ENG-3 now lives in OPS: neither the comment nor the update is made.
    f.fake.data("IssueRef", issue_ref("ENG-3", "OPS"));
    for (op, args) in [
        ("linear.add_comment", json!({"id": "ENG-3", "body": "x"})),
        ("linear.update_issue", json!({"id": "ENG-3", "title": "x"})),
    ] {
        let r = run(&f, &c, &l, op, args).await;
        assert!(refused(&r), "{op}: {r:?}");
        says_nothing_of(&r, "OPS");
    }
    assert_eq!(f.fake.ops(), ["IssueRef", "IssueRef"], "no write was sent");
    // The pre-read answer is read strictly: no team, a team that is no text, an id that is no UUID.
    for bad in [
        json!({"issue": {"id": ISSUE_ID, "identifier": "ENG-3"}}),
        json!({"issue": {"id": ISSUE_ID, "team": {"key": 7}}}),
        json!({"issue": {"id": "ENG-3", "team": {"key": "ENG"}}}),
        json!({"issue": {"team": {"key": "ENG"}}}),
        json!({"issue": []}),
    ] {
        f.fake.data("IssueRef", bad.clone());
        let r = run(
            &f,
            &c,
            &l,
            "linear.add_comment",
            json!({"id": "ENG-3", "body": "x"}),
        )
        .await;
        assert!(refused(&r), "{bad}: {r:?}");
    }
    assert_eq!(f.fake.count("GQL CommentCreate"), 0);
    // An issue Linear does not show is not found, and nothing is written.
    f.fake.data("IssueRef", json!({"issue": null}));
    let r = run(
        &f,
        &c,
        &l,
        "linear.add_comment",
        json!({"id": "ENG-3", "body": "x"}),
    )
    .await;
    assert_eq!(r, Err(CallError::NotFound));
}

#[tokio::test]
async fn a_state_of_another_team_is_not_moved_to() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG", "OPS"]);
    f.fake.data("IssueRef", issue_ref("ENG-3", "ENG"));
    // The state belongs to OPS, which the limit DOES allow: still not this issue's team.
    f.fake.data(
        "StateRef",
        json!({"workflowState": {"id": STATE_ID, "team": {"key": "OPS"}}}),
    );
    let args = json!({"id": "ENG-3", "state_id": STATE_ID});
    let r = run(&f, &c, &l, "linear.update_issue", args.clone()).await;
    assert!(refused(&r), "{r:?}");
    assert_eq!(f.fake.count("GQL IssueUpdate"), 0);
    // The same team's state is accepted.
    f.fake.data(
        "StateRef",
        json!({"workflowState": {"id": STATE_ID, "team": {"key": "ENG"}}}),
    );
    f.fake.data(
        "IssueUpdate",
        json!({"issueUpdate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "ENG-3", "team": {"key": "ENG"}}}}),
    );
    assert!(
        run(&f, &c, &l, "linear.update_issue", args.clone())
            .await
            .is_ok()
    );
    // A state Linear does not have, or one that names no team, is not accepted.
    f.fake.data("StateRef", json!({"workflowState": null}));
    let r = run(&f, &c, &l, "linear.update_issue", args.clone()).await;
    assert_eq!(r, Err(CallError::NotFound));
    f.fake
        .data("StateRef", json!({"workflowState": {"id": STATE_ID}}));
    assert!(refused(&run(&f, &c, &l, "linear.update_issue", args).await));
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_write_that_lands_in_another_team_is_refused_on_the_answer_too() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    f.fake.data("IssueRef", issue_ref("ENG-3", "ENG"));
    f.fake.data(
        "IssueUpdate",
        json!({"issueUpdate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "OPS-3", "team": {"key": "OPS"}}}}),
    );
    let r = run(
        &f,
        &c,
        &l,
        "linear.update_issue",
        json!({"id": "ENG-3", "title": "x"}),
    )
    .await;
    assert!(refused(&r), "{r:?}");
    // A create: the team is looked up by key and must answer as that team.
    let args = json!({"team": "ENG", "title": "x"});
    f.fake.data(
        "TeamRef",
        json!({"teams": {"nodes": [{"id": TEAM_ENG, "key": "OPS"}]}}),
    );
    let r = run(&f, &c, &l, "linear.create_issue", args.clone()).await;
    assert_eq!(
        r,
        Err(CallError::NotFound),
        "a team that answers as another is not used"
    );
    assert_eq!(f.fake.count("GQL IssueCreate"), 0);
    f.fake.data(
        "TeamRef",
        json!({"teams": {"nodes": [{"id": "not-a-uuid", "key": "ENG"}]}}),
    );
    let r = run(&f, &c, &l, "linear.create_issue", args.clone()).await;
    assert_eq!(r, Err(CallError::NotFound));
    f.fake.data(
        "TeamRef",
        json!({"teams": {"nodes": [{"id": TEAM_ENG, "key": "ENG"}]}}),
    );
    f.fake.data(
        "IssueCreate",
        json!({"issueCreate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "OPS-1", "team": {"key": "OPS"}}}}),
    );
    let r = run(&f, &c, &l, "linear.create_issue", args).await;
    assert!(refused(&r), "{r:?}");
}

#[tokio::test]
async fn the_lists_are_cut_to_the_limit_and_carry_no_totals() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    f.fake.data(
        "Teams",
        json!({"teams": {"nodes": [
            {"id": TEAM_ENG, "key": "ENG", "name": "Eng"},
            {"id": ISSUE_ID, "key": "OPS", "name": "Secret ops"},
            {"id": ISSUE_ID, "name": "no key"}],
            "pageInfo": {"hasNextPage": false}}}),
    );
    let v = run(&f, &c, &l, "linear.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(
        v,
        json!({"count": 1, "teams": [{"id": TEAM_ENG, "key": "ENG", "name": "Eng"}],
            "truncated": false})
    );
    assert_eq!(
        f.fake.last("GQL Teams").unwrap().body["filter"],
        json!({"key": {"in": ["ENG"]}}),
        "the request is cut too, not only the answer"
    );
    // Projects are read through teams: another team's node is dropped with its projects.
    f.fake.data(
        "Projects",
        json!({"teams": {"nodes": [
            {"key": "ENG", "projects": {"nodes": [{"id": "p1", "name": "Mine"}]}},
            {"key": "OPS", "projects": {"nodes": [{"id": "p2", "name": "Theirs"}]}}]}}),
    );
    let v = run(&f, &c, &l, "linear.list_projects", json!({}))
        .await
        .unwrap();
    let names: Vec<_> = v["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Mine"]);
    assert_eq!(
        f.fake.last("GQL Projects").unwrap().body["filter"],
        json!({"key": {"in": ["ENG"]}})
    );
    // A workflow-state list is refused if one state says another team.
    f.fake.data(
        "States",
        json!({"workflowStates": {"nodes": [
            {"id": STATE_ID, "name": "Todo", "team": {"key": "ENG"}},
            {"id": ISSUE_ID, "name": "Todo", "team": {"key": "OPS"}}]}}),
    );
    let r = run(
        &f,
        &c,
        &l,
        "linear.list_workflow_states",
        json!({"team": "ENG"}),
    )
    .await;
    assert!(refused(&r), "{r:?}");
    f.fake.data(
        "States",
        json!({"workflowStates": {"nodes": [{"id": STATE_ID, "name": "Todo"}]}}),
    );
    let r = run(
        &f,
        &c,
        &l,
        "linear.list_workflow_states",
        json!({"team": "ENG"}),
    )
    .await;
    assert!(refused(&r), "a state that names no team cannot be checked");
}

#[tokio::test]
async fn an_unlimited_connection_reaches_every_team() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake
        .data("Issue", json!({"issue": issue("OPS-9", "OPS")}));
    let r = run(
        &f,
        &c,
        &Limit::any(),
        "linear.get_issue",
        json!({"id": "OPS-9"}),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn a_comment_on_an_issue_that_moved_is_refused_and_shows_nothing_of_the_other_team() {
    let f = fx(false).await;
    let c = f.key().await;
    let l = limited(&["ENG"]);
    f.fake.data("IssueRef", issue_ref("ENG-3", "ENG"));
    // Between the pre-read and the write the issue moved to OPS: the answer names it.
    f.fake.data(
        "CommentCreate",
        json!({"commentCreate": {"success": true, "comment": {"id": "c9",
            "url": "https://linear.app/acme/issue/OPS-9#comment-c9", "createdAt": "t",
            "issue": {"identifier": "OPS-9", "team": {"key": "OPS"}}}}}),
    );
    let r = run(
        &f,
        &c,
        &l,
        "linear.add_comment",
        json!({"id": "ENG-3", "body": "x"}),
    )
    .await;
    assert!(refused(&r), "{r:?}");
    says_nothing_of(&r, "OPS");
    // An answer that does not say which issue it is on cannot be checked either.
    f.fake.data(
        "CommentCreate",
        json!({"commentCreate": {"success": true, "comment": {"id": "c9", "url": "u"}}}),
    );
    let r = run(
        &f,
        &c,
        &l,
        "linear.add_comment",
        json!({"id": "ENG-3", "body": "x"}),
    )
    .await;
    assert!(refused(&r), "{r:?}");
}
