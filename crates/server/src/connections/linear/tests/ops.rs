//! Every operation: what it asks of Linear (always one of the adapter's own documents), and what
//! it hands back.

use serde_json::{Value, json};

use super::*;
use crate::connections::linear::{CallError, Limit};

pub(super) async fn run(
    f: &Fx,
    c: &Connection,
    l: &Limit,
    op: &str,
    args: Value,
) -> Result<Value, CallError> {
    f.linear.call(&f.cx(NOW), c, l, op, &args).await
}

fn any() -> Limit {
    Limit::any()
}

#[tokio::test]
async fn get_issue_asks_for_one_identifier_and_returns_the_issue() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake
        .data("Issue", json!({"issue": issue("ENG-12", "ENG")}));
    let v = run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-12"}))
        .await
        .unwrap();
    assert_eq!(v["identifier"], "ENG-12");
    assert_eq!(v["team"]["key"], "ENG");
    let seen = f.fake.last("GQL Issue").unwrap();
    assert_eq!(seen.body, json!({"id": "ENG-12"}));
    // A personal API key goes in the header as it is, with no Bearer.
    assert_eq!(seen.auth.as_deref(), Some(API_KEY));
    assert_eq!(seen.content_type.as_deref(), Some("application/json"));
    assert_eq!(f.fake.bad(), 0);
    // An issue Linear does not have is a plain not-found.
    f.fake.data("Issue", json!({"issue": null}));
    let r = run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-99"})).await;
    assert_eq!(r, Err(CallError::NotFound));
}

#[tokio::test]
async fn an_oauth_connection_sends_a_bearer() {
    let f = fx(true).await;
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    f.fake
        .data("Issue", json!({"issue": issue("ENG-1", "ENG")}));
    run(&f, &c, &any(), "linear.get_issue", json!({"id": "ENG-1"}))
        .await
        .unwrap();
    let want = format!("Bearer {ACCESS}");
    assert_eq!(f.fake.last("GQL Issue").unwrap().auth, Some(want));
}

#[tokio::test]
async fn search_builds_its_filter_from_typed_arguments_only() {
    let f = fx(false).await;
    let c = f.key().await;
    let page = json!({"issues": {"nodes": [issue("ENG-1", "ENG")],
        "pageInfo": {"hasNextPage": true, "endCursor": "abc"}}});
    f.fake.data("Issues", page);
    let args = json!({"team": "ENG", "text": "crash \" } { issues", "state": "In Progress",
        "state_type": "started", "assignee": "me", "priority": 2, "label": "bug",
        "order_by": "updated", "first": 10, "after": "cursor-1"});
    let v = run(&f, &c, &any(), "linear.search_issues", args)
        .await
        .unwrap();
    assert_eq!(v["issues"][0]["identifier"], "ENG-1");
    assert_eq!(v["page_info"]["endCursor"], "abc");
    let vars = f.fake.last("GQL Issues").unwrap().body;
    assert_eq!(vars["first"], 10);
    assert_eq!(vars["after"], "cursor-1");
    assert_eq!(vars["orderBy"], "updatedAt");
    let parts = vars["filter"]["and"].as_array().unwrap();
    assert_eq!(parts[0], json!({"team": {"key": {"eq": "ENG"}}}));
    assert_eq!(parts.len(), 7);
    // The caller's text is a value in the variables, and the document is still the constant.
    let text = parts[1]["or"][0]["title"]["containsIgnoreCase"].as_str();
    assert_eq!(text, Some("crash \" } { issues"));
    assert_eq!(f.fake.bad(), 0);
    // No arguments at all: no filter, the defaults.
    run(&f, &c, &any(), "linear.search_issues", json!({}))
        .await
        .unwrap();
    let vars = f.fake.last("GQL Issues").unwrap().body;
    assert_eq!(vars["filter"], Value::Null);
    assert_eq!(vars["first"], 25);
}

#[tokio::test]
async fn create_issue_resolves_the_team_then_sends_a_closed_input() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake.data(
        "TeamRef",
        json!({"teams": {"nodes": [{"id": TEAM_ENG, "key": "ENG"}]}}),
    );
    f.fake.data(
        "IssueCreate",
        json!({"issueCreate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "ENG-40", "title": "T", "url": "u",
                "team": {"key": "ENG"}}}}),
    );
    let args = json!({"team": "ENG", "title": "Fix it", "description": "Because", "priority": 1});
    let v = run(&f, &c, &any(), "linear.create_issue", args)
        .await
        .unwrap();
    assert_eq!(v["identifier"], "ENG-40");
    assert_eq!(f.fake.ops(), ["TeamRef", "IssueCreate"]);
    let input = f.fake.last("GQL IssueCreate").unwrap().body["input"].clone();
    assert_eq!(
        input,
        json!({"title": "Fix it", "description": "Because", "priority": 1, "teamId": TEAM_ENG})
    );
    assert_eq!(f.fake.bad(), 0);
    // `success: false` is not a success.
    f.fake
        .data("IssueCreate", json!({"issueCreate": {"success": false}}));
    let args = json!({"team": "ENG", "title": "Again"});
    let r = run(&f, &c, &any(), "linear.create_issue", args).await;
    assert_eq!(r, Err(CallError::BadRequest(200)));
}

#[tokio::test]
async fn update_issue_reads_the_issue_first_and_writes_by_uuid() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake.data("IssueRef", issue_ref("ENG-5", "ENG"));
    f.fake.data(
        "IssueUpdate",
        json!({"issueUpdate": {"success": true,
            "issue": {"id": ISSUE_ID, "identifier": "ENG-5", "title": "New", "url": "u",
                "state": {"name": "Done"}, "team": {"key": "ENG"}}}}),
    );
    let args = json!({"id": "ENG-5", "title": "New", "priority": 3, "state_id": STATE_ID});
    let v = run(&f, &c, &any(), "linear.update_issue", args)
        .await
        .unwrap();
    assert_eq!(v["state"]["name"], "Done");
    assert_eq!(f.fake.ops(), ["IssueRef", "IssueUpdate"]);
    let vars = f.fake.last("GQL IssueUpdate").unwrap().body;
    assert_eq!(vars["id"], ISSUE_ID, "by UUID, not by the identifier");
    assert_eq!(
        vars["input"],
        json!({"title": "New", "priority": 3, "stateId": STATE_ID})
    );
    assert_eq!(f.fake.bad(), 0);
    // Nothing to change is refused before any request.
    let before = f.fake.seen().len();
    let r = run(
        &f,
        &c,
        &any(),
        "linear.update_issue",
        json!({"id": "ENG-5"}),
    )
    .await;
    assert!(matches!(r, Err(CallError::Refused(_))));
    assert_eq!(f.fake.seen().len(), before);
}

#[tokio::test]
async fn add_comment_reads_the_issue_then_comments_by_uuid() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake.data("IssueRef", issue_ref("ENG-5", "ENG"));
    f.fake.data(
        "CommentCreate",
        json!({"commentCreate": {"success": true,
            "comment": {"id": "c1", "url": "u", "createdAt": "2026-11-06T10:00:00.000Z",
                "issue": {"identifier": "ENG-5", "team": {"key": "ENG"}}}}}),
    );
    let args = json!({"id": "ENG-5", "body": "Looks good"});
    let v = run(&f, &c, &any(), "linear.add_comment", args)
        .await
        .unwrap();
    assert_eq!(v["id"], "c1");
    assert!(
        v.get("issue").is_none(),
        "the issue is checked, not returned"
    );
    let vars = f.fake.last("GQL CommentCreate").unwrap().body;
    assert_eq!(
        vars["input"],
        json!({"issueId": ISSUE_ID, "body": "Looks good"})
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn the_lists_ask_fixed_documents_and_return_plain_lists() {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake.data(
        "Teams",
        json!({"teams": {"nodes": [{"id": TEAM_ENG, "key": "ENG", "name": "Eng"}]}}),
    );
    let v = run(&f, &c, &any(), "linear.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(v["teams"][0]["key"], "ENG");
    assert_eq!(
        f.fake.last("GQL Teams").unwrap().body["filter"],
        Value::Null
    );
    f.fake.data(
        "States",
        json!({"workflowStates": {"nodes": [
            {"id": STATE_ID, "name": "Todo", "type": "unstarted", "position": 1.0,
             "team": {"key": "ENG"}}]}}),
    );
    let v = run(
        &f,
        &c,
        &any(),
        "linear.list_workflow_states",
        json!({"team": "ENG"}),
    )
    .await
    .unwrap();
    assert_eq!(v["states"][0]["id"], STATE_ID);
    assert_eq!(
        f.fake.last("GQL States").unwrap().body,
        json!({"key": "ENG"})
    );
    f.fake.data(
        "Projects",
        json!({"teams": {"nodes": [{"key": "ENG", "projects": {"nodes": [
            {"id": "p1", "name": "Launch", "state": "started", "url": "u"},
            {"id": "p1", "name": "Launch", "state": "started", "url": "u"}]}}]}}),
    );
    let v = run(
        &f,
        &c,
        &any(),
        "linear.list_projects",
        json!({"team": "ENG", "first": 5}),
    )
    .await
    .unwrap();
    let list = v["projects"].as_array().unwrap();
    assert_eq!(list.len(), 1, "a project seen twice is listed once");
    assert_eq!(list[0]["team"], "ENG");
    let vars = f.fake.last("GQL Projects").unwrap().body;
    assert_eq!(vars, json!({"filter": {"key": {"eq": "ENG"}}, "first": 5}));
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn nothing_a_caller_adds_reaches_a_document_or_a_variable() {
    let f = fx(false).await;
    let c = f.key().await;
    let smuggled = [
        (
            "linear.get_issue",
            json!({"id": "ENG-1", "query": "{ viewer { id } }"}),
        ),
        (
            "linear.get_issue",
            json!({"id": "ENG-1", "fields": ["parent"]}),
        ),
        (
            "linear.get_issue",
            json!({"id": "ENG-1", "alias": "x: issue(id: \"OPS-1\")"}),
        ),
        (
            "linear.search_issues",
            json!({"filter": {"team": {"key": {"eq": "OPS"}}}}),
        ),
        ("linear.search_issues", json!({"first": 51})),
        ("linear.search_issues", json!({"first": 0})),
        ("linear.search_issues", json!({"state_type": "everything"})),
        ("linear.search_issues", json!({"assignee": "someone"})),
        ("linear.search_issues", json!({"order_by": "priority"})),
        ("linear.search_issues", json!({"after": "has space"})),
        (
            "linear.update_issue",
            json!({"id": "ENG-1", "teamId": TEAM_ENG}),
        ),
        (
            "linear.update_issue",
            json!({"id": "ENG-1", "parentId": ISSUE_ID}),
        ),
        (
            "linear.update_issue",
            json!({"id": "ENG-1", "state_id": "not-a-uuid"}),
        ),
        ("linear.update_issue", json!({"id": "ENG-1", "priority": 5})),
        (
            "linear.create_issue",
            json!({"team": "ENG", "title": "t", "teamId": TEAM_ENG}),
        ),
        (
            "linear.create_issue",
            json!({"team": "ENG", "title": "t", "projectId": ISSUE_ID}),
        ),
        ("linear.create_issue", json!({"team": "eng", "title": "t"})),
        ("linear.create_issue", json!({"team": "ENG"})),
        (
            "linear.add_comment",
            json!({"id": "ENG-1", "body": "b", "issueId": ISSUE_ID}),
        ),
        ("linear.add_comment", json!({"id": ISSUE_ID, "body": "b"})),
        (
            "linear.list_workflow_states",
            json!({"team": "ENG\", team2: x"}),
        ),
        ("linear.list_projects", json!({"first": 51})),
        ("linear.list_teams", json!({"first": 5})),
        ("linear.nope", json!({})),
    ];
    for (op, args) in smuggled {
        let r = run(&f, &c, &any(), op, args.clone()).await;
        assert!(
            matches!(r, Err(CallError::Refused(_))),
            "{op} {args}: {r:?}"
        );
    }
    assert!(
        f.fake.seen().is_empty(),
        "a refused call asks Linear nothing"
    );
    // A refusal says which NAME is unknown, never echoing a long value back.
    let r = run(
        &f,
        &c,
        &any(),
        "linear.get_issue",
        json!({"x".repeat(500): 1}),
    )
    .await;
    let Err(CallError::Refused(why)) = r else {
        panic!("{r:?}")
    };
    assert!(why.len() < 120, "{why}");
}
