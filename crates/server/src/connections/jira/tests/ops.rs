//! The operations and the project limit: what is sent, and every way a limited connection might
//! try to reach another project.

use serde_json::{Value, json};

use super::*;
use crate::connections::jira::{CallError, Limit, resource_of};

fn limited(keys: &[&str]) -> Limit {
    Limit::only(&keys.iter().map(|k| (*k).to_owned()).collect::<Vec<_>>())
}

async fn run(f: &Fx, c: &Connection, l: &Limit, op: &str, args: Value) -> Result<Value, CallError> {
    f.jira.call(&f.cx(NOW), c, l, op, &args).await
}

fn refused(r: &Result<Value, CallError>) -> bool {
    matches!(r, Err(CallError::Refused(_)))
}

fn search_key() -> String {
    format!("POST {}", site_path("/search/jql"))
}

fn issues(projects: &[&str]) -> Value {
    let list: Vec<Value> = projects
        .iter()
        .enumerate()
        .map(|(i, p)| json!({"key": format!("{p}-{}", i + 1), "fields": {"project": {"key": p}}}))
        .collect();
    json!({"issues": list})
}

#[tokio::test]
async fn a_limited_search_adds_the_project_constraint_and_orders_by_name() {
    let f = fx(false).await;
    let c = f.basic().await;
    f.fake.reply(&search_key(), 200, issues(&["ABC", "DEF"]));
    let args = json!({"jql": "status = Open", "order_by": ["created desc", "priority"]});
    let v = run(
        &f,
        &c,
        &limited(&["ABC", "DEF"]),
        "jira.search_issues",
        args,
    )
    .await;
    assert_eq!(v.unwrap()["issues"].as_array().unwrap().len(), 2);
    let sent = f.fake.last(&search_key()).unwrap();
    assert_eq!(
        sent.body["jql"],
        r#"project in ("ABC", "DEF") AND (status = Open) ORDER BY created DESC, priority"#
    );
    assert!(
        sent.body["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "project")
    );
    let basic = format!("Basic {}", base64_of(&format!("{EMAIL}:{API_TOKEN}")));
    assert_eq!(sent.auth.as_deref(), Some(basic.as_str()));
    // An empty JQL is just the constraint; a project argument narrows to that one.
    run(
        &f,
        &c,
        &limited(&["ABC", "DEF"]),
        "jira.search_issues",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        f.fake.last(&search_key()).unwrap().body["jql"],
        r#"project in ("ABC", "DEF")"#
    );
    let one = json!({"project": "DEF", "jql": "x = 1"});
    run(&f, &c, &limited(&["ABC", "DEF"]), "jira.search_issues", one)
        .await
        .unwrap();
    assert_eq!(
        f.fake.last(&search_key()).unwrap().body["jql"],
        r#"project = "DEF" AND (x = 1)"#
    );
    assert_eq!(
        resource_of("jira.search_issues", &json!({"project": "DEF"})),
        Ok(Some("DEF".into()))
    );
    assert_eq!(resource_of("jira.search_issues", &json!({})), Ok(None));
}

fn base64_of(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[tokio::test]
async fn jql_that_tries_to_leave_the_wrapper_is_refused_before_any_request() {
    let f = fx(false).await;
    let c = f.basic().await;
    f.fake.reply(&search_key(), 200, issues(&["ABC"]));
    let l = limited(&["ABC"]);
    let attacks = [
        "1=1) OR (project = SECRET",
        "x = 1) OR project = SECRET OR (y = 2",
        ") OR project = SECRET OR (",
        "(x = 1",
        "x = 1))",
        r#"summary ~ "a\" ) OR (project = SECRET"#,
        "summary ~ 'unclosed",
        "x = 1 ORDER BY created",
        "x = 1 order   by created",
        "x = 1\nORDER\nBY created",
        "x = \u{201C}a) OR (project = SECRET\u{201D}",
        "x = `a",
        "x = \u{FF09} OR project = SECRET",
        "x = 1\u{0}",
    ];
    for a in attacks {
        let r = run(&f, &c, &l, "jira.search_issues", json!({"jql": a})).await;
        assert!(refused(&r), "{a:?} -> {r:?}");
    }
    assert_eq!(f.fake.count(&search_key()), 0, "none of them reached Jira");
    // Balanced and quoted is fine: the quote hides the parenthesis, so it stays inside the wrapper.
    let ok = r#"summary ~ "x) OR (project = SECRET" AND (a = 1 OR b = 2)"#;
    run(&f, &c, &l, "jira.search_issues", json!({"jql": ok}))
        .await
        .unwrap();
    let jql = f.fake.last(&search_key()).unwrap().body["jql"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(jql, format!(r#"project in ("ABC") AND ({ok})"#));
    // A bare other-project clause is wrapped, so it can only narrow.
    run(
        &f,
        &c,
        &l,
        "jira.search_issues",
        json!({"jql": "project = SECRET"}),
    )
    .await
    .unwrap();
    let jql = f.fake.last(&search_key()).unwrap().body["jql"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(jql, r#"project in ("ABC") AND (project = SECRET)"#);
    // order_by takes names, not JQL.
    for o in [
        json!(["created; drop"]),
        json!(["a b c"]),
        json!(["x) OR (y"]),
        json!(["a sideways"]),
        json!("created"),
    ] {
        let r = run(&f, &c, &l, "jira.search_issues", json!({"order_by": o})).await;
        assert!(refused(&r), "{o}");
    }
}

#[tokio::test]
async fn a_search_naming_another_project_or_returning_one_is_refused() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    for p in ["SECRET", "abc", "AB C", "ABC\" OR project = \"X"] {
        let r = run(&f, &c, &l, "jira.search_issues", json!({"project": p})).await;
        assert!(refused(&r), "{p}");
    }
    assert_eq!(f.fake.count(&search_key()), 0);
    // A result outside the limit (the constraint failed somewhere) refuses the whole answer.
    f.fake.reply(&search_key(), 200, issues(&["ABC", "SECRET"]));
    let r = run(&f, &c, &l, "jira.search_issues", json!({})).await;
    assert!(refused(&r), "{r:?}");
    f.fake.reply(
        &search_key(),
        200,
        json!({"issues": [{"key": "ABC-1", "fields": {}}]}),
    );
    assert!(refused(
        &run(&f, &c, &l, "jira.search_issues", json!({})).await
    ));
    f.fake.reply(&search_key(), 200, json!({"nope": true}));
    assert!(refused(
        &run(&f, &c, &l, "jira.search_issues", json!({})).await
    ));
    // No project reachable at all, and a lowercase entry in a grant, reach nothing.
    let none = limited(&["abc"]);
    assert!(refused(
        &run(&f, &c, &none, "jira.search_issues", json!({})).await
    ));
    assert!(refused(
        &run(&f, &c, &none, "jira.get_issue", json!({"key": "ABC-1"})).await
    ));
}

#[tokio::test]
async fn issues_are_addressed_by_key_only_and_a_moved_issue_is_caught() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let one = |k: &str| format!("GET {}", site_path(&format!("/issue/{k}")));
    f.fake.reply(
        &one("ABC-1"),
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
    );
    let ok = run(
        &f,
        &c,
        &l,
        "jira.get_issue",
        json!({"key": "ABC-1", "fields": ["summary"]}),
    )
    .await;
    assert_eq!(ok.unwrap()["key"], "ABC-1");
    assert_eq!(
        f.fake.last(&one("ABC-1")).unwrap().query,
        "fields=summary,project"
    );
    for k in [
        "SECRET-1",
        "10042",
        "ABC-1/../SECRET-2",
        "abc-1",
        "ABC-1?x=1",
        "ABC-01",
        "ABC-1 ",
        "../SECRET-1",
        "ABC-1%2f..%2fSECRET-2",
    ] {
        let r = run(&f, &c, &l, "jira.get_issue", json!({"key": k})).await;
        assert!(refused(&r), "{k}");
    }
    assert_eq!(
        f.fake.count(&one("SECRET-1")) + f.fake.count(&one("10042")),
        0
    );
    // The old key of an issue that moved to another project resolves there: the answer says so.
    f.fake.reply(
        &one("ABC-2"),
        200,
        json!({"key": "SECRET-9", "fields": {"project": {"key": "SECRET"}}}),
    );
    let r = run(&f, &c, &l, "jira.get_issue", json!({"key": "ABC-2"})).await;
    assert!(refused(&r), "{r:?}");
}

#[tokio::test]
async fn a_change_reads_the_project_first_and_never_writes_outside_the_limit() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let pre = |k: &str| format!("GET {}", site_path(&format!("/issue/{k}")));
    let put = format!("PUT {}", site_path("/issue/ABC-1"));
    let post = |p: &str| format!("POST {}", site_path(p));
    f.fake.reply(
        &pre("ABC-1"),
        200,
        json!({"fields": {"project": {"key": "ABC"}}}),
    );
    f.fake.reply(&put, 204, Value::Null);
    f.fake
        .reply(&post("/issue/ABC-1/comment"), 201, json!({"id": "1"}));
    f.fake
        .reply(&post("/issue/ABC-1/transitions"), 204, Value::Null);
    run(
        &f,
        &c,
        &l,
        "jira.update_issue",
        json!({"key": "ABC-1", "summary": "New", "labels": ["a"]}),
    )
    .await
    .unwrap();
    let sent = f.fake.last(&put).unwrap();
    assert_eq!(
        sent.body,
        json!({"fields": {"summary": "New", "labels": ["a"]}})
    );
    assert_eq!(f.fake.last(&pre("ABC-1")).unwrap().query, "fields=project");
    run(
        &f,
        &c,
        &l,
        "jira.add_comment",
        json!({"key": "ABC-1", "body": "Hello\nthere"}),
    )
    .await
    .unwrap();
    let body = f.fake.last(&post("/issue/ABC-1/comment")).unwrap().body;
    assert_eq!(body["body"]["type"], "doc");
    assert_eq!(body["body"]["content"].as_array().unwrap().len(), 2);
    run(
        &f,
        &c,
        &l,
        "jira.transition_issue",
        json!({"key": "ABC-1", "transition_id": "31"}),
    )
    .await
    .unwrap();
    assert_eq!(
        f.fake.last(&post("/issue/ABC-1/transitions")).unwrap().body,
        json!({"transition": {"id": "31"}})
    );
    // An issue that moved away is read first, so nothing is written to it.
    f.fake.reply(
        &pre("ABC-1"),
        200,
        json!({"fields": {"project": {"key": "SECRET"}}}),
    );
    let writes = f.fake.seen().iter().filter(|s| s.method != "GET").count();
    let ops = [
        ("jira.update_issue", json!({"key": "ABC-1", "summary": "x"})),
        ("jira.add_comment", json!({"key": "ABC-1", "body": "x"})),
        (
            "jira.transition_issue",
            json!({"key": "ABC-1", "transition_id": "31"}),
        ),
        ("jira.list_transitions", json!({"key": "ABC-1"})),
    ];
    for (op, args) in ops {
        assert!(refused(&run(&f, &c, &l, op, args).await), "{op}");
    }
    assert_eq!(
        f.fake.seen().iter().filter(|s| s.method != "GET").count(),
        writes
    );
    // Foreign keys and arguments that would carry a project are refused outright.
    for (op, args) in [
        (
            "jira.update_issue",
            json!({"key": "SECRET-1", "summary": "x"}),
        ),
        (
            "jira.update_issue",
            json!({"key": "ABC-1", "project": "SECRET"}),
        ),
        (
            "jira.update_issue",
            json!({"key": "ABC-1", "fields": {"project": {"key": "SECRET"}}}),
        ),
        ("jira.update_issue", json!({"key": "ABC-1"})),
        (
            "jira.transition_issue",
            json!({"key": "ABC-1", "transition_id": "../31"}),
        ),
        (
            "jira.transition_issue",
            json!({"key": "ABC-1", "transition_id": 31}),
        ),
        (
            "jira.add_comment",
            json!({"key": "ABC-1", "body": "x", "visibility": {}}),
        ),
        ("jira.nope", json!({})),
    ] {
        assert!(refused(&run(&f, &c, &l, op, args).await), "{op}");
    }
}

#[tokio::test]
async fn create_takes_a_typed_project_and_nothing_that_could_smuggle_another() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let key = format!("POST {}", site_path("/issue"));
    f.fake.reply(&key, 201, json!({"key": "ABC-7"}));
    let args = json!({"project": "ABC", "summary": "S", "issue_type": "Task", "description": "d"});
    run(&f, &c, &l, "jira.create_issue", args).await.unwrap();
    let fields = f.fake.last(&key).unwrap().body["fields"].clone();
    assert_eq!(fields["project"], json!({"key": "ABC"}));
    assert_eq!(fields["issuetype"], json!({"name": "Task"}));
    let n = f.fake.count(&key);
    let base = json!({"summary": "S", "issue_type": "Task"});
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    for args in [
        with("project", json!("SECRET")),
        with("project", json!({"key": "SECRET"})),
        with("project", json!({"id": "10001"})),
        with("project", json!("abc")),
        with("fields", json!({"project": {"key": "SECRET"}})),
        with("parent", json!("SECRET-1")),
        with("project_id", json!("10001")),
    ] {
        assert!(
            refused(&run(&f, &c, &l, "jira.create_issue", args.clone()).await),
            "{args}"
        );
    }
    assert_eq!(f.fake.count(&key), n);
}

#[tokio::test]
async fn the_project_list_is_cut_to_the_limit() {
    let f = fx(false).await;
    let c = f.basic().await;
    let key = format!("GET {}", site_path("/project/search"));
    let all = json!({"values": [{"key": "ABC"}, {"key": "SECRET"}, {"key": "DEF"}], "total": 3, "isLast": true});
    f.fake.reply(&key, 200, all.clone());
    let v = run(
        &f,
        &c,
        &limited(&["ABC", "DEF"]),
        "jira.list_projects",
        json!({}),
    )
    .await
    .unwrap();
    let keys: Vec<_> = v["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["ABC", "DEF"]);
    assert!(
        v.get("total").is_none(),
        "totals count projects the caller may not see"
    );
    assert!(
        f.fake
            .last(&key)
            .unwrap()
            .query
            .contains("keys=ABC&keys=DEF")
    );
    let v = run(
        &f,
        &c,
        &Limit::any(),
        "jira.list_projects",
        json!({"max_results": 10}),
    )
    .await
    .unwrap();
    assert_eq!(v["values"].as_array().unwrap().len(), 3);
    assert!(!f.fake.last(&key).unwrap().query.contains("keys="));
}

#[tokio::test]
async fn an_unlimited_connection_passes_the_jql_through_and_the_limit_reads_a_grant() {
    let f = fx(false).await;
    let c = f.basic().await;
    f.fake.reply(&search_key(), 200, json!({"issues": []}));
    let jql = "assignee = currentUser() ORDER BY created DESC";
    run(
        &f,
        &c,
        &Limit::any(),
        "jira.search_issues",
        json!({"jql": jql}),
    )
    .await
    .unwrap();
    assert_eq!(f.fake.last(&search_key()).unwrap().body["jql"], jql);
    let grant = |v: &[&str]| {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "projects".to_owned(),
            v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        );
        Limit::from_grant(&m)
    };
    assert_eq!(Limit::from_grant(&Default::default()), Limit::any());
    assert_eq!(
        grant(&["ABC", "*"]),
        limited(&["ABC"]),
        "`*` is a literal, not a wildcard"
    );
    assert_eq!(grant(&["ABC", "x y", "DEF"]), limited(&["ABC", "DEF"]));
    assert_eq!(grant(&["lower"]), limited(&[]));
    let other = f
        .connect("other", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    let mut wrong = other.clone();
    wrong.kind = "github".into();
    let r = run(
        &f,
        &wrong,
        &Limit::any(),
        "jira.get_issue",
        json!({"key": "ABC-1"}),
    )
    .await;
    assert!(matches!(r, Err(CallError::Internal(_))));
}

#[tokio::test]
async fn a_limited_connection_reads_only_fields_that_cannot_name_other_projects() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let one = format!("GET {}", site_path("/issue/ABC-1"));
    f.fake.reply(
        &one,
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
    );
    for bad in [
        "issuelinks",
        "parent",
        "subtasks",
        "customfield_10010",
        "*all",
        "comment",
        "worklog",
    ] {
        let r = run(
            &f,
            &c,
            &l,
            "jira.get_issue",
            json!({"key": "ABC-1", "fields": [bad]}),
        )
        .await;
        assert!(refused(&r), "{bad}");
        let r = run(&f, &c, &l, "jira.search_issues", json!({"fields": [bad]})).await;
        assert!(refused(&r), "{bad}");
    }
    assert_eq!(f.fake.count(&one), 0);
    let fine = [
        "summary", "status", "priority", "assignee", "reporter", "labels", "created",
    ];
    run(
        &f,
        &c,
        &l,
        "jira.get_issue",
        json!({"key": "ABC-1", "fields": fine}),
    )
    .await
    .unwrap();
    // Unlimited connections may ask for anything.
    run(
        &f,
        &c,
        &Limit::any(),
        "jira.get_issue",
        json!({"key": "ABC-1", "fields": ["issuelinks"]}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_answer_that_names_an_issue_of_another_project_is_refused_without_naming_it() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    let one = format!("GET {}", site_path("/issue/ABC-1"));
    let leaks = [
        json!({"fields": {"project": {"key": "ABC"}, "summary": "blocked by SECRET-12 today"}}),
        json!({"fields": {"project": {"key": "ABC"}, "labels": ["SECRET-9"]}}),
        json!({"fields": {"project": {"key": "ABC"}, "description": {"x": [{"text": "(see:SECRET-3)"}]}}}),
        json!({"fields": {"project": {"key": "ABC"}, "summary": "https://x/browse/SECRET-77"}}),
    ];
    for body in leaks {
        f.fake.reply(&one, 200, body.clone());
        let r = run(&f, &c, &l, "jira.get_issue", json!({"key": "ABC-1"})).await;
        let Err(CallError::Refused(why)) = r else {
            panic!("{body}")
        };
        assert!(!why.contains("SECRET"), "{why}");
        assert!(why.contains("outside_limit"), "{why}");
    }
    // Keys of the permitted project, and words that only look alike, are fine.
    let ok = json!({"fields": {"project": {"key": "ABC"}, "summary": "ABC-2 and ABCD-x and sECRET-1 and ABC-"}});
    f.fake.reply(&one, 200, ok);
    run(&f, &c, &l, "jira.get_issue", json!({"key": "ABC-1"}))
        .await
        .unwrap();
    let hit = json!({"issues": [{"key": "ABC-1", "fields": {"project": {"key": "ABC"}, "summary": "dup of SECRET-4"}}]});
    f.fake.reply(&search_key(), 200, hit);
    let r = run(&f, &c, &l, "jira.search_issues", json!({})).await;
    assert!(
        matches!(r, Err(CallError::Refused(ref w)) if !w.contains("SECRET")),
        "{r:?}"
    );
    let r = run(&f, &c, &l, "jira.get_issue", json!({"key": "SECRET-1"})).await;
    assert!(
        matches!(r, Err(CallError::Refused(ref w)) if !w.contains("SECRET")),
        "{r:?}"
    );
}

#[tokio::test]
async fn a_backslash_outside_quotes_is_refused_and_the_star_is_not_a_wildcard() {
    let f = fx(false).await;
    let c = f.basic().await;
    let l = limited(&["ABC"]);
    f.fake.reply(&search_key(), 200, issues(&["ABC"]));
    let attacks = [
        r#"summary ~ a\" ) OR project = SECRET OR ( x ~ "b"#,
        r#"summary ~ a\" ) OR project = SECRET OR ("#,
        r"x = 1 \",
        r"x \= 1",
        r#"summary ~ \"a" OR project = SECRET OR summary ~ "b"#,
    ];
    for a in attacks {
        let r = run(&f, &c, &l, "jira.search_issues", json!({"jql": a})).await;
        assert!(
            matches!(r, Err(CallError::Refused(ref w)) if !w.contains("SECRET")),
            "{a:?} -> {r:?}"
        );
    }
    assert_eq!(f.fake.count(&search_key()), 0);
    // A backslash INSIDE a quoted string is an escape and stays allowed.
    run(
        &f,
        &c,
        &l,
        "jira.search_issues",
        json!({"jql": r#"summary ~ "a\"b""#}),
    )
    .await
    .unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert(
        "projects".to_owned(),
        vec!["ABC".to_owned(), "*".to_owned()],
    );
    assert_eq!(
        Limit::from_grant(&m),
        limited(&["ABC"]),
        "`*` is a literal, as in C1's value_matches"
    );
}
