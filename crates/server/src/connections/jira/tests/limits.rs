//! What a limited connection may read: fields, answers that name other projects, JQL escapes.

use serde_json::{Value, json};

use super::*;
use crate::connections::jira::{CallError, Limit};

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
