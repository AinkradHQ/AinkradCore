//! The whole path with a fake runner message: a call in, the upstream request out, the result back,
//! the audit row, and the tool list.

use super::*;

/// A GitHub connection granted to members (and to agent `bot`), a session allowed `read_repo`.
async fn ready() -> (Fx, Connection, String) {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[("repos", &["acme/*"])])
        .await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    (f, c, s)
}

#[tokio::test]
async fn a_github_read_runs_with_the_token_and_is_audited() {
    let (f, c, s) = ready().await;
    f.gh.push(200, &[], ISSUE);
    let r = f
        .ask(
            &s,
            "github.get_issue",
            json!({"repo": "acme/app", "number": 7}),
        )
        .await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.result.unwrap()["title"], "Broken build");
    let seen = f.gh.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/repos/acme/app/issues/7");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {GH_TOKEN}").as_str())
    );
    let uses = f.uses().await;
    assert_eq!(uses.len(), 1);
    let u = &uses[0];
    assert_eq!(
        (
            u["action"].as_str(),
            u["result"].as_str(),
            u["agent"].as_str()
        ),
        (Some("github.get_issue"), Some("ok"), Some("bot"))
    );
    assert_eq!(u["capability"], "read_repo");
    assert_eq!(u["session"], s.as_str());
    assert!(
        !u.to_string().contains("Broken build"),
        "no payload in the audit row"
    );
    let (status, _) = f.status(c.id).await;
    assert_eq!(status, "active");
}

#[tokio::test]
async fn a_jira_read_runs_through_the_shared_adapter() {
    let f = fx().await;
    let c = f.jira("acme").await;
    f.member(c.id, &["read_issues"], &[("projects", &["ABC"])])
        .await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f.session(&["read_issues"]).await;
    let one = format!("GET {}", jt::site_path("/issue/ABC-1"));
    f.j.fake.reply(
        &one,
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}, "summary": "Fix it"}}),
    );
    let r = f.ask(&s, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.result.unwrap()["key"], "ABC-1");
    assert_eq!(f.uses().await[0]["result"], "ok");
}

#[tokio::test]
async fn the_tool_list_is_the_operations_of_the_capabilities_the_session_can_use() {
    let (f, c, s) = ready().await;
    let names = |t: Vec<ainkrad_proto::v2::ConnTool>| -> Vec<String> {
        t.into_iter().map(|t| t.name).collect()
    };
    let t = names(f.b.tools(&f.env(), &s).await.unwrap());
    assert!(t.contains(&"github.get_issue".to_owned()));
    assert!(
        t.iter().all(|n| n.starts_with("github.")),
        "no Jira without a grant: {t:?}"
    );
    assert!(
        !t.contains(&"github.create_issue".to_owned()),
        "write is not granted"
    );
    // A write grant the session's allowlist does not name adds nothing.
    f.member(c.id, &["read_repo", "issues_write"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo", "issues_write"], &[])
        .await;
    let t = names(f.b.tools(&f.env(), &s).await.unwrap());
    assert!(
        !t.contains(&"github.create_issue".to_owned()),
        "outside the allowlist: {t:?}"
    );
    let wide = f.session(&["read_repo", "issues_write"]).await;
    let t = names(f.b.tools(&f.env(), &wide).await.unwrap());
    assert!(t.contains(&"github.create_issue".to_owned()));
    // A grant revoked mid-session: the list shrinks.
    grants::revoke(&f.j.pool, c.id, ("agent", "bot"), who())
        .await
        .unwrap();
    let t = f.b.tools(&f.env(), &wide).await.unwrap();
    assert!(t.is_empty(), "the agent's grant is gone: {t:?}");
}

#[tokio::test]
async fn a_grant_revoked_mid_session_refuses_the_next_call() {
    let (f, c, s) = ready().await;
    f.gh.push(200, &[], ISSUE);
    assert!(
        f.ask(
            &s,
            "github.get_issue",
            json!({"repo": "acme/app", "number": 7})
        )
        .await
        .ok
    );
    grants::revoke(&f.j.pool, c.id, ("role", "member"), who())
        .await
        .unwrap();
    let r = f
        .ask(
            &s,
            "github.get_issue",
            json!({"repo": "acme/app", "number": 7}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "not_granted"));
    assert_eq!(f.gh.seen().len(), 1, "nothing went upstream");
    let uses = f.uses().await;
    assert_eq!(uses.len(), 2, "the refusal is recorded too");
    assert_eq!(
        (uses[1]["result"].as_str(), uses[1]["code"].as_str()),
        (Some("refused"), Some("not_granted"))
    );
}

#[tokio::test]
async fn a_result_is_plain_or_a_plain_refusal() {
    let (f, _c, s) = ready().await;
    f.gh.push(
        404,
        &[],
        r#"{"message":"Not Found","documentation_url":"https://docs.github.com/x"}"#,
    );
    let r = f
        .ask(
            &s,
            "github.get_issue",
            json!({"repo": "acme/app", "number": 9}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "not_found"));
    let text = serde_json::to_string(&r).unwrap();
    assert!(
        !text.contains("docs.github.com") && !text.contains("Not Found"),
        "{text}"
    );
    assert!(r.result.is_none());
}
