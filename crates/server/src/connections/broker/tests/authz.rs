//! Who may call: the session decides, never the call.

use super::*;

const READ: [&str; 1] = ["read_repo"];

async fn ready() -> (Fx, Connection) {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo", "issues_write"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo", "issues_write"], &[])
        .await;
    (f, c)
}

fn get(n: u64) -> Value {
    json!({"repo": "acme/app", "number": n})
}

#[tokio::test]
async fn a_session_that_is_over_the_wrong_runner_and_a_stranger_are_refused() {
    let (f, _c) = ready().await;
    let s = f.session(&READ).await;
    // The runner a session is not on may not call for it.
    let r = f.call(OTHER_RUNNER, &s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "session"));
    // A session the Core never made.
    let r = f.ask("as_nosuchsession", "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "session"));
    // Over.
    sessions::end(&f.j.pool, &s, "ended", &json!({"kind": "succeeded"}), NOW)
        .await
        .unwrap();
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "session_over"));
    assert!(f.gh.seen().is_empty(), "nothing went upstream");
    assert!(
        f.b.tools(&f.env(), &s).await.unwrap().is_empty(),
        "no tools once over"
    );
    let uses = f.uses().await;
    assert_eq!(uses.len(), 3, "every refusal is a row: {uses:?}");
    assert!(uses.iter().all(|u| u["result"] == "refused"));
}

#[tokio::test]
async fn another_users_session_reaches_none_of_this_users_connections() {
    let (f, _c) = ready().await;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&f.j.pool)
        .await
        .unwrap();
    let s = f.session(&READ).await;
    sqlx::query("UPDATE core_agent_sessions SET user_id = 2 WHERE id = ?")
        .bind(&s)
        .execute(&f.j.pool)
        .await
        .unwrap();
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "no_connection"));
    assert!(f.gh.seen().is_empty());
    assert!(f.b.tools(&f.env(), &s).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_session_row_decides_user_and_agent_not_the_call() {
    let (f, _c) = ready().await;
    let s = f.session(&READ).await;
    // Fields that would name a user, an agent, a session, a connection or a capability are not
    // arguments of any operation: refused whole, nothing is sent.
    for extra in [
        ("user", json!(2)),
        ("agent", json!("root")),
        ("session", json!("as_other")),
        ("connection", json!("main")),
        ("capability", json!("push")),
        ("allowlist", json!(["push"])),
    ] {
        let mut args = get(1);
        args[extra.0] = extra.1;
        let r = f.ask(&s, "github.get_issue", args).await;
        assert_eq!((r.ok, code(&r)), (false, "bad_args"), "{}", extra.0);
    }
    assert!(f.gh.seen().is_empty());
    let uses = f.uses().await;
    assert!(
        uses.iter()
            .all(|u| u["agent"] == "bot" && u["user"] == 1 && u["session"] == s.as_str()),
        "the audit names what the Core knows: {uses:?}"
    );
}

#[tokio::test]
async fn the_agents_own_grant_gates_the_tools() {
    let (f, c) = ready().await;
    // An agent without a grant of its own: the user's grant alone is not enough.
    let s = f.session(&READ).await;
    grants::revoke(&f.j.pool, c.id, ("agent", "bot"), who())
        .await
        .unwrap();
    assert!(f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "not_granted"));
    // A kind with no connection at all.
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let j = f.session(&["read_issues"]).await;
    let r = f.ask(&j, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert_eq!((r.ok, code(&r)), (false, "no_connection"));
    assert!(f.gh.seen().is_empty());
}

#[tokio::test]
async fn the_allowlist_and_the_capability_bound_each_operation() {
    let (f, c) = ready().await;
    let s = f.session(&READ).await;
    // Granted, but the session's allowlist does not name it.
    let r = f
        .ask(
            &s,
            "github.create_issue",
            json!({"repo": "acme/app", "body": {"title": "x"}}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "not_allowlisted"));
    // Allowlisted, but this grant does not carry it.
    f.member(c.id, &["read_repo"], &[]).await;
    let w = f.session(&["read_repo", "issues_write"]).await;
    let r = f
        .ask(
            &w,
            "github.create_issue",
            json!({"repo": "acme/app", "body": {"title": "x"}}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "capability_missing"));
    assert!(f.gh.seen().is_empty());
}

#[tokio::test]
async fn an_unknown_tool_is_refused_and_audited_without_naming_an_operation() {
    let (f, _c) = ready().await;
    let s = f.session(&READ).await;
    for tool in [
        "github.drop_repo",
        "gitlab.get_issue",
        "x",
        "github.get_issue.x",
    ] {
        let r = f.ask(&s, tool, get(1)).await;
        assert_eq!((r.ok, code(&r)), (false, "unknown_tool"), "{tool}");
    }
    let uses = f.uses().await;
    assert_eq!(uses.len(), 4);
    assert!(
        uses.iter()
            .all(|u| u["code"] == "unknown_tool" && u.get("action").is_none())
    );
    assert!(
        !f.audit_text().await.contains("drop_repo"),
        "an unvalidated name is not written"
    );
}

#[tokio::test]
async fn secrets_mode_off_means_no_tools_and_no_calls() {
    let (f, _c) = ready().await;
    let s = f.session(&READ).await;
    assert!(!f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    f.mode("0").await;
    assert!(f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "secrets_disabled"));
    assert!(f.gh.seen().is_empty(), "nothing opened, nothing sent");
    // No master key at all.
    f.mode("1").await;
    let env = Env {
        sealer: None,
        ..f.env()
    };
    let call = ToolCall {
        tc_seq: 1,
        id: "c".to_owned(),
        tool: "github.get_issue".to_owned(),
        args: get(1),
    };
    let r = f.b.handle(&env, RUNNER, &s, &call).await;
    assert_eq!((r.ok, code(&r)), (false, "secrets_unavailable"));
}

#[tokio::test]
async fn a_disabled_or_exported_connection_is_refused() {
    let (f, c) = ready().await;
    let s = f.session(&READ).await;
    crate::store::connections::set_disabled(&f.j.pool, c.id, true, who())
        .await
        .unwrap();
    assert!(f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "disabled"));
    crate::store::connections::set_disabled(&f.j.pool, c.id, false, who())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE core_connections SET status = 'disabled', state_reason = 'exported' WHERE id = ?",
    )
    .bind(c.id)
    .execute(&f.j.pool)
    .await
    .unwrap();
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "no_credential"));
    assert!(f.gh.seen().is_empty());
}

/// The default: every session has access with no row written (decision of C4's review).
#[tokio::test]
async fn a_plain_session_of_a_user_with_a_grant_has_the_tools_and_can_call() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[]).await;
    let s = f.bare_session(RUNNER).await;
    let names: Vec<String> =
        f.b.tools(&f.env(), &s)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
    assert!(names.contains(&"github.get_issue".to_owned()), "{names:?}");
    assert!(
        !names.contains(&"github.create_issue".to_owned()),
        "write is not granted"
    );
    f.gh.push(200, &[], ISSUE);
    let r = f.ask(&s, "github.get_issue", get(7)).await;
    assert!(r.ok, "{r:?}");
    let u = f.uses().await;
    assert_eq!(
        (u[0]["result"].as_str(), u[0]["agent"].is_null()),
        (Some("ok"), true)
    );
}

#[tokio::test]
async fn a_session_of_a_user_without_grants_has_none() {
    let f = fx().await;
    f.github("main", GH_TOKEN).await; // exists, granted to nobody
    let s = f.bare_session(RUNNER).await;
    assert!(f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    let r = f.ask(&s, "github.get_issue", get(7)).await;
    assert_eq!((r.ok, code(&r)), (false, "not_granted"));
    assert!(f.gh.seen().is_empty());
}

#[tokio::test]
async fn an_agent_session_without_an_allowlist_has_none_until_one_is_set() {
    let (f, _c) = ready().await;
    let s = f.bare_session(RUNNER).await;
    sqlx::query("UPDATE core_agent_sessions SET agent = 'bot' WHERE id = ?")
        .bind(&s)
        .execute(&f.j.pool)
        .await
        .unwrap();
    assert!(
        f.b.tools(&f.env(), &s).await.unwrap().is_empty(),
        "C1's rule"
    );
    let r = f.ask(&s, "github.get_issue", get(7)).await;
    assert_eq!((r.ok, code(&r)), (false, "allowlist_required"));
    assert!(f.gh.seen().is_empty());
    access::set(&f.j.pool, &s, &["read_repo".to_owned()])
        .await
        .unwrap();
    assert!(!f.b.tools(&f.env(), &s).await.unwrap().is_empty());
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&s, "github.get_issue", get(7)).await.ok);
}
