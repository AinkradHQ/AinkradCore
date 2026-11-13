//! Code Mode search (E1.4): what a session may see follows its creator device's scopes NOW.

use super::*;
use crate::ops_catalog::conn::{self, Ran};
use crate::ops_catalog::{Risk, session_scopes};

#[tokio::test]
async fn a_sessions_scopes_are_its_creator_devices_current_ones() {
    let f = fx().await;
    let s = f.bare_session(RUNNER).await;
    let set = |scopes: &'static str, status: &'static str| {
        let pool = f.j.pool.clone();
        async move {
            sqlx::query("UPDATE core_devices SET scopes = ?, status = ? WHERE id = ?")
                .bind(scopes)
                .bind(status)
                .bind(RUNNER)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set(r#"["read","agent"]"#, "active").await;
    assert_eq!(
        session_scopes(&f.j.pool, &s).await.unwrap(),
        ["read", "agent"]
    );
    // A scope taken away shows on the next call.
    set(r#"["read"]"#, "active").await;
    assert_eq!(session_scopes(&f.j.pool, &s).await.unwrap(), ["read"]);
    // A revoked device sees nothing; so does an unknown session.
    set(r#"["read"]"#, "rejected").await;
    assert!(session_scopes(&f.j.pool, &s).await.unwrap().is_empty());
    assert!(
        session_scopes(&f.j.pool, "as_nope")
            .await
            .unwrap()
            .is_empty()
    );
}

fn call(args: Value) -> ToolCall {
    ToolCall {
        tc_seq: 1,
        id: "c-1".to_owned(),
        tool: "ainkrad.call".to_owned(),
        args,
    }
}

async fn run(f: &Fx, s: &str, op: &str, args: Value) -> Ran {
    conn::run(&f.b, &f.env(), RUNNER, s, op, &args, &call(json!({})))
        .await
        .unwrap()
}

#[tokio::test]
async fn a_session_without_a_grant_cannot_see_or_call_a_connection_op() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    // Granted to someone else's agent only.
    f.grant(c.id, ("agent", "other"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    assert!(conn::ops(&f.b, &f.env(), &s).await.unwrap().is_empty());
    let args = json!({"repo": "acme/app", "number": 7});
    assert!(matches!(
        run(&f, &s, "connections.github.get_issue", args).await,
        Ran::Unknown
    ));
    assert!(f.gh.seen().is_empty(), "nothing went upstream");
}

#[tokio::test]
async fn a_granted_read_runs_through_the_broker_scrubbed_and_fenced_and_a_write_is_left_alone() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.default(c.id).await;
    f.member(c.id, &["read_repo", "issues_write"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo", "issues_write"], &[])
        .await;
    let s = f.session(&["read_repo", "issues_write"]).await;
    let ops = conn::ops(&f.b, &f.env(), &s).await.unwrap();
    let get = ops
        .iter()
        .find(|o| o.id == "connections.github.get_issue")
        .unwrap();
    assert_eq!(get.risk, Risk::Read);
    let w = ops
        .iter()
        .find(|o| o.id == "connections.github.comment_issue")
        .unwrap();
    assert_eq!(w.risk, Risk::Risky, "a write carries its class");
    let def = crate::ops_catalog::render(get);
    assert!(
        def.contains("ainkrad.connections.github.get_issue("),
        "{def}"
    );
    assert!(!def.contains(GH_TOKEN));

    // The upstream echoes the credential: it is scrubbed, and the text is inside the envelope,
    // identical to what the old tool returns.
    let echo = format!(r#"{{"number":7,"title":"{GH_TOKEN} Broken"}}"#);
    f.gh.push(200, &[], &echo);
    let args = json!({"repo": "acme/app", "number": 7});
    let Ran::Done(_, new) = run(&f, &s, "connections.github.get_issue", args.clone()).await else {
        panic!("not run")
    };
    f.gh.push(200, &[], &echo);
    let old = f.ask(&s, "github.get_issue", args).await;
    assert!(new.ok && old.ok);
    assert_eq!(new.result, old.result);
    let text = new.result.unwrap().to_string();
    assert!(
        !text.contains(GH_TOKEN) && text.contains("Broken"),
        "{text}"
    );
    assert!(!f.audit_text().await.contains(GH_TOKEN));

    // The write op is not run here (E6's dispatcher does), and nothing went upstream for it.
    let seen = f.gh.seen().len();
    let body = json!({"repo": "acme/app", "number": 7, "body": {"body": "hi"}});
    assert!(matches!(
        run(&f, &s, "connections.github.comment_issue", body).await,
        Ran::NotRead(_)
    ));
    assert_eq!(f.gh.seen().len(), seen);
    // The old per-connection tool list is unchanged beside it.
    let old = f.b.tools(&f.env(), &s).await.unwrap();
    assert!(old.iter().any(|t| t.name == "github.get_issue"));
}

#[tokio::test]
async fn the_hide_switch_is_off_by_default_and_follows_the_setting() {
    let f = fx().await;
    assert!(!conn::hidden(&f.j.pool).await);
    for (v, want) in [("1", true), ("0", false)] {
        crate::store::settings::set(
            &f.j.pool,
            Key::CodeModeHideConnTools,
            Scope::Server,
            v,
            AuditActor::System,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(conn::hidden(&f.j.pool).await, want);
    }
    assert!(
        f.audit_text()
            .await
            .contains("code_mode.hide_connection_tools")
    );
}

#[tokio::test]
async fn the_switch_changes_the_tool_list_a_session_is_sent_on_the_next_poll() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.default(c.id).await;
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    let names = || async {
        super::super::supervise::listed(&f.b, &f.env(), &s)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect::<Vec<_>>()
    };
    let set = |v: &'static str| {
        crate::store::settings::set(
            &f.j.pool,
            Key::CodeModeHideConnTools,
            Scope::Server,
            v,
            AuditActor::System,
            NOW,
        )
    };
    // Off (the default): the old tools stay, beside the two Code Mode tools (back-compat).
    let n = names().await;
    assert!(n.iter().any(|t| t == "github.get_issue"), "{n:?}");
    assert!(n.iter().any(|t| t == "ainkrad.search"));
    // On: only the two Code Mode tools, at the next listing.
    set("1").await.unwrap();
    let n = names().await;
    assert_eq!(n.len(), 2, "{n:?}");
    // Off again: the old list is back.
    set("0").await.unwrap();
    assert!(names().await.iter().any(|t| t == "github.get_issue"));
}
