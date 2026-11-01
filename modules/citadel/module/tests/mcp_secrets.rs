//! A secret leased to a run's session never appears in anything the MCP route stores, returns,
//! logs or audits (E2-29, B-M2): the Core masks the session's leased values itself, in the
//! forms the redactor knows, and refuses the call when it cannot. Over HTTP, real router.

mod common;
mod mcp_harness;
mod work_seed;

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::store::secrets::{self, NewValue};
use citadel_module::domain::work::{Actor, NewComment};
use citadel_module::store::work::create_comment;
use mcp_harness::*;
use serde_json::{Value, json};

/// A real-looking value with no known key prefix: only the lease tells the Core it is secret.
const VALUE: &str = "zq83-plainvalue-without-prefix-4417";

struct Rig {
    w: W,
    co: Co,
    token: String,
}

/// A run whose session was leased `names`, each stored as `value`.
async fn rig(secrets_to_lease: &[(&str, &str)]) -> Rig {
    let mut w = world().await;
    let sealer = Arc::new(SecretBox::new(&[7; 32]));
    w.fx.app.secrets = Some(sealer.clone());
    let app = &w.fx.app;
    let now = app.clock.now();
    ainkrad_core_server::store::settings::set(
        &app.pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let mut leased = Vec::new();
    for (name, value) in secrets_to_lease {
        let new = NewValue {
            value,
            runners: None,
            delivery: None,
        };
        secrets::create(&app.pool, &sealer, name, &new, &w.fx.dev.id, AuditActor::System, &now)
            .await
            .unwrap();
        leased.push(json!({"name": name, "var": "LEASED_VAR"}));
    }
    let co = w.co("A", "AAA").await;
    sqlx::query(
        "UPDATE core_agent_sessions SET secrets = ? \
         WHERE id = (SELECT session_id FROM citadel_runs WHERE id = ?)",
    )
    .bind(serde_json::to_string(&leased).unwrap())
    .bind(co.run.id.0)
    .execute(&app.pool)
    .await
    .unwrap();
    let token = w.token(co.run.id).await;
    Rig { w, co, token }
}

fn b64_of(s: &str) -> String {
    b64(s.as_bytes())
}

/// How many rows of every table (all columns) hold `needle`.
async fn rows_holding(app: &ainkrad_core_server::api::App, needle: &str) -> Vec<String> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&app.pool)
    .await
    .unwrap();
    let mut hit = Vec::new();
    for table in tables {
        if table == "core_secrets" {
            continue; // sealed, and the one place the value belongs
        }
        let cols: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT name FROM pragma_table_info('{table}')"
        )))
        .fetch_all(&app.pool)
        .await
        .unwrap();
        let any = cols
            .iter()
            .map(|c| format!("coalesce(CAST(\"{c}\" AS TEXT), '')"))
            .collect::<Vec<_>>()
            .join(" || ' ' || ");
        let n = count(
            app,
            &format!("SELECT count(*) FROM \"{table}\" WHERE ({any}) LIKE '%{needle}%'"),
        )
        .await;
        if n > 0 {
            hit.push(table);
        }
    }
    hit
}

#[tokio::test]
async fn a_leased_value_is_masked_in_what_an_agent_writes_in_every_form() {
    let r = rig(&[("citadel.plain", VALUE)]).await;
    let app = &r.w.fx.app;
    let (hex_form, pct) = (
        VALUE.bytes().map(|b| format!("{b:02x}")).collect::<String>(),
        VALUE.bytes().map(|b| format!("%{b:02X}")).collect::<String>(),
    );
    for (i, text) in [
        format!("the key is {VALUE} ok"),
        format!("base64 {}", b64_of(VALUE)),
        format!("hex {hex_form}"),
        format!("percent {pct}"),
        format!("json {}", serde_json::to_string(&json!({"k": VALUE})).unwrap()),
    ]
    .into_iter()
    .enumerate()
    {
        ok(&r.w, &r.token, "comment", json!({"body": text, "idempotency_key": format!("k{i}")}))
            .await;
    }
    // A question and a proposal take the same chokepoint.
    ok(&r.w, &r.token, "ask_human", json!({"question": format!("is {VALUE} right?")})).await;
    // Even an invalid call that echoes its arguments back.
    let (failed, echoed) =
        invoke(&r.w, &r.token, "get_issue", json!({"issue_id": VALUE})).await;
    assert!(failed);
    assert!(!echoed.contains(VALUE), "{echoed}");
    for needle in [VALUE.to_owned(), b64_of(VALUE), hex_form, pct] {
        let hit = rows_holding(app, &needle).await;
        assert!(hit.is_empty(), "{needle} is in {hit:?}");
    }
    // The audit trail says what happened, not what was said.
    assert!(count(app, "SELECT count(*) FROM audit_events WHERE action = 'citadel.mcp.comment'").await >= 5);
}

#[tokio::test]
async fn a_value_already_stored_is_masked_on_the_way_back_to_the_agent() {
    let r = rig(&[("citadel.plain", VALUE)]).await;
    // Written before the secret was leased (a human, or an earlier run): the row holds it.
    create_comment(
        &r.w.fx.app.pool,
        &NewComment {
            issue_id: citadel_module::domain::work::IssueId(r.co.seed.issue),
            author: Actor::Agent(citadel_module::domain::org::AgentId(r.co.seed.agent)),
            body: format!("old note with {VALUE} in it"),
            run_id: None,
            idempotency_key: None,
        },
    )
    .await
    .unwrap();
    let got = ok(&r.w, &r.token, "get_issue", json!({})).await;
    let text = got.to_string();
    assert!(!text.contains(VALUE), "{text}");
    assert!(text.contains("[redacted:citadel.plain]"), "{text}");
    // And in a published artifact: stored masked, the count says so.
    let report = format!("# report\nthe token is {VALUE}\n");
    let published = ok(
        &r.w,
        &r.token,
        "publish_artifact",
        json!({"name": "report.md", "kind": "report", "content": b64_of(&report)}),
    )
    .await;
    assert!(published["redactions"].as_i64().unwrap() >= 1, "{published}");
    let read = ok(&r.w, &r.token, "get_artifact", json!({})).await;
    assert!(!read.to_string().contains(VALUE), "{read}");
}

#[tokio::test]
async fn a_run_that_cannot_be_masked_gets_no_tools_and_writes_nothing() {
    // The master key is gone: the leased value cannot be known, so nothing runs unmasked.
    let mut r = rig(&[("citadel.plain", VALUE)]).await;
    let before = count(&r.w.fx.app, "SELECT count(*) FROM citadel_comments").await;
    r.w.fx.app.secrets = None;
    for name in ["comment", "get_issue", "ask_human"] {
        let (failed, text) = invoke(&r.w, &r.token, name, json!({"body": VALUE, "question": VALUE})).await;
        assert!(failed, "{name}: {text}");
        assert!(!text.contains(VALUE), "{text}");
    }
    // A different key cannot open the sealed value either.
    r.w.fx.app.secrets = Some(Arc::new(SecretBox::new(&[9; 32])));
    let (failed, _) = invoke(&r.w, &r.token, "comment", json!({"body": "hi"})).await;
    assert!(failed);
    let after = count(&r.w.fx.app, "SELECT count(*) FROM citadel_comments").await;
    assert_eq!(before, after, "a comment was written without masking");
    assert!(rows_holding(&r.w.fx.app, VALUE).await.is_empty());
}

#[tokio::test]
async fn a_leased_value_too_short_to_match_refuses_the_call() {
    let r = rig(&[("citadel.short", "abc123")]).await;
    let why = refused(&r.w, &r.token, "comment", json!({"body": "hi"})).await;
    assert!(why.contains("too short to mask"), "{why}");
    assert!(!why.contains("abc123"));
}

#[tokio::test]
async fn a_run_with_nothing_leased_is_unchanged() {
    let r = rig(&[]).await;
    let c = ok(&r.w, &r.token, "comment", json!({"body": "plain progress"})).await;
    assert!(c["comment_id"].is_number());
    let _: Value = ok(&r.w, &r.token, "get_issue", json!({})).await;
}
