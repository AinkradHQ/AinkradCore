//! The `citadel` CLI's route (E15.18 step 3): one operation per POST behind the run-token gate,
//! the role's schema, batches in order that stop at the first failure, every operation audited
//! and permission-checked as its MCP call.

use ainkrad_core::settings::{Key, Scope};
use serde_json::json;

use super::*;

/// `POST /mcp/v1/call/<op>` with `body`, as the script sends it.
async fn cli(app: &App, token: Option<&str>, op: &str, body: &str) -> (StatusCode, Value) {
    let mut req = Request::post(format!("/mcp/v1/call/{op}"))
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    send(app, req.body(Body::from(body.to_owned())).unwrap()).await
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn operations_schema_and_batches_through_the_gate() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let t = Some(a.token.expose());

    // The gate: no token, or a query string, is refused.
    let (status, _) = cli(&fx.app, None, "get_issue", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = cli(&fx.app, t, "get_issue?token=x", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // One operation: an empty body is no arguments.
    let (status, issue) = cli(&fx.app, t, "get_issue", "").await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["key"], "AAA-1");
    let (status, bad) = cli(&fx.app, t, "comment", "[1]").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    let (status, bad) = cli(&fx.app, t, "comment", "{nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    // Outside the role's list, still the tool's own permission check.
    let (from, to) = super::plan::DATES;
    let sprint = json!({"name": "S", "starts_on": from, "ends_on": to}).to_string();
    let (status, why) = cli(&fx.app, t, "plan_sprint", &sprint).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{why}");
    assert!(why["error"].as_str().unwrap().contains("product owner"));

    // The role's operations, one compact line each.
    let (status, schema) = cli(&fx.app, t, "schema", "").await;
    assert_eq!(status, StatusCode::OK);
    let line = schema["get_issue"].as_str().unwrap();
    assert!(
        line.starts_with(
            "(comments_after?:int, comments_before?:int, issue_id?:int, limit?:int) Read your issue"
        ),
        "{line}"
    );
    assert_eq!(
        schema["transition"]
            .as_str()
            .unwrap()
            .split(')')
            .next()
            .unwrap(),
        "(blocker_issue_id?:int, issue_id?:int, reviewer_agent_id?:int, \
         reviewer_user_id?:int, transition:start|submit_for_review|block|done"
    );
    assert!(schema.get("plan_sprint").is_none(), "a developer's list");

    // A batch, in order, every operation audited as its own call.
    let before = audited(&fx, "mcp.comment").await;
    let ops = json!([{"op": "comment", "args": {"body": "one"}},
                     {"op": "comment", "args": {"body": "two"}},
                     {"op": "get_issue"}]);
    let (status, out) = cli(&fx.app, t, "batch", &ops.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let results = out["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[2]["comments"].as_array().unwrap().len(), 2);
    assert_eq!(audited(&fx, "mcp.comment").await, before + 2);

    // It stops at the first failure, with what ran before it.
    let ops = json!({"ops": [{"op": "comment", "args": {"body": "three"}},
                             {"op": "transition", "args": {"transition": "fly"}},
                             {"op": "comment", "args": {"body": "never"}}]});
    let (status, out) = cli(&fx.app, t, "batch", &ops.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert_eq!(out["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        (
            out["failed"]["index"].as_i64(),
            out["failed"]["op"].as_str()
        ),
        (Some(1), Some("transition"))
    );
    assert_eq!(
        audited(&fx, "mcp.comment").await,
        before + 3,
        "never ran the third"
    );
    let nested = json!([{"op": "batch", "args": {}}]).to_string();
    let (status, _) = cli(&fx.app, t, "batch", &nested).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // At most `cli.max_batch_ops`.
    let by = AuditActor::User(ainkrad_core::work::UserId(1));
    let at = Scope::Company(a.company);
    crate::store::settings::set(&fx.app.pool, Key::CliMaxBatchOps, at, "2", by, NOW)
        .await
        .unwrap();
    let (status, out) = cli(&fx.app, t, "batch", &ops.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        out["error"].as_str().unwrap().contains("at most 2"),
        "{out}"
    );
    assert_eq!(
        audited(&fx, "mcp.comment").await,
        before + 3,
        "refused whole"
    );
}
