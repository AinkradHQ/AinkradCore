//! `POST /api/v1/runners/{id}/noop` keeps the audit log flat (security review RH4): the first
//! call per caller, runner and outcome in a window is audited, the rest only counted.

use super::*;

#[tokio::test]
async fn a_thousand_noop_calls_write_one_audit_row() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    let runner = TestDevice::enroll(
        &fx.app.pool,
        "vm",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let uri = format!("/api/v1/runners/{}/noop", runner.id);
    let rows = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE action = 'runner.command'",
        )
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
    };
    for _ in 0..1000 {
        // The runner is not connected: every call is the same refused outcome.
        let (status, body) = send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), None)).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::CONFLICT, &json!("runner_offline"))
        );
    }
    assert_eq!(rows().await, 1, "one row, the rest counted");
    let key = format!("runner.command:noop:{}:{}:false", fx.dev.id, runner.id);
    assert_eq!(fx.app.auth.refusals.count(&key), 1000);
    // A new window audits again.
    fx.clock.advance(crate::auth::refusals::WINDOW);
    send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), None)).await;
    assert_eq!(rows().await, 2);
}
