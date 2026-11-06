//! Account health (KAN-438 S3): what a gateway report, a subscription session's end and its plan
//! snapshot do to an account's state, with a clock the test moves. The trusted channel (the
//! gateway) may cool, mark unhealthy and count; the harness's output (forgeable) only cools and
//! counts, and no signal of any kind disables an account or reaches another account.

use ainkrad_proto::v2::{
    AgentEvents, AgentState, GatewayReport, GatewayReportKind, UpstreamStatus,
};

use super::gateway_store::{G, gw as fixture, usage};
use super::*;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::agents as store;
use crate::store::{accounts as acc, health};

pub(super) const BY: ainkrad_core::audit::AuditActor = super::super::BY;

/// `secs` after the fixed test time.
pub(super) fn at(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

pub(super) async fn view(fx: &Fx, id: i64) -> (String, Option<String>, Option<String>) {
    let a = acc::get(&fx.app.pool, id).await.unwrap();
    (a.state, a.state_reason, a.state_until)
}

pub(super) async fn counts(fx: &Fx, id: i64) -> (i64, i64, i64) {
    sqlx::query_as("SELECT fail_streak, auth_streak, backoff_secs FROM core_accounts WHERE id = ?")
        .bind(id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

pub(super) async fn state_rows(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'account.state_set'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn class_of(fx: &Fx, session: &str) -> Option<String> {
    sqlx::query_scalar("SELECT upstream_class FROM core_agent_sessions WHERE id = ?")
        .bind(session)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

// ---- the gateway channel ------------------------------------------------------------------

fn up(seq: u64, status: UpstreamStatus) -> GatewayReport {
    GatewayReport {
        kind: GatewayReportKind::Upstream,
        status,
        model: None,
        ..usage(seq, 0, 0)
    }
}

async fn feed(g: &G, reports: Vec<GatewayReport>, now: &str) {
    let ev = AgentEvents {
        session: g.session.id.clone(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: reports,
        plan_limit: None,
    };
    store::apply(&g.fx.app.pool, &g.session.id, &ev, now)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_rate_limit_cools_with_a_backoff_that_doubles_per_cooldown_and_resets_on_success() {
    let g = fixture().await;
    let id = g.account.id;
    feed(&g, vec![up(1, UpstreamStatus::RateLimited)], &at(0)).await;
    assert_eq!(
        view(&g.fx, id).await,
        ("cooling".into(), Some("rate_limited".into()), Some(at(60)))
    );
    assert_eq!(
        class_of(&g.fx, &g.session.id).await.as_deref(),
        Some("rate_limited")
    );
    // A resend of the report, and a second 429 inside the window, change nothing: once per report,
    // and the backoff does not double inside one cooldown.
    let rows = state_rows(&g.fx).await;
    feed(&g, vec![up(1, UpstreamStatus::RateLimited)], &at(5)).await;
    feed(&g, vec![up(2, UpstreamStatus::RateLimited)], &at(10)).await;
    assert_eq!(state_rows(&g.fx).await, rows);
    assert_eq!(counts(&g.fx, id).await.2, 60);
    // Lazy recovery: no timer, the next look finds the window over (audited by the system).
    health::recover(&g.fx.app.pool, id, &at(61)).await.unwrap();
    assert_eq!(view(&g.fx, id).await.0, "active");
    assert_eq!(state_rows(&g.fx).await, rows + 1);
    // The next cooldown, with no success between, is twice as long; then four times.
    feed(&g, vec![up(3, UpstreamStatus::RateLimited)], &at(100)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(220)));
    health::recover(&g.fx.app.pool, id, &at(221)).await.unwrap();
    feed(&g, vec![up(4, UpstreamStatus::RateLimited)], &at(300)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(540)));
    // A success starts it again, and an ok usage report is one.
    health::recover(&g.fx.app.pool, id, &at(541)).await.unwrap();
    feed(&g, vec![usage(5, 10, 10)], &at(600)).await;
    assert_eq!(counts(&g.fx, id).await.2, 0);
    feed(&g, vec![up(6, UpstreamStatus::RateLimited)], &at(700)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(760)));
}

#[tokio::test]
async fn retry_after_and_reset_at_lengthen_a_cooldown_and_are_bounded() {
    let g = fixture().await;
    let id = g.account.id;
    let long = GatewayReport {
        retry_after: Some(300),
        reset_at: Some(at(120)),
        ..up(1, UpstreamStatus::RateLimited)
    };
    feed(&g, vec![long], &at(0)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(300)));
    // A later, longer ask extends the open window; a hostile huge one is clamped to a day.
    let huge = GatewayReport {
        retry_after: Some(u64::MAX),
        ..up(2, UpstreamStatus::RateLimited)
    };
    feed(&g, vec![huge], &at(10)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(10 + 24 * 3600)));
}

#[tokio::test]
async fn quota_limits_until_reset_or_six_hours_and_outranks_a_cooldown() {
    let g = fixture().await;
    let id = g.account.id;
    feed(&g, vec![up(1, UpstreamStatus::RateLimited)], &at(0)).await;
    feed(&g, vec![up(2, UpstreamStatus::Quota)], &at(1)).await;
    assert_eq!(
        view(&g.fx, id).await,
        (
            "limited".into(),
            Some("quota".into()),
            Some(at(1 + 6 * 3600))
        )
    );
    // A rate limit never lowers it.
    feed(&g, vec![up(3, UpstreamStatus::RateLimited)], &at(2)).await;
    assert_eq!(view(&g.fx, id).await.0, "limited");
    // A reset the upstream names ends it there.
    health::recover(&g.fx.app.pool, id, &at(7 * 3600))
        .await
        .unwrap();
    let q = GatewayReport {
        reset_at: Some(at(7 * 3600 + 900)),
        ..up(4, UpstreamStatus::Quota)
    };
    feed(&g, vec![q], &at(7 * 3600)).await;
    assert_eq!(view(&g.fx, id).await.2, Some(at(7 * 3600 + 900)));
}

#[tokio::test]
async fn three_upstream_errors_in_ten_minutes_make_the_account_unhealthy_for_ten() {
    let g = fixture().await;
    let id = g.account.id;
    for (seq, s) in [UpstreamStatus::ServerError, UpstreamStatus::Unreachable]
        .into_iter()
        .enumerate()
    {
        feed(&g, vec![up(seq as u64 + 1, s)], &at(seq as i64 * 60)).await;
    }
    assert_eq!(view(&g.fx, id).await.0, "active");
    assert_eq!(counts(&g.fx, id).await.0, 2);
    // The window runs from the first error: an error after it starts a new count.
    feed(&g, vec![up(3, UpstreamStatus::TlsFailed)], &at(700)).await;
    assert_eq!(
        (view(&g.fx, id).await.0, counts(&g.fx, id).await.0),
        ("active".into(), 1)
    );
    feed(&g, vec![up(4, UpstreamStatus::RefusedAddress)], &at(760)).await;
    feed(&g, vec![up(5, UpstreamStatus::ServerError)], &at(800)).await;
    assert_eq!(
        view(&g.fx, id).await,
        (
            "unhealthy".into(),
            Some("upstream_errors".into()),
            Some(at(1400))
        )
    );
    assert_eq!(counts(&g.fx, id).await.0, 0);
    health::recover(&g.fx.app.pool, id, &at(1401))
        .await
        .unwrap();
    assert_eq!(view(&g.fx, id).await.0, "active");
}

#[tokio::test]
async fn an_auth_failure_report_changes_no_state_and_an_admins_state_is_never_overwritten() {
    let g = fixture().await;
    let id = g.account.id;
    feed(&g, vec![up(1, UpstreamStatus::AuthFailed)], &at(0)).await;
    assert_eq!(
        view(&g.fx, id).await.0,
        "active",
        "still the confirmed path's to decide"
    );
    assert!(
        crate::store::gateway::pending_auth(&g.fx.app.pool, id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        class_of(&g.fx, &g.session.id).await.as_deref(),
        Some("auth_failed")
    );
    // Disabled stays disabled; an admin's own cooling (a reason that is not a code) stays too.
    for (state, reason) in [("disabled", "stored a new key"), ("limited", "my own hold")] {
        acc::set_state(
            &g.fx.app.pool,
            id,
            state,
            Some(reason),
            Some(&at(99_999)),
            "d",
            BY,
            &at(1),
        )
        .await
        .unwrap();
        feed(&g, vec![up(2, UpstreamStatus::Quota)], &at(2)).await;
        let a = view(&g.fx, id).await;
        assert_eq!((a.0.as_str(), a.1.as_deref()), (state, Some(reason)));
        sqlx::query("UPDATE core_agent_sessions SET gw_seq = 1 WHERE id = ?")
            .bind(&g.session.id)
            .execute(&g.fx.app.pool)
            .await
            .unwrap();
    }
}
