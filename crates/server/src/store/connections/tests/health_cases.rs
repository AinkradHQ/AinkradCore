use ainkrad_proto::v2::UpstreamStatus as U;

use super::*;
use health::Signal;
use verdict::TestOutcome;

fn up(status: U) -> Signal<'static> {
    Signal::Upstream {
        status,
        retry_after: None,
        reset_at: None,
    }
}

async fn state(fx: &Fx, id: i64) -> (String, Option<String>) {
    let c = get(&fx.pool, 1, id).await.unwrap();
    (c.status, c.state_reason)
}

async fn sig(fx: &Fx, id: i64, s: Signal<'_>, secs: i64) {
    health::signal(&fx.pool, 1, id, s, &at(secs)).await.unwrap();
}

fn st(status: &str, reason: Option<&str>) -> (String, Option<String>) {
    (status.to_owned(), reason.map(str::to_owned))
}

#[tokio::test]
async fn a_rate_limit_cools_with_a_doubling_backoff_and_recovers_lazily() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    sig(&fx, c.id, up(U::RateLimited), 0).await;
    assert_eq!(state(&fx, c.id).await, st("cooling", Some("rate_limited")));
    let until = get(&fx.pool, 1, c.id).await.unwrap().state_until.unwrap();
    assert_eq!(until, at(60));
    // Past the window the next look makes it active again, audited by the system.
    assert!(!usable_at(&fx, c.id, 30).await);
    assert!(usable_at(&fx, c.id, 61).await);
    sig(&fx, c.id, up(U::RateLimited), 100).await;
    assert_eq!(
        get(&fx.pool, 1, c.id).await.unwrap().state_until.unwrap(),
        at(220),
        "60 doubled to 120"
    );
    let log = actions(&fx).await;
    assert_eq!(
        log.iter().filter(|a| *a == "connection.state_set").count(),
        3,
        "{log:?}"
    );
}

async fn usable_at(fx: &Fx, id: i64, secs: i64) -> bool {
    health::recover(&fx.pool, id, &at(secs)).await.unwrap();
    verdict::usable(&get(&fx.pool, 1, id).await.unwrap()).is_ok()
}

#[tokio::test]
async fn upstream_errors_count_in_a_window_and_a_success_starts_over() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    sig(&fx, c.id, up(U::ServerError), 0).await;
    sig(&fx, c.id, up(U::Unreachable), 10).await;
    sig(&fx, c.id, up(U::Ok), 20).await;
    sig(&fx, c.id, up(U::TlsFailed), 30).await;
    sig(&fx, c.id, up(U::ServerError), 40).await;
    assert_eq!(
        state(&fx, c.id).await.0,
        "active",
        "a success reset the count"
    );
    sig(&fx, c.id, up(U::RefusedAddress), 50).await;
    assert_eq!(
        state(&fx, c.id).await,
        st("unhealthy", Some("upstream_errors"))
    );
    assert!(usable_at(&fx, c.id, 50 + 601).await, "ten minutes later");
    // Errors a window apart do not add up.
    sig(&fx, c.id, up(U::ServerError), 1000).await;
    sig(&fx, c.id, up(U::ServerError), 1700).await;
    sig(&fx, c.id, up(U::ServerError), 2400).await;
    assert_eq!(state(&fx, c.id).await.0, "active");
}

#[tokio::test]
async fn quota_limits_and_a_higher_state_is_not_shortened() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let reset = at(7200);
    let q = Signal::Upstream {
        status: U::Quota,
        retry_after: None,
        reset_at: Some(&reset),
    };
    sig(&fx, c.id, q, 0).await;
    assert_eq!(state(&fx, c.id).await, st("limited", Some("quota")));
    sig(&fx, c.id, up(U::RateLimited), 10).await;
    assert_eq!(
        state(&fx, c.id).await.0,
        "limited",
        "a lower rank never overwrites"
    );
    assert_eq!(
        get(&fx.pool, 1, c.id).await.unwrap().state_until.unwrap(),
        reset
    );
}

#[tokio::test]
async fn agent_signals_may_only_cool_an_active_connection() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    for class in ["auth", "permanent", "transient", "core", "step:x"] {
        sig(&fx, c.id, Signal::Agent { class }, 0).await;
    }
    for _ in 0..10 {
        sig(&fx, c.id, Signal::Agent { class: "auth" }, 0).await;
    }
    assert_eq!(
        state(&fx, c.id).await.0,
        "active",
        "nothing an agent says but a limit counts"
    );
    assert!(!get(&fx.pool, 1, c.id).await.unwrap().disabled);
    sig(
        &fx,
        c.id,
        Signal::Agent {
            class: "rate_limited",
        },
        0,
    )
    .await;
    assert_eq!(state(&fx, c.id).await, st("cooling", Some("rate_limited")));
    // Over a trusted, longer state it changes nothing; it cannot extend or lower it.
    sig(&fx, c.id, up(U::Quota), 1).await;
    assert_eq!(state(&fx, c.id).await.0, "limited");
    sig(
        &fx,
        c.id,
        Signal::Agent {
            class: "rate_limited",
        },
        2,
    )
    .await;
    assert_eq!(state(&fx, c.id).await.0, "limited");
    // Never the auth path, whatever it claims, and its cooling is clamped.
    let d = make(&fx, "fake", "d").await;
    sig(&fx, d.id, Signal::Agent { class: "quota" }, 0).await;
    let until = unix_secs(&get(&fx.pool, 1, d.id).await.unwrap().state_until.unwrap()).unwrap();
    assert!(until <= unix_secs(NOW).unwrap() + crate::store::health::HARNESS_MAX_SECS);
}

#[tokio::test]
async fn an_auth_failure_needs_a_test_before_anything_is_disabled() {
    let fx = fx().await;
    let c = make_with(&fx, "fake", "a", "reject-me-0001").await;
    sig(&fx, c.id, up(U::AuthFailed), 0).await;
    sig(&fx, c.id, up(U::AuthFailed), 1).await;
    let after = get(&fx.pool, 1, c.id).await.unwrap();
    assert_eq!(
        (after.status.as_str(), after.state_reason.as_deref()),
        ("unhealthy", Some("auth_suspected"))
    );
    assert!(!after.disabled);
    assert_eq!(
        verdict::usable(&after).unwrap_err().0,
        "auth_pending",
        "out of use, not disabled"
    );
    assert_eq!(
        actions(&fx)
            .await
            .iter()
            .filter(|a| *a == "connection.auth_failed")
            .count(),
        1,
        "one signal, one row"
    );
    // Time does not end it, and an agent cannot confirm it.
    assert!(!usable_at(&fx, c.id, 86_400).await);
    sig(&fx, c.id, Signal::Agent { class: "auth" }, 5).await;
    assert_eq!(state(&fx, c.id).await.0, "unhealthy");
    // The test the service rejects is the confirmation.
    let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, c.id, w(&at(10)))
        .await
        .unwrap();
    assert_eq!(
        (t.status.as_str(), t.state_reason.as_deref()),
        ("disabled", Some("auth_failed"))
    );
    assert_eq!(t.last_tested_at.as_deref(), Some(at(10).as_str()));
    assert_eq!(verdict::usable(&t).unwrap_err().0, "auth_failed");
    // A replaced credential clears it; so does an admin's re-enable.
    let fresh = Material::new("c1probe-fresh-0001", None, None).unwrap();
    let r = secret::replace(&fx.pool, &fx.sealer, c.id, &fresh, w(&at(20)))
        .await
        .unwrap();
    assert_eq!(r.status, "active");
    let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, c.id, w(&at(30)))
        .await
        .unwrap();
    assert_eq!(
        (t.status.as_str(), t.identity.as_deref()),
        ("active", Some("acct-c1pr"))
    );
    let d = make_with(&fx, "fake", "d", "reject-me-0002").await;
    verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, d.id, w(&at(40)))
        .await
        .unwrap();
    assert_eq!(
        state(&fx, d.id).await.0,
        "disabled",
        "a test alone can confirm"
    );
    assert_eq!(
        set_disabled(&fx.pool, d.id, false, w(&at(50)))
            .await
            .unwrap()
            .status,
        "active"
    );
}

#[tokio::test]
async fn a_passing_test_clears_a_suspicion_and_an_inconclusive_one_never_disables() {
    let fx = fx().await;
    let ok = make(&fx, "fake", "ok").await;
    sig(&fx, ok.id, up(U::AuthFailed), 0).await;
    let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, ok.id, w(&at(5)))
        .await
        .unwrap();
    assert_eq!(t.status, "active");
    assert_eq!(t.identity.as_deref(), Some("acct-c1pr"));
    let down = make_with(&fx, "fake", "down", "down-0000-aaaa").await;
    sig(&fx, down.id, up(U::AuthFailed), 0).await;
    for i in 1..=2 {
        let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, down.id, w(&at(i)))
            .await
            .unwrap();
        assert_eq!(
            t.status, "unhealthy",
            "try {i}: still waiting for a verdict"
        );
    }
    let t = verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, down.id, w(&at(3)))
        .await
        .unwrap();
    assert_eq!(
        (t.status.as_str(), t.disabled),
        ("active", false),
        "dropped as inconclusive, never disabled"
    );
    assert!(
        actions(&fx)
            .await
            .contains(&"connection.auth_inconclusive".to_owned())
    );
    // A test that says nothing about a healthy connection changes nothing but the time.
    let h = verdict::record_test(
        &fx.pool,
        ok.id,
        version(&fx, ok.id).await,
        TestOutcome::Inconclusive,
        w(&at(9)),
    )
    .await
    .unwrap();
    assert_eq!(
        (h.status.as_str(), h.last_tested_at.as_deref()),
        ("active", Some(at(9).as_str()))
    );
}

#[tokio::test]
async fn a_changed_identity_is_audited() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let id = |s: &str| {
        TestOutcome::Passed(crate::connections::adapter::Identity {
            subject: s.to_owned(),
        })
    };
    verdict::record_test(
        &fx.pool,
        c.id,
        version(&fx, c.id).await,
        id("octocat"),
        w(NOW),
    )
    .await
    .unwrap();
    verdict::record_test(
        &fx.pool,
        c.id,
        version(&fx, c.id).await,
        id("octocat"),
        w(NOW),
    )
    .await
    .unwrap();
    verdict::record_test(
        &fx.pool,
        c.id,
        version(&fx, c.id).await,
        id("someone-else"),
        w(NOW),
    )
    .await
    .unwrap();
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.tested' ORDER BY seq",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    let flags: Vec<bool> = rows
        .iter()
        .map(|r| r.contains(r#""identity_changed":true"#))
        .collect();
    assert_eq!(flags, [false, false, true]);
    assert_eq!(
        get(&fx.pool, 1, c.id).await.unwrap().identity.as_deref(),
        Some("someone-else")
    );
}
