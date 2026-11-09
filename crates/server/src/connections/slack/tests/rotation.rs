//! A rotating token below `secrets.mode` 2 (its refresh token is never spent for a token that
//! cannot be stored), at mode 2, and an app that no longer signs anyone in but still renews.

use serde_json::json;

use super::*;
use crate::connections::slack::CallError;
use crate::store::connections::{secret, suspend};

async fn due_connection(f: &Fx) -> Connection {
    f.connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await
}

async fn state_of(f: &Fx, id: i64) -> (String, Option<String>) {
    let c = crate::store::connections::get(&f.pool, 1, id)
        .await
        .unwrap();
    (c.status, c.state_reason)
}

#[tokio::test]
async fn a_refresh_token_is_not_spent_below_mode_2_whatever_state_the_connection_is_in() {
    use crate::store::connections::health::{self, Signal};
    use ainkrad_proto::v2::UpstreamStatus;
    let signals: [(&str, Signal<'static>, &str); 3] = [
        ("active", Signal::Success, "active"),
        (
            "cooling",
            Signal::Agent {
                class: "rate_limited",
            },
            "cooling",
        ),
        (
            "auth_suspected",
            Signal::Upstream {
                status: UpstreamStatus::AuthFailed,
                retry_after: None,
                reset_at: None,
            },
            "unhealthy",
        ),
    ];
    for (name, signal, status) in signals {
        // Mode 1: the gate refuses every real Slack token a rotation hands out.
        let f = fx(true).await;
        let served = f.fake.rotating();
        let c = due_connection(&f).await;
        health::signal(&f.pool, 1, c.id, signal, NOW).await.unwrap();
        assert_eq!(state_of(&f, c.id).await.0, status, "{name}");
        let e = f
            .slack
            .fresh(&f.cx(NOW), c.id)
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(e, CallError::NeedsMode2, "{name}");
        assert_eq!((e.health(), e.code()), (None, "needs_mode_2"));
        // Suspended from the state it was in; the pending auth test is dropped.
        let (now_status, why) = state_of(&f, c.id).await;
        assert_eq!(
            (now_status.as_str(), why.as_deref()),
            ("unhealthy", Some("needs_mode_2")),
            "{name}"
        );
        let pending: (i64, i64) =
            sqlx::query_as("SELECT auth_pending, fail_streak FROM core_connections WHERE id = ?")
                .bind(c.id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(pending, (0, 0), "{name}");
        // Slack was never asked: the refresh token is whole, and a test says nothing more.
        assert_eq!(
            served.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{name}"
        );
        assert_eq!(f.fake.count("oauth.v2.access"), 0, "{name}");
        let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
        assert_eq!(stored.refresh(), Some(REFRESH), "{name}");
        for _ in 0..2 {
            let t = f.slack.test_connection(&f.cx(NOW), c.id).await.unwrap();
            assert_eq!(
                (t.status.as_str(), t.state_reason.as_deref()),
                ("unhealthy", Some("needs_mode_2")),
                "{name}"
            );
        }
        assert_eq!(f.fake.count("oauth.v2.access"), 0, "{name}");
    }
}

#[tokio::test]
async fn a_test_of_a_suspected_connection_below_mode_2_ends_needs_mode_2_not_auth_failed() {
    use crate::store::connections::health::{self, Signal};
    use ainkrad_proto::v2::UpstreamStatus;
    let f = fx(true).await;
    f.fake
        .on("oauth.v2.access", |_| Reply::err("invalid_refresh_token"));
    let c = due_connection(&f).await;
    let signal = Signal::Upstream {
        status: UpstreamStatus::AuthFailed,
        retry_after: None,
        reset_at: None,
    };
    health::signal(&f.pool, 1, c.id, signal, NOW).await.unwrap();
    for _ in 0..3 {
        let t = f.slack.test_connection(&f.cx(NOW), c.id).await.unwrap();
        assert_eq!(
            (t.status.as_str(), t.state_reason.as_deref()),
            ("unhealthy", Some("needs_mode_2"))
        );
    }
    assert_eq!(
        f.fake.count("oauth.v2.access"),
        0,
        "never the spent token again"
    );
}

#[tokio::test]
async fn mode_2_renews_and_stores_real_shaped_tokens() {
    let f = fx_rotating(true).await;
    let body = "a1B2c3D4e5".repeat(3);
    let (access, refresh) = (format!("xoxe.xoxb-{body}"), format!("xoxe-1-{body}"));
    let (a, r) = (access.clone(), refresh.clone());
    f.fake.on("oauth.v2.access", move |_| {
        Reply::ok(
            json!({"access_token": a, "refresh_token": r, "token_type": "bot",
            "expires_in": 43200}),
        )
    });
    let c = due_connection(&f).await;
    let m = f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        (m.access(), m.refresh()),
        (access.as_str(), Some(refresh.as_str()))
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(stored.access(), access);
    assert_eq!(state_of(&f, c.id).await, ("active".to_owned(), None));
}

#[tokio::test]
async fn a_suspension_that_cannot_be_written_is_an_error_and_still_spends_nothing() {
    let f = fx(true).await;
    f.fake.rotating();
    let c = due_connection(&f).await;
    sqlx::query("CREATE TRIGGER no_update BEFORE UPDATE ON core_connections BEGIN SELECT RAISE(ABORT, 'no'); END")
        .execute(&f.pool)
        .await
        .unwrap();
    let e = f
        .slack
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(e, CallError::Internal(_)), "{e:?}");
    assert_eq!(e.health(), None);
    assert_eq!(f.fake.count("oauth.v2.access"), 0);
}

#[tokio::test]
async fn a_disabled_connection_and_one_already_suspended_are_left_as_they_are() {
    let f = fx(true).await;
    let c = due_connection(&f).await;
    assert!(suspend::needs_mode_2(&f.pool, 1, c.id, NOW).await.unwrap());
    assert!(
        !suspend::needs_mode_2(&f.pool, 1, c.id, NOW).await.unwrap(),
        "already suspended"
    );
    let d = f
        .connect("other", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    sqlx::query("UPDATE core_connections SET status = 'disabled', state_reason = 'auth_failed' WHERE id = ?")
        .bind(d.id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(!suspend::needs_mode_2(&f.pool, 1, d.id, NOW).await.unwrap());
    assert_eq!(
        state_of(&f, d.id).await,
        ("disabled".to_owned(), Some("auth_failed".to_owned()))
    );
    // Storing a credential again ends the suspension.
    secret::replace(&f.pool, &f.sealer, c.id, &bot(), f.cx(NOW).who)
        .await
        .unwrap();
    assert_eq!(state_of(&f, c.id).await, ("active".to_owned(), None));
}

#[tokio::test]
async fn an_app_without_a_sign_in_still_renews_but_starts_and_finishes_nothing() {
    let f = fx_rotating(true).await;
    f.fake.rotating();
    let c = due_connection(&f).await;
    let renewal = OAuthApp::renewal_only("1234.5678", CLIENT_SECRET).unwrap();
    assert!(f.slack.set_app(Some(renewal)));
    assert!(!f.slack.app_configured() && f.slack.redirects().is_empty());
    assert_eq!(
        f.slack.start(1, REDIRECT, None),
        Err(crate::connections::slack::FlowError::NotConfigured)
    );
    let m = f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("xoxe-1-test-ref2-91c4d2"));
    assert_eq!(
        f.fake.last("oauth.v2.access").unwrap().form["client_secret"],
        CLIENT_SECRET
    );
    // A sign-in begun under the full app cannot be finished once the app stopped signing in.
    let full = OAuthApp::new("1234.5678", CLIENT_SECRET, REDIRECT).unwrap();
    f.slack.set_app(Some(full));
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    f.slack
        .set_app(OAuthApp::renewal_only("1234.5678", CLIENT_SECRET));
    let r = f.slack.finish(1, &s.state, "code", NOW).await;
    assert!(matches!(
        r,
        Err(crate::connections::slack::FlowError::NotConfigured)
    ));
    assert!(
        OAuthApp::renewal_only("", "x").is_none() && OAuthApp::renewal_only("x", "\n").is_none()
    );
    // Only removing the app stops the renewal.
    f.slack.set_app(None);
    let e = f
        .slack
        .fresh(&f.cx(&at(50_000)), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::OAuthNotConfigured);
}
