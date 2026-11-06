//! The scheduler's events and settings (S7): a cooldown, a limit and an unhealthy account each
//! raise one `account.limited` or `account.health` event in the transaction of the change (none for
//! a window that is only lengthened), a device sees them only with `admin`, no payload holds a
//! token or a word an upstream said, and the `scheduler.*` settings are validated and read.

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{PlanLimit, PlanWindow, UpstreamStatus};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::gateway_store::{G, gw};
use super::health::{at, view};
use super::*;
use crate::scheduler::unix_secs;
use crate::store::health::{self, Signal};

async fn signal(g: &G, s: Signal<'_>, secs: i64) {
    let mut tx = crate::store::begin_write(&g.fx.app.pool).await.unwrap();
    let (account, session) = (g.account.id, &g.session.id);
    health::on_signal(&mut tx, account, session, s, &at(secs))
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn upstream(status: UpstreamStatus) -> Signal<'static> {
    Signal::Gateway {
        status,
        retry_after: None,
        reset_at: None,
    }
}

async fn raised(fx: &Fx) -> Vec<(String, Value)> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, payload FROM events WHERE kind IN ('account.limited', 'account.health') \
         ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(k, p)| (k, serde_json::from_str(&p).unwrap()))
        .collect()
}

#[tokio::test]
async fn each_change_of_state_raises_one_event_and_a_longer_window_none() {
    let g = gw().await;
    let id = g.account.id;
    // A rate limit cools it: one `account.limited` from the gateway.
    signal(&g, upstream(UpstreamStatus::RateLimited), 0).await;
    let first =
        json!({"account": id, "class": "rate_limited", "until": at(60), "source": "gateway"});
    assert_eq!(raised(&g.fx).await, [("account.limited".to_owned(), first)]);
    // A second 429 inside the window only lengthens it: no second event.
    signal(&g, upstream(UpstreamStatus::RateLimited), 10).await;
    assert_eq!(raised(&g.fx).await.len(), 1);
    // A quota failure on top is a new reason: `limited` for the default 6 hours.
    signal(&g, upstream(UpstreamStatus::Quota), 20).await;
    let all = raised(&g.fx).await;
    assert_eq!(all.len(), 2);
    assert_eq!(
        all[1].1,
        json!({"account": id, "class": "quota", "until": at(20 + 6 * 3600), "source": "gateway"})
    );
    // Three upstream errors in ten minutes: `account.health`, once, on the third.
    health::recover(&g.fx.app.pool, id, &at(30_000))
        .await
        .unwrap();
    for n in 0..2 {
        signal(&g, upstream(UpstreamStatus::ServerError), 30_000 + n).await;
    }
    assert_eq!(raised(&g.fx).await.len(), 2, "two errors raise nothing");
    signal(&g, upstream(UpstreamStatus::ServerError), 30_002).await;
    let all = raised(&g.fx).await;
    assert_eq!(all.len(), 3);
    assert_eq!(
        (all[2].0.as_str(), &all[2].1),
        (
            "account.health",
            &json!({"account": id, "state": "unhealthy", "reason": "upstream_errors"})
        )
    );
    // Three failed sign-ins in a row (the harness's word) keep it out: `auth_suspected`.
    health::recover(&g.fx.app.pool, id, &at(31_000))
        .await
        .unwrap();
    for n in 0..3 {
        signal(&g, Signal::HarnessEnd { class: "auth" }, 31_000 + n).await;
    }
    let all = raised(&g.fx).await;
    assert_eq!(all.len(), 4);
    assert_eq!(
        all[3].1,
        json!({"account": id, "state": "unhealthy", "reason": "auth_suspected"})
    );
    // A plan limit from the harness cools it, saying whose word it is.
    health::recover(&g.fx.app.pool, id, &at(40_000))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE core_accounts SET state = 'active', state_reason = NULL, state_until = NULL",
    )
    .execute(&g.fx.app.pool)
    .await
    .unwrap();
    let resets = unix_secs(&at(40_000 + 3600)).unwrap();
    let plan = PlanLimit {
        status: "rejected".to_owned(),
        windows: vec![PlanWindow {
            name: "five_hour".to_owned(),
            utilization: 1.0,
            resets_at: Some(resets),
        }],
    };
    signal(&g, Signal::HarnessPlan { plan: &plan }, 40_000).await;
    let all = raised(&g.fx).await;
    assert_eq!(all.len(), 5);
    assert_eq!(
        all[4].1,
        json!({"account": id, "class": "plan_limit", "until": at(40_000 + 3600), "source": "harness"})
    );
    // Nothing in any payload is a label, a key or a word from upstream: only these keys.
    for (kind, p) in &all {
        let mut keys: Vec<_> = p.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let want: &[&str] = match kind.as_str() {
            "account.limited" => &["account", "class", "source", "until"],
            _ => &["account", "reason", "state"],
        };
        assert_eq!(keys, want, "{kind}");
    }
    assert_eq!(view(&g.fx, id).await.0, "cooling");
}

#[tokio::test]
async fn the_events_are_admin_only() {
    let g = gw().await;
    signal(&g, upstream(UpstreamStatus::RateLimited), 0).await;
    let reader = g.fx.enroll("reader", &["read", "agent"]).await;
    let kinds = |body: &Value| -> Vec<String> {
        body["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| e["kind"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let admin = send(
        &g.fx.app,
        req(Method::GET, "/api/v1/events", Some(&g.fx.dev), None),
    )
    .await;
    assert_eq!(admin.0, StatusCode::OK, "{}", admin.1);
    assert!(
        kinds(&admin.1).iter().any(|k| k == "account.limited"),
        "{}",
        admin.1
    );
    let theirs = send(
        &g.fx.app,
        req(Method::GET, "/api/v1/events", Some(&reader), None),
    )
    .await;
    assert_eq!(theirs.0, StatusCode::OK, "{}", theirs.1);
    assert!(
        kinds(&theirs.1).iter().all(|k| !k.starts_with("account.")),
        "{}",
        theirs.1
    );
}

#[tokio::test]
async fn the_scheduler_settings_are_validated_listed_and_read() {
    let fx = fx().await;
    let put = |key: &str, value: Value| {
        let uri = format!("/api/v1/settings/server/{key}");
        let fx = &fx;
        async move { send(&fx.app, req(Method::PUT, &uri, Some(&fx.dev), Some(value))).await }
    };
    // Defaults and bounds, as listed.
    let all = fx.ok("/api/v1/settings").await;
    let find = |key: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|s| s["key"] == key)
            .unwrap()
            .clone()
    };
    for (key, default, min, max) in [
        ("scheduler.wait_max_secs", 900, 1, 86_400),
        ("scheduler.quota_cooldown_secs", 21_600, 60, 604_800),
        ("scheduler.max_hops", 4, 0, 16),
        ("scheduler.failovers_per_10min", 10, 0, 1_000),
    ] {
        let s = find(key);
        assert_eq!(
            (&s["default"], &s["min"], &s["max"], &s["value"]),
            (&json!(default), &json!(min), &json!(max), &json!(default)),
            "{key}"
        );
        // Out of bounds either way, and not an integer: refused, nothing changes.
        for (value, code) in [
            (json!(min - 1), "out_of_bounds"),
            (json!(max + 1), "out_of_bounds"),
            (json!("5"), "not_integer"),
            (json!(1.5), "not_integer"),
        ] {
            let r = put(key, json!({"value": value})).await;
            assert_eq!(
                (r.0, r.1["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some(code)),
                "{key} {value}: {}",
                r.1
            );
        }
        let r = put(key, json!({"value": max})).await;
        assert_eq!(r.0, StatusCode::OK, "{key}: {}", r.1);
        assert_eq!(r.1["value"], max);
    }
    // The default of the wait is the allocator's own constant.
    assert_eq!(
        crate::store::alloc::WAIT_MAX_SECS,
        Key::SchedulerWaitMaxSecs.default()
    );
}

#[tokio::test]
async fn the_quota_cooldown_setting_is_what_a_quota_waits_when_nothing_says() {
    let g = gw().await;
    let key = Key::SchedulerQuotaCooldownSecs;
    crate::store::settings::set(
        &g.fx.app.pool,
        key,
        Scope::Server,
        "120",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    signal(&g, upstream(UpstreamStatus::Quota), 0).await;
    assert_eq!(view(&g.fx, g.account.id).await.2, Some(at(120)));
    assert_eq!(raised(&g.fx).await[0].1["until"], json!(at(120)));
}
