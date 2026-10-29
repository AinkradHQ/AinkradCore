//! Account thresholds are the account's settings (E15.17): drops, how long it stays unhealthy,
//! cool-offs, the harness report's warning and refusal, and a new limit's warning.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{AccountId, AccountStatus, Billing, LimitUnit, NewAccountLimit};
use ainkrad_core::org::ModelRoute;
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;

use super::settings::set;
use super::wake::{runner, wake};
use super::*;
use crate::store::gov::{
    apply_signal, assign_account, create_account, get_account, new_account, record_drop,
    set_account_limit, set_billing,
};
use crate::store::org::{get_agent, set_fallbacks};

const BY: AuditActor = AuditActor::User(UserId(1));
const NOW: &str = "2026-10-22T10:00:00.000Z";

/// A run of a fresh company's agent on its first of two Claude accounts.
async fn on_account(pool: &SqlitePool) -> (Run, AccountId, AccountId) {
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let mut ids = vec![];
    for label in ["one", "two"] {
        let new = new_account(pool, Harness::Claude, label, None, None, None, None);
        let a = create_account(pool, &new.await.unwrap(), BY).await.unwrap();
        assign_account(pool, a.id, company, true, BY).await.unwrap();
        ids.push(a.id);
    }
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    let run = dispatch_next(pool, r, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.account_id, Some(ids[0]));
    (run, ids[0], ids[1])
}

async fn status(pool: &SqlitePool, a: AccountId) -> (AccountStatus, Option<String>) {
    let a = get_account(pool, a).await.unwrap().unwrap();
    (a.status, a.status_until)
}

#[tokio::test]
async fn drop_threshold_window_and_sick_time_are_the_accounts_settings() {
    let db = db().await;
    let pool = &db.pool;
    let (run, a, _) = on_account(pool).await;
    let at = Scope::Account(a);
    set(pool, Key::DropThreshold, at, 2).await;
    set(pool, Key::DropWindowSecs, at, 60).await;
    set(pool, Key::UnhealthySecs, at, 120).await;
    let drop_at = |t: &'static str| record_drop(pool, run.id, "reset", AuditActor::System, t);
    drop_at("2026-10-22T10:00:00.000Z").await.unwrap();
    // 90 s later the first has left the 60 s window (the default 10 min would count both).
    drop_at("2026-10-22T10:01:30.000Z").await.unwrap();
    assert_eq!(status(pool, a).await.0, AccountStatus::Active);
    drop_at("2026-10-22T10:02:00.000Z").await.unwrap();
    assert_eq!(
        status(pool, a).await,
        (
            AccountStatus::Unhealthy,
            Some("2026-10-22T10:04:00.000Z".to_owned())
        ),
        "two in a minute, sick for 2 min"
    );
}

#[tokio::test]
async fn a_refused_turn_cools_off_for_the_accounts_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (run, first, second) = on_account(pool).await;
    set_billing(pool, Harness::Claude, Billing::Metered, BY)
        .await
        .unwrap();
    let haiku = ModelRoute {
        harness: Harness::Claude,
        model: "claude-haiku".to_owned(),
    };
    set_fallbacks(pool, run.agent_id, std::slice::from_ref(&haiku), BY)
        .await
        .unwrap();
    set(pool, Key::RefusalCoolOffSecs, Scope::Account(first), 300).await;
    let to = Fallback {
        to: &haiku,
        account: Some(second),
        class: "rate_limited",
        reason: "429",
    };
    switch_route(pool, run.id, &to, AuditActor::System, NOW)
        .await
        .unwrap();
    assert_eq!(
        status(pool, first).await,
        (
            AccountStatus::Limited,
            Some("2026-10-22T10:05:00.000Z".to_owned())
        ),
        "5 min, not the default 15"
    );
}

#[tokio::test]
async fn the_harness_report_warns_and_refuses_by_the_accounts_settings() {
    let db = db().await;
    let pool = &db.pool;
    let (run, a, _) = on_account(pool).await;
    set(pool, Key::AccountWarnPercent, Scope::Account(a), 50).await;
    set(pool, Key::RefusedSecs, Scope::Account(a), 600).await;
    let report = json!({"type": "rate_limit", "status": "allowed",
                        "windows": [{"name": "five_hour", "utilization": 0.6}]});
    apply_signal(pool, run.id, &report, NOW).await.unwrap();
    let warned: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'account.warning'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(warned, 1, "60% crosses 50%, not the default 80%");
    let refused = json!({"type": "rate_limit", "status": "rejected", "windows": []});
    apply_signal(pool, run.id, &refused, NOW).await.unwrap();
    assert_eq!(
        status(pool, a).await,
        (
            AccountStatus::Limited,
            Some("2026-10-22T10:10:00.000Z".to_owned())
        ),
        "no reset given: 10 min, not the default hour"
    );
}

#[tokio::test]
async fn a_new_limit_warns_at_the_accounts_setting_unless_given() {
    let db = db().await;
    let pool = &db.pool;
    let (_, a, _) = on_account(pool).await;
    let new = |warn| NewAccountLimit {
        window_secs: 3600,
        unit: LimitUnit::Tokens,
        max: 1000,
        warn_percent: warn,
    };
    let l = set_account_limit(pool, a, new(None), BY, NOW)
        .await
        .unwrap();
    assert_eq!(l.warn_percent, 80, "the default");
    set(pool, Key::AccountWarnPercent, Scope::Account(a), 65).await;
    let l = set_account_limit(pool, a, new(None), BY, NOW)
        .await
        .unwrap();
    assert_eq!(l.warn_percent, 65);
    let l = set_account_limit(pool, a, new(Some(90)), BY, NOW)
        .await
        .unwrap();
    assert_eq!(l.warn_percent, 90, "given beats the setting");
}
