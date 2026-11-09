//! A subscription account that is disabled or deleted (KAN-434, KAN-441 L5): not leased, an earlier
//! lease revoked, the live sessions holding the token killed (the token stays valid at Anthropic:
//! the user revokes it there), and the disable-versus-launch race.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents as sessions;
use ainkrad_core_server::store::secrets;
use ainkrad_proto::v2::*;

use super::agents;
use super::gateway::{command, count, events};
use super::login::{TOKEN, everything, refusal};
use super::subscription::{S, make, refused_start, sub, up};

#[tokio::test]
async fn a_disabled_or_deleted_account_is_not_leased_and_an_earlier_lease_is_revoked() {
    let w = up("sub-gone").await;
    let (pool, id) = (&w.core.app.pool, w.account.id);
    let (now, unix) = (w.core.app.clock.now(), w.core.app.clock.unix());
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let mint = || {
        secrets::lease(
            pool,
            &w.account.secret_name,
            &w.runner,
            None,
            &w.runner,
            AuditActor::System,
            &now,
            unix,
        )
    };
    let (runner, now_ref) = (&w.runner, &now);
    let redeem = |l: String| async move {
        secrets::redeem(pool, sealer, &l, runner, AuditActor::System, now_ref, unix).await
    };

    // Disabled: no start, and a lease minted before is dead.
    let (before, _) = mint().await.unwrap();
    let off = service::subscription::set_state(
        &w.core.app,
        id,
        "disabled",
        Some("test"),
        None,
        &w.runner,
        AuditActor::System,
    );
    off.await.unwrap();
    assert_eq!(refusal(redeem(before).await).0, "not_found");
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let why = refused_start(&w, &row).await;
    assert!(
        why.contains("disabled") && why.contains("not active"),
        "{why}"
    );
    let on = service::subscription::set_state(
        &w.core.app,
        id,
        "active",
        None,
        None,
        &w.runner,
        AuditActor::System,
    );
    on.await.unwrap();

    // Deleted: a lease minted before is revoked with the key, and no start leases it again.
    let (before, _) = mint().await.unwrap();
    service::subscription::delete(&w.core.app, id, &w.runner, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(refusal(redeem(before).await).0, "not_found");
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let why = refused_start(&w, &row).await;
    assert!(why.contains("no longer exists"), "{why}");
    assert_eq!(agents::state_of(&w.core, &row.id).await.state, "ended");
    assert!(!everything(&w.core).await.contains(TOKEN));
    // The only leases ever minted here were the two this test made by hand.
    let leased = "SELECT count(*) FROM audit_events WHERE action = 'secret.leased'";
    assert_eq!(count(&w.core, leased).await, 2);
}

/// A running session of the account, answered as started.
async fn running(name: &str) -> (S, sessions::Session) {
    let mut w = up(name).await;
    let row = make(&w, "claude", &sub(&w.account), None).await;
    let (app, started) = (w.core.app.clone(), row.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &started).await;
    });
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentStart(_)), "{cmd:?}");
    let ev = events(&row.id, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentStart(ev)))
        .await;
    (w, row)
}

/// Answers reads as running until the Core sends a kill for `session`, which it answers as ended.
async fn expect_kill(fake: &mut super::Fake, session: &str) {
    let wait = async {
        loop {
            let (stream, cmd) = command(fake).await;
            match cmd {
                Command::AgentRead(_) => {
                    let ev = events(session, AgentState::Running, vec![]);
                    fake.send(stream, Body::Result(Reply::AgentRead(ev))).await;
                }
                Command::AgentStop(stop) => {
                    assert!(stop.kill && stop.session == session, "{stop:?}");
                    let ev = events(session, AgentState::Ended, vec![]);
                    fake.send(stream, Body::Result(Reply::AgentStop(ev))).await;
                    return;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("the Core never killed the session");
}

async fn killed(why: &str, w: &S) {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.killed'")
            .fetch_all(&w.core.app.pool)
            .await
            .unwrap();
    assert!(rows.len() == 1 && rows[0].contains(why), "{rows:?}");
}

#[tokio::test]
async fn disabling_the_account_kills_the_live_sessions_holding_its_token() {
    let (mut w, row) = running("sub-kill-off").await;
    let (app, id, by) = (w.core.app.clone(), w.account.id, w.runner.clone());
    let off = tokio::spawn(async move {
        service::subscription::set_state(
            &app,
            id,
            "disabled",
            Some("x"),
            None,
            &by,
            AuditActor::System,
        )
        .await
    });
    expect_kill(&mut w.fake, &row.id).await;
    off.await.unwrap().unwrap();
    killed("the subscription account is disabled", &w).await;
}

#[tokio::test]
async fn deleting_the_account_kills_the_live_sessions_holding_its_token() {
    let (mut w, row) = running("sub-kill-del").await;
    let (app, id, by) = (w.core.app.clone(), w.account.id, w.runner.clone());
    let del = tokio::spawn(async move {
        service::subscription::delete(&app, id, &by, AuditActor::System).await
    });
    expect_kill(&mut w.fake, &row.id).await;
    del.await.unwrap().unwrap();
    killed("the subscription account was deleted", &w).await;
}

#[tokio::test]
async fn an_account_disabled_after_the_live_check_and_before_the_lease_leaves_no_lease() {
    let w = up("sub-race").await;
    let row = make(&w, "claude", &sub(&w.account), None).await;
    // The account goes away between the launch's live read and the write of the lease.
    let off = service::subscription::set_state(
        &w.core.app,
        w.account.id,
        "disabled",
        Some("race"),
        None,
        &w.runner,
        AuditActor::System,
    );
    off.await.unwrap();
    let minted =
        service::subscription::mint_for_tests(&w.core.app, &row, &sub(&w.account)[0]).await;
    let why = match minted {
        Err(e) => service::describe(&e),
        Ok(_) => panic!("a lease was handed out for a disabled account"),
    };
    assert!(why.contains("disabled or deleted while"), "{why}");
    let live = "SELECT count(*) FROM core_secret_leases";
    assert_eq!(
        count(&w.core, live).await,
        0,
        "the lease it wrote was revoked"
    );
}
