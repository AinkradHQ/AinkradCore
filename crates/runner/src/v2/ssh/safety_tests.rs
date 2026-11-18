//! Security review of Y2-01: cancel and deadlines, silent commands, the pool's key set, input shapes.

use std::sync::atomic::Ordering::SeqCst;

use super::fixture::*;
use super::pool::pins_hold;
use super::*;

fn after(ms: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_millis(ms)
}

#[tokio::test]
async fn a_cancel_during_the_lease_redemption_connects_to_nothing_and_sends_nothing() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    *leases.delay.lock().unwrap() = Duration::from_millis(600);
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(());
    });
    let e = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "name"), rx)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        (s.seen.conns.load(SeqCst), s.seen.execs.load(SeqCst)),
        (0, 0)
    );
}

#[tokio::test]
async fn a_dropped_cancel_sender_cancels_too() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let (tx, rx) = oneshot::channel::<()>();
    drop(tx);
    let e = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "name"), rx)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.seen.execs.load(SeqCst), 0);
}

#[tokio::test]
async fn a_cancel_after_the_dial_never_sends_the_command() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let d = ssh(&leases);
    let r = req(s.hop("me", "l_1"), vec![], "name");
    // The connection is up and idle; the cancel is already there when the command would go.
    let conn = d.connect(&r.target, &r.hops).await.unwrap();
    for fired in [true, false] {
        let (tx, rx) = oneshot::channel();
        match fired {
            true => tx.send(()).unwrap(),
            false => drop(tx),
        }
        let e = d.run_on(&conn.0, "name", after(10_000), 1000, rx).await;
        assert_eq!(e.unwrap_err().code, ErrorCode::Cancelled);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.seen.execs.load(SeqCst), 0);
}

#[tokio::test]
async fn one_deadline_covers_the_redemption_too() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    *leases.delay.lock().unwrap() = Duration::from_millis(900);
    let mut r = req(s.hop("me", "l_1"), vec![], "name");
    r.limits.timeout_ms = Some(200);
    let started = Instant::now();
    let e = ssh(&leases).run(&r, never()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::SshFailed);
    assert!(e.message.contains("timed out"), "{e:?}");
    assert!(started.elapsed() < Duration::from_millis(700));
    assert_eq!(s.seen.execs.load(SeqCst), 0);
}

#[tokio::test]
async fn a_timed_out_command_gets_a_kill_signal() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let mut r = req(s.hop("me", "l_1"), vec![], "sleep");
    r.limits.timeout_ms = Some(300);
    assert!(ssh(&leases).run(&r, never()).await.unwrap().timed_out);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(s.seen.signals.load(SeqCst), 1);
}

#[tokio::test]
async fn no_inactivity_timeout_and_a_channel_without_an_exit_status_is_a_failure() {
    // russh's own would drop a command that stays silent past it, under the exec ceiling.
    assert!(config(false).inactivity_timeout.is_none());
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let e = ssh(&leases)
        .run(&req(s.hop("me", "l_1"), vec![], "noexit"), never())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SshFailed);
    assert!(e.message.contains("exit status"), "{e:?}");
}

#[tokio::test]
async fn a_pooled_chain_needs_every_hops_key() {
    let leases = Leases::default();
    let (j, t) = (serve("J", true).await, serve("T", true).await);
    leases.key("l_j");
    leases.key("l_t");
    let d = ssh(&leases);
    let r = req(t.hop("me", "l_t"), vec![j.hop("j", "l_j")], "name");
    d.run(&r, never()).await.unwrap();
    d.run(&r, never()).await.unwrap();
    assert_eq!(
        leases.redeemed.load(SeqCst),
        4,
        "a lease was skipped on the pool hit"
    );
    assert_eq!(
        (j.seen.conns.load(SeqCst), t.seen.conns.load(SeqCst)),
        (1, 1)
    );
    // The same lease now holds another key (a rotated jump key): not the connection that
    // the old key opened.
    leases.key("l_j");
    d.run(&r, never()).await.unwrap();
    assert_eq!(
        (j.seen.conns.load(SeqCst), t.seen.conns.load(SeqCst)),
        (2, 2)
    );
    // A lease that cannot be redeemed fails the op even with a live pooled connection.
    leases.keys.lock().unwrap().remove("l_j");
    let e = d.run(&r, never()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::SshAuthFailed);
}

#[tokio::test]
async fn an_idle_connection_is_closed_without_another_call() {
    let (leases, s) = (Leases::default(), serve("T", true).await);
    leases.key("l_1");
    let d = ssh(&leases).with_idle(Duration::from_millis(300));
    d.run(&req(s.hop("me", "l_1"), vec![], "name"), never())
        .await
        .unwrap();
    assert_eq!(d.pool.lock().unwrap().len(), 1);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(d.pool.lock().unwrap().len(), 0, "the sweeper did not run");
}

#[test]
fn hosts_users_and_pins_that_could_read_as_another_field_are_refused() {
    let hop = |host: &str, user: &str| SshHop {
        host: host.to_owned(),
        port: 22,
        user: user.to_owned(),
        pinned_keys: vec![],
        lease: "l_1".to_owned(),
    };
    for ok in [
        ("example.com", "me"),
        ("10.0.0.1", "_svc-1.a"),
        ("fe80::1", "u"),
    ] {
        assert!(check_hop(&hop(ok.0, ok.1)).is_ok(), "{ok:?}");
    }
    for bad in [
        ("a>b", "me"),
        ("h#k", "me"),
        ("a@b", "me"),
        ("-oProxyCommand=x", "me"),
        ("h ost", "me"),
        ("", "me"),
        ("h", "a@b"),
        ("h", "-r"),
        ("h", "a b"),
        ("h", "x:y"),
        ("h", ""),
    ] {
        assert!(check_hop(&hop(bad.0, bad.1)).is_err(), "{bad:?}");
    }
}

#[test]
fn a_pin_recheck_needs_one_key_per_hop() {
    let hop = |pin: &str| SshHop {
        host: "h".to_owned(),
        port: 22,
        user: "u".to_owned(),
        pinned_keys: vec![pin.to_owned()],
        lease: "l".to_owned(),
    };
    let (a, b) = (hop("SHA256:aaa"), hop("SHA256:bbb"));
    let chain = [&a, &b];
    assert!(pins_hold(
        &["SHA256:aaa".into(), "SHA256:bbb".into()],
        &chain
    ));
    assert!(!pins_hold(&["SHA256:aaa".into()], &chain), "zip truncation");
    assert!(!pins_hold(
        &["SHA256:aaa".into(), "SHA256:xxx".into()],
        &chain
    ));
    assert!(!pins_hold(&[], &chain));
}

#[test]
fn a_hop_never_shows_its_lease() {
    let hop = SshHop {
        host: "h".to_owned(),
        port: 22,
        user: "u".to_owned(),
        pinned_keys: vec![],
        lease: "l_SECRETLEASE".to_owned(),
    };
    assert!(!format!("{hop:?}").contains("SECRETLEASE"));
}
