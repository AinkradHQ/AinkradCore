use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::store::connect;

const T0: i64 = 1_800_000_000;

async fn pool() -> (SqlitePool, PathBuf) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "core-health-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (connect(&dir.join("core.db")).await.unwrap(), dir)
}

/// Readings where nothing is wrong.
fn fine() -> Readings {
    Readings {
        backup_at: Some(T0 - 3_600),
        db_created: Some(T0 - 86_400 * 100),
        cert_not_after: Some(T0 + 60 * 86_400),
        disk_free_bytes: Some(50),
        disk_total_bytes: Some(100),
    }
}

async fn rows(pool: &SqlitePool) -> Vec<(String, serde_json::Value)> {
    let mut rows = audit::page(pool, None, Some("alarm."), None, None, 50)
        .await
        .unwrap();
    rows.reverse();
    rows.into_iter()
        .map(|e| (e.action, serde_json::from_str(&e.details).unwrap()))
        .collect()
}

async fn kinds(pool: &SqlitePool) -> Vec<String> {
    let all = events::list_events(pool, 0, 1000).await.unwrap();
    all.into_iter()
        .filter(|e| e.kind.starts_with("alarm."))
        .map(|e| e.kind)
        .collect()
}

/// Drives `alarm` through breach -> raised -> still breached (nothing new) -> ok -> cleared with a
/// fake clock: the debounce, the single row per transition, the event beside it.
async fn drill(alarm: Alarm, bad: impl Fn(&mut Readings)) {
    let (pool, dir) = pool().await;
    let h = Health::new(&dir.join("core.db"));
    let mut breached = fine();
    bad(&mut breached);
    let name = alarm.name();

    // Not yet: the first sighting only starts the clock.
    assert!(h.tick_with(&pool, T0, &breached).await.unwrap().is_empty());
    assert!(!h.active(alarm));
    // A reading that recovers inside the debounce writes nothing at all (no flapping).
    assert!(
        h.tick_with(&pool, T0 + 60, &fine())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        h.tick_with(&pool, T0 + 70, &breached)
            .await
            .unwrap()
            .is_empty()
    );
    let t = h
        .tick_with(&pool, T0 + 70 + DEBOUNCE_SECS - 1, &breached)
        .await
        .unwrap();
    assert!(t.is_empty(), "one second short of the debounce");
    assert!(rows(&pool).await.is_empty());

    let t = h
        .tick_with(&pool, T0 + 70 + DEBOUNCE_SECS, &breached)
        .await
        .unwrap();
    assert_eq!(t.len(), 1);
    assert!(t[0].raised && t[0].alarm == alarm);
    assert!(h.active(alarm));
    // Standing: ticks and a whole new process add nothing.
    for i in 1..5 {
        let at = T0 + 400 + i * 60;
        assert!(h.tick_with(&pool, at, &breached).await.unwrap().is_empty());
    }
    let again = Health::new(&dir.join("core.db"));
    assert!(
        again
            .tick_with(&pool, T0 + 900, &breached)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(again.active(alarm), "restored from the audit log");
    let r = rows(&pool).await;
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].0, "alarm.raised");
    assert_eq!(r[0].1["alarm"], name);
    assert_eq!(kinds(&pool).await, ["alarm.raised"]);

    // It clears after the same debounce, once.
    assert!(
        again
            .tick_with(&pool, T0 + 4_000, &fine())
            .await
            .unwrap()
            .is_empty()
    );
    let t = again
        .tick_with(&pool, T0 + 4_000 + DEBOUNCE_SECS, &fine())
        .await
        .unwrap();
    assert!(t.len() == 1 && !t[0].raised);
    assert!(!again.active(alarm));
    assert!(
        again
            .tick_with(&pool, T0 + 5_000, &fine())
            .await
            .unwrap()
            .is_empty()
    );
    let r = rows(&pool).await;
    let actions: Vec<&str> = r.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(actions, ["alarm.raised", "alarm.cleared"]);
    assert_eq!(kinds(&pool).await, ["alarm.raised", "alarm.cleared"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_stale_backup_raises_and_clears() {
    drill(Alarm::BackupAge, |r| r.backup_at = Some(T0 - 3 * 86_400)).await;
}

#[tokio::test]
async fn a_certificate_near_its_end_raises_and_clears() {
    drill(Alarm::CertExpiry, |r| {
        r.cert_not_after = Some(T0 + 5 * 86_400)
    })
    .await;
}

#[tokio::test]
async fn a_full_disk_raises_and_clears() {
    drill(Alarm::DiskFree, |r| r.disk_free_bytes = Some(5)).await;
}

#[tokio::test]
async fn no_backup_ever_counts_from_the_database_and_unknown_readings_change_nothing() {
    let r = Readings {
        backup_at: None,
        db_created: Some(T0 - 3 * 86_400),
        ..Readings::default()
    };
    let th = Thresholds {
        backup_max_age_secs: 86_400,
        cert_min_days: 14,
        disk_min_free_pct: 10,
    };
    assert_eq!(
        r.check(Alarm::BackupAge, T0, &th),
        Some((true, 3 * 86_400, 86_400))
    );
    assert_eq!(
        r.check(Alarm::CertExpiry, T0, &th),
        None,
        "no certificate: no alarm"
    );
    assert_eq!(r.check(Alarm::DiskFree, T0, &th), None);
    let exact = Readings {
        cert_not_after: Some(T0 + 14 * 86_400),
        ..Readings::default()
    };
    assert_eq!(
        exact.check(Alarm::CertExpiry, T0, &th),
        Some((false, 14, 14))
    );
    let one_less = Readings {
        cert_not_after: Some(T0 + 14 * 86_400 - 1),
        ..Readings::default()
    };
    assert_eq!(
        one_less.check(Alarm::CertExpiry, T0, &th),
        Some((true, 13, 14))
    );

    // An unknown reading does not clear a standing alarm.
    let (pool, dir) = pool().await;
    let h = Health::new(&dir.join("core.db"));
    let bad = Readings {
        disk_free_bytes: Some(1),
        disk_total_bytes: Some(100),
        ..Readings::default()
    };
    h.tick_with(&pool, T0, &bad).await.unwrap();
    h.tick_with(&pool, T0 + DEBOUNCE_SECS, &bad).await.unwrap();
    assert!(h.active(Alarm::DiskFree));
    for i in 0..4 {
        let at = T0 + 1_000 + i * 200;
        h.tick_with(&pool, at, &Readings::default()).await.unwrap();
    }
    assert!(h.active(Alarm::DiskFree));
    assert_eq!(rows(&pool).await.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_thresholds_are_settings_with_bounds_and_the_host_is_read_from_the_home() {
    let (pool, dir) = pool().await;
    let th = Thresholds::load(&pool).await.unwrap();
    assert_eq!(
        (
            th.backup_max_age_secs,
            th.cert_min_days,
            th.disk_min_free_pct
        ),
        (172_800, 14, 10)
    );
    let now = crate::scheduler::iso_of_unix(T0);
    let by = crate::api::v1::BY;
    for (key, bad) in [
        (Key::AlarmDiskMinFreePct, "0"),
        (Key::AlarmDiskMinFreePct, "91"),
        (Key::AlarmCertMinDays, "0"),
        (Key::AlarmBackupMaxAgeSecs, "60"),
    ] {
        let set = settings::set(&pool, key, Scope::Server, bad, by, &now).await;
        assert!(set.is_err(), "{} = {bad}", key.name());
    }
    settings::set(
        &pool,
        Key::AlarmDiskMinFreePct,
        Scope::Server,
        "25",
        by,
        &now,
    )
    .await
    .unwrap();
    assert_eq!(Thresholds::load(&pool).await.unwrap().disk_min_free_pct, 25);

    // Newest `*.age` wins; other files do not count.
    std::fs::create_dir_all(dir.join("backups")).unwrap();
    std::fs::write(dir.join("backups/a.age"), b"x").unwrap();
    std::fs::write(dir.join("backups/.partial.db"), b"x").unwrap();
    let r = Readings::gather(&dir.join("core.db")).await;
    assert!(r.backup_at.is_some() && r.db_created.is_some());
    assert!(r.cert_not_after.is_none());
    assert!(r.disk_total_bytes.is_some_and(|t| t > 0), "df works here");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_alarm_push_names_the_alarm_and_reaches_admins_only() {
    use crate::push::{Classifier, Platform, policy};
    let event = events::StoredEvent {
        seq: 1,
        at: String::new(),
        kind: "alarm.raised".to_owned(),
        payload: sqlx::types::Json(
            json!({"alarm": "disk_free", "value": 4, "threshold": 10, "path": "/secret/place"}),
        ),
    };
    let n = policy::clean(Platform.notification(&event).unwrap());
    assert_eq!((n.kind, n.scope), ("alarm_raised", "admin"));
    assert_eq!(
        n.data,
        json!({"alarm": "disk_free", "value": 4, "threshold": 10})
    );
    assert!(!n.title.contains("/secret"));
}

/// A reading that flaps around its threshold (ten minutes bad, ten good, for six hours) is not
/// 18 raise/clear pairs: the alarm changes at most once per `MIN_GAP_SECS`, and the held change
/// lands as soon as the gap is over.
#[tokio::test]
async fn a_flapping_reading_writes_one_transition_per_gap() {
    let (pool, dir) = pool().await;
    let h = Health::new(&dir.join("core.db"));
    let mut bad = fine();
    bad.disk_free_bytes = Some(5);
    let mut changes = vec![];
    for minute in 0..6 * 60 {
        let at = T0 + minute * 60;
        let readings = if (minute / 10) % 2 == 0 {
            &bad
        } else {
            &fine()
        };
        for t in h.tick_with(&pool, at, readings).await.unwrap() {
            changes.push((at - T0, t.raised));
        }
    }
    assert!(changes.len() <= 6, "{changes:?}");
    assert!(changes[0].1, "{changes:?}");
    for pair in changes.windows(2) {
        assert!(pair[1].0 - pair[0].0 >= MIN_GAP_SECS, "{changes:?}");
        assert_ne!(pair[0].1, pair[1].1, "alternating: {changes:?}");
    }
    assert_eq!(
        rows(&pool).await.len(),
        changes.len(),
        "one row each, no more"
    );
    assert_eq!(kinds(&pool).await.len(), changes.len());
    let _ = std::fs::remove_dir_all(dir);
}
