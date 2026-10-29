use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::ids::UserId;

use super::*;
use crate::auth::testing::TestDevice;
use crate::store::connect;
use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};

/// A migrated database in its own temp dir, removed on drop.
struct Db {
    pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-audit-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    allow(&pool).await;
    Db { pool, dir }
}

/// The actions these tests record.
async fn allow(pool: &SqlitePool) {
    let actions = [
        "thing.state_changed",
        "thing.created",
        "thing.commented",
        "server.started",
        "run.started",
    ];
    crate::store::kinds::allow(pool, &[], &actions).await;
}

fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

fn is_chained(e: &Error) -> bool {
    let text = e.to_string();
    text.contains("hash-chained") || text.contains("unknown audit action")
}

fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

fn new_event(action: &str) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::User(UserId(1)),
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "thing".to_owned(),
            id: 7,
        }),
        details: r#"{"from":"todo","to":"in_progress"}"#.to_owned(),
    }
}

async fn count(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn append_and_read_back() {
    let db = db().await;
    let e = append_one(&db.pool, &new_event("thing.state_changed"))
        .await
        .unwrap();
    assert_eq!(e.actor, AuditActor::User(UserId(1)));
    assert_eq!(e.action, "thing.state_changed");
    assert_eq!(
        e.entity.as_ref().map(|x| (x.kind.as_str(), x.id)),
        Some(("thing", 7))
    );
    assert!(!e.at.is_empty());

    let system = NewAuditEvent {
        actor: AuditActor::System,
        entity: None,
        ..new_event("server.started")
    };
    let s = append_one(&db.pool, &system).await.unwrap();
    assert_eq!(s.actor, AuditActor::System);
    assert_eq!(s.entity, None);

    let all = list(&db.pool, &AuditFilter::default(), None, 10)
        .await
        .unwrap();
    assert_eq!(all, vec![e, s]);
}

#[tokio::test]
async fn update_and_delete_are_rejected() {
    let db = db().await;
    let e = append_one(&db.pool, &new_event("thing.created"))
        .await
        .unwrap();

    let err = sqlx::query("UPDATE audit_events SET action = 'thing.deleted' WHERE seq = ?")
        .bind(e.seq.0)
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "audit events are append-only"), "{err}");

    let err = sqlx::query("DELETE FROM audit_events WHERE seq = ?")
        .bind(e.seq.0)
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "audit events are append-only"), "{err}");

    let err = sqlx::query("DELETE FROM audit_events")
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "audit events are append-only"), "{err}");

    let all = list(&db.pool, &AuditFilter::default(), None, 10)
        .await
        .unwrap();
    assert_eq!(all, vec![e]);
}

#[tokio::test]
async fn append_rolls_back_with_its_transaction() {
    let db = db().await;
    let mut tx = crate::store::begin_write(&db.pool).await.unwrap();
    append(&mut tx, &new_event("thing.created")).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(count(&db.pool).await, 0);

    let mut tx = crate::store::begin_write(&db.pool).await.unwrap();
    append(&mut tx, &new_event("thing.created")).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(count(&db.pool).await, 1);
}

#[tokio::test]
async fn seq_strictly_increases() {
    let db = db().await;
    let mut last = 0;
    for _ in 0..20 {
        let e = append_one(&db.pool, &new_event("thing.commented"))
            .await
            .unwrap();
        assert!(e.seq.0 > last);
        last = e.seq.0;
    }
}

#[tokio::test]
async fn event_survives_deleting_its_entity() {
    let db = db().await;
    let clock = std::sync::Arc::new(crate::scheduler::SystemClock);
    let mac = TestDevice::enroll(&db.pool, "Mac", "device", &[], "fp", clock).await;
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM core_devices WHERE id = ?")
        .bind(&mac.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let entity = AuditEntity {
        kind: "device".to_owned(),
        id: seq,
    };
    sqlx::query("DELETE FROM core_devices WHERE seq = ?")
        .bind(seq)
        .execute(&db.pool)
        .await
        .unwrap();

    let filter = AuditFilter {
        entity: Some(entity),
        ..AuditFilter::default()
    };
    let left = list(&db.pool, &filter, None, 10).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].action, "device.enrolled");
}

#[tokio::test]
async fn rejects_invalid_details_action_and_actor() {
    let db = db().await;
    let bad_json = NewAuditEvent {
        details: "{not json".to_owned(),
        ..new_event("thing.created")
    };
    let err = append_one(&db.pool, &bad_json).await.unwrap_err();
    assert!(is_constraint(&err), "{err}");

    // A malformed action can never be registered, so it is refused as unknown.
    for action in ["thing", "Thing.Created", "thing created", ".created", ""] {
        let err = append_one(&db.pool, &new_event(action)).await.unwrap_err();
        assert!(
            err.to_string().contains("unknown audit action"),
            "{action}: {err}"
        );
    }
    // Raw inserts break the CHECKs below, and are refused before them by the chain trigger.

    let err = sqlx::query(
        "INSERT INTO audit_events (actor_kind, actor_id, action) VALUES ('system', 1, 'a.b')",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(is_chained(&err), "{err}");
    let err = sqlx::query(
        "INSERT INTO audit_events (actor_kind, actor_id, action) VALUES ('robot', 1, 'a.b')",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(is_chained(&err), "{err}");
    let err = sqlx::query(
        "INSERT INTO audit_events (actor_kind, action, entity_kind) VALUES ('system', 'a.b', 'thing')",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(is_chained(&err), "{err}");
    assert_eq!(count(&db.pool).await, 0);
}

#[tokio::test]
async fn list_filters_and_pages() {
    let db = db().await;
    let by_system = NewAuditEvent {
        actor: AuditActor::System,
        ..new_event("run.started")
    };
    let a = append_one(&db.pool, &by_system).await.unwrap();
    let b = append_one(&db.pool, &new_event("thing.created"))
        .await
        .unwrap();
    let other = NewAuditEvent {
        entity: Some(AuditEntity {
            kind: "thing".to_owned(),
            id: 8,
        }),
        ..new_event("thing.created")
    };
    let c = append_one(&db.pool, &other).await.unwrap();

    let by = |filter: AuditFilter| {
        let pool = db.pool.clone();
        async move { list(&pool, &filter, None, 10).await.unwrap() }
    };
    assert_eq!(
        by(AuditFilter {
            actor: Some(AuditActor::System),
            ..AuditFilter::default()
        })
        .await,
        vec![a.clone()]
    );
    assert_eq!(
        by(AuditFilter {
            entity: Some(AuditEntity {
                kind: "thing".to_owned(),
                id: 7,
            }),
            ..AuditFilter::default()
        })
        .await,
        vec![a.clone(), b.clone()]
    );

    let page = list(&db.pool, &AuditFilter::default(), None, 2)
        .await
        .unwrap();
    assert_eq!(page, vec![a, b.clone()]);
    let page = list(&db.pool, &AuditFilter::default(), Some(b.seq), 2)
        .await
        .unwrap();
    assert_eq!(page, vec![c]);
}

#[tokio::test]
async fn migrates_up_down_up_with_events() {
    let db = db().await;
    append_one(&db.pool, &new_event("thing.created"))
        .await
        .unwrap();
    // Undo the baseline: dropping the table must not trip the delete trigger.
    undo(&db.pool, CORE, CORE_MIGRATIONS, 0).await.unwrap();
    let present: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'audit_events'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(present, 0);
    migrate_core(&db.pool).await.unwrap();
    assert_eq!(count(&db.pool).await, 0);
    crate::store::kinds::register_platform(&db.pool)
        .await
        .unwrap();
    allow(&db.pool).await;
    append_one(&db.pool, &new_event("thing.created"))
        .await
        .unwrap();
    let err = sqlx::query("DELETE FROM audit_events")
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "audit events are append-only"), "{err}");
}
