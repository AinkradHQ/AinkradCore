//! The settings store (E15.17): most specific wins, bounds and scopes are refused with the
//! reason, every change is audited and read back as history, a reset inherits again, and the
//! migration carries the old approval deadlines over and back.

use std::sync::atomic::{AtomicUsize, Ordering};

use citadel_core::exec::{NewRunner, RunnerId};
use citadel_core::org::Harness;
use citadel_core::work::{NewProject, ProjectMode, SprintApproval, UserId};

use super::*;
use crate::store::exec::register_runner;
use crate::store::gov::{create_account, new_account};
use crate::store::org::create_company;
use crate::store::work::create_project;
use crate::store::{MIGRATOR, connect};

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

struct Db(SqlitePool, std::path::PathBuf);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-settings-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Db(connect(&dir.join("citadel.db")).await.unwrap(), dir)
}

/// A company with two projects.
async fn company(pool: &SqlitePool) -> (CompanyId, ProjectId, ProjectId) {
    let c = create_company(pool, "A").await.unwrap().id;
    let mut ids = vec![];
    for key in ["CIT", "MKT"] {
        let p = NewProject {
            company_id: c,
            team_id: None,
            name: key.to_owned(),
            key: key.to_owned(),
            mode: ProjectMode::Scrum,
            sprint_approval: SprintApproval::Owner,
        };
        ids.push(create_project(pool, &p).await.unwrap().id);
    }
    (c, ids[0], ids[1])
}

async fn set(pool: &SqlitePool, key: Key, at: Scope, value: &str) -> Result<Effective, SetError> {
    super::set(pool, key, at, value, BY, NOW).await
}

#[tokio::test]
async fn project_beats_company_beats_server_and_reset_inherits() {
    let db = db().await;
    let pool = &db.0;
    let (c, cit, mkt) = company(pool).await;
    let key = Key::StuckAfterSecs;
    let (p, co) = (Scope::Project(cit), Scope::Company(c));
    let read = |at| async move {
        let e = effective(pool, key, at).await.unwrap();
        (e.value, e.source)
    };
    assert_eq!(read(p).await, (600, None), "the default");
    set(pool, key, Scope::Server, "900").await.unwrap();
    assert_eq!(read(p).await, (900, Some(Scope::Server)));
    set(pool, key, co, "1200").await.unwrap();
    assert_eq!(read(p).await, (1200, Some(co)));
    let e = set(pool, key, p, "300").await.unwrap();
    assert_eq!((e.value, e.source), (300, Some(p)));
    assert_eq!(
        read(Scope::Project(mkt)).await,
        (1200, Some(co)),
        "the other project"
    );
    assert_eq!(read(co).await, (1200, Some(co)));
    // Reset returns each scope to what it inherits.
    let e = reset(pool, key, p, BY, NOW).await.unwrap();
    assert_eq!((e.value, e.source), (1200, Some(co)));
    reset(pool, key, co, BY, NOW).await.unwrap();
    assert_eq!(read(p).await, (900, Some(Scope::Server)));
    reset(pool, key, Scope::Server, BY, NOW).await.unwrap();
    assert_eq!(read(p).await, (600, None));
    // A reset of nothing is a no-op, not an audit.
    reset(pool, key, p, BY, NOW).await.unwrap();
    assert_eq!(history(pool, key, None).await.unwrap().len(), 6);
    // Listing: every setting allowed at the scope, with its value there.
    let all = list(pool, p).await.unwrap();
    assert!(
        all.iter()
            .all(|e| e.spec.scopes.contains(&ScopeKind::Project))
    );
    assert!(all.iter().any(|e| e.spec.key == key));
    assert!(!all.iter().any(|e| e.spec.key == Key::LeaseTtlSecs));
    assert_eq!(
        list(pool, Scope::Server).await.unwrap().len(),
        REGISTRY.len()
    );
}

#[tokio::test]
async fn runner_and_account_values_beat_the_server_only_for_themselves() {
    let db = db().await;
    let pool = &db.0;
    let new = |name: &str| NewRunner {
        name: name.to_owned(),
        tags: vec![],
    };
    let (mac, _) = register_runner(pool, &new("mac")).await.unwrap();
    let (pc, _) = register_runner(pool, &new("pc")).await.unwrap();
    let account = new_account(pool, Harness::Claude, "a", None, None, None, None);
    let a = create_account(pool, &account.await.unwrap(), BY)
        .await
        .unwrap();
    set(pool, Key::LeaseTtlSecs, Scope::Server, "60")
        .await
        .unwrap();
    set(pool, Key::LeaseTtlSecs, Scope::Runner(mac.id), "30")
        .await
        .unwrap();
    let ttl = |r: RunnerId| async move {
        value(pool, Key::LeaseTtlSecs, Scope::Runner(r))
            .await
            .unwrap()
    };
    assert_eq!((ttl(mac.id).await, ttl(pc.id).await), (30, 60));
    set(pool, Key::DropThreshold, Scope::Account(a.id), "5")
        .await
        .unwrap();
    let at = Scope::Account(a.id);
    assert_eq!(value(pool, Key::DropThreshold, at).await.unwrap(), 5);
}

#[tokio::test]
async fn bad_values_scopes_and_targets_are_refused_and_change_nothing() {
    let db = db().await;
    let pool = &db.0;
    let (c, p, _) = company(pool).await;
    let code = |e: SetError| match e {
        SetError::Refused(e) => e.code().to_owned(),
        SetError::NoScope(s) => format!("no {s}"),
        SetError::Db(e) => panic!("{e}"),
    };
    let cap = Key::RunTokenCap;
    let refused = [
        (cap, Scope::Project(p), "999", "out_of_bounds"),
        (cap, Scope::Project(p), "100000001", "out_of_bounds"),
        (cap, Scope::Project(p), "1.5", "not_integer"),
        (cap, Scope::Project(p), "\"5000\"", "not_integer"),
        (cap, Scope::Runner(RunnerId(1)), "5000", "wrong_scope"),
        (Key::LeaseTtlSecs, Scope::Company(c), "30", "wrong_scope"),
        (
            Key::SchedulerTickSecs,
            Scope::Company(c),
            "5",
            "wrong_scope",
        ),
        (cap, Scope::Project(ProjectId(99)), "5000", "no project:99"),
        (cap, Scope::Company(CompanyId(99)), "5000", "no company:99"),
    ];
    for (key, at, value, why) in refused {
        let e = set(pool, key, at, value).await.unwrap_err();
        assert_eq!(code(e), why, "{} at {at} = {value}", key.name());
    }
    let e = reset(pool, Key::LeaseTtlSecs, Scope::Company(c), BY, NOW).await;
    assert_eq!(code(e.unwrap_err()), "wrong_scope");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM settings")
        .fetch_one(pool)
        .await
        .unwrap();
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'setting.%'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((rows, audits), (0, 0));
    // The bounds themselves are accepted.
    set(pool, cap, Scope::Project(p), "1000").await.unwrap();
    set(pool, cap, Scope::Project(p), "100000000")
        .await
        .unwrap();
}

#[tokio::test]
async fn every_change_is_audited_and_read_back_as_history() {
    let db = db().await;
    let pool = &db.0;
    let (c, p, _) = company(pool).await;
    let key = Key::KnowledgeBudgetBytes;
    set(pool, key, Scope::Project(p), "4096").await.unwrap();
    super::set(
        pool,
        key,
        Scope::Project(p),
        "8192",
        AuditActor::System,
        "2026-10-22T11:00:00.000Z",
    )
    .await
    .unwrap();
    set(pool, key, Scope::Company(c), "2048").await.unwrap();
    reset(pool, key, Scope::Project(p), BY, "2026-10-22T12:00:00.000Z")
        .await
        .unwrap();
    let all = history(pool, key, None).await.unwrap();
    let seen: Vec<_> = all
        .iter()
        .map(|c| (c.scope.to_string(), c.old, c.new, c.actor))
        .collect();
    let project = format!("project:{}", p.0);
    let company = format!("company:{}", c.0);
    assert_eq!(
        seen,
        [
            (project.clone(), Some(8192), None, BY),
            (company, None, Some(2048), BY),
            (project.clone(), Some(4096), Some(8192), AuditActor::System),
            (project.clone(), None, Some(4096), BY),
        ]
    );
    assert_eq!(all[0].at, "2026-10-22T12:00:00.000Z");
    assert_eq!(all[2].at, "2026-10-22T11:00:00.000Z");
    let only = history(pool, key, Some(Scope::Company(c))).await.unwrap();
    assert_eq!(only.len(), 1);
    // The audit rows name the scope as their entity and carry its company.
    let (kind, id, company_id): (String, i64, i64) = sqlx::query_as(
        "SELECT entity_kind, entity_id, company_id FROM audit_events \
         WHERE action = 'setting.reset'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((kind.as_str(), id, company_id), ("project", p.0, c.0));
    let (by_kind, at): (String, String) =
        sqlx::query_as("SELECT updated_by_kind, updated_at FROM settings WHERE key = ?")
            .bind(key.name())
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((by_kind.as_str(), at.as_str()), ("user", NOW));
}

#[tokio::test]
async fn the_migration_carries_approval_deadlines_over_and_back() {
    let db = db().await;
    let pool = &db.0;
    const BEFORE: i64 = 20261024000002;
    MIGRATOR.undo(pool, BEFORE).await.unwrap();
    sqlx::query(
        "UPDATE approval_deadlines SET deadline_secs = CASE kind WHEN 'pr_merge' THEN 3600 \
         WHEN 'permission_escalation' THEN 120 ELSE deadline_secs END",
    )
    .execute(pool)
    .await
    .unwrap();
    MIGRATOR.run(pool).await.unwrap();
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM settings ORDER BY key")
            .fetch_all(pool)
            .await
            .unwrap();
    let expected = [
        ("approval.deadline.permission_escalation", "120"),
        ("approval.deadline.pr_merge", "3600"),
    ];
    let rows: Vec<(&str, &str)> = rows.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(rows, expected, "only what differs from the defaults");
    let pr = Key::DeadlinePrMerge;
    assert_eq!(value(pool, pr, Scope::Server).await.unwrap(), 3600);
    set(pool, Key::DeadlineHireAgent, Scope::Server, "60")
        .await
        .unwrap();
    MIGRATOR.undo(pool, BEFORE).await.unwrap();
    let back: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT kind, deadline_secs FROM approval_deadlines ORDER BY kind")
            .fetch_all(pool)
            .await
            .unwrap();
    let back: Vec<(&str, Option<i64>)> = back.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    assert_eq!(
        back,
        [
            ("budget_overrun", None),
            ("hire_agent", Some(60)),
            ("permission_escalation", Some(120)),
            ("pr_merge", Some(3600)),
            ("sprint_commit", None),
        ]
    );
    MIGRATOR.run(pool).await.unwrap();
}
