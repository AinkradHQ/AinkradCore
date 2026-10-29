use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::gov::{
    ApprovalKind, ApprovalStatus, BudgetPeriod, KnowledgeKind, KnowledgeStatus, NewApproval,
    NewKnowledgeEntry, NewSkill, SkillAttach,
};
use ainkrad_core::org::{AgentStatus, Harness, NewAgent, OrgRole};
use ainkrad_core::work::{
    NewProject, NewSprint, Project, ProjectMode, SprintApproval, SprintState, UserId,
};

use ainkrad_core::gov::{BudgetScope, NewBudget};
use ainkrad_core::org::{AgentId, CompanyId};
use ainkrad_core::work::{ProjectId, SprintId};
use sqlx::SqlitePool;

use super::*;
use crate::store::connect;
use crate::store::org::{create_agent, create_company, create_department, delete_company};
use crate::store::work::{create_project, create_sprint, delete_sprint};

mod approvals;
mod knowledge;
mod settings;
mod skills;

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
    let dir = std::env::temp_dir().join(format!("citadel-gov-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    Db { pool, dir }
}

const ADMIN: UserId = UserId(1);

fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

/// A company with one agent and one project.
async fn fixture(pool: &SqlitePool, name: &str) -> (CompanyId, AgentId, Project) {
    let c = create_company(pool, name).await.unwrap();
    let a = NewAgent {
        company_id: c.id,
        name: "PO".to_owned(),
        role: "Product Owner".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let a = create_agent(pool, &a).await.unwrap();
    let p = NewProject {
        company_id: c.id,
        team_id: None,
        name: "Citadel".to_owned(),
        key: "CIT".to_owned(),
        mode: ProjectMode::Scrum,
        sprint_approval: SprintApproval::Owner,
    };
    (c.id, a.id, create_project(pool, &p).await.unwrap())
}

async fn sprint(pool: &SqlitePool, project_id: ProjectId) -> SprintId {
    let s = NewSprint {
        project_id,
        name: "Sprint 1".to_owned(),
        goal: String::new(),
        state: SprintState::Planned,
        starts_on: None,
        ends_on: None,
    };
    create_sprint(pool, &s).await.unwrap().id
}

#[tokio::test]
async fn approval_crud_with_reply() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let s = sprint(pool, p.id).await;
    let new = NewApproval {
        company_id: c,
        kind: ApprovalKind::SprintCommit,
        issue_id: None,
        sprint_id: Some(s),
        agent_id: None,
        requested_by: po,
        payload: r#"{"points":21}"#.to_owned(),
    };
    let mut a = create_approval(pool, &new).await.unwrap();
    assert_eq!((a.status, a.decided_by), (ApprovalStatus::Pending, None));
    assert_eq!(get_approval(pool, a.id).await.unwrap(), Some(a.clone()));

    // Decided exactly when there is a decider.
    a.status = ApprovalStatus::Rejected;
    let no_decider = update_approval(pool, &a).await.unwrap_err();
    assert!(is_constraint(&no_decider), "{no_decider}");
    a.decided_by = Some(ADMIN);
    a.reply = Some("Drop CIT-7, then resubmit.".to_owned());
    assert!(update_approval(pool, &a).await.unwrap());
    a.decided_at = get_approval(pool, a.id).await.unwrap().unwrap().decided_at;
    assert!(a.decided_at.is_some(), "a decided approval has a time");
    assert_eq!(list_approvals(pool, c).await.unwrap(), vec![a.clone()]);

    let bad_json = create_approval(
        pool,
        &NewApproval {
            payload: "{".to_owned(),
            ..new.clone()
        },
    )
    .await
    .unwrap_err();
    assert!(is_constraint(&bad_json), "{bad_json}");

    // The approval outlives its subject.
    delete_sprint(pool, s).await.unwrap();
    assert_eq!(
        get_approval(pool, a.id).await.unwrap().unwrap().sprint_id,
        None
    );
    assert!(delete_approval(pool, a.id).await.unwrap());
    assert!(!delete_approval(pool, a.id).await.unwrap());

    // Requester and subjects belong to the approval's company.
    let (_, foreign_agent, foreign_project) = fixture(pool, "B").await;
    let foreign_sprint = sprint(pool, foreign_project.id).await;
    for (bad, message) in [
        (
            NewApproval {
                requested_by: foreign_agent,
                ..new.clone()
            },
            "requester belongs to another company",
        ),
        (
            NewApproval {
                kind: ApprovalKind::HireAgent,
                agent_id: Some(foreign_agent),
                ..new.clone()
            },
            "agent belongs to another company",
        ),
        (
            NewApproval {
                sprint_id: Some(foreign_sprint),
                ..new.clone()
            },
            "sprint belongs to another company",
        ),
    ] {
        let e = create_approval(pool, &bad).await.unwrap_err();
        assert!(is_raised(&e, message), "{e}");
    }
}

#[tokio::test]
async fn budget_crud_and_one_per_scope_and_period() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let new = NewBudget {
        scope: BudgetScope::Agent(po),
        period: BudgetPeriod::Month,
        token_cap: 5_000_000,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let mut b = create_budget(pool, &new).await.unwrap();
    assert_eq!(get_budget(pool, b.id).await.unwrap(), Some(b.clone()));

    let dup = create_budget(
        pool,
        &NewBudget {
            token_cap: 1,
            usd_cap_micros: None,
            ..new.clone()
        },
    )
    .await
    .unwrap_err();
    assert!(is_constraint(&dup), "{dup}");
    // Another period, or the same id under another scope, is a different budget.
    create_budget(
        pool,
        &NewBudget {
            period: BudgetPeriod::Day,
            ..new.clone()
        },
    )
    .await
    .unwrap();
    let s = sprint(pool, p.id).await;
    for scope in [
        BudgetScope::Company(c),
        BudgetScope::Project(p.id),
        BudgetScope::Sprint(s),
        BudgetScope::Department(create_department(pool, c, "Eng").await.unwrap().id),
    ] {
        let made = create_budget(
            pool,
            &NewBudget {
                scope,
                ..new.clone()
            },
        )
        .await
        .unwrap();
        assert_eq!(list_budgets(pool, scope).await.unwrap(), vec![made]);
    }
    assert_eq!(
        list_budgets(pool, BudgetScope::Agent(po))
            .await
            .unwrap()
            .len(),
        2
    );

    b.token_cap = 8_000_000;
    b.warn_at_percent = 90;
    b.hard_stop = false;
    assert!(update_budget(pool, &b).await.unwrap());
    assert_eq!(get_budget(pool, b.id).await.unwrap(), Some(b.clone()));
    b.warn_at_percent = 0;
    let bad_warn = update_budget(pool, &b).await.unwrap_err();
    assert!(is_constraint(&bad_warn), "{bad_warn}");

    // Only the scope's own column may be set.
    let two_targets = sqlx::query(
        "INSERT INTO budgets (scope, company_id, agent_id, period, token_cap) \
         VALUES ('agent', ?, ?, 'week', 1)",
    )
    .bind(c.0)
    .bind(po.0)
    .execute(pool)
    .await
    .unwrap_err();
    assert!(is_constraint(&two_targets), "{two_targets}");

    assert!(delete_budget(pool, b.id).await.unwrap());
    // A budget goes with its scope.
    delete_company(pool, c).await.unwrap();
    assert_eq!(
        list_budgets(pool, BudgetScope::Company(c)).await.unwrap(),
        vec![]
    );
    assert_eq!(
        list_budgets(pool, BudgetScope::Agent(po)).await.unwrap(),
        vec![]
    );
}

#[tokio::test]
async fn skill_crud_versions_and_attachments() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, p) = fixture(pool, "A").await;
    let new = NewSkill {
        company_id: c,
        name: "swift-review".to_owned(),
        version: 1,
        body: "# Review\n".to_owned(),
        attach: SkillAttach::Role("QA".to_owned()),
    };
    let mut s = create_skill(pool, &new).await.unwrap();
    assert_eq!(get_skill(pool, s.id).await.unwrap(), Some(s.clone()));
    let dup = create_skill(pool, &new).await.unwrap_err();
    assert!(is_constraint(&dup), "{dup}");
    let v2 = create_skill(
        pool,
        &NewSkill {
            version: 2,
            attach: SkillAttach::Project(p.id),
            ..new.clone()
        },
    )
    .await
    .unwrap();
    assert_eq!(list_skills(pool, c).await.unwrap(), vec![s.clone(), v2]);

    let d = create_department(pool, c, "Eng").await.unwrap();
    s.attach = SkillAttach::Department(d.id);
    s.body = "# Review v1.1\n".to_owned();
    assert!(update_skill(pool, &s).await.unwrap());
    assert_eq!(get_skill(pool, s.id).await.unwrap(), Some(s.clone()));
    s.attach = SkillAttach::Company;
    assert!(update_skill(pool, &s).await.unwrap());
    assert_eq!(get_skill(pool, s.id).await.unwrap(), Some(s.clone()));

    // Attachments stay within the skill's company.
    let (_, _, foreign) = fixture(pool, "B").await;
    let e = create_skill(
        pool,
        &NewSkill {
            version: 3,
            attach: SkillAttach::Project(foreign.id),
            ..new.clone()
        },
    )
    .await
    .unwrap_err();
    assert!(is_raised(&e, "project belongs to another company"), "{e}");
    s.attach = SkillAttach::Project(foreign.id);
    let e = update_skill(pool, &s).await.unwrap_err();
    assert!(is_raised(&e, "project belongs to another company"), "{e}");

    assert!(delete_skill(pool, s.id).await.unwrap());
    assert!(!delete_skill(pool, s.id).await.unwrap());
}

#[tokio::test]
async fn knowledge_entry_crud_and_review() {
    let db = db().await;
    let pool = &db.pool;
    let (_, po, p) = fixture(pool, "A").await;
    let new = NewKnowledgeEntry {
        project_id: p.id,
        kind: KnowledgeKind::Landmine,
        title: "SQLite busy timeout".to_owned(),
        body: "Keep it at 5s.".to_owned(),
        status: KnowledgeStatus::Proposed,
        proposed_by: Some(po),
        decided_by: None,
    };
    let mut k = create_knowledge_entry(pool, &new).await.unwrap();
    assert_eq!(
        get_knowledge_entry(pool, k.id).await.unwrap(),
        Some(k.clone())
    );

    k.status = KnowledgeStatus::Accepted;
    let no_decider = update_knowledge_entry(pool, &k).await.unwrap_err();
    assert!(is_constraint(&no_decider), "{no_decider}");
    k.decided_by = Some(ADMIN);
    k.body = "Keep it at 5 s; WAL on.".to_owned();
    assert!(update_knowledge_entry(pool, &k).await.unwrap());
    assert_eq!(
        list_knowledge_entries(pool, p.id).await.unwrap(),
        vec![k.clone()]
    );

    // A human-written entry is accepted at once.
    create_knowledge_entry(
        pool,
        &NewKnowledgeEntry {
            kind: KnowledgeKind::Decision,
            status: KnowledgeStatus::Accepted,
            proposed_by: None,
            decided_by: Some(ADMIN),
            ..new.clone()
        },
    )
    .await
    .unwrap();

    let (_, foreign_agent, _) = fixture(pool, "B").await;
    let e = create_knowledge_entry(
        pool,
        &NewKnowledgeEntry {
            proposed_by: Some(foreign_agent),
            ..new
        },
    )
    .await
    .unwrap_err();
    assert!(is_raised(&e, "agent belongs to another company"), "{e}");

    assert!(delete_knowledge_entry(pool, k.id).await.unwrap());
    assert_eq!(get_knowledge_entry(pool, k.id).await.unwrap(), None);
}

#[tokio::test]
async fn device_key_crud_and_only_the_key_hash_is_stored() {
    let db = db().await;
    let pool = &db.pool;
    let key = "ck_device_s3cret";
    let mut d = create_device_key(pool, "MacBook", key).await.unwrap();
    assert_eq!(d.revoked_at, None);
    assert_eq!(get_device_key(pool, d.id).await.unwrap(), Some(d.clone()));
    assert_eq!(
        get_device_key_by_key(pool, key).await.unwrap(),
        Some(d.clone())
    );
    assert_eq!(get_device_key_by_key(pool, "ck_other").await.unwrap(), None);
    assert!(!format!("{d:?}").contains(key));
    let stored: Vec<u8> = sqlx::query_scalar("SELECT key_hash FROM device_keys WHERE id = ?")
        .bind(d.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(stored, crate::store::key_hash(key));
    assert_ne!(stored, key.as_bytes());

    let dup = create_device_key(pool, "iPhone", key).await.unwrap_err();
    assert!(is_constraint(&dup), "{dup}");

    d.last_used_at = Some("2026-10-21T10:00:00Z".to_owned());
    d.revoked_at = Some("2026-10-21T11:00:00Z".to_owned());
    assert!(update_device_key(pool, &d).await.unwrap());
    assert_eq!(
        get_device_key_by_key(pool, key).await.unwrap(),
        Some(d.clone())
    );
    assert_eq!(list_device_keys(pool).await.unwrap(), vec![d.clone()]);
    assert!(delete_device_key(pool, d.id).await.unwrap());
    assert!(!delete_device_key(pool, d.id).await.unwrap());
}
