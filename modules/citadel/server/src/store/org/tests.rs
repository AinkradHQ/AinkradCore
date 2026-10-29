use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use citadel_core::org::{AgentStatus, Harness, OrgRole, TeamRole};

use super::*;
use crate::store::connect;

mod avatars;
mod hire;
mod service;
mod template;

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
    let dir = std::env::temp_dir().join(format!("citadel-org-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    Db { pool, dir }
}

fn new_agent(company_id: CompanyId, name: &str, org_role: OrgRole) -> NewAgent {
    NewAgent {
        company_id,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec!["macos".to_owned()],
        status: AgentStatus::Active,
    }
}

fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

#[tokio::test]
async fn company_crud() {
    let db = db().await;
    let pool = &db.pool;
    let mut c = create_company(pool, "Ainkrad").await.unwrap();
    assert_eq!(get_company(pool, c.id).await.unwrap(), Some(c.clone()));
    c.name = "Ainkrad HQ".to_owned();
    assert!(update_company(pool, &c).await.unwrap());
    assert_eq!(list_companies(pool).await.unwrap(), vec![c.clone()]);
    assert!(delete_company(pool, c.id).await.unwrap());
    assert!(!delete_company(pool, c.id).await.unwrap());
    assert_eq!(get_company(pool, c.id).await.unwrap(), None);
}

#[tokio::test]
async fn department_crud_and_name_unique_per_company() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    let mut eng = create_department(pool, a.id, "Engineering").await.unwrap();
    assert_eq!(
        get_department(pool, eng.id).await.unwrap(),
        Some(eng.clone())
    );

    let dup = create_department(pool, a.id, "Engineering")
        .await
        .unwrap_err();
    assert!(is_constraint(&dup), "{dup}");
    create_department(pool, b.id, "Engineering").await.unwrap();

    eng.name = "R&D".to_owned();
    assert!(update_department(pool, &eng).await.unwrap());
    assert_eq!(
        list_departments(pool, a.id).await.unwrap(),
        vec![eng.clone()]
    );
    assert!(delete_department(pool, eng.id).await.unwrap());
    assert!(list_departments(pool, a.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn team_crud() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let eng = create_department(pool, c.id, "Engineering").await.unwrap();
    let ops = create_department(pool, c.id, "Ops").await.unwrap();
    let mut t = create_team(pool, eng.id, "Core").await.unwrap();
    assert_eq!(get_team(pool, t.id).await.unwrap(), Some(t.clone()));

    t.name = "Platform".to_owned();
    t.department_id = ops.id;
    assert!(update_team(pool, &t).await.unwrap());
    assert!(list_teams(pool, eng.id).await.unwrap().is_empty());
    assert_eq!(list_teams(pool, ops.id).await.unwrap(), vec![t.clone()]);
    assert!(delete_team(pool, t.id).await.unwrap());
    assert_eq!(get_team(pool, t.id).await.unwrap(), None);
}

#[tokio::test]
async fn agent_crud() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let ceo = create_agent(pool, &new_agent(c.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();
    let mut dev = create_agent(
        pool,
        &NewAgent {
            reports_to: Some(ceo.id),
            ..new_agent(c.id, "Dev", OrgRole::None)
        },
    )
    .await
    .unwrap();
    assert_eq!(dev.reports_to, Some(ceo.id));
    assert_eq!(dev.runner_tags, vec!["macos".to_owned()]);
    assert_eq!(get_agent(pool, dev.id).await.unwrap(), Some(dev.clone()));

    dev.role = "QA".to_owned();
    dev.harness = Harness::Codex;
    dev.model = "gpt-5".to_owned();
    dev.runner_tags = vec!["linux".to_owned(), "docker".to_owned()];
    dev.status = AgentStatus::PendingApproval;
    dev.org_role = OrgRole::Cto;
    assert!(update_agent(pool, &dev).await.unwrap());
    assert_eq!(get_agent(pool, dev.id).await.unwrap(), Some(dev.clone()));
    assert_eq!(
        list_agents(pool, c.id).await.unwrap(),
        vec![ceo.clone(), dev.clone()]
    );

    // Deleting a manager leaves the report in place, unattached.
    assert!(delete_agent(pool, ceo.id).await.unwrap());
    assert_eq!(
        get_agent(pool, dev.id).await.unwrap().unwrap().reports_to,
        None
    );
}

#[tokio::test]
async fn one_ceo_and_one_cto_per_company() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    create_agent(pool, &new_agent(a.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();
    create_agent(pool, &new_agent(a.id, "Cto", OrgRole::Cto))
        .await
        .unwrap();
    create_agent(pool, &new_agent(a.id, "Dev1", OrgRole::None))
        .await
        .unwrap();
    create_agent(pool, &new_agent(a.id, "Dev2", OrgRole::None))
        .await
        .unwrap();

    let second_ceo = create_agent(pool, &new_agent(a.id, "Ceo2", OrgRole::Ceo))
        .await
        .unwrap_err();
    assert!(is_constraint(&second_ceo), "{second_ceo}");
    let second_cto = create_agent(pool, &new_agent(a.id, "Cto2", OrgRole::Cto))
        .await
        .unwrap_err();
    assert!(is_constraint(&second_cto), "{second_cto}");
    // Another company gets its own CEO.
    create_agent(pool, &new_agent(b.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();
}

#[tokio::test]
async fn reports_to_unknown_agent_is_rejected() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let err = create_agent(
        pool,
        &NewAgent {
            reports_to: Some(AgentId(999)),
            ..new_agent(c.id, "Dev", OrgRole::None)
        },
    )
    .await
    .unwrap_err();
    assert!(is_constraint(&err), "{err}");
}

#[tokio::test]
async fn membership_crud_and_one_po_and_lead_per_team() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let d = create_department(pool, c.id, "Engineering").await.unwrap();
    let team = create_team(pool, d.id, "Core").await.unwrap();
    let other = create_team(pool, d.id, "Web").await.unwrap();
    let mut ids = Vec::new();
    for name in ["Po", "Lead", "Dev1", "Dev2", "Po2"] {
        ids.push(
            create_agent(pool, &new_agent(c.id, name, OrgRole::None))
                .await
                .unwrap()
                .id,
        );
    }
    let seat = |agent_id, team_role| TeamMembership {
        team_id: team.id,
        agent_id,
        team_role,
    };
    for m in [
        seat(ids[0], TeamRole::ProductOwner),
        seat(ids[1], TeamRole::TeamLead),
        seat(ids[2], TeamRole::Member),
        seat(ids[3], TeamRole::Member),
    ] {
        create_membership(pool, &m).await.unwrap();
    }

    let po2 = create_membership(pool, &seat(ids[4], TeamRole::ProductOwner))
        .await
        .unwrap_err();
    assert!(is_constraint(&po2), "{po2}");
    let lead2 = create_membership(pool, &seat(ids[4], TeamRole::TeamLead))
        .await
        .unwrap_err();
    assert!(is_constraint(&lead2), "{lead2}");
    // Another team gets its own PO.
    create_membership(
        pool,
        &TeamMembership {
            team_id: other.id,
            agent_id: ids[4],
            team_role: TeamRole::ProductOwner,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        get_membership(pool, team.id, ids[2]).await.unwrap(),
        Some(seat(ids[2], TeamRole::Member))
    );
    // Promoting a member to lead is rejected while the seat is taken, accepted once free.
    let promote = update_membership(pool, &seat(ids[2], TeamRole::TeamLead))
        .await
        .unwrap_err();
    assert!(is_constraint(&promote), "{promote}");
    assert!(delete_membership(pool, team.id, ids[1]).await.unwrap());
    assert!(
        update_membership(pool, &seat(ids[2], TeamRole::TeamLead))
            .await
            .unwrap()
    );
    assert_eq!(
        list_memberships(pool, team.id).await.unwrap(),
        vec![
            seat(ids[0], TeamRole::ProductOwner),
            seat(ids[2], TeamRole::TeamLead),
            seat(ids[3], TeamRole::Member),
        ]
    );

    // Deleting an agent drops its seats.
    assert!(delete_agent(pool, ids[3]).await.unwrap());
    assert_eq!(get_membership(pool, team.id, ids[3]).await.unwrap(), None);
}

#[tokio::test]
async fn deleting_a_company_cascades_to_the_whole_org() {
    let db = db().await;
    let pool = &db.pool;
    let keep = create_company(pool, "Keep").await.unwrap();
    let kept_agent = create_agent(pool, &new_agent(keep.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();

    let c = create_company(pool, "Gone").await.unwrap();
    let d = create_department(pool, c.id, "Engineering").await.unwrap();
    let t = create_team(pool, d.id, "Core").await.unwrap();
    let ceo = create_agent(pool, &new_agent(c.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();
    let dev = create_agent(
        pool,
        &NewAgent {
            reports_to: Some(ceo.id),
            ..new_agent(c.id, "Dev", OrgRole::None)
        },
    )
    .await
    .unwrap();
    create_membership(
        pool,
        &TeamMembership {
            team_id: t.id,
            agent_id: dev.id,
            team_role: TeamRole::Member,
        },
    )
    .await
    .unwrap();

    assert!(delete_company(pool, c.id).await.unwrap());
    assert_eq!(get_department(pool, d.id).await.unwrap(), None);
    assert_eq!(get_team(pool, t.id).await.unwrap(), None);
    assert_eq!(get_agent(pool, ceo.id).await.unwrap(), None);
    assert_eq!(get_agent(pool, dev.id).await.unwrap(), None);
    assert!(list_memberships(pool, t.id).await.unwrap().is_empty());
    assert_eq!(list_companies(pool).await.unwrap(), vec![keep]);
    assert_eq!(
        get_agent(pool, kept_agent.id).await.unwrap(),
        Some(kept_agent)
    );
}
