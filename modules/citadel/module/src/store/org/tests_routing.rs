//! The escalation chain (E6.3), the fallback chain (E15.3), tiers and routing rules (E15.5):
//! the store-level parts of the monolith's `store/exec/tests/{chain,fallbacks,tiers}.rs`.
//!
//! Those tests drive the run engine (dispatch, runs, token caps, accounts, the per-task cost
//! report); what is here is their assertions that need only the org tables: who
//! `escalation_target_in` names at each rung (the monolith asserted it by failing runs), and
//! what `set_fallbacks`, `set_tiers` and `set_tier_rules` accept and keep. Not ported (S7/S5/S9):
//! dispatch picking the tier/model/account, `fallback_routes`, `switch_route`,
//! `resume_session`, `task_costs`.

use super::tests_util::*;
use super::*;
use crate::domain::org::{AgentStatus, Harness, ModelRoute, OrgRole, TeamRole, Tier};
use crate::domain::work::{
    IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectMode, SprintApproval,
    UserId,
};
use crate::store::work::{create_issue, create_project};
use sqlx::SqlitePool;

struct Org {
    ceo: AgentId,
    cto: AgentId,
    po: AgentId,
    lead: AgentId,
    dev: AgentId,
    company: CompanyId,
    project: crate::domain::work::ProjectId,
    team: TeamId,
}

async fn org(pool: &SqlitePool) -> Org {
    let c = create_company(pool, "A").await.unwrap().id;
    let mut ids = vec![];
    for (name, org_role) in [
        ("Ceo", OrgRole::Ceo),
        ("Cto", OrgRole::Cto),
        ("Po", OrgRole::None),
        ("Lead", OrgRole::None),
        ("Dev", OrgRole::None),
    ] {
        let a = NewAgent {
            runner_tags: vec![],
            status: AgentStatus::Active,
            role: name.to_owned(),
            ..new_agent(c, name, org_role)
        };
        ids.push(create_agent(pool, &a).await.unwrap().id);
    }
    let d = add_department(pool, c, "Engineering", BY).await.unwrap();
    let t = add_team(pool, d.id, "Core", BY).await.unwrap();
    for (agent, role) in [
        (ids[2], TeamRole::ProductOwner),
        (ids[3], TeamRole::TeamLead),
        (ids[4], TeamRole::Member),
    ] {
        seat_member(pool, t.id, agent, role, None, BY)
            .await
            .unwrap();
    }
    // Reporting lines up to the CEO are the org chart's; escalation does not follow them.
    for (agent, manager) in [(ids[4], ids[3]), (ids[3], ids[1]), (ids[2], ids[0])] {
        set_manager(pool, agent, Some(manager), BY).await.unwrap();
    }
    let p = NewProject {
        company_id: c,
        team_id: Some(t.id),
        name: "P".to_owned(),
        key: "PRJ".to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    let project = create_project(pool, &p).await.unwrap().id;
    Org {
        ceo: ids[0],
        cto: ids[1],
        po: ids[2],
        lead: ids[3],
        dev: ids[4],
        company: c,
        project,
        team: t.id,
    }
}

async fn issue(pool: &SqlitePool, o: &Org) -> IssueId {
    let new = NewIssue {
        project_id: o.project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &new).await.unwrap().id
}

async fn target(pool: &SqlitePool, i: IssueId, from: AgentId) -> NextActor {
    let mut conn = pool.acquire().await.unwrap();
    escalation_target_in(&mut conn, i, from).await.unwrap()
}

async fn pause(pool: &SqlitePool, a: AgentId) {
    sqlx::query("UPDATE citadel_agents SET status = 'paused' WHERE id = ?")
        .bind(a.0)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn escalation_climbs_the_team_to_the_admin_without_the_ceo() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let i = issue(pool, &o).await;
    let agent = NextActor::Agent;
    assert_eq!(target(pool, i, o.dev).await, agent(o.lead), "dev -> lead");
    assert_eq!(target(pool, i, o.lead).await, agent(o.po), "lead -> PO");
    assert_eq!(
        target(pool, i, o.po).await,
        NextActor::Human(ESCALATION_USER),
        "PO -> Ahmed"
    );
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(product_owner_in(&mut conn, i).await.unwrap(), Some(o.po));
    drop(conn);

    // A seat whose agent cannot run is skipped: with the lead paused, dev goes to the PO.
    pause(pool, o.lead).await;
    assert_eq!(target(pool, i, o.dev).await, agent(o.po));
}

#[tokio::test]
async fn a_cross_department_issue_reaches_the_ceo_then_the_cto() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let i = issue(pool, &o).await;
    assert_eq!(is_cross_department(pool, i).await.unwrap(), Some(false));
    assert!(set_cross_department(pool, i, true, BY).await.unwrap());
    assert_eq!(is_cross_department(pool, i).await.unwrap(), Some(true));
    assert!(
        !set_cross_department(pool, IssueId(999), true, BY)
            .await
            .unwrap()
    );
    assert_eq!(target(pool, i, o.po).await, NextActor::Agent(o.ceo));
    assert_eq!(
        target(pool, i, o.ceo).await,
        NextActor::Human(ESCALATION_USER),
        "past the CEO, Ahmed"
    );

    pause(pool, o.ceo).await;
    assert_eq!(target(pool, i, o.po).await, NextActor::Agent(o.cto));
    assert!(
        actions(pool)
            .await
            .iter()
            .any(|a| a == "citadel.issue.cross_department_set")
    );
}

/// An issue of a project with no team (an intake request) goes straight to the admin.
#[tokio::test]
async fn without_a_team_escalation_goes_to_the_admin() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    sqlx::query("UPDATE citadel_projects SET team_id = NULL")
        .execute(pool)
        .await
        .unwrap();
    let i = issue(pool, &o).await;
    assert_eq!(
        target(pool, i, o.dev).await,
        NextActor::Human(ESCALATION_USER)
    );
    let _ = (o.company, o.team);
}

fn route(harness: Harness, model: &str) -> ModelRoute {
    ModelRoute {
        harness,
        model: model.to_owned(),
    }
}

#[tokio::test]
async fn fallbacks_are_set_as_a_whole_and_checked() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let dev = o.dev;
    let chain = [
        route(Harness::Claude, "claude-sonnet"),
        route(Harness::Codex, "gpt-x"),
    ];
    assert!(set_fallbacks(pool, dev, &chain, BY).await.unwrap());
    assert_eq!(list_fallbacks(pool, dev).await.unwrap(), chain);
    for bad in [
        vec![route(Harness::Claude, "claude-opus")],
        vec![route(Harness::Codex, "x"), route(Harness::Codex, "x")],
        vec![route(Harness::Codex, " ")],
    ] {
        let e = set_fallbacks(pool, dev, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }
    assert_eq!(list_fallbacks(pool, dev).await.unwrap(), chain, "kept");
    let mut conn = pool.acquire().await.unwrap();
    let effective = fallbacks_in(&mut conn, dev).await.unwrap();
    assert_eq!(effective, chain, "no preset: its own");
    drop(conn);
    assert!(set_fallbacks(pool, dev, &[], BY).await.unwrap());
    assert!(list_fallbacks(pool, dev).await.unwrap().is_empty());
    assert!(!set_fallbacks(pool, AgentId(999), &chain, BY).await.unwrap());
}

#[tokio::test]
async fn tiers_are_set_as_a_whole_and_checked() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let dev = o.dev;
    let small = (Tier::Small, route(Harness::Claude, "claude-haiku"));
    assert!(
        set_tiers(pool, dev, std::slice::from_ref(&small), BY)
            .await
            .unwrap()
    );
    assert_eq!(list_tiers(pool, dev).await.unwrap(), vec![small.clone()]);
    for bad in [
        vec![(Tier::Standard, route(Harness::Claude, "x"))],
        vec![(Tier::Small, route(Harness::Claude, " "))],
        vec![
            (Tier::Small, route(Harness::Claude, "a")),
            (Tier::Small, route(Harness::Codex, "b")),
        ],
    ] {
        let e = set_tiers(pool, dev, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        tier_route_in(&mut conn, dev, Tier::Small).await.unwrap(),
        Some(small.1)
    );
    assert_eq!(
        tier_route_in(&mut conn, dev, Tier::Large).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn routing_rules_are_set_as_a_whole_and_default_when_empty() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let project = o.project;
    let (rules, defaults) = list_tier_rules(pool, project).await.unwrap();
    assert!(defaults);
    assert_eq!(rules.len(), DEFAULT_RULES.len());
    for bad in [
        vec![("chore".to_owned(), Tier::Small)],
        vec![("kind:epic".to_owned(), Tier::Small)],
        vec![
            ("label:a".to_owned(), Tier::Small),
            ("label:a".to_owned(), Tier::Large),
        ],
    ] {
        let e = set_tier_rules(pool, project, &bad, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{bad:?}");
    }
    let rules = vec![("kind:bug".to_owned(), Tier::Large)];
    assert!(set_tier_rules(pool, project, &rules, BY).await.unwrap());
    assert_eq!(
        list_tier_rules(pool, project).await.unwrap(),
        (rules, false)
    );
    let n = actions(pool)
        .await
        .iter()
        .filter(|a| *a == "citadel.project.tier_rules_set")
        .count();
    assert_eq!(n, 1);
    assert!(set_tier_rules(pool, project, &[], BY).await.unwrap());
    assert!(list_tier_rules(pool, project).await.unwrap().1);
    let gone = crate::domain::work::ProjectId(999);
    assert!(!set_tier_rules(pool, gone, &[], BY).await.unwrap());
}
