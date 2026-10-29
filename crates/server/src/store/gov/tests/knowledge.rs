//! Knowledge review (E8.2): the team lead or a human decides proposals, never the proposer
//! itself; a rejection needs a reason; an accepted spec proposal becomes the spec; accepted
//! entries reach runs; every step is audited. And the migration keeps retro links.

use ainkrad_core::audit::{AuditActor, AuditFilter};
use ainkrad_core::gov::KnowledgeEntryId;
use ainkrad_core::org::{TeamMembership, TeamRole};

use super::*;
use crate::store::MIGRATOR;
use crate::store::audit;
use crate::store::org::{create_membership, create_team};
use crate::store::work::{project_spec, set_project_spec, update_project};

/// The fixture's project, owned by a team with `lead` as its team lead.
async fn led(pool: &SqlitePool, c: CompanyId, p: &Project, lead: AgentId) {
    let dept = create_department(pool, c, "Eng").await.unwrap();
    let team = create_team(pool, dept.id, "Core").await.unwrap();
    let owned = Project {
        team_id: Some(team.id),
        ..p.clone()
    };
    assert!(update_project(pool, &owned).await.unwrap());
    let seat = TeamMembership {
        team_id: team.id,
        agent_id: lead,
        team_role: TeamRole::TeamLead,
    };
    create_membership(pool, &seat).await.unwrap();
}

async fn second_agent(pool: &SqlitePool, c: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id: c,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

fn landmine(p: &Project, title: &str) -> Proposal {
    Proposal {
        project: p.id,
        kind: KnowledgeKind::Landmine,
        title: title.to_owned(),
        body: "Details.".to_owned(),
        spec: false,
        profile_field: None,
        rationale: None,
    }
}

#[tokio::test]
async fn the_lead_or_a_human_decides_and_accepted_entries_reach_runs() {
    let db = db().await;
    let pool = &db.pool;
    let (c, lead, p) = fixture(pool, "A").await;
    led(pool, c, &p, lead).await;
    let dev = second_agent(pool, c, "Dev").await;

    let k = propose(pool, &landmine(&p, "Flaky port"), dev)
        .await
        .unwrap();
    assert_eq!(k.status, KnowledgeStatus::Proposed);
    assert!(
        project_knowledge(pool, p.id)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(
        pending_knowledge(pool, p.id).await.unwrap(),
        vec![k.clone()]
    );

    let by_dev = decide_knowledge(pool, k.id, true, AuditActor::Agent(dev), None).await;
    assert!(matches!(by_dev, Err(KnowledgeError::NotLead)), "{by_dev:?}");
    let no_reason = decide_knowledge(pool, k.id, false, AuditActor::Agent(lead), Some(" ")).await;
    assert!(
        matches!(no_reason, Err(KnowledgeError::Invalid(_))),
        "{no_reason:?}"
    );

    let accepted = decide_knowledge(pool, k.id, true, AuditActor::Agent(lead), Some("Seen it"))
        .await
        .unwrap();
    assert_eq!(accepted.status, KnowledgeStatus::Accepted);
    assert_eq!(accepted.decided_by_agent, Some(lead));
    assert_eq!(accepted.decided_by, None);
    assert_eq!(accepted.reason.as_deref(), Some("Seen it"));
    let given = project_knowledge(pool, p.id).await.unwrap();
    assert_eq!(given.entries, vec![accepted]);
    let again = decide_knowledge(pool, k.id, false, AuditActor::User(ADMIN), Some("x")).await;
    assert!(
        matches!(again, Err(KnowledgeError::NotPending(_))),
        "{again:?}"
    );

    // The lead's own proposal goes to someone else; a human rejects it with a reason.
    let own = propose(pool, &landmine(&p, "Mine"), lead).await.unwrap();
    let self_review = decide_knowledge(pool, own.id, true, AuditActor::Agent(lead), None).await;
    assert!(
        matches!(self_review, Err(KnowledgeError::OwnProposal)),
        "{self_review:?}"
    );
    let rejected = decide_knowledge(pool, own.id, false, AuditActor::User(ADMIN), Some("Dup"))
        .await
        .unwrap();
    assert_eq!(
        (rejected.status, rejected.decided_by),
        (KnowledgeStatus::Rejected, Some(ADMIN))
    );
    let missing = decide_knowledge(
        pool,
        KnowledgeEntryId(99),
        true,
        AuditActor::User(ADMIN),
        None,
    );
    assert!(matches!(missing.await, Err(KnowledgeError::NotFound)));

    // Another company's lead is not this project's lead.
    let (c2, other_lead, p2) = fixture(pool, "B").await;
    led(pool, c2, &p2, other_lead).await;
    let k2 = propose(pool, &landmine(&p, "Third"), dev).await.unwrap();
    let foreign = decide_knowledge(pool, k2.id, true, AuditActor::Agent(other_lead), None).await;
    assert!(
        matches!(foreign, Err(KnowledgeError::NotLead)),
        "{foreign:?}"
    );

    let filter = AuditFilter {
        company_id: Some(c),
        ..AuditFilter::default()
    };
    let actions: Vec<String> = audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .filter(|a| a.starts_with("knowledge."))
        .collect();
    assert_eq!(
        actions,
        [
            "knowledge.proposed",
            "knowledge.accepted",
            "knowledge.proposed",
            "knowledge.rejected",
            "knowledge.proposed",
        ]
    );
}

#[tokio::test]
async fn an_accepted_spec_proposal_replaces_the_spec() {
    let db = db().await;
    let pool = &db.pool;
    let (c, lead, p) = fixture(pool, "A").await;
    led(pool, c, &p, lead).await;
    let dev = second_agent(pool, c, "Dev").await;
    set_project_spec(pool, p.id, "Old spec.", AuditActor::User(ADMIN))
        .await
        .unwrap();

    let not_state = Proposal {
        spec: true,
        profile_field: None,
        rationale: None,
        ..landmine(&p, "Spec?")
    };
    let refused = propose(pool, &not_state, dev).await;
    assert!(
        matches!(refused, Err(KnowledgeError::Invalid(_))),
        "{refused:?}"
    );
    let edit = Proposal {
        project: p.id,
        kind: KnowledgeKind::State,
        title: "Add the export screen".to_owned(),
        body: "New spec: with export.".to_owned(),
        spec: true,
        profile_field: None,
        rationale: None,
    };
    let k = propose(pool, &edit, dev).await.unwrap();
    assert!(k.targets_spec);
    assert_eq!(
        project_spec(pool, p.id).await.unwrap().unwrap(),
        "Old spec."
    );
    decide_knowledge(pool, k.id, true, AuditActor::Agent(lead), None)
        .await
        .unwrap();
    assert_eq!(
        project_spec(pool, p.id).await.unwrap().unwrap(),
        "New spec: with export."
    );
    // It became the spec, so runs do not get it again as knowledge.
    assert!(
        project_knowledge(pool, p.id)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    let filter = AuditFilter {
        company_id: Some(c),
        ..AuditFilter::default()
    };
    let spec_set = audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.action == "project.spec_set" && e.actor == AuditActor::Agent(lead))
        .count();
    assert_eq!(spec_set, 1);
}

/// The rebuild of `knowledge_entries` (E8.2) keeps every entry and every retro link, down and
/// up again.
#[tokio::test]
async fn the_review_migration_keeps_entries_and_retro_links() {
    let db = db().await;
    let pool = &db.pool;
    let (_, po, p) = fixture(pool, "A").await;
    let s = sprint(pool, p.id).await;
    let k = propose(pool, &landmine(&p, "Kept"), po).await.unwrap();
    sqlx::query("INSERT INTO sprint_retro_items (entry_id, sprint_id) VALUES (?, ?)")
        .bind(k.id.0)
        .bind(s.0)
        .execute(pool)
        .await
        .unwrap();
    let links = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sprint_retro_items")
            .fetch_one(pool)
            .await
            .unwrap()
    };
    MIGRATOR.undo(pool, 20261022000011).await.unwrap();
    assert_eq!(links().await, 1);
    MIGRATOR.run(pool).await.unwrap();
    assert_eq!(links().await, 1);
    assert_eq!(get_knowledge_entry(pool, k.id).await.unwrap(), Some(k));
}
