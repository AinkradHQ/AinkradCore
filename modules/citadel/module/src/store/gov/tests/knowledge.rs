//! Knowledge review (E8.2): the team lead or a human decides proposals, never the proposer
//! itself; a rejection needs a reason; an accepted spec proposal becomes the spec; accepted
//! entries reach runs; every step is audited.
//!
//! Adapted: the Core's audit actor is a user or the system, so an agent's step is the system with
//! `agent_id` in the details; the review's actor is `Decider`; the audit is read with SQL.

use super::*;
use crate::domain::gov::KnowledgeEntryId;
use crate::domain::org::{TeamMembership, TeamRole};
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

    let by_dev = decide_knowledge(pool, k.id, true, Decider::Agent(dev), None).await;
    assert!(matches!(by_dev, Err(KnowledgeError::NotLead)), "{by_dev:?}");
    let no_reason = decide_knowledge(pool, k.id, false, Decider::Agent(lead), Some(" ")).await;
    assert!(
        matches!(no_reason, Err(KnowledgeError::Invalid(_))),
        "{no_reason:?}"
    );

    let accepted = decide_knowledge(pool, k.id, true, Decider::Agent(lead), Some("Seen it"))
        .await
        .unwrap();
    assert_eq!(accepted.status, KnowledgeStatus::Accepted);
    assert_eq!(accepted.decided_by_agent, Some(lead));
    assert_eq!(accepted.decided_by, None);
    assert_eq!(accepted.reason.as_deref(), Some("Seen it"));
    let given = project_knowledge(pool, p.id).await.unwrap();
    assert_eq!(given.entries, vec![accepted]);
    let again = decide_knowledge(pool, k.id, false, Decider::User(ADMIN), Some("x")).await;
    assert!(
        matches!(again, Err(KnowledgeError::NotPending(_))),
        "{again:?}"
    );

    // The lead's own proposal goes to someone else; a human rejects it with a reason.
    let own = propose(pool, &landmine(&p, "Mine"), lead).await.unwrap();
    let self_review = decide_knowledge(pool, own.id, true, Decider::Agent(lead), None).await;
    assert!(
        matches!(self_review, Err(KnowledgeError::OwnProposal)),
        "{self_review:?}"
    );
    let rejected = decide_knowledge(pool, own.id, false, Decider::User(ADMIN), Some("Dup"))
        .await
        .unwrap();
    assert_eq!(
        (rejected.status, rejected.decided_by),
        (KnowledgeStatus::Rejected, Some(ADMIN))
    );
    let missing = decide_knowledge(pool, KnowledgeEntryId(99), true, Decider::User(ADMIN), None);
    assert!(matches!(missing.await, Err(KnowledgeError::NotFound)));

    // Another company's lead is not this project's lead.
    let (c2, other_lead, p2) = fixture(pool, "B").await;
    led(pool, c2, &p2, other_lead).await;
    let k2 = propose(pool, &landmine(&p, "Third"), dev).await.unwrap();
    let foreign = decide_knowledge(pool, k2.id, true, Decider::Agent(other_lead), None).await;
    assert!(
        matches!(foreign, Err(KnowledgeError::NotLead)),
        "{foreign:?}"
    );

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'citadel.knowledge.%' \
         AND json_extract(details, '$.company_id') = ? ORDER BY seq",
    )
    .bind(c.0)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "citadel.knowledge.proposed",
            "citadel.knowledge.accepted",
            "citadel.knowledge.proposed",
            "citadel.knowledge.rejected",
            "citadel.knowledge.proposed",
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
    set_project_spec(pool, p.id, "Old spec.", BY).await.unwrap();

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
    decide_knowledge(pool, k.id, true, Decider::Agent(lead), None)
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
    let spec_set: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.project.spec_set' \
         AND json_extract(details, '$.company_id') = ? \
         AND json_extract(details, '$.agent_id') = ?",
    )
    .bind(c.0)
    .bind(lead.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(spec_set, 1);
}

/// The monolith rebuilt `knowledge_entries` in a migration (E8.2) and tested that down and up
/// again keeps every entry and retro link; the module has one squashed baseline.
#[tokio::test]
#[ignore = "squashed baseline: there is no E8.2 migration to undo"]
async fn the_review_migration_keeps_entries_and_retro_links() {
    todo!("monolith store/gov/tests/knowledge.rs: MIGRATOR.undo/run")
}
