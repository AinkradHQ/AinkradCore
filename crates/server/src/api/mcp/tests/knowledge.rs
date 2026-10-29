//! Knowledge in a run's context (E8.1): only accepted entries, most relevant first, within the
//! budget, with what was left out reported. And their review by the team lead (E8.2).

use ainkrad_core::audit::AuditFilter;
use ainkrad_core::gov::{
    KNOWLEDGE_BUDGET_BYTES, KnowledgeKind, KnowledgeStatus, NewKnowledgeEntry,
};
use ainkrad_core::work::UserId;
use serde_json::json;

use super::plan::{ok, planning_team, refused};
use super::*;
use crate::store::gov::{Proposal, add_knowledge, create_knowledge_entry, propose};
use crate::store::work::get_issue;

#[tokio::test]
async fn context_gives_only_accepted_knowledge_within_the_budget_and_lists_the_rest() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let project = get_issue(pool, a.issue).await.unwrap().unwrap().project_id;
    let admin = UserId(1);
    // Two 6 KiB decisions, a 6 KiB retro note, then a small landmine: 16 KiB holds the
    // landmine and both decisions; the retro is left out.
    let big = "x".repeat(6 * 1024);
    let mut ids = vec![];
    for (kind, title, body) in [
        (KnowledgeKind::Decision, "Old decision", big.as_str()),
        (KnowledgeKind::Retro, "Retro", big.as_str()),
        (KnowledgeKind::Decision, "New decision", big.as_str()),
        (KnowledgeKind::Landmine, "Never force-push", "It eats work."),
    ] {
        let k = add_knowledge(pool, project, kind, title, body, admin)
            .await
            .unwrap();
        assert_eq!(k.status, KnowledgeStatus::Accepted);
        ids.push(k.id.0);
    }
    for status in [KnowledgeStatus::Proposed, KnowledgeStatus::Rejected] {
        let k = NewKnowledgeEntry {
            project_id: project,
            kind: KnowledgeKind::Landmine,
            title: format!("{} landmine", status.as_str()),
            body: "not for runs".to_owned(),
            status,
            proposed_by: Some(a.agent),
            decided_by: (status != KnowledgeStatus::Proposed).then_some(admin),
        };
        create_knowledge_entry(pool, &k).await.unwrap();
    }

    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    let titles: Vec<&str> = ctx["knowledge"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["Never force-push", "New decision", "Old decision"],
        "landmines first, newest first, only accepted"
    );
    let used: usize = ctx["knowledge"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["title"].as_str().unwrap().len() + k["body"].as_str().unwrap().len())
        .sum();
    assert!(used <= KNOWLEDGE_BUDGET_BYTES, "{used}");
    assert_eq!(
        ctx["dropped_knowledge"],
        json!([{"id": ids[1], "kind": "retro", "title": "Retro"}]),
        "the overflow is reported, never dropped silently"
    );

    let filter = AuditFilter {
        company_id: Some(a.company),
        ..AuditFilter::default()
    };
    let added = audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.action == "knowledge.added")
        .count();
    assert_eq!(added, 4, "every entry the admin adds is audited");
}

/// The team lead sees the pending proposals in its context and decides them over MCP; nobody
/// else does, and not its own. A spec proposal, accepted, becomes the spec.
#[tokio::test]
async fn the_lead_reviews_proposals_over_mcp() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let (project, _, dev) = planning_team(pool, &a).await;
    // `a`'s agent leads the team instead of owning its product.
    sqlx::query("UPDATE team_memberships SET team_role = 'team_lead' WHERE agent_id = ?")
        .bind(a.agent.0)
        .execute(pool)
        .await
        .unwrap();
    let proposal = |kind, title: &str, spec| Proposal {
        project,
        kind,
        title: title.to_owned(),
        body: "Body.".to_owned(),
        spec,
        profile_field: None,
        rationale: None,
    };
    let k = propose(
        pool,
        &proposal(KnowledgeKind::Landmine, "Ports", false),
        dev,
    )
    .await
    .unwrap();
    let spec = propose(pool, &proposal(KnowledgeKind::State, "New spec", true), dev)
        .await
        .unwrap();

    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    let pending: Vec<i64> = ctx["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_i64().unwrap())
        .collect();
    assert_eq!(pending, [k.id.0, spec.id.0]);
    assert_eq!(ctx["proposals"][1]["spec"], true);
    let by_b = ok(&fx, &b, "get_context", json!({})).await;
    assert_eq!(by_b["proposals"], json!([]), "not a lead: no proposals");

    let why = refused(
        &fx,
        &b,
        "review_knowledge",
        json!({"entry_id": k.id.0, "verdict": "accept"}),
    )
    .await;
    assert!(
        why.contains("no entry"),
        "another company's entry looks like none: {why}"
    );
    let why = refused(
        &fx,
        &a,
        "review_knowledge",
        json!({"entry_id": k.id.0, "verdict": "reject"}),
    )
    .await;
    assert!(why.contains("reason"), "{why}");
    let done = ok(
        &fx,
        &a,
        "review_knowledge",
        json!({"entry_id": k.id.0, "verdict": "accept", "reason": "Bit us twice"}),
    )
    .await;
    assert_eq!(done["status"], "accepted");
    let done = ok(
        &fx,
        &a,
        "review_knowledge",
        json!({"entry_id": spec.id.0, "verdict": "accept"}),
    )
    .await;
    assert_eq!(done["spec_applied"], true);
    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    assert_eq!(ctx["project"]["spec"], "Body.");
    assert_eq!(ctx["knowledge"][0]["title"], "Ports");
    assert_eq!(ctx["proposals"], json!([]));

    let mine = ok(
        &fx,
        &a,
        "propose_knowledge",
        json!({"kind": "decision", "title": "Mine", "body": "x"}),
    )
    .await;
    let why = refused(
        &fx,
        &a,
        "review_knowledge",
        json!({"entry_id": mine["knowledge_entry_id"], "verdict": "accept"}),
    )
    .await;
    assert!(why.contains("own proposal"), "{why}");
    let why = refused(
        &fx,
        &a,
        "propose_knowledge",
        json!({"kind": "landmine", "title": "T", "body": "x", "target": "spec"}),
    )
    .await;
    assert!(why.contains("state"), "{why}");
}
