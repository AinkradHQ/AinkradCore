//! E15.13's acceptance: a run's instructions contain its project's profile, within the
//! `profile.budget_bytes` setting with what does not fit named; an agent's proposed change to
//! the profile applies only when a human accepts it, never on the team lead's say.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::KnowledgeEntryId;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::ProjectMode;
use ainkrad_core_server::profile::ProfilePatch;
use ainkrad_core_server::store::{gov, settings, work};
use serde_json::json;

use super::stage::{ADMIN, Stage};

const DEPLOY_RULE: &str = "cargo deny check passes";

#[tokio::test]
async fn a_run_is_told_the_profile_and_a_proposal_applies_only_when_accepted() {
    let mut stage = Stage::new("profile").await;
    let o = stage.org().await;
    let project = stage.project(&o, "PF", ProjectMode::Kanban).await;
    let pool = stage.pool.clone();
    let admin = AuditActor::User(ADMIN);
    let patch: ProfilePatch = serde_json::from_value(json!({
        "stack": "Rust 1.93, axum, SQLite",
        "definition_of_done": ["make test passes", "every PR merged"],
        "protected_branches": ["main", "development"],
        "environments": [{"name": "Staging", "url": "https://staging.example", "deploy": "ask"}],
        "docs": ["Docs/Specs/api.md"],
    }))
    .unwrap();
    work::update_profile(&pool, project, &patch, admin)
        .await
        .unwrap()
        .unwrap();

    // The developer is told the profile, and proposes a new rule for the definition of done.
    let first = stage.issue(project, "First", None).await;
    let rules = json!(["make test passes", "every PR merged", DEPLOY_RULE]).to_string();
    let proposal = json!({"kind": "decision", "title": "Run cargo deny",
                          "target": "profile.definition_of_done", "body": rules});
    stage
        .play(
            first,
            &[
                ("transition", json!({"transition": "start"})),
                ("propose_knowledge", proposal),
                ("transition", json!({"transition": "done"})),
            ],
        )
        .await;
    stage.assign(first, o.dev).await;
    assert_eq!(stage.ended(first, 1).await, "succeeded");
    let told = stage.instructions(first, 1).await;
    assert!(
        told.contains(
            "# Project profile\n\n## definition of done\n\n- make test passes\n- every PR merged\n"
        ),
        "{told}"
    );
    assert!(
        told.contains("- Protected (never push to them): main, development\n"),
        "{told}"
    );
    assert!(told.contains("- Staging (https://staging.example): ask before deploying\n"));
    assert!(!told.contains("Left out for size"), "{told}");
    let replies = stage.replies(first, 1).await;
    assert_eq!(replies[1]["status"], "proposed", "{replies:?}");
    let entry = KnowledgeEntryId(replies[1]["knowledge_entry_id"].as_i64().unwrap());

    // Proposed is not applied, and the team lead cannot decide it.
    let rules_now = || async {
        let p = work::project_profile(&pool, project)
            .await
            .unwrap()
            .unwrap();
        p.profile.definition_of_done
    };
    assert_eq!(rules_now().await.len(), 2);
    let by_lead = gov::decide_knowledge(&pool, entry, true, AuditActor::Agent(o.lead), None).await;
    assert!(by_lead.is_err(), "{by_lead:?}");
    assert_eq!(rules_now().await.len(), 2);

    // The admin accepts it: applied and audited with the entry.
    gov::decide_knowledge(&pool, entry, true, admin, None)
        .await
        .unwrap();
    assert_eq!(
        rules_now().await.last().map(String::as_str),
        Some(DEPLOY_RULE)
    );
    let audit: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'project.profile_set' \
         ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        audit.contains(&format!("\"knowledge_entry\":{}", entry.0)),
        "{audit}"
    );

    // A tight budget for this project: what fits is given, the rest named; the whole profile
    // is in the agent's context.
    let (key, at, now) = (
        Key::ProfileBudgetBytes,
        Scope::Project(project),
        stage.now(),
    );
    settings::set(&pool, key, at, "150", admin, &now)
        .await
        .unwrap();
    let next = stage.issue(project, "Second", None).await;
    stage.play(next, &[("get_context", json!({}))]).await;
    stage.assign(next, o.dev).await;
    assert_eq!(stage.ended(next, 1).await, "succeeded");
    let told = stage.instructions(next, 1).await;
    assert!(told.contains(DEPLOY_RULE), "{told}");
    assert!(
        told.contains("Left out for size (read them with get_context): "),
        "{told}"
    );
    assert!(told.contains("environments"), "{told}");
    assert!(!told.contains("https://staging.example"), "{told}");
    let ctx = &stage.replies(next, 1).await[0];
    assert_eq!(
        ctx["profile"]["environments"][0]["name"], "Staging",
        "{ctx}"
    );
}
