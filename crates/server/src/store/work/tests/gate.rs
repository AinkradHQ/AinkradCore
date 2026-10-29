//! The sprint commit gate (E5.4): a sprint starts only through it, under either policy; a
//! rejection goes back to the product owner with the reply; over capacity needs a reason.

use ainkrad_core::gov::{ApprovalKind, ApprovalStatus};
use ainkrad_core::org::{TeamMembership, TeamRole};

use super::*;
use crate::store::gov::{DecideError, decide_approval, get_approval, update_approval};
use crate::store::org::create_membership;

const NOW: &str = "2026-10-21T10:00:00.000Z";

struct Team {
    project: Project,
    po: AgentId,
    dev: AgentId,
    /// The product owner's planning issue.
    planning: IssueId,
    sprint: Sprint,
}

/// A scrum project under `policy`, its team (a product owner, and a developer with a capacity
/// of 5), the product owner's planning issue, and a planned sprint holding a 3-point issue.
async fn team(pool: &SqlitePool, policy: SprintApproval) -> Team {
    let (c, mut project) = project_fixture(pool).await;
    let dept = create_department(pool, c, "Eng").await.unwrap();
    let t = create_team(pool, dept.id, "Core").await.unwrap();
    project.team_id = Some(t.id);
    project.sprint_approval = policy;
    assert!(update_project(pool, &project).await.unwrap());
    let (po, dev) = (agent(pool, c, "PO").await, agent(pool, c, "Dev").await);
    for (agent_id, team_role) in [(po, TeamRole::ProductOwner), (dev, TeamRole::Member)] {
        let m = TeamMembership {
            team_id: t.id,
            agent_id,
            team_role,
        };
        create_membership(pool, &m).await.unwrap();
    }
    assert!(set_member_capacity(pool, t.id, dev, Some(5)).await.unwrap());
    let planning = NewIssue {
        next_actor: Some(NextActor::Agent(po)),
        ..new_issue(project.id, "Plan sprint 1")
    };
    let planning = create_issue(pool, &planning).await.unwrap().id;
    let s = NewSprint {
        goal: "Ship".to_owned(),
        starts_on: Some("2026-10-21".to_owned()),
        ends_on: Some("2026-11-03".to_owned()),
        ..new_sprint(project.id, "S1", SprintState::Planned)
    };
    let sprint = plan_sprint(pool, &s, AuditActor::Agent(po)).await.unwrap();
    let work = NewIssue {
        points: Some(3),
        ..new_issue(project.id, "Work")
    };
    let work = create_issue(pool, &work).await.unwrap();
    add_to_sprint(pool, sprint.id, work.id, AuditActor::Agent(po))
        .await
        .unwrap();
    Team {
        project,
        po,
        dev,
        planning,
        sprint,
    }
}

async fn state(pool: &SqlitePool, s: SprintId) -> SprintState {
    get_sprint(pool, s).await.unwrap().unwrap().state
}

async fn gate_of_start(pool: &SqlitePool, s: SprintId) -> serde_json::Value {
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'sprint.started' AND entity_id = ?",
    )
    .bind(s.0)
    .fetch_one(pool)
    .await
    .unwrap();
    serde_json::from_str::<serde_json::Value>(&details).unwrap()["gate"].clone()
}

#[tokio::test]
async fn the_product_owner_commits_alone_under_its_policy() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::ProductOwner).await;
    let s = t.sprint.id;
    let e = commit_sprint(pool, s, t.dev, None, None, NOW)
        .await
        .unwrap_err();
    assert!(matches!(e, SprintError::NotProductOwner), "{e}");
    assert_eq!(state(pool, s).await, SprintState::Planned);

    let started = commit_sprint(pool, s, t.po, Some(t.planning), None, NOW).await;
    assert!(matches!(started, Ok(Commit::Started(ref s)) if s.state == SprintState::Active));
    assert_eq!(state(pool, s).await, SprintState::Active);
    let gate = gate_of_start(pool, s).await;
    assert_eq!(gate["by"], "product_owner");
    assert_eq!(
        (gate["points"].as_u64(), gate["capacity"].as_u64()),
        (Some(3), Some(5))
    );
    let approvals = crate::store::gov::list_approvals(pool, t.project.company_id).await;
    assert!(approvals.unwrap().is_empty(), "no approval needed");
}

#[tokio::test]
async fn under_the_owner_policy_the_sprint_waits_for_the_approval() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let s = t.sprint.id;
    let Commit::Pending(a) = commit_sprint(pool, s, t.po, Some(t.planning), None, NOW)
        .await
        .unwrap()
    else {
        panic!("the owner decides");
    };
    assert_eq!(
        (a.kind, a.status),
        (ApprovalKind::SprintCommit, ApprovalStatus::Pending)
    );
    assert_eq!(
        (a.sprint_id, a.issue_id, a.requested_by),
        (Some(s), Some(t.planning), t.po)
    );
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(
        (payload["points"].as_u64(), payload["capacity"].as_u64()),
        (Some(3), Some(5))
    );
    assert_eq!(
        (
            payload["goal"].as_str(),
            payload["issues"][0]["key"].as_str()
        ),
        (Some("Ship"), Some("CIT-2"))
    );
    assert_eq!(state(pool, s).await, SprintState::Planned);

    // Frozen while it waits: no new commit, no scope change.
    let again = commit_sprint(pool, s, t.po, None, None, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(again, SprintError::AwaitingApproval(id) if id == a.id),
        "{again}"
    );
    let extra = create_issue(pool, &new_issue(t.project.id, "x"))
        .await
        .unwrap();
    let frozen = add_to_sprint(pool, s, extra.id, BY).await.unwrap_err();
    assert!(
        matches!(frozen, SprintError::AwaitingApproval(_)),
        "{frozen}"
    );

    // A raw approval write is not the gate: the sprint does not start.
    let mut raw = a.clone();
    raw.status = ApprovalStatus::Approved;
    raw.decided_by = Some(ADMIN);
    assert!(update_approval(pool, &raw).await.unwrap());
    assert_eq!(state(pool, s).await, SprintState::Planned);
    raw.status = ApprovalStatus::Pending;
    raw.decided_by = None;
    assert!(update_approval(pool, &raw).await.unwrap());

    let decided = decide_approval(pool, a.id, true, ADMIN, Some("Go"), NOW)
        .await
        .unwrap();
    assert_eq!(
        (decided.status, decided.decided_by),
        (ApprovalStatus::Approved, Some(ADMIN))
    );
    assert_eq!(state(pool, s).await, SprintState::Active);
    let gate = gate_of_start(pool, s).await;
    assert_eq!(
        (gate["by"].as_str(), gate["approval"].as_i64()),
        (Some("owner"), Some(a.id.0))
    );
    let twice = decide_approval(pool, a.id, false, ADMIN, None, NOW).await;
    assert!(matches!(
        twice,
        Err(DecideError::NotPending(ApprovalStatus::Approved))
    ));
    let woken: Vec<(i64, Option<i64>, String)> = sqlx::query_as(
        "SELECT agent_id, issue_id, source FROM wake_requests WHERE idempotency_key LIKE 'approval:%'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(woken, [(t.po.0, Some(t.planning.0), "approval".to_owned())]);
}

const BY: AuditActor = AuditActor::User(ADMIN);

#[tokio::test]
async fn a_rejection_returns_the_sprint_to_the_product_owner_with_the_reply() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let s = t.sprint.id;
    let Ok(Commit::Pending(a)) = commit_sprint(pool, s, t.po, Some(t.planning), None, NOW).await
    else {
        panic!("pending");
    };
    let reply = "Too much for one sprint; drop the migration";
    let decided = decide_approval(pool, a.id, false, ADMIN, Some(reply), NOW)
        .await
        .unwrap();
    assert_eq!(
        (decided.status, decided.reply.as_deref()),
        (ApprovalStatus::Rejected, Some(reply))
    );
    assert_eq!(state(pool, s).await, SprintState::Planned);

    let comments = list_comments(pool, t.planning).await.unwrap();
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].author, Actor::Human(ADMIN));
    assert!(comments[0].body.contains(reply), "{}", comments[0].body);
    let (agent, reason): (i64, String) = sqlx::query_as(
        "SELECT agent_id, reason FROM wake_requests WHERE source = 'approval' AND issue_id = ?",
    )
    .bind(t.planning.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(agent, t.po.0);
    assert!(
        reason.contains("rejected") && reason.contains(reply),
        "{reason}"
    );

    // Back with the product owner: estimates, the scope can change and it can commit again.
    let work = list_issues(pool, t.project.id).await.unwrap()[1].id;
    estimate_issue(pool, work, Some(2), BY).await.unwrap();
    let extra = create_issue(pool, &new_issue(t.project.id, "x"))
        .await
        .unwrap();
    add_to_sprint(pool, s, extra.id, BY).await.unwrap();
    remove_from_sprint(pool, extra.id, BY).await.unwrap();
    assert!(matches!(
        commit_sprint(pool, s, t.po, Some(t.planning), None, NOW).await,
        Ok(Commit::Pending(_))
    ));
}

#[tokio::test]
async fn over_capacity_needs_a_reason_kept_in_the_approval_and_the_audit() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let s = t.sprint.id;
    let big = NewIssue {
        points: Some(8),
        ..new_issue(t.project.id, "Big")
    };
    let big = create_issue(pool, &big).await.unwrap();
    add_to_sprint(pool, s, big.id, BY).await.unwrap();
    for blank in [None, Some("  ")] {
        let e = commit_sprint(pool, s, t.po, None, blank, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(
                e,
                SprintError::OverCapacity {
                    points: 11,
                    capacity: 5
                }
            ),
            "{e}"
        );
    }
    let why = "the launch slips otherwise";
    let Ok(Commit::Pending(a)) = commit_sprint(pool, s, t.po, None, Some(why), NOW).await else {
        panic!("pending");
    };
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(payload["override_reason"], why);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'sprint.commit_requested'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(details.contains(why), "{details}");
}

/// Approving when the sprint cannot start (another sprint is active) fails the decision,
/// which stays pending.
#[tokio::test]
async fn an_approval_that_cannot_start_the_sprint_stays_pending() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let Ok(Commit::Pending(a)) = commit_sprint(pool, t.sprint.id, t.po, None, None, NOW).await
    else {
        panic!("pending");
    };
    let other = raw_sprint(pool, t.project.id, "S0", SprintState::Active).await;
    let e = decide_approval(pool, a.id, true, ADMIN, None, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(e, DecideError::Sprint(SprintError::ActiveExists(id)) if id == other.id),
        "{e}"
    );
    let still = get_approval(pool, a.id).await.unwrap().unwrap();
    assert_eq!(still.status, ApprovalStatus::Pending);
    assert_eq!(state(pool, t.sprint.id).await, SprintState::Planned);
}

/// While the commit awaits its approval, the points of the sprint's issues are frozen on every
/// path; an approval whose points no longer match the sprint's fails, and stays pending.
#[tokio::test]
async fn estimates_are_frozen_while_the_commit_awaits_approval() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let s = t.sprint.id;
    let Ok(Commit::Pending(a)) = commit_sprint(pool, s, t.po, Some(t.planning), None, NOW).await
    else {
        panic!("pending");
    };
    let mut work = list_issues(pool, t.project.id).await.unwrap()[1].clone();
    assert_eq!((work.title.as_str(), work.points), ("Work", Some(3)));

    let e = estimate_issue(pool, work.id, Some(5), BY)
        .await
        .unwrap_err();
    assert!(
        matches!(e, SprintError::AwaitingApproval(id) if id == a.id),
        "{e}"
    );
    let frozen = "estimates are frozen while the sprint commit awaits approval";
    work.points = Some(5);
    let e = update_issue(pool, &work).await.unwrap_err();
    assert!(is_raised(&e, frozen), "{e}");
    work.points = Some(3);
    work.title = "Work, renamed".to_owned();
    assert!(
        update_issue(pool, &work).await.unwrap(),
        "other edits go through"
    );
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(work.id),
        sprint_id: Some(s),
        points: Some(1),
        ..new_issue(t.project.id, "Sub")
    };
    let e = create_issue(pool, &sub).await.unwrap_err();
    assert!(is_raised(&e, frozen), "{e}");

    // Past the trigger (a hand edit of the database), the approval no longer matches.
    for sql in [
        "DROP TRIGGER issues_points_frozen_update",
        "UPDATE issues SET points = 5 WHERE title = 'Work, renamed'",
    ] {
        sqlx::query(sql).execute(pool).await.unwrap();
    }
    let e = decide_approval(pool, a.id, true, ADMIN, None, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(e, DecideError::Sprint(SprintError::EstimatesChanged)),
        "{e}"
    );
    let still = get_approval(pool, a.id).await.unwrap().unwrap();
    assert_eq!(still.status, ApprovalStatus::Pending);
    assert_eq!(state(pool, s).await, SprintState::Planned);

    sqlx::query("UPDATE issues SET points = 3 WHERE id = ?")
        .bind(work.id.0)
        .execute(pool)
        .await
        .unwrap();
    decide_approval(pool, a.id, true, ADMIN, None, NOW)
        .await
        .unwrap();
    assert_eq!(state(pool, s).await, SprintState::Active);
}

#[tokio::test]
async fn a_sprint_whose_commit_waits_is_not_deleted() {
    let db = db().await;
    let pool = &db.pool;
    let t = team(pool, SprintApproval::Owner).await;
    let s = t.sprint.id;
    let Ok(Commit::Pending(a)) = commit_sprint(pool, s, t.po, Some(t.planning), None, NOW).await
    else {
        panic!("pending");
    };
    let e = delete_empty_sprint(pool, s, BY).await.unwrap_err();
    assert!(
        matches!(e, SprintError::AwaitingApproval(id) if id == a.id),
        "{e}"
    );

    // Rejected and emptied: deleted, and the approval keeps its record without the sprint.
    decide_approval(pool, a.id, false, ADMIN, None, NOW)
        .await
        .unwrap();
    let work = list_issues(pool, t.project.id).await.unwrap()[1].id;
    remove_from_sprint(pool, work, BY).await.unwrap();
    delete_empty_sprint(pool, s, BY).await.unwrap();
    let kept = get_approval(pool, a.id).await.unwrap().unwrap();
    assert_eq!(
        (kept.status, kept.sprint_id),
        (ApprovalStatus::Rejected, None)
    );
}
