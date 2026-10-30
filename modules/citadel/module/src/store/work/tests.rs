//! The work store's tests (S4a): the shared fixtures (`pub(crate)`, for `planning_tests` too) and
//! the project, epic, sprint, label and repo rows. The issue, backlog, kanban, sprint, gate,
//! review and repo suites are in `tests/`.

use crate::domain::org::{AgentId, AgentStatus, Harness, NewAgent, OrgRole};
use crate::domain::work::{
    Actor, BlockerLink, EpicStatus, IssueId, IssueKind, IssueState, NewComment, NewIssue,
    NextActor, ProjectMode, ProjectRepo, SprintApproval, SprintState, UserId,
};
use ainkrad_core::audit::AuditActor;

use super::*;
use crate::store::org::{
    create_agent, create_company, create_department, create_team, delete_agent, delete_company,
};
pub(crate) use crate::testing::db;

mod backlog;
mod gate;
mod issues;
mod kanban;
mod repos;
mod review;
mod sprint_scope;
mod sprints;

pub(crate) const ADMIN: UserId = UserId(1);

pub(crate) fn is_constraint(e: &Error) -> bool {
    matches!(e, Error::Database(d) if d.message().contains("constraint failed"))
}

pub(crate) fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

pub(crate) fn new_project(company_id: CompanyId, key: &str) -> NewProject {
    NewProject {
        company_id,
        team_id: None,
        name: format!("Project {key}"),
        key: key.to_owned(),
        mode: ProjectMode::Scrum,
        sprint_approval: SprintApproval::Owner,
    }
}

pub(crate) fn new_issue(project_id: ProjectId, title: &str) -> NewIssue {
    NewIssue {
        project_id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Story,
        title: title.to_owned(),
        body: String::new(),
        state: IssueState::Backlog,
        owner: None,
        next_actor: Some(NextActor::Human(ADMIN)),
        points: None,
        sprint_id: None,
    }
}

pub(crate) fn new_sprint(project_id: ProjectId, name: &str, state: SprintState) -> NewSprint {
    NewSprint {
        project_id,
        name: name.to_owned(),
        goal: String::new(),
        state,
        starts_on: None,
        ends_on: None,
    }
}

/// A sprint put straight into `state` with raw SQL, past the engine's rules.
pub(crate) async fn raw_sprint(
    pool: &SqlitePool,
    p: ProjectId,
    name: &str,
    state: SprintState,
) -> Sprint {
    let s = create_sprint(pool, &new_sprint(p, name, SprintState::Planned))
        .await
        .unwrap();
    sqlx::query("UPDATE citadel_sprints SET state = ? WHERE id = ?")
        .bind(state.as_str())
        .bind(s.id.0)
        .execute(pool)
        .await
        .unwrap();
    Sprint { state, ..s }
}

pub(crate) async fn agent(pool: &SqlitePool, company_id: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

/// A company with one project.
pub(crate) async fn project_fixture(pool: &SqlitePool) -> (CompanyId, Project) {
    let c = create_company(pool, "A").await.unwrap();
    let p = create_project(pool, &new_project(c.id, "CIT"))
        .await
        .unwrap();
    (c.id, p)
}

#[tokio::test]
async fn project_crud_and_team_must_share_company() {
    let db = db().await;
    let pool = &db.pool;
    let (c, mut p) = project_fixture(pool).await;
    assert_eq!(get_project(pool, p.id).await.unwrap(), Some(p.clone()));

    let dup = create_project(pool, &new_project(c, "CIT"))
        .await
        .unwrap_err();
    assert!(is_constraint(&dup), "{dup}");
    let bad_key = create_project(pool, &new_project(c, "cit-1"))
        .await
        .unwrap_err();
    assert!(is_constraint(&bad_key), "{bad_key}");

    let d = create_department(pool, c, "Engineering").await.unwrap();
    let team = create_team(pool, d.id, "Core").await.unwrap();
    p.team_id = Some(team.id);
    p.team_ids = vec![team.id];
    p.mode = ProjectMode::Kanban;
    p.sprint_approval = SprintApproval::ProductOwner;
    assert!(update_project(pool, &p).await.unwrap());
    assert_eq!(list_projects(pool, c).await.unwrap(), vec![p.clone()]);

    let other = create_company(pool, "B").await.unwrap();
    let foreign = create_project(
        pool,
        &NewProject {
            team_id: Some(team.id),
            ..new_project(other.id, "B")
        },
    )
    .await
    .unwrap_err();
    assert!(
        is_raised(&foreign, "team belongs to another company"),
        "{foreign}"
    );

    assert!(delete_project(pool, p.id).await.unwrap());
    assert_eq!(get_project(pool, p.id).await.unwrap(), None);
}

#[tokio::test]
async fn epic_sprint_and_label_crud() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;

    let mut e = create_epic(pool, p.id, "Engine").await.unwrap();
    assert_eq!(e.status, EpicStatus::Open);
    e.title = "Execution engine".to_owned();
    e.status = EpicStatus::InProgress;
    assert!(update_epic(pool, &e).await.unwrap());
    assert_eq!(list_epics(pool, p.id).await.unwrap(), vec![e.clone()]);
    assert!(delete_epic(pool, e.id).await.unwrap());
    assert_eq!(get_epic(pool, e.id).await.unwrap(), None);

    let mut s = create_sprint(pool, &new_sprint(p.id, "S1", SprintState::Planned))
        .await
        .unwrap();
    s.goal = "Ship it".to_owned();
    s.starts_on = Some("2026-10-21".to_owned());
    s.ends_on = Some("2026-11-04".to_owned());
    assert!(update_sprint(pool, &s).await.unwrap());
    assert_eq!(get_sprint(pool, s.id).await.unwrap(), Some(s.clone()));
    s.ends_on = Some("2026-10-01".to_owned());
    let backwards = update_sprint(pool, &s).await.unwrap_err();
    assert!(is_constraint(&backwards), "{backwards}");
    assert!(delete_sprint(pool, s.id).await.unwrap());
    assert!(list_sprints(pool, p.id).await.unwrap().is_empty());

    let mut l = create_label(pool, p.id, "bug").await.unwrap();
    let dup = create_label(pool, p.id, "bug").await.unwrap_err();
    assert!(is_constraint(&dup), "{dup}");
    l.name = "defect".to_owned();
    assert!(update_label(pool, &l).await.unwrap());
    assert_eq!(get_label(pool, l.id).await.unwrap(), Some(l.clone()));
    let i = create_issue(pool, &new_issue(p.id, "One")).await.unwrap();
    add_issue_label(pool, i.id, l.id, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(
        list_issue_labels(pool, i.id).await.unwrap(),
        vec![l.clone()]
    );
    assert!(
        remove_issue_label(pool, i.id, l.id, AuditActor::System)
            .await
            .unwrap()
    );
    add_issue_label(pool, i.id, l.id, AuditActor::System)
        .await
        .unwrap();
    assert!(delete_label(pool, l.id).await.unwrap());
    assert!(list_issue_labels(pool, i.id).await.unwrap().is_empty());
    assert!(list_labels(pool, p.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn one_active_sprint_per_project() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    // Only a planned sprint is created; the rest is `start_sprint` and `close_sprint`.
    for state in [SprintState::Active, SprintState::Closed] {
        let e = create_sprint(pool, &new_sprint(p.id, "S", state)).await;
        assert!(matches!(e, Err(Error::InvalidArgument(_))), "{e:?}");
    }
    raw_sprint(pool, p.id, "S1", SprintState::Active).await;
    raw_sprint(pool, p.id, "S0", SprintState::Closed).await;
    let mut s2 = create_sprint(pool, &new_sprint(p.id, "S2", SprintState::Planned))
        .await
        .unwrap();
    raw_sprint(pool, other.id, "W1", SprintState::Active).await;

    // The index holds even against a raw write.
    let second = sqlx::query("UPDATE citadel_sprints SET state = 'active' WHERE id = ?")
        .bind(s2.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(is_constraint(&second), "{second}");
    // An edit does not change the state, so it cannot slip past the index either.
    s2.state = SprintState::Active;
    assert!(update_sprint(pool, &s2).await.unwrap());
    assert_eq!(
        get_sprint(pool, s2.id).await.unwrap().unwrap().state,
        SprintState::Planned
    );
}

#[tokio::test]
async fn deletes_cascade_down_the_hierarchy() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let owner = agent(pool, c, "Owner").await;
    let e = create_epic(pool, p.id, "Epic").await.unwrap();
    let s = create_sprint(pool, &new_sprint(p.id, "S1", SprintState::Planned))
        .await
        .unwrap();
    let story = create_issue(
        pool,
        &NewIssue {
            epic_id: Some(e.id),
            sprint_id: Some(s.id),
            owner: Some(Actor::Agent(owner)),
            ..new_issue(p.id, "Story")
        },
    )
    .await
    .unwrap();
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(story.id),
        next_actor: Some(NextActor::Agent(dev)),
        ..new_issue(p.id, "Sub")
    };
    let sub = create_issue(pool, &sub).await.unwrap();
    let other = create_issue(pool, &new_issue(p.id, "Other")).await.unwrap();
    add_blocker(
        pool,
        BlockerLink {
            blocker: story.id,
            blocked: other.id,
        },
    )
    .await
    .unwrap();
    let comment = |author| NewComment {
        issue_id: other.id,
        author,
        body: "x".to_owned(),
        run_id: None,
        idempotency_key: None,
    };
    let note = create_comment(pool, &comment(Actor::Agent(dev)))
        .await
        .unwrap();

    // Epic and sprint go; the issue stays, unattached. An owner leaving clears the owner.
    assert!(delete_epic(pool, e.id).await.unwrap());
    assert!(delete_sprint(pool, s.id).await.unwrap());
    assert!(delete_agent(pool, owner).await.unwrap());
    let story_now = get_issue(pool, story.id).await.unwrap().unwrap();
    assert_eq!(
        (story_now.epic_id, story_now.sprint_id, story_now.owner),
        (None, None, None)
    );

    // An agent that is a next actor or a comment author cannot be deleted.
    assert!(is_constraint(&delete_agent(pool, dev).await.unwrap_err()));

    // Deleting a story takes its subtasks and links.
    assert!(
        delete_issue(pool, story.id, AuditActor::System)
            .await
            .unwrap()
    );
    assert_eq!(get_issue(pool, sub.id).await.unwrap(), None);
    assert!(list_blockers(pool, other.id).await.unwrap().is_empty());

    // Deleting the company takes the projects, issues, comments and agents in one go.
    let keep = create_company(pool, "Keep").await.unwrap();
    let kept = create_project(pool, &new_project(keep.id, "KEEP"))
        .await
        .unwrap();
    assert!(delete_company(pool, c).await.unwrap());
    assert_eq!(get_project(pool, p.id).await.unwrap(), None);
    assert_eq!(get_issue(pool, other.id).await.unwrap(), None);
    assert_eq!(get_comment(pool, note.id).await.unwrap(), None);
    assert_eq!(list_projects(pool, keep.id).await.unwrap(), vec![kept]);
}

#[tokio::test]
async fn a_project_repo_is_set_validated_and_read_through_its_issues() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let repo = |url: &str, branch: &str| ProjectRepo {
        project_id: p.id,
        url: url.to_owned(),
        default_branch: branch.to_owned(),
    };
    assert_eq!(get_project_repo(pool, p.id).await.unwrap(), None);
    let ours = repo("https://example.test/acme/citadel.git", "development");
    set_project_repo(pool, &ours).await.unwrap();
    set_project_repo(pool, &repo("/srv/old.git", "main"))
        .await
        .unwrap();
    set_project_repo(pool, &ours).await.unwrap();
    assert_eq!(
        get_project_repo(pool, p.id).await.unwrap(),
        Some(ours.clone())
    );
    for (url, branch) in [
        ("https://ghp_secret@example.test/a/b.git", "main"),
        ("--upload-pack=x", "main"),
        ("/srv/r.git", "-f"),
    ] {
        let refused = set_project_repo(pool, &repo(url, branch)).await;
        assert!(matches!(refused, Err(Error::InvalidArgument(_))), "{url}");
    }

    let first = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    let second = create_issue(pool, &new_issue(p.id, "b")).await.unwrap();
    let found = issue_repo(pool, second.id).await.unwrap();
    assert_eq!(found, Some((ours, "CIT-2".to_owned())));
    sqlx::query("UPDATE citadel_issues SET state = 'cancelled', next_user_id = NULL WHERE id = ?")
        .bind(first.id.0)
        .execute(pool)
        .await
        .unwrap();
    let closed = closed_issues(pool, &[first.id.0, second.id.0, 999]).await;
    assert_eq!(closed.unwrap(), vec![first.id.0, 999]);

    assert!(delete_project(pool, p.id).await.unwrap());
    let left = "SELECT count(*) FROM citadel_project_repos";
    assert_eq!(
        sqlx::query_scalar::<_, i64>(left)
            .fetch_one(pool)
            .await
            .unwrap(),
        0
    );
}
