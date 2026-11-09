//! The requirement conversation hub (E15.11): a dev's question lands in the requirement's
//! thread and its answer wakes that dev, not the CEO; answering in the issue thread clears the
//! card; a message to the owner wakes the CEO, then the product owner after the hand-off; a new
//! question is pushed.

use citadel_core::work::{IssueTransition, QuestionState};

use super::intake::{Org, org, route};
use super::*;
use crate::store::events::list_events;

const BY: AuditActor = AuditActor::User(ADMIN);

/// R-1 routed to Engineering with its plan approved: (requirement, kickoff, the dev's task,
/// handed to the dev).
async fn working(pool: &SqlitePool, o: &Org) -> (Requirement, IssueId, IssueId) {
    let intake = submit_intake(pool, o.company, "Phone alerts", "", BY)
        .await
        .unwrap();
    let routes = [route(o.eng, "ALR", ProjectMode::Kanban)];
    let r = route_intake(pool, intake.id, Actor::Agent(o.ceo), &routes)
        .await
        .unwrap();
    let mut p = r[0].project.clone();
    p.sprint_approval = SprintApproval::ProductOwner;
    update_project(pool, &p).await.unwrap();
    let req = intake.requirement_id.unwrap();
    let epic = NewPlanEpic {
        project: p.id,
        title: "APNs",
        tasks: vec![PlannedTask {
            epic: None,
            title: "Sender",
            body: "",
            points: Some(3),
            assignee: Some(o.dev),
        }],
    };
    let planned = plan_requirement(pool, req, o.eng_po, &[epic], &[])
        .await
        .unwrap();
    submit_plan(pool, req, o.eng_po, None, "2026-10-22T10:00:00.000Z")
        .await
        .unwrap();
    let task = planned.tasks[0];
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(o.dev),
    };
    transition_issue(pool, task, &to_dev, AuditActor::Agent(o.eng_po))
        .await
        .unwrap();
    transition_issue(
        pool,
        task,
        &IssueTransition::Start,
        AuditActor::Agent(o.dev),
    )
    .await
    .unwrap();
    let r = get_requirement(pool, req).await.unwrap().unwrap();
    // Every wake so far has been served.
    sqlx::query("UPDATE wake_requests SET status = 'dispatched' WHERE status = 'pending'")
        .execute(pool)
        .await
        .unwrap();
    let kickoff = r.owner_issue_id.unwrap();
    (r, kickoff, task)
}

/// (agent, issue, idempotency key) of every wake a run will serve, oldest first.
async fn wakes(pool: &SqlitePool) -> Vec<(i64, Option<i64>, String)> {
    sqlx::query_as(
        "SELECT agent_id, issue_id, idempotency_key FROM wake_requests \
         WHERE status <> 'coalesced' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_devs_question_shows_in_the_thread_and_the_answer_wakes_that_dev() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, _, task) = working(pool, &o).await;
    let opts = [".p8 key".to_owned(), ".p12 certificate".to_owned()];
    let q = ask_human(pool, o.dev, None, task, "Token key or certificate?", &opts)
        .await
        .unwrap();
    assert_eq!(
        (q.requirement_id, q.state),
        (Some(r.id), QuestionState::Open)
    );
    // Waiting on the admin, with the question in the dev's own thread too.
    let i = get_issue(pool, task).await.unwrap().unwrap();
    assert_eq!(i.next_actor, Some(NextActor::Human(ADMIN)));
    let own = list_comments(pool, task).await.unwrap();
    assert!(
        own.last()
            .unwrap()
            .body
            .contains("Token key or certificate?")
    );
    let thread = requirement_thread(pool, r.id).await.unwrap().unwrap();
    let card = thread
        .iter()
        .find_map(|t| match t {
            ThreadItem::Question {
                question,
                issue_key,
            } => Some((question.agent_id, issue_key.clone())),
            _ => None,
        })
        .expect("a card in the requirement's thread");
    assert_eq!(card, (o.dev, "ALR-2".to_owned()));

    let before = wakes(pool).await.len();
    let posted = post_to_requirement(pool, r.id, ADMIN, ".p8, carry on", To::Auto)
        .await
        .unwrap();
    let Posted::Answered(a) = posted else {
        panic!("auto-targets the open question: {posted:?}")
    };
    assert_eq!(
        (a.state, a.answered_in.as_deref()),
        (QuestionState::Answered, Some("requirement"))
    );
    let new = wakes(pool).await[before..].to_vec();
    assert_eq!(
        new,
        [(o.dev.0, Some(task.0), format!("answer:{}", q.id.0))],
        "the dev, not the CEO"
    );
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM wake_requests WHERE idempotency_key = ?")
            .bind(format!("answer:{}", q.id.0))
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        reason.contains(".p8, carry on"),
        "the run is told the answer: {reason}"
    );
    let i = get_issue(pool, task).await.unwrap().unwrap();
    assert_eq!(i.next_actor, Some(NextActor::Agent(o.dev)));
    let answer = list_comments(pool, task).await.unwrap().pop().unwrap();
    assert_eq!(
        (answer.author, answer.body.as_str()),
        (Actor::Human(ADMIN), ".p8, carry on")
    );
    // Answered once: naming it again is refused.
    let again = post_to_requirement(pool, r.id, ADMIN, "x", To::Question(q.id)).await;
    assert!(
        matches!(again, Err(HubError::Closed(QuestionState::Answered))),
        "{again:?}"
    );

    // A new question is pushed.
    let pushed: Vec<_> = list_events(pool, 0, 1000)
        .await
        .unwrap()
        .iter()
        .filter_map(crate::push::notification)
        .filter(|n| n.kind == "question")
        .collect();
    assert_eq!(pushed.len(), 1);
    assert!(pushed[0].body.contains("Token key"), "{:?}", pushed[0]);
    assert_eq!(pushed[0].data["issue_id"], task.0);
}

#[tokio::test]
async fn answering_in_the_issue_thread_clears_the_card() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, kickoff, task) = working(pool, &o).await;
    let q = ask_human(pool, o.dev, None, task, "Which region?", &[])
        .await
        .unwrap();
    let (_, woke) = post_comment(pool, task, ADMIN, "eu-west", None, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(woke, Some(o.dev));
    let q = get_question(pool, q.id).await.unwrap().unwrap();
    assert_eq!(
        (q.state, q.answered_in.as_deref()),
        (QuestionState::Answered, Some("issue"))
    );
    assert_eq!(q.answer.as_deref(), Some("eu-west"));
    assert!(
        list_questions(pool, Some(r.id), None, true)
            .await
            .unwrap()
            .is_empty()
    );
    // Nothing left open: a post goes to the owner, the product owner since the hand-off.
    let posted = post_to_requirement(pool, r.id, ADMIN, "How is it going?", To::Auto)
        .await
        .unwrap();
    let Posted::ToOwner(_, woke) = posted else {
        panic!("{posted:?}")
    };
    assert_eq!(woke, Some((o.eng_po, kickoff)));
}

#[tokio::test]
async fn the_owner_is_the_ceo_until_the_hand_off_then_the_product_owner() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let intake = submit_intake(pool, o.company, "Audit log", "", BY)
        .await
        .unwrap();
    let req = intake.requirement_id.unwrap();
    let Posted::ToOwner(c, woke) = post_to_requirement(pool, req, ADMIN, "Hi", To::Owner)
        .await
        .unwrap()
    else {
        panic!("no question: the owner")
    };
    assert_eq!(woke, Some((o.ceo, intake.id)));
    let thread = requirement_thread(pool, req).await.unwrap().unwrap();
    assert!(matches!(&thread[0], ThreadItem::Message { comment, .. } if comment.id == c));

    let routes = [route(o.eng, "AUD", ProjectMode::Kanban)];
    let r = route_intake(pool, intake.id, Actor::Agent(o.ceo), &routes)
        .await
        .unwrap();
    let Posted::ToOwner(_, woke) = post_to_requirement(pool, req, ADMIN, "Again", To::Owner)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(woke, Some((o.eng_po, r[0].kickoff.id)));
    // The CEO can still post (#45); a dev cannot.
    agent_post_to_requirement(pool, req, o.ceo, None, "Still here")
        .await
        .unwrap();
    let e = agent_post_to_requirement(pool, req, o.dev, None, "me too").await;
    assert!(matches!(e, Err(HubError::NotAllowed)), "{e:?}");
}
