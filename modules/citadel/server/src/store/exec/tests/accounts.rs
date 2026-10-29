//! The account pool at dispatch (E15.1): runs rotate across a company's accounts, never touch
//! another company's, wait when none is active, and are billed as their account.

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::gov::{AccountId, AccountStatus, Billing, NewAccount};

use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::gov::{
    assign_account, create_account, new_account, run_account, set_account_status, set_billing,
};

const BY: AuditActor = AuditActor::User(UserId(1));

/// `2026-10-22T10:<minute>:00.000Z`.
pub(super) fn at(minute: u32) -> String {
    format!("2026-10-22T10:{minute:02}:00.000Z")
}

pub(super) async fn account(pool: &SqlitePool, label: &str, company: CompanyId) -> AccountId {
    let new = new_account(pool, Harness::Claude, label, None, None, None, None)
        .await
        .unwrap();
    let a = create_account(pool, &new, BY).await.unwrap();
    assert!(assign_account(pool, a.id, company, true, BY).await.unwrap());
    a.id
}

/// A fresh `todo` issue of the company's project (made on first use).
pub(super) async fn fresh_issue(pool: &SqlitePool, company: CompanyId) -> IssueId {
    let project: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE company_id = ?")
        .bind(company.0)
        .fetch_optional(pool)
        .await
        .unwrap();
    let Some(project) = project else {
        return issue(pool, company).await;
    };
    let i = NewIssue {
        project_id: citadel_core::work::ProjectId(project),
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "More".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

/// Dispatches the agent's next wake on a fresh issue at `minute`, ends it, and returns the
/// account its run worked as.
pub(super) async fn next_account(
    pool: &SqlitePool,
    dev: AgentId,
    company: CompanyId,
    r: RunnerId,
    minute: u32,
) -> Option<AccountId> {
    let i = fresh_issue(pool, company).await;
    enqueue_wake(pool, &wake(dev, Some(i), &format!("w{minute}")))
        .await
        .unwrap();
    let run = dispatch(pool, r, &at(minute)).await?;
    let a = run_account(pool, run.id).await.unwrap().map(|a| a.id);
    let by = AuditActor::Runner(r);
    start_run(pool, run.id, by, None, &at(minute))
        .await
        .unwrap();
    transition_run(pool, run.id, by, &RunEvent::Succeed, &at(minute))
        .await
        .unwrap();
    a
}

#[tokio::test]
async fn runs_rotate_across_three_accounts_of_their_company_only() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap().id;
    let b = create_company(pool, "B").await.unwrap().id;
    let (dev_a, dev_b) = (agent(pool, a).await, agent(pool, b).await);
    let one = account(pool, "claude-1", a).await;
    let two = account(pool, "claude-2", a).await;
    let three = account(pool, "claude-3", a).await;
    let theirs = account(pool, "claude-b", b).await;
    let r = runner(pool, "box").await;

    let mut used = vec![];
    for minute in 1..=6 {
        used.push(next_account(pool, dev_a, a, r, minute).await.unwrap());
    }
    assert_eq!(
        used,
        [one, two, three, one, two, three],
        "least recently used first"
    );
    assert_eq!(next_account(pool, dev_b, b, r, 7).await, Some(theirs));

    // A disabled account is skipped; with every one of A's off, A's runs wait.
    set_account_status(pool, two, AccountStatus::Disabled, None, BY)
        .await
        .unwrap();
    assert_eq!(next_account(pool, dev_a, a, r, 8).await, Some(one));
    assert_eq!(next_account(pool, dev_a, a, r, 9).await, Some(three));
    for off in [one, three] {
        set_account_status(pool, off, AccountStatus::Disabled, None, BY)
            .await
            .unwrap();
    }
    assert_eq!(
        next_account(pool, dev_a, a, r, 10).await,
        None,
        "never B's account, never the runner's own login"
    );
    let waiting = "SELECT count(*) FROM wake_requests WHERE status = 'pending'";
    let pending: i64 = sqlx::query_scalar(waiting).fetch_one(pool).await.unwrap();
    assert_eq!(pending, 1, "the wake waits for an account");
    // Every run's account belongs to its own company, and the schema refuses another's.
    let crossed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runs r JOIN agents g ON g.id = r.agent_id \
         WHERE NOT EXISTS (SELECT 1 FROM account_companies ac WHERE ac.account_id = r.account_id \
             AND ac.company_id = g.company_id)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(crossed, 0);
    let refused = sqlx::query("UPDATE runs SET account_id = ? WHERE agent_id = ?")
        .bind(theirs.0)
        .bind(dev_a.0)
        .execute(pool)
        .await;
    assert!(refused.is_err(), "another company's account is refused");
}

#[tokio::test]
async fn a_harness_without_accounts_runs_on_the_runners_login() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap().id;
    let dev = agent(pool, a).await;
    let r = runner(pool, "box").await;
    // No account at all: the runner's own login, as before E15.1.
    assert_eq!(next_account(pool, dev, a, r, 1).await, None);
    let i = fresh_issue(pool, a).await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    assert!(dispatch(pool, r, &at(2)).await.is_some());
    // Once the pool has a Claude account, even of another company, A's Claude runs wait.
    let b = create_company(pool, "B").await.unwrap().id;
    account(pool, "claude-b", b).await;
    let i = fresh_issue(pool, a).await;
    enqueue_wake(pool, &wake(dev, Some(i), "w2")).await.unwrap();
    assert!(dispatch(pool, r, &at(3)).await.is_none());
}

#[tokio::test]
async fn usage_is_billed_and_attributed_as_the_runs_account() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap().id;
    let dev = agent(pool, a).await;
    // The harness is metered; the account is a subscription, and wins.
    set_billing(pool, Harness::Claude, Billing::Metered, BY)
        .await
        .unwrap();
    let new = NewAccount {
        billing: Billing::Subscription,
        ..new_account(pool, Harness::Claude, "sub", None, None, None, None)
            .await
            .unwrap()
    };
    let sub = create_account(pool, &new, BY).await.unwrap().id;
    assign_account(pool, sub, a, true, BY).await.unwrap();
    let r = runner(pool, "box").await;
    let i = fresh_issue(pool, a).await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    let run = dispatch(pool, r, &at(1)).await.unwrap();
    let totals = Usage {
        input_tokens: 10,
        output_tokens: 5,
        cache_tokens: 0,
        cost_usd_micros: Some(900),
    };
    record_run_usage(pool, &run, 1, &totals, &at(2))
        .await
        .unwrap();
    let (account, billing, cost): (Option<i64>, String, Option<i64>) = sqlx::query_as(
        "SELECT account_id, billing, cost_usd_micros FROM cost_events WHERE run_id = ?",
    )
    .bind(run.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(account, Some(sub.0));
    assert_eq!(billing, "subscription");
    assert_eq!(cost, None, "a subscription has no dollars");
    // A new account starts from its harness's billing.
    let d = new_account(pool, Harness::Claude, "d", None, None, None, None)
        .await
        .unwrap();
    assert_eq!(d.billing, Billing::Metered);
    assert_eq!(d.config_dir, "accounts/d");
}

#[tokio::test]
async fn bad_accounts_are_refused() {
    let db = db().await;
    let pool = &db.pool;
    let ok = new_account(
        pool,
        Harness::Claude,
        "claude-a",
        Some("claude-a.token".to_owned()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        ok.credential_env.as_deref(),
        Some("CLAUDE_CODE_OAUTH_TOKEN"),
        "the harness's first auth variable"
    );
    let bad = [
        NewAccount {
            label: "Has Space".to_owned(),
            ..ok.clone()
        },
        NewAccount {
            credential_ref: Some("/etc/passwd".to_owned()),
            ..ok.clone()
        },
        NewAccount {
            config_dir: "../home".to_owned(),
            ..ok.clone()
        },
        NewAccount {
            credential_env: Some("LD_PRELOAD".to_owned()),
            ..ok.clone()
        },
        NewAccount {
            credential_env: None,
            ..ok.clone()
        },
    ];
    for new in bad {
        let e = create_account(pool, &new, BY).await.unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)), "{new:?}: {e}");
    }
    create_account(pool, &ok, BY).await.unwrap();
    assert!(create_account(pool, &ok, BY).await.is_err(), "label taken");
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'account.created'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(audited, 1);
}
