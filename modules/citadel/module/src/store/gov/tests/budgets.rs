//! Not in the monolith's `store/gov/tests`: the budget guard's own tests lived with the run
//! engine. This one checks what the guard reads and writes (the spend counters, the overrun
//! approval, the raise), through cost events written raw (their run id is a plain integer).

use super::approvals::issue;
use super::*;
use crate::domain::gov::BudgetId;
use serde_json::json;
use crate::domain::work::IssueId;
use ainkrad_core_server::store::costs;

const NOW: &str = "2026-10-22T10:00:00.000Z";

async fn spend(pool: &SqlitePool, agent: AgentId, issue: IssueId, tokens: i64) -> costs::Recorded {
    let mut conn = pool.acquire().await.unwrap();
    let owned = subjects_in(&mut conn, agent, Some(issue)).await.unwrap();
    drop(conn);
    let subjects: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let key = format!("k{tokens}");
    let c = costs::NewCost {
        session: "run:1",
        epoch: 0,
        account_id: None,
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "m",
        input_tokens: tokens,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: None,
        approximate: false,
        subjects: &subjects,
        idempotency_key: &key,
        occurred_at: NOW,
    };
    costs::record(pool, &c, NOW).await.unwrap()
}

#[tokio::test]
async fn an_exhausted_budget_blocks_once_and_a_raise_lets_the_agent_run_again() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    let b = NewBudget {
        scope: BudgetScope::Agent(po),
        period: BudgetPeriod::Total,
        token_cap: 100,
        usd_cap_micros: None,
        warn_at_percent: 50,
        hard_stop: true,
    };
    let b = set_budget(pool, &b, BY).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(admit_in(&mut conn, po, c, Some(i), NOW).await.unwrap());
    drop(conn);

    // 60 of 100 crosses the 50% warning once; the Core sends it as the cost is recorded.
    let warned = spend(pool, po, i, 60).await.guard.warned;
    assert_eq!(
        warned.iter().map(|s| s.budget.id).collect::<Vec<_>>(),
        [b.id.0]
    );
    assert!(spend(pool, po, i, 5).await.guard.warned.is_empty());
    spend(pool, po, i, 35).await;
    let standing = company_budgets(pool, c, NOW).await.unwrap();
    assert_eq!(
        (standing[0].spent, standing[0].period_key.as_str()),
        (100, "total")
    );
    let mut conn = pool.acquire().await.unwrap();
    assert!(!admit_in(&mut conn, po, c, Some(i), NOW).await.unwrap());
    assert!(!admit_in(&mut conn, po, c, Some(i), NOW).await.unwrap());
    drop(conn);
    let pending = list_approvals(pool, c).await.unwrap();
    assert_eq!(pending.len(), 1, "one overrun approval per period");
    assert_eq!(pending[0].kind, ApprovalKind::BudgetOverrun);

    approve_budget_raise(pool, pending[0].id, 500, ADMIN, None, NOW)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(admit_in(&mut conn, po, c, Some(i), NOW).await.unwrap());
}

/// Rows as the old Citadel tables held them: two budgets (set before the events, so the old trigger
/// counted them), three events (priced from a price, reported by the harness, and a subscription's
/// with no dollars) and a pending overrun approval naming the agent budget by its old id.
async fn old_world(pool: &SqlitePool) -> (CompanyId, AgentId, IssueId) {
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    sqlx::query(
        "INSERT INTO citadel_prices (harness, model, version, input_micros_per_mtok, \
         output_micros_per_mtok, cache_micros_per_mtok, created_at) \
         VALUES ('claude', 'claude-opus', 1, 3000000, 15000000, 300000, '2026-10-01T00:00:00.000Z')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO citadel_budgets (scope, agent_id, period, token_cap, warn_at_percent) \
         VALUES ('agent', ?, 'total', 1000000000, 50)",
    )
    .bind(po.0)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO citadel_budgets (scope, company_id, period, token_cap, usd_cap_micros) \
         VALUES ('company', ?, 'month', 0, 90000000)",
    )
    .bind(c.0)
    .execute(pool)
    .await
    .unwrap();
    for (key, tokens, cost, priced, price, billing) in [
        ("old-1", 1_000_000, Some(3_000_000), 1, Some(1), "metered"),
        ("old-2", 2_000, Some(500), 1, None, "metered"),
        ("old-3", 70, None, 0, None, "subscription"),
    ] {
        sqlx::query(
            "INSERT INTO citadel_cost_events (run_id, agent_id, issue_id, input_tokens, \
             output_tokens, cache_tokens, cost_usd_micros, priced, idempotency_key, created_at, \
             price_id, billing) VALUES (7, ?, ?, ?, 0, 0, ?, ?, ?, '2026-10-22T09:00:00.000Z', ?, ?)",
        )
        .bind(po.0)
        .bind(i.0)
        .bind(tokens)
        .bind(cost)
        .bind(priced)
        .bind(key)
        .bind(price)
        .bind(billing)
        .execute(pool)
        .await
        .unwrap();
    }
    let new = NewApproval {
        company_id: c,
        kind: ApprovalKind::BudgetOverrun,
        issue_id: Some(i),
        sprint_id: None,
        agent_id: None,
        requested_by: po,
        payload: r#"{"budget": 1, "period": "total", "unit": "tokens"}"#.to_owned(),
    };
    create_approval(pool, &new).await.unwrap();
    // The Core already holds a budget, so the copied ones get ids of its own.
    sqlx::query(
        "INSERT INTO core_budgets (subject_kind, subject_id, company, period, token_cap, \
         created_at, updated_at) VALUES ('company', '999', '999', 'day', 1, ?1, ?1)",
    )
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    (c, po, i)
}

#[tokio::test]
async fn the_old_ledger_and_budgets_move_into_the_core_verified_and_run_only_once() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, i) = old_world(pool).await;
    sqlx::query("UPDATE citadel_agents SET model = 'claude-opus-4-6[1m] x@y+z'")
        .execute(pool)
        .await
        .unwrap();
    let count = |sql: &'static str| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .unwrap()
    };

    // A dry run verifies and writes nothing.
    let dry = migrate_core::migrate_to_core(pool, true).await.unwrap();
    assert!(dry.dry_run);
    assert_eq!(
        (dry.source.events, dry.source.unpriced, dry.source.budgets),
        (3, 1, 2)
    );
    assert_eq!(dry.source, dry.core);
    assert_eq!(count("SELECT count(*) FROM core_cost_events").await, 0);
    assert_eq!(count("SELECT count(*) FROM core_budgets").await, 1);

    let done = migrate_core::migrate_to_core(pool, false).await.unwrap();
    assert_eq!(
        (
            done.events_copied,
            done.budgets_copied,
            done.approvals_rewritten
        ),
        (3, 2, 1)
    );
    assert_eq!(done.source, done.core);
    assert_eq!(
        (done.source.tokens, done.source.usd_micros),
        (1_002_070, 3_000_500)
    );
    // Basis per event: a price the old ledger named keeps its rates, a harness's own figure is its own,
    // a subscription's tokens have no dollars.
    let rows: Vec<(String, String, Option<i64>, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT idempotency_key, basis, cost_usd_micros, rate_input, provider, session \
         FROM core_cost_events ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let key = |k: &str, b: &str, cost, rate| {
        (
            k.to_owned(),
            b.to_owned(),
            cost,
            rate,
            "anthropic".to_owned(),
            "run:7".to_owned(),
        )
    };
    assert_eq!(
        rows,
        [
            key("old-1", "list_price", Some(3_000_000), Some(3_000_000)),
            key("old-2", "provider_reported", Some(500), None),
            key("old-3", "unpriced", None, None),
        ]
    );
    // What each counted against, and the budget's counters rebuilt from them.
    let subjects: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, subject_id FROM core_cost_subjects s JOIN core_cost_events e ON e.id = s.event_id \
         WHERE e.idempotency_key = 'old-1' ORDER BY kind",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let (cid, aid, iid) = (c.0.to_string(), po.0.to_string(), i.0.to_string());
    assert!(subjects.contains(&("agent".to_owned(), aid.clone())));
    assert!(subjects.contains(&("company".to_owned(), cid.clone())));
    assert!(subjects.contains(&("issue".to_owned(), iid)));
    let spent = company_budgets(pool, c, "2026-10-22T10:00:00.000Z")
        .await
        .unwrap();
    assert_eq!(spent.len(), 2);
    let agent_budget = spent
        .iter()
        .find(|s| s.budget.scope == BudgetScope::Agent(po))
        .unwrap();
    assert_eq!(
        (agent_budget.spent, agent_budget.budget.warn_at_percent),
        (1_002_070, 50)
    );
    // The pending overrun now names its budget by the Core's id.
    let named: i64 = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.budget') FROM citadel_approvals WHERE kind = 'budget_overrun'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(named, agent_budget.budget.id.0);
    assert_ne!(named, 1);
    // The source is untouched, and the copy runs once: a second run (real, dry or by the command) is
    // refused, so a raise approved since is never overwritten and a budget deleted since never returns.
    assert_eq!(count("SELECT count(*) FROM citadel_cost_events").await, 3);
    sqlx::query("UPDATE core_budget_spend SET raised = raised + 7 WHERE budget_id = ?")
        .bind(agent_budget.budget.id.0)
        .execute(pool)
        .await
        .unwrap();
    remove_budget(pool, agent_budget.budget.id, AuditActor::System)
        .await
        .unwrap();
    for dry in [false, true] {
        let err = migrate_core::migrate_to_core(pool, dry)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("it runs once"), "{err}");
    }
    assert!(migrate_core::command(pool, &["--dry-run"]).await.is_err());
    assert!(migrate_core::command(pool, &["--now"]).await.is_err());
    assert_eq!(count("SELECT count(*) FROM core_cost_events").await, 3);
    assert_eq!(
        count("SELECT count(*) FROM core_budgets WHERE subject_kind = 'agent'").await,
        0,
        "the deleted budget did not come back"
    );
    // A model name the Core ledger would refuse was cleaned on the way in.
    let model: String =
        sqlx::query_scalar("SELECT model FROM core_cost_events WHERE idempotency_key = 'old-1'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(model, "claude-opus-4-6_1m__x_y_z");
}

#[tokio::test]
async fn a_copy_that_does_not_match_its_source_writes_nothing() {
    let db = db().await;
    let pool = &db.pool;
    old_world(pool).await;
    // The Core already holds an event under one of the source's keys, with other numbers.
    sqlx::query(
        "INSERT INTO core_cost_events (session, epoch, provider, harness, model, input_tokens, \
         output_tokens, cache_tokens, basis, idempotency_key, occurred_at, created_at) \
         VALUES ('run:7', 0, 'anthropic', 'claude', 'm', 1, 0, 0, 'unpriced', 'old-2', ?1, ?1)",
    )
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    let err = migrate_core::migrate_to_core(pool, false)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match its source"),
        "{err}"
    );
    let (events, budgets): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM core_cost_events), (SELECT count(*) FROM core_budgets)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((events, budgets), (1, 1), "rolled back to what was there");
}

#[tokio::test]
async fn deleting_a_department_or_a_sprint_deletes_its_budgets_and_the_seam_only_sees_citadels() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _po, p) = fixture(pool, "A").await;
    let d = create_department(pool, c, "Eng").await.unwrap().id;
    let s = sprint(pool, p.id).await;
    let new = |scope| NewBudget {
        scope,
        period: BudgetPeriod::Day,
        token_cap: 10,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let dept = set_budget(pool, &new(BudgetScope::Department(d)), AuditActor::System)
        .await
        .unwrap();
    let spr = set_budget(pool, &new(BudgetScope::Sprint(s)), AuditActor::System)
        .await
        .unwrap();
    // The company is its budgets' binding; an unknown scope is refused and nothing is written.
    assert_eq!(company_budgets(pool, c, NOW).await.unwrap().len(), 2);
    assert!(
        set_budget(
            pool,
            &new(BudgetScope::Sprint(SprintId(9999))),
            AuditActor::System
        )
        .await
        .is_err()
    );
    // The seam knows Citadel's budgets and not the Core's own (an account's).
    sqlx::query(
        "INSERT INTO core_budgets (subject_kind, subject_id, period, token_cap, created_at, updated_at) \
         VALUES ('account', '1', 'day', 1, ?1, ?1)",
    )
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    let owner = |id: i64| async move {
        sqlx::query_scalar::<_, Option<i64>>(BUDGET_COMPANY)
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap()
    };
    assert_eq!(owner(dept.id.0).await, Some(Some(c.0)));
    let account_budget: i64 =
        sqlx::query_scalar("SELECT id FROM core_budgets WHERE subject_kind = 'account'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(owner(account_budget).await, None);
    assert!(
        !remove_budget(pool, BudgetId(account_budget), AuditActor::System)
            .await
            .unwrap()
    );

    crate::store::org::service::remove_department(pool, d, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(get_budget(pool, dept.id).await.unwrap(), None);
    crate::store::work::issues::delete_empty_sprint(pool, s, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(get_budget(pool, spr.id).await.unwrap(), None);
}

#[test]
fn a_free_text_model_becomes_a_name_the_core_ledger_takes() {
    use ainkrad_core_server::store::prices::valid_model;
    let long = "m".repeat(100);
    for (given, want) in [
        ("claude-opus-4-6[1m]", "claude-opus-4-6_1m_"),
        ("my model", "my_model"),
        ("a@b", "a_b"),
        ("c+d", "c_d"),
        ("gpt-5.1:mini/x", "gpt-5.1:mini/x"),
        (long.as_str(), &long[..80]),
        ("", "unknown"),
        ("é", "_"),
    ] {
        let got = core_model(given);
        assert_eq!(got, want, "{given}");
        assert!(valid_model(&got), "{got}");
    }
}

#[tokio::test]
async fn a_raise_needs_a_core_budget_id_of_the_approvals_own_company() {
    let db = db().await;
    let pool = &db.pool;
    let (ca, po_a, _pa) = fixture(pool, "A").await;
    let (cb, po_b, _pb) = fixture(pool, "B").await;
    let b = set_budget(
        pool,
        &NewBudget {
            scope: BudgetScope::Agent(po_b),
            period: BudgetPeriod::Total,
            token_cap: 100,
            usd_cap_micros: None,
            warn_at_percent: 50,
            hard_stop: true,
        },
        BY,
    )
    .await
    .unwrap();
    let approval = |company: CompanyId, by: AgentId, mark: bool| {
        let payload = json!({"budget": b.id.0, "period": "total", "unit": "tokens",
                             "core_budget": mark});
        async move {
            create_approval(
                pool,
                &NewApproval {
                    company_id: company,
                    kind: ApprovalKind::BudgetOverrun,
                    issue_id: None,
                    sprint_id: None,
                    agent_id: None,
                    requested_by: by,
                    payload: payload.to_string(),
                },
            )
            .await
            .unwrap()
        }
    };
    let raised = || async move {
        sqlx::query_scalar::<_, i64>("SELECT coalesce(sum(raised), 0) FROM core_budget_spend")
            .fetch_one(pool)
            .await
            .unwrap()
    };
    let mut conn = pool.acquire().await.unwrap();
    // Company A's approval whose number happens to be company B's budget id: refused, nothing raised.
    let other = approval(ca, po_a, true).await;
    assert!(raise_in(&mut conn, &other, 50, ADMIN).await.is_err());
    // An approval of the right company that was never marked as a Core id (an old Citadel number).
    let old = approval(cb, po_b, false).await;
    assert!(raise_in(&mut conn, &old, 50, ADMIN).await.is_err());
    assert_eq!(raised().await, 0);
    let own = approval(cb, po_b, true).await;
    raise_in(&mut conn, &own, 50, ADMIN).await.unwrap();
    assert_eq!(raised().await, 50);
}

#[tokio::test]
async fn a_core_budget_tagged_to_the_company_neither_breaks_its_list_nor_stands_in_for_an_approval() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    let b = set_budget(
        pool,
        &NewBudget {
            scope: BudgetScope::Agent(po),
            period: BudgetPeriod::Total,
            token_cap: 100,
            usd_cap_micros: None,
            warn_at_percent: 50,
            hard_stop: true,
        },
        BY,
    )
    .await
    .unwrap();
    // A Core account budget bound to the company: not Citadel's, so the company's list skips it.
    sqlx::query(
        "INSERT INTO core_budgets (subject_kind, subject_id, company, period, token_cap, created_at, \
         updated_at) VALUES ('account', '1', ?1, 'day', 1, ?2, ?2)",
    )
    .bind(c.0.to_string())
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    let listed = company_budgets(pool, c, NOW).await.unwrap();
    assert_eq!(listed.iter().map(|s| s.budget.id).collect::<Vec<_>>(), [b.id]);
    // An approval that names the exhausted budget's number but is no adapter's (an old Citadel id)
    // does not count as the question asked: admission opens its own.
    spend(pool, po, i, 100).await;
    create_approval(
        pool,
        &NewApproval {
            company_id: c,
            kind: ApprovalKind::BudgetOverrun,
            issue_id: Some(i),
            sprint_id: None,
            agent_id: None,
            requested_by: po,
            payload: json!({"budget": b.id.0, "period": "total", "unit": "tokens"}).to_string(),
        },
    )
    .await
    .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(!admit_in(&mut conn, po, c, Some(i), NOW).await.unwrap());
    drop(conn);
    assert_eq!(list_approvals(pool, c).await.unwrap().len(), 2);
}
