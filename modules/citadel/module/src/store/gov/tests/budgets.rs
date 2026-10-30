//! Not in the monolith's `store/gov/tests`: the budget guard's own tests lived with the run
//! engine. This one checks what the guard reads and writes (the spend counters, the overrun
//! approval, the raise), through cost events written raw (their run id is a plain integer).

use super::approvals::issue;
use super::*;

const NOW: &str = "2026-10-22T10:00:00.000Z";

async fn spend(pool: &SqlitePool, agent: AgentId, tokens: i64) {
    sqlx::query(
        "INSERT INTO citadel_cost_events (run_id, agent_id, input_tokens, output_tokens, \
         cache_tokens, priced, idempotency_key, created_at) VALUES (1, ?, ?, 0, 0, 0, ?, ?)",
    )
    .bind(agent.0)
    .bind(tokens)
    .bind(format!("k{tokens}"))
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
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

    spend(pool, po, 60).await;
    let mut conn = pool.acquire().await.unwrap();
    let warned = warn_in(&mut conn, po, Some(i), NOW).await.unwrap();
    assert_eq!(warned, [b.id]);
    assert!(
        warn_in(&mut conn, po, Some(i), NOW)
            .await
            .unwrap()
            .is_empty()
    );
    drop(conn);
    spend(pool, po, 40).await;
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
