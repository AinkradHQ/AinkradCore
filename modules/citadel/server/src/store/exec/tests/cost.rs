//! The cost ledger (E7.3): a harness's reported cost is stored as is; token-only usage is
//! priced from the versioned price table; with neither, a run is unpriced (NULL, never 0) and
//! reported as such; a subscription harness records tokens only; report totals are exact.

use citadel_core::audit::AuditActor;
use citadel_core::gov::Billing;

use super::*;
use crate::store::gov::{CostScope, cost_json, cost_report, set_billing, set_price};

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

fn totals(input: i64, output: i64, cache: i64, cost: Option<i64>) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        cache_tokens: cache,
        cost_usd_micros: cost,
    }
}

/// An agent of the fixture's company on `harness` with `model`.
async fn on(pool: &SqlitePool, dev: AgentId, harness: Harness, model: &str) -> AgentId {
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let a = NewAgent {
        company_id: company,
        name: format!("{} {model}", harness.as_str()),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness,
        model: model.to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

async fn run_of(pool: &SqlitePool, agent: AgentId, harness: Harness, i: IssueId) -> Run {
    let new = NewRun {
        harness,
        ..new_run(agent, Some(i))
    };
    create_run(pool, &new).await.unwrap()
}

/// (cost, priced, price version, billing) of the run's events, oldest first.
async fn events(pool: &SqlitePool, run: &Run) -> Vec<(Option<i64>, bool, Option<i64>, String)> {
    sqlx::query_as(
        "SELECT c.cost_usd_micros, c.priced, p.version, c.billing FROM cost_events c \
         LEFT JOIN prices p ON p.id = c.price_id WHERE c.run_id = ? ORDER BY c.id",
    )
    .bind(run.id.0)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_reported_cost_is_the_runs_cost() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set_price(pool, Harness::Claude, "claude-opus", [1, 1, 1], BY, NOW)
        .await
        .unwrap();
    let run = run_of(pool, dev, Harness::Claude, i).await;
    // Mid-turn: tokens only, priced from the table; the turn's close reports the session cost.
    record_run_usage(pool, &run, 1, &totals(1_000_000, 0, 0, None), NOW)
        .await
        .unwrap();
    record_run_usage(pool, &run, 2, &totals(2_000_000, 0, 0, Some(1_710)), NOW)
        .await
        .unwrap();
    let e = events(pool, &run).await;
    assert_eq!(
        e.iter().map(|e| (e.0, e.2)).collect::<Vec<_>>(),
        [(Some(1), Some(1)), (Some(1_709), None)],
        "the report corrects the estimate; it is not priced from the table"
    );
    let stored = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(
        stored.usage.cost_usd_micros,
        Some(1_710),
        "what the harness reported"
    );
}

#[tokio::test]
async fn token_only_usage_is_priced_by_the_latest_price_version() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let codex = on(pool, dev, Harness::Codex, "gpt-5").await;
    let run = run_of(pool, codex, Harness::Codex, i).await;
    // $3 in, $15 out, $0.30 cache per million tokens.
    let v1 = set_price(
        pool,
        Harness::Codex,
        "gpt-5",
        [3_000_000, 15_000_000, 300_000],
        BY,
        NOW,
    );
    assert_eq!(v1.await.unwrap().version, 1);
    record_run_usage(
        pool,
        &run,
        1,
        &totals(1_000_000, 100_000, 2_000_000, None),
        NOW,
    )
    .await
    .unwrap();
    let v2 = set_price(
        pool,
        Harness::Codex,
        "gpt-5",
        [6_000_000, 30_000_000, 600_000],
        BY,
        NOW,
    );
    assert_eq!(v2.await.unwrap().version, 2);
    record_run_usage(
        pool,
        &run,
        2,
        &totals(1_000_001, 100_000, 2_000_000, None),
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        events(pool, &run).await,
        [
            (Some(5_100_000), true, Some(1), "metered".to_owned()),
            (Some(6), true, Some(2), "metered".to_owned()),
        ],
        "3 + 1.5 + 0.6 dollars at v1; one more input token at v2's $6/Mtok"
    );
    let stored = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(stored.usage.cost_usd_micros, Some(5_100_006));
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'price.set'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(audited, 2);
}

#[tokio::test]
async fn an_unpriced_run_is_reported_unpriced_never_zero() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let agy = on(pool, dev, Harness::Agy, "gemini-3").await;
    let run = run_of(pool, agy, Harness::Agy, i).await;
    record_run_usage(pool, &run, 1, &totals(500, 50, 0, None), NOW)
        .await
        .unwrap();
    assert_eq!(
        events(pool, &run).await,
        [(None, false, None, "metered".to_owned())]
    );
    let stored = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(stored.usage.cost_usd_micros, None);
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let r = cost_report(pool, CostScope::Company(company))
        .await
        .unwrap();
    assert_eq!((r.runs, r.unpriced_runs, r.unpriced_tokens), (1, 1, 550));
    let shown = cost_json(&r);
    assert_eq!(shown["unpriced"], "1 runs");
    assert_eq!(shown["priced_runs"], 0);
}

#[tokio::test]
async fn subscription_runs_count_tokens_and_report_totals_are_exact() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let codex = on(pool, dev, Harness::Codex, "gpt-5").await;
    let agy = on(pool, dev, Harness::Agy, "gemini-3").await;
    set_price(
        pool,
        Harness::Codex,
        "gpt-5",
        [1_250_000, 10_000_000, 125_000],
        BY,
        NOW,
    )
    .await
    .unwrap();

    let reported = run_of(pool, dev, Harness::Claude, i).await;
    record_run_usage(
        pool,
        &reported,
        1,
        &totals(10, 20, 30, Some(1_234_567)),
        NOW,
    )
    .await
    .unwrap();
    let priced = run_of(pool, codex, Harness::Codex, i).await;
    record_run_usage(pool, &priced, 1, &totals(333_333, 0, 0, None), NOW)
        .await
        .unwrap();
    let unpriced = run_of(pool, agy, Harness::Agy, i).await;
    record_run_usage(pool, &unpriced, 1, &totals(7, 0, 0, None), NOW)
        .await
        .unwrap();
    set_billing(pool, Harness::Claude, Billing::Subscription, BY)
        .await
        .unwrap();
    let sub = run_of(pool, dev, Harness::Claude, i).await;
    record_run_usage(pool, &sub, 1, &totals(1_000, 0, 0, Some(99_000)), NOW)
        .await
        .unwrap();
    assert_eq!(
        events(pool, &sub).await,
        [(None, false, None, "subscription".to_owned())],
        "no dollars for a subscription, even reported ones"
    );

    let r = cost_report(pool, CostScope::Company(company))
        .await
        .unwrap();
    // 1.234567 reported + 333333 tokens at $1.25/Mtok = 0.416666 (0.41666625, rounded).
    assert_eq!(r.cost_usd_micros, 1_234_567 + 416_666);
    assert_eq!(
        (r.runs, r.priced_runs, r.unpriced_runs, r.subscription_runs),
        (4, 2, 1, 1)
    );
    assert_eq!(
        (r.input_tokens, r.output_tokens, r.cache_tokens),
        (334_350, 20, 30)
    );
    assert_eq!((r.unpriced_tokens, r.subscription_tokens), (7, 1_000));
    assert_eq!(cost_json(&r)["cost_usd"], "1.651233");
}

/// The cost comes at the turn's close, after its tokens were reported: it still goes in, once,
/// even a reported $0 (a free model), which is a price, not a missing one.
#[tokio::test]
async fn a_cost_reported_after_its_tokens_still_prices_the_run() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let oc = on(pool, dev, Harness::Opencode, "free").await;
    let run = run_of(pool, oc, Harness::Opencode, i).await;
    let cost_of = |id| async move {
        get_run(pool, id)
            .await
            .unwrap()
            .unwrap()
            .usage
            .cost_usd_micros
    };
    let first = record_run_usage(pool, &run, 1, &totals(900, 100, 0, None), NOW).await;
    assert!(first.unwrap().is_some());
    assert_eq!(cost_of(run.id).await, None);
    let late = record_run_usage(pool, &run, 2, &totals(900, 100, 0, Some(0)), NOW)
        .await
        .unwrap()
        .expect("the cost is news");
    assert_eq!(
        (late.usage.input_tokens, late.usage.cost_usd_micros),
        (0, Some(0))
    );
    assert_eq!(cost_of(run.id).await, Some(0));
    let again = record_run_usage(pool, &run, 3, &totals(900, 100, 0, Some(0)), NOW).await;
    assert_eq!(again.unwrap(), None, "nothing new");
    assert_eq!(events(pool, &run).await.len(), 2);
}
