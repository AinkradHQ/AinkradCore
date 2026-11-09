//! Usage per attempt for a subscription session (KAN-436 S1): the harness meter's running total
//! becomes ledger deltas under `hm:<session>:<epoch>:<in>.<out>.<cache>`, unpriced, against the
//! account of the Core's own session row, in the transaction of the cursor; and no session has two
//! ledger writers (a gateway session and a module session never get an `hm:` row).

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::runner::Tokens;
use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};
use serde_json::json;

use super::accounts_store::setup;
use super::gateway_store::{gw as gateway, usage as report};
use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::budgets::{self, NewBudget};
use crate::store::{accounts as acc, settings};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";

struct M {
    fx: Fx,
    account: acc::Account,
    session: store::Session,
}

async fn session(
    fx: &Fx,
    runner: &str,
    owner: Option<&str>,
    secrets: &[SessionSecret],
) -> store::Session {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets,
        created_by: &fx.dev.id,
    };
    store::create_owned(&fx.app.pool, &new, owner, BY, NOW)
        .await
        .unwrap()
}

fn sub_secret(a: &acc::Account) -> SessionSecret {
    SessionSecret {
        name: a.secret_name.clone(),
        var: "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
    }
}

/// A subscription account and a session that names it.
async fn m() -> M {
    let (fx, vm, sealer) = setup().await;
    let gate = settings::set(
        &fx.app.pool,
        Key::SecretsProviderAccounts,
        Scope::Server,
        "1",
        BY,
        NOW,
    );
    gate.await.unwrap();
    let new = acc::NewAccount {
        provider: "claude-sub",
        label: "claude-me",
        value: TOKEN,
        runners: std::slice::from_ref(&vm.id),
        cap: None,
    };
    let account = acc::create_by(
        &fx.app.pool,
        &sealer,
        &new,
        "subscription",
        &fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
    let session = session(&fx, &vm.id, None, &[sub_secret(&account)]).await;
    M {
        fx,
        account,
        session,
    }
}

fn tokens(input: u64, output: u64, cache: u64) -> Tokens {
    Tokens {
        input,
        output,
        cache_read: cache,
        cache_write: 0,
        // The harness's own (notional) cost: never what the ledger records.
        cost_usd_micros: Some(999_999),
    }
}

fn events(id: &str, usage: Tokens, entries: Vec<TranscriptEntry>) -> AgentEvents {
    AgentEvents {
        session: id.to_owned(),
        state: AgentState::Running,
        last_seq: entries.last().map_or(0, |e| e.seq),
        entries,
        harness_session: None,
        usage: Some(usage),
        outcome: None,
        gateway: vec![],
        plan_limit: None,
    }
}

async fn feed(fx: &Fx, id: &str, usage: Tokens) -> u64 {
    let ev = events(id, usage, vec![]);
    store::apply(&fx.app.pool, id, &ev, NOW).await.unwrap()
}

async fn meter(fx: &Fx, id: &str) -> Vec<(String, i64, i64, i64)> {
    sqlx::query_as(
        "SELECT idempotency_key, input_tokens, output_tokens, cache_tokens \
         FROM core_cost_events WHERE session = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&fx.app.pool)
    .await
    .unwrap()
}

fn key(id: &str, epoch: i64, c: &str) -> String {
    format!("hm:{id}:{epoch}:{c}")
}

#[tokio::test]
async fn a_running_total_becomes_deltas_and_a_resend_or_a_lower_total_records_nothing() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(100, 20, 5)).await;
    feed(&m.fx, id, tokens(100, 20, 5)).await; // a resend
    feed(&m.fx, id, tokens(160, 50, 5)).await;
    feed(&m.fx, id, tokens(90, 10, 0)).await; // below the mark
    feed(&m.fx, id, tokens(160, 50, 5)).await;
    assert_eq!(
        meter(&m.fx, id).await,
        [
            (key(id, 0, "100.20.5"), 100, 20, 5),
            (key(id, 0, "160.50.5"), 60, 30, 0),
        ]
    );
}

#[tokio::test]
async fn the_same_sum_with_another_split_is_a_new_row_never_a_ledger_conflict() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(60, 40, 0)).await;
    feed(&m.fx, id, tokens(40, 60, 0)).await; // sum 100 again, split 40/60: only output rose
    feed(&m.fx, id, tokens(60, 60, 0)).await;
    let rows = meter(&m.fx, id).await;
    assert_eq!(
        rows,
        [
            (key(id, 0, "60.40.0"), 60, 40, 0),
            (key(id, 0, "60.60.0"), 0, 20, 0),
        ]
    );
}

/// What `agents::launch` does on a resume or a wake, restart included: the state moves to
/// `running` with the resume counted (the epoch), then the start answer is applied.
async fn resume(m: &M, answer: Option<Tokens>) {
    let id = &m.session.id;
    let p = &m.fx.app.pool;
    store::set_state(p, id, "interrupted", "the runner restarted", false, NOW)
        .await
        .unwrap();
    store::set_state(p, id, "running", "resumed", true, NOW)
        .await
        .unwrap();
    let mut ev = events(id, tokens(0, 0, 0), vec![]);
    ev.usage = answer;
    store::apply(p, id, &ev, NOW).await.unwrap();
}

#[tokio::test]
async fn a_resumed_runs_stale_total_is_not_booked_again_and_its_real_total_counts_from_zero() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(500, 40, 10)).await;
    // An older runner still carries the last run's total in the start answer and the reads until
    // the new run reports: nothing is recorded, and the epoch's mark does not move.
    resume(&m, Some(tokens(500, 40, 10))).await;
    feed(&m.fx, id, tokens(500, 40, 10)).await;
    assert_eq!(meter(&m.fx, id).await.len(), 1);
    // The new run's first real total is small: all of it is new.
    feed(&m.fx, id, tokens(30, 0, 0)).await;
    feed(&m.fx, id, tokens(30, 0, 0)).await;
    feed(&m.fx, id, tokens(80, 5, 0)).await;
    // And again, a second resume (a wake): the same.
    resume(&m, Some(tokens(80, 5, 0))).await;
    feed(&m.fx, id, tokens(80, 5, 0)).await;
    feed(&m.fx, id, tokens(7, 0, 0)).await;
    assert_eq!(
        meter(&m.fx, id).await,
        [
            (key(id, 0, "500.40.10"), 500, 40, 10),
            (key(id, 1, "30.0.0"), 30, 0, 0),
            (key(id, 1, "80.5.0"), 50, 5, 0),
            (key(id, 2, "7.0.0"), 7, 0, 0),
        ]
    );
}

#[tokio::test]
async fn a_runner_that_clears_its_total_at_a_start_counts_the_new_run_from_zero() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(500, 0, 0)).await;
    resume(&m, None).await; // the start answer carries no usage
    feed(&m.fx, id, tokens(30, 0, 0)).await;
    let rows = meter(&m.fx, id).await;
    assert_eq!(rows[1], (key(id, 1, "30.0.0"), 30, 0, 0), "{rows:?}");
}

#[tokio::test]
async fn the_sessions_row_agrees_with_the_ledger_and_shows_no_notional_dollars() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(100, 20, 5)).await;
    resume(&m, Some(tokens(100, 20, 5))).await; // stale: the row does not change
    feed(&m.fx, id, tokens(10, 0, 0)).await;
    let row = store::get(&m.fx.app.pool, id).await.unwrap().unwrap();
    assert_eq!(
        (row.usage.input, row.usage.output, row.usage.cache_read),
        (110, 20, 5)
    );
    assert_eq!(
        row.usage.cost_usd_micros, None,
        "the harness's figure is notional"
    );
}

#[tokio::test]
async fn a_sessions_unreadable_secrets_record_nothing() {
    let m = m().await;
    sqlx::query("UPDATE core_agent_sessions SET secrets = '[1]' WHERE id = ?")
        .bind(&m.session.id)
        .execute(&m.fx.app.pool)
        .await
        .unwrap();
    feed(&m.fx, &m.session.id, tokens(10, 0, 0)).await;
    assert!(meter(&m.fx, &m.session.id).await.is_empty());
}

#[tokio::test]
async fn the_mark_lives_in_the_row_so_a_restart_mid_session_counts_nothing_twice() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(100, 0, 0)).await;
    // A Core restart: the same pool, no memory. The runner resends its total, then goes on.
    let again = crate::store::agents::get(&m.fx.app.pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.id, *id);
    feed(&m.fx, id, tokens(100, 0, 0)).await;
    feed(&m.fx, id, tokens(130, 0, 0)).await;
    let rows = meter(&m.fx, id).await;
    assert_eq!(
        rows.iter().map(|r| r.1).collect::<Vec<_>>(),
        [100, 30],
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_subscription_row_is_unpriced_for_the_sessions_own_account_and_moves_tokens_not_dollars()
{
    let m = m().await;
    let id = &m.session.id;
    let bud = |kind: &'static str, tokens, usd| NewBudget {
        kind,
        subject: "",
        company: None,
        period: "day",
        token_cap: tokens,
        usd_cap_micros: usd,
        warn_at_percent: None,
        hard_stop: true,
    };
    let subject = m.account.id.to_string();
    let mut tok = bud("account", 1000, None);
    tok.subject = &subject;
    let tok = budgets::set(&m.fx.app.pool, &tok, &m.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let mut usd = bud("account", 0, Some(5_000));
    usd.subject = &subject;
    usd.period = "week";
    let usd = budgets::set(&m.fx.app.pool, &usd, &m.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    feed(&m.fx, id, tokens(100, 20, 5)).await;
    let (cost, basis, provider, account, harness): (
        Option<i64>,
        String,
        String,
        Option<i64>,
        String,
    ) = sqlx::query_as(
        "SELECT cost_usd_micros, basis, provider, account_id, harness \
             FROM core_cost_events WHERE session = ?",
    )
    .bind(id)
    .fetch_one(&m.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        (
            cost,
            basis.as_str(),
            provider.as_str(),
            account,
            harness.as_str()
        ),
        (None, "unpriced", "claude-sub", Some(m.account.id), "claude")
    );
    let st = |b: &budgets::Budget| budgets::standing_of(&m.fx.app.pool, b.id, NOW);
    let tok = st(&tok).await.unwrap().unwrap();
    let usd = st(&usd).await.unwrap().unwrap();
    assert_eq!((tok.spent, tok.usd_spent), (125, 0));
    assert_eq!((usd.spent, usd.usd_spent), (125, 0), "no dollar moved");
}

#[tokio::test]
async fn the_cursor_and_the_ledger_commit_together() {
    let m = m().await;
    let id = &m.session.id;
    let entry = |seq| TranscriptEntry {
        seq,
        at: 1,
        body: json!({"type": "line", "n": seq}),
    };
    // A ledger that refuses the write fails the whole answer: nothing is held, so nothing is acknowledged.
    sqlx::raw_sql(
        "CREATE TRIGGER no_ledger BEFORE INSERT ON core_cost_events \
         BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .execute(&m.fx.app.pool)
    .await
    .unwrap();
    let ev = events(id, tokens(70, 0, 0), vec![entry(1), entry(2)]);
    assert!(store::apply(&m.fx.app.pool, id, &ev, NOW).await.is_err());
    let row = store::get(&m.fx.app.pool, id).await.unwrap().unwrap();
    assert_eq!(row.last_seq, 0);
    let mark: i64 = sqlx::query_scalar("SELECT hm_in FROM core_agent_sessions WHERE id = ?")
        .bind(id)
        .fetch_one(&m.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(mark, 0);
    sqlx::raw_sql("DROP TRIGGER no_ledger")
        .execute(&m.fx.app.pool)
        .await
        .unwrap();
    // The resend then lands both.
    assert_eq!(store::apply(&m.fx.app.pool, id, &ev, NOW).await.unwrap(), 2);
    assert_eq!(meter(&m.fx, id).await.len(), 1);
}

#[tokio::test]
async fn a_report_cannot_name_the_account_or_start_a_gateway_for_a_subscription_session() {
    let m = m().await;
    let id = &m.session.id;
    let mut ev = events(id, tokens(10, 0, 0), vec![]);
    ev.gateway = vec![report(1, 9_999, 0)];
    store::apply(&m.fx.app.pool, id, &ev, NOW).await.unwrap();
    // The report is ignored and never acknowledged; the meter's row carries the row's account.
    assert_eq!(
        crate::store::gateway::acked(&m.fx.app.pool, id)
            .await
            .unwrap(),
        0
    );
    let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT idempotency_key, account_id FROM core_cost_events WHERE session = ?",
    )
    .bind(id)
    .fetch_all(&m.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows, [(key(id, 0, "10.0.0"), Some(m.account.id))]);
}

#[tokio::test]
async fn a_gateway_session_never_writes_a_meter_row() {
    let g = gateway().await;
    let id = &g.session.id;
    let ev = events(id, tokens(500, 5, 5), vec![]);
    store::apply(&g.fx.app.pool, id, &ev, NOW).await.unwrap();
    assert!(meter(&g.fx, id).await.is_empty());
    let mut ev = events(id, tokens(900, 5, 5), vec![]);
    ev.gateway = vec![report(1, 7, 0)];
    store::apply(&g.fx.app.pool, id, &ev, NOW).await.unwrap();
    let keys = meter(&g.fx, id).await;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, format!("gw:{id}:0:1"), "the gateway's, only");
}

#[tokio::test]
async fn a_module_session_and_a_session_with_no_account_are_untouched() {
    let (fx, vm, _) = setup().await;
    let plain = session(&fx, &vm.id, None, &[]).await;
    feed(&fx, &plain.id, tokens(100, 1, 1)).await;
    assert!(meter(&fx, &plain.id).await.is_empty());
    let row = store::get(&fx.app.pool, &plain.id).await.unwrap().unwrap();
    assert_eq!(row.usage.input, 100, "the max() columns still move");
    // A module's session, even one that somehow names a subscription: the Citadel reconcile's.
    let m = m().await;
    let secrets = [sub_secret(&m.account)];
    let owned = session(&m.fx, &m.session.runner, Some("citadel"), &secrets).await;
    feed(&m.fx, &owned.id, tokens(100, 1, 1)).await;
    assert!(meter(&m.fx, &owned.id).await.is_empty());
}

#[tokio::test]
async fn an_account_deleted_under_a_live_session_still_gets_its_last_readings() {
    let m = m().await;
    let id = &m.session.id;
    feed(&m.fx, id, tokens(100, 20, 5)).await;
    let by = &m.fx.dev.id;
    acc::delete(&m.fx.app.pool, m.account.id, by, BY)
        .await
        .unwrap();
    // The runner's final reading arrives after the delete: the row's account id and the secret's
    // name still say whose it is (ids are never reused).
    feed(&m.fx, id, tokens(150, 30, 5)).await;
    let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT idempotency_key, account_id FROM core_cost_events WHERE session = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&m.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|r| r.1 == Some(m.account.id)));
}
