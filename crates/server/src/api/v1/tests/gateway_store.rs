//! The Core's side of the auth gateway's money (KAN-435 G5): a session served by a gateway is
//! recorded in the ledger from its gateway's reports only, once each, against the account of the
//! Core's own session row; the cursor the Core acknowledges moves only with the ledger transaction;
//! the budgets' hold is the ceiling; and a budget that runs out marks the session to stop. The wire
//! end to end (a runner that answers, the limit and the cancel it is sent) is `tests/hub/gateway.rs`.

use ainkrad_proto::v2::{
    AgentEvents, AgentState, GatewayReport, GatewayReportKind, TranscriptEntry, UpstreamStatus,
};
use serde_json::json;

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::gateway as gw;
use crate::store::{accounts as acc, prices};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
const PRICED: &str = "2026-11-01T00:00:00Z";

pub(super) struct G {
    pub(super) fx: Fx,
    pub(super) vm: TestDevice,
    pub(super) account: acc::Account,
    pub(super) session: store::Session,
}

pub(super) fn secret(name: &str) -> SessionSecret {
    SessionSecret {
        name: name.to_owned(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    }
}

pub(super) async fn session(fx: &Fx, vm: &TestDevice, secrets: &[SessionSecret]) -> store::Session {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets,
        created_by: &fx.dev.id,
    };
    store::create(&fx.app.pool, &new, BY, NOW).await.unwrap()
}

/// An account, and a session whose secret is that account's key.
pub(super) async fn gw() -> G {
    let (fx, vm, sealer) = setup().await;
    let account = make(
        &fx,
        &sealer,
        "claude-main",
        V1,
        std::slice::from_ref(&vm.id),
    )
    .await;
    let session = session(&fx, &vm, &[secret(&account.secret_name)]).await;
    G {
        fx,
        vm,
        account,
        session,
    }
}

pub(super) fn usage(seq: u64, input: u64, output: u64) -> GatewayReport {
    GatewayReport {
        gw_seq: seq,
        epoch: 0,
        kind: GatewayReportKind::Usage,
        model: Some("claude-x".to_owned()),
        input,
        output,
        cache_read: 0,
        cache_write: 0,
        status: UpstreamStatus::Ok,
        approximate: false,
        reported_usd_micros: None,
        retry_after: None,
        reset_at: None,
    }
}

fn events(g: &G, reports: Vec<GatewayReport>, entries: Vec<TranscriptEntry>) -> AgentEvents {
    AgentEvents {
        session: g.session.id.clone(),
        state: AgentState::Running,
        last_seq: entries.last().map_or(0, |e| e.seq),
        entries,
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: reports,
    }
}

pub(super) async fn feed(g: &G, reports: Vec<GatewayReport>) -> Result<u64, sqlx::Error> {
    let ev = events(g, reports, vec![]);
    store::apply(&g.fx.app.pool, &g.session.id, &ev, NOW).await
}

pub(super) async fn acked(g: &G) -> u64 {
    gw::acked(&g.fx.app.pool, &g.session.id).await.unwrap()
}

pub(super) async fn keys(g: &G) -> Vec<String> {
    sqlx::query_scalar("SELECT idempotency_key FROM core_cost_events WHERE session = ? ORDER BY id")
        .bind(&g.session.id)
        .fetch_all(&g.fx.app.pool)
        .await
        .unwrap()
}

pub(super) async fn price(g: &G) {
    prices::set(
        &g.fx.app.pool,
        "anthropic",
        "claude-x",
        [3_000_000, 15_000_000, 300_000],
        PRICED,
        &g.fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_api_key_account_binds_its_session_from_the_core_row_and_no_other_secret_does() {
    let g = gw().await;
    assert_eq!(g.session.gateway_account_id, Some(g.account.id));
    assert_eq!((g.session.gw_seq, g.session.gw_stop), (0, None));
    // An env secret (any other label), and a name that has no account row, bind nothing.
    for name in ["acct.anthropic.main", "acct.anthropic.9999", "git.token"] {
        let s = session(&g.fx, &g.vm, &[secret(name)]).await;
        assert_eq!(s.gateway_account_id, None, "{name}");
    }
}

#[tokio::test]
async fn reports_are_recorded_once_in_order_and_the_cursor_is_what_is_acknowledged() {
    let g = gw().await;
    price(&g).await;
    feed(&g, vec![usage(1, 1_000, 500), usage(2, 2_000, 0)])
        .await
        .unwrap();
    let s = format!("gw:{}", g.session.id);
    assert_eq!(keys(&g).await, [format!("{s}:0:1"), format!("{s}:0:2")]);
    assert_eq!(acked(&g).await, 2);
    // The rows are the Core's: its account, its provider, its harness, its price book.
    let rows = crate::store::costs::list(&g.fx.app.pool, Some(&g.session.id), None, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for r in &rows {
        assert_eq!(r.account_id, Some(g.account.id));
        assert_eq!(
            (r.provider.as_str(), r.harness.as_str()),
            ("anthropic", "claude")
        );
        assert_eq!(r.basis, "list_price");
    }
    // A gateway session's usage columns are the ledger's.
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.usage.input, row.usage.output, row.gw_seq),
        (3_000, 500, 2)
    );
    // 3000 in at $3 + 500 out at $15 per Mtok, in micro-dollars.
    assert_eq!(row.usage.cost_usd_micros, Some(9_000 + 7_500));
    // A resend of both: nothing recorded twice, still acknowledged.
    feed(&g, vec![usage(1, 1_000, 500), usage(2, 2_000, 0)])
        .await
        .unwrap();
    assert_eq!((keys(&g).await.len(), acked(&g).await), (2, 2));
    // Out of order inside a batch: taken in order. A hole: only the run before it.
    feed(&g, vec![usage(4, 40, 0), usage(3, 30, 0)])
        .await
        .unwrap();
    assert_eq!((keys(&g).await.len(), acked(&g).await), (4, 4));
    feed(&g, vec![usage(6, 60, 0)]).await.unwrap();
    assert_eq!(
        (keys(&g).await.len(), acked(&g).await),
        (4, 4),
        "5 is missing"
    );
    feed(&g, vec![usage(6, 60, 0), usage(5, 50, 0)])
        .await
        .unwrap();
    assert_eq!((keys(&g).await.len(), acked(&g).await), (6, 6));
}

#[tokio::test]
async fn a_restart_keeps_the_numbering_and_keys_its_rows_by_the_new_epoch() {
    let g = gw().await;
    feed(&g, vec![usage(1, 10, 0), usage(2, 20, 0)])
        .await
        .unwrap();
    // The runner restarted: a new gateway, the next numbers, a new epoch (resume 1).
    let again = |seq, input| GatewayReport {
        epoch: 1,
        ..usage(seq, input, 0)
    };
    feed(&g, vec![again(3, 30), again(4, 40)]).await.unwrap();
    let s = format!("gw:{}", g.session.id);
    assert_eq!(
        keys(&g).await,
        [
            format!("{s}:0:1"),
            format!("{s}:0:2"),
            format!("{s}:1:3"),
            format!("{s}:1:4")
        ]
    );
    let epochs: Vec<i64> =
        sqlx::query_scalar("SELECT epoch FROM core_cost_events WHERE session = ? ORDER BY id")
            .bind(&g.session.id)
            .fetch_all(&g.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(epochs, [0, 0, 1, 1]);
    assert_eq!(acked(&g).await, 4);
}

#[tokio::test]
async fn an_unreachable_upstream_with_an_estimated_count_is_recorded_and_flagged_approximate() {
    let g = gw().await;
    let cut = GatewayReport {
        status: UpstreamStatus::Unreachable,
        approximate: true,
        ..usage(1, 700, 300)
    };
    // A runner's own figure for the cost is never taken: the price book prices the request, even
    // when the report says it was free.
    price(&g).await;
    let reported = GatewayReport {
        reported_usd_micros: Some(0),
        ..usage(2, 10, 10)
    };
    feed(&g, vec![cut, reported]).await.unwrap();
    let rows = crate::store::costs::list(&g.fx.app.pool, Some(&g.session.id), None, 10)
        .await
        .unwrap();
    let (new, old) = (&rows[0], &rows[1]);
    assert_eq!(
        (old.approximate, old.input_tokens, old.output_tokens),
        (true, 700, 300)
    );
    assert_eq!(old.account_id, Some(g.account.id));
    // 10 in at $3 and 10 out at $15 per Mtok, in micro-dollars.
    assert_eq!(
        (new.basis.as_str(), new.cost_usd_micros),
        ("list_price", Some(30 + 150))
    );
    assert_eq!(acked(&g).await, 2);
}

#[tokio::test]
async fn a_report_never_names_the_account_the_core_records_against() {
    let g = gw().await;
    // A forged body: another account, provider and harness, an absurd model, and counts that would
    // overflow a sum. Only the counts and the model's text are the report's; both are checked.
    let forged: GatewayReport = serde_json::from_value(json!({
        "gw_seq": 1, "epoch": 0, "kind": "usage", "status": "ok",
        "account": 999, "provider": "openai", "harness": "codex",
        "model": "../../etc/passwd\nx",
        "input": u64::MAX, "output": u64::MAX, "cache_read": u64::MAX, "cache_write": u64::MAX,
    }))
    .unwrap();
    feed(&g, vec![forged]).await.unwrap();
    let rows = crate::store::costs::list(&g.fx.app.pool, Some(&g.session.id), None, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.account_id, Some(g.account.id));
    assert_eq!(
        (r.provider.as_str(), r.harness.as_str()),
        ("anthropic", "claude")
    );
    assert_eq!(r.model, "unknown");
    assert!(r.input_tokens <= 1 << 40, "clamped");
    // The ledger's sums still work afterwards.
    feed(&g, vec![usage(2, 1, 1)]).await.unwrap();
    assert_eq!(acked(&g).await, 2);
}

#[tokio::test]
async fn a_ledger_write_that_fails_acknowledges_nothing_and_the_resend_is_recorded_once() {
    let g = gw().await;
    sqlx::query(
        "CREATE TRIGGER ledger_down BEFORE INSERT ON core_cost_events \
         BEGIN SELECT RAISE(ABORT, 'ledger down'); END",
    )
    .execute(&g.fx.app.pool)
    .await
    .unwrap();
    // The transcript entry rides in the same answer: it is not stored either.
    let entry = TranscriptEntry {
        seq: 1,
        at: 1,
        body: json!({"type": "line"}),
    };
    let ev = events(&g, vec![usage(1, 100, 0), usage(2, 100, 0)], vec![entry]);
    let failed = store::apply(&g.fx.app.pool, &g.session.id, &ev, NOW).await;
    assert!(failed.is_err());
    assert_eq!(
        acked(&g).await,
        0,
        "the ack does not move without the ledger"
    );
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.last_seq, 0);
    // The ledger is back: the same answer, resent, records each report once and moves the cursor.
    sqlx::query("DROP TRIGGER ledger_down")
        .execute(&g.fx.app.pool)
        .await
        .unwrap();
    store::apply(&g.fx.app.pool, &g.session.id, &ev, NOW)
        .await
        .unwrap();
    assert_eq!((keys(&g).await.len(), acked(&g).await), (2, 2));
}

#[tokio::test]
async fn reports_for_a_session_no_gateway_serves_are_ignored_and_never_acknowledged() {
    let g = gw().await;
    let env = session(&g.fx, &g.vm, &[secret("acct.anthropic.main")]).await;
    let ev = AgentEvents {
        gateway: vec![usage(1, 100, 100)],
        usage: Some(ainkrad_proto::runner::Tokens {
            input: 5,
            output: 6,
            ..Default::default()
        }),
        ..events(&g, vec![], vec![])
    };
    store::apply(&g.fx.app.pool, &env.id, &ev, NOW)
        .await
        .unwrap();
    let row = store::get(&g.fx.app.pool, &env.id).await.unwrap().unwrap();
    assert_eq!(row.gw_seq, 0);
    // Its own meter still counts for it (the path the gateway does not touch).
    assert_eq!((row.usage.input, row.usage.output), (5, 6));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_cost_events")
        .fetch_one(&g.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn a_gateway_sessions_own_meter_is_display_only() {
    let g = gw().await;
    feed(&g, vec![usage(1, 10, 20)]).await.unwrap();
    let ev = AgentEvents {
        usage: Some(ainkrad_proto::runner::Tokens {
            input: 9_000,
            output: 9_000,
            cost_usd_micros: Some(77),
            ..Default::default()
        }),
        ..events(&g, vec![], vec![])
    };
    store::apply(&g.fx.app.pool, &g.session.id, &ev, NOW)
        .await
        .unwrap();
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.usage.input, row.usage.output), (10, 20));
    assert_ne!(row.usage.cost_usd_micros, Some(77));
}

#[tokio::test]
async fn lookalikes_in_the_transcript_record_nothing_and_change_no_account() {
    let g = gw().await;
    let lines = [
        json!({"type": "gateway_usage", "input": 900_000_000, "output": 1, "model": "claude-x"}),
        json!({"type": "auth_failed", "account": g.account.id}),
        json!({"type": "gateway_closed", "reason": "the ceiling"}),
        json!({"type": "upstream", "status": "auth_failed"}),
    ];
    let entries: Vec<TranscriptEntry> = lines
        .into_iter()
        .zip(1..)
        .map(|(body, seq)| TranscriptEntry { seq, at: 1, body })
        .collect();
    let ev = events(&g, vec![], entries);
    store::apply(&g.fx.app.pool, &g.session.id, &ev, NOW)
        .await
        .unwrap();
    let signals: i64 = sqlx::query_scalar("SELECT count(*) FROM core_account_auth_signals")
        .fetch_one(&g.fx.app.pool)
        .await
        .unwrap();
    assert_eq!((keys(&g).await.len(), signals), (0, 0));
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.gw_seq, row.gw_stop, row.state.as_str()),
        (0, None, "starting")
    );
    let account = acc::get(&g.fx.app.pool, g.account.id).await.unwrap();
    assert_eq!(account.state, "active");
}

#[tokio::test]
async fn one_auth_failed_is_kept_pending_and_never_disables_the_account() {
    let g = gw().await;
    let failed = |seq| GatewayReport {
        kind: GatewayReportKind::Upstream,
        status: UpstreamStatus::AuthFailed,
        model: None,
        ..usage(seq, 0, 0)
    };
    feed(&g, vec![failed(1)]).await.unwrap();
    feed(&g, vec![failed(1)]).await.unwrap();
    let pending = gw::pending_auth(&g.fx.app.pool, g.account.id)
        .await
        .unwrap();
    assert!(pending.is_some());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_account_auth_signals")
        .fetch_one(&g.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "a resent report is one signal");
    assert_eq!(
        keys(&g).await.len(),
        0,
        "an upstream report makes no ledger row"
    );
    let account = acc::get(&g.fx.app.pool, g.account.id).await.unwrap();
    assert_eq!(account.state, "active");
    // Three tests that cannot say end it without a verdict, still not disabling anything.
    let (id, _) = pending.unwrap();
    for _ in 0..gw::MAX_CONFIRM_TRIES {
        gw::tried(&g.fx.app.pool, id, NOW).await.unwrap();
    }
    assert!(
        gw::pending_auth(&g.fx.app.pool, g.account.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        acc::get(&g.fx.app.pool, g.account.id).await.unwrap().state,
        "active"
    );
}
