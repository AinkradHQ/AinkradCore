//! What a session's gateway reported, and what the Core does with it (KAN-435 G5): recorded into the
//! ledger inside the transaction that stores the answer, the cursor that is acknowledged, the stop a
//! budget orders and the auth failures kept for a check. See [`super`] for the rules.

use ainkrad_proto::v2::{GatewayReport, GatewayReportKind, UpstreamStatus, ceiling_tokens};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::super::agents::SessionSecret;
use super::super::budgets::guard;
use super::super::costs::{self, NewCost};
use super::super::prices;
use super::super::secrets::Error;
use super::{MAX_CONFIRM_TRIES, account_secret, gateway_secret, refs, subjects_of};

/// The largest count the ledger takes from one report (a runner's number is not trusted to be sane:
/// the sums over the ledger must never overflow).
const MAX_COUNT: u64 = 1 << 40;

/// Why a hard-stop budget of the account or its pools has nothing left, if one has.
async fn exhausted(
    conn: &mut SqliteConnection,
    account: i64,
    session: &str,
    now: &str,
) -> Result<Option<String>, sqlx::Error> {
    let owned = subjects_of(conn, account).await?;
    let all = guard::standings_for(conn, &refs(&owned), now, session, true).await?;
    Ok(all.iter().find(|s| s.exhausted()).map(|s| {
        format!(
            "budget exhausted: {} {} ({}, {})",
            s.budget.kind, s.budget.subject, s.budget.period, s.period_key
        )
    }))
}

fn clamp(n: u64) -> i64 {
    i64::try_from(n.min(MAX_COUNT)).unwrap_or(i64::MAX)
}

/// Records what a session's gateway reported, in the caller's transaction; whether the session is
/// served by a gateway at all (a report for any other session is ignored, and never acknowledged).
///
/// Takes the run of reports that continues `gw_seq` (a duplicate is skipped, a hole stops the run:
/// the rest waits for the next read) and records each usage report in the ledger under
/// `gw:<session>:<epoch>:<gw_seq>`, against the account and provider of the Core's own row, priced
/// by the Core's price book, whatever the report's status says (an unreachable upstream with an
/// approximate count is still spend). An upstream `auth_failed` is kept as a pending signal. Then it
/// looks at the budgets: any hard-stop budget with nothing left marks the session to be stopped. A
/// report the ledger refuses for good (a count it cannot take) is logged and passed over, never
/// retried forever: the cursor would never move and the runner would fail closed.
pub async fn absorb(
    conn: &mut SqliteConnection,
    session: &str,
    reports: &[GatewayReport],
    now: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT gateway_account_id, gw_seq, harness, secrets, gw_stop FROM core_agent_sessions \
         WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(false) };
    let Some(account) = row.try_get::<Option<i64>, _>("gateway_account_id")? else {
        return Ok(false);
    };
    let (seq, harness): (i64, String) = (row.try_get("gw_seq")?, row.try_get("harness")?);
    let secrets: Vec<SessionSecret> =
        serde_json::from_str(&row.try_get::<String, _>("secrets")?).unwrap_or_default();
    let Some((provider, _)) = gateway_secret(&secrets).and_then(|s| account_secret(&s.name)) else {
        tracing::error!(session, "a gateway session without its account secret");
        return Ok(true);
    };
    let mut cursor = u64::try_from(seq).unwrap_or(0);
    let start = cursor;
    let mut ordered: Vec<&GatewayReport> = reports.iter().collect();
    ordered.sort_by_key(|r| r.gw_seq);
    for r in ordered {
        if r.gw_seq <= cursor {
            continue; // held already: a resend, still acknowledged
        }
        if r.gw_seq != cursor + 1 {
            break; // a hole: the rest waits for the next read, from the cursor
        }
        record(conn, session, account, provider, &harness, r, now).await?;
        cursor = r.gw_seq;
    }
    if cursor > start {
        sqlx::query("UPDATE core_agent_sessions SET gw_seq = ? WHERE id = ?")
            .bind(i64::try_from(cursor).unwrap_or(i64::MAX))
            .bind(session)
            .execute(&mut *conn)
            .await?;
        refresh_usage(conn, session).await?;
    }
    // After every answer, not only after a new report: a stop a crash lost is found again here.
    if row.try_get::<Option<String>, _>("gw_stop")?.is_none()
        && let Some(why) = exhausted(conn, account, session, now).await?
    {
        sqlx::query(
            "UPDATE core_agent_sessions SET gw_stop = ? WHERE id = ? AND gw_stop IS NULL \
             AND state NOT IN ('ended', 'lost')",
        )
        .bind(why)
        .bind(session)
        .execute(&mut *conn)
        .await?;
    }
    Ok(true)
}

/// One report, in order.
async fn record(
    conn: &mut SqliteConnection,
    session: &str,
    account: i64,
    provider: &str,
    harness: &str,
    r: &GatewayReport,
    now: &str,
) -> Result<(), sqlx::Error> {
    let key = format!("gw:{session}:{}:{}", r.epoch, r.gw_seq);
    if r.kind == GatewayReportKind::Usage {
        let cache = r.cache_read.saturating_add(r.cache_write);
        let reported = r.reported_usd_micros.map(clamp);
        if ceiling_tokens(r.input, r.output, cache, 0) > 0 || reported.is_some() {
            // The model is the request's own text: a name the ledger does not take is "unknown".
            let model = r
                .model
                .as_deref()
                .filter(|m| prices::valid_model(m))
                .unwrap_or("unknown");
            let cost = NewCost {
                session,
                epoch: i64::from(r.epoch),
                account_id: Some(account),
                legacy_account_id: None,
                provider,
                harness,
                model,
                input_tokens: clamp(r.input),
                output_tokens: clamp(r.output),
                cache_tokens: clamp(cache),
                reported_usd_micros: reported,
                approximate: r.approximate,
                subjects: &[],
                idempotency_key: &key,
                occurred_at: now,
            };
            match costs::record_in(conn, &cost, now).await {
                Ok(_) => {}
                Err(Error::Db(e)) => return Err(e),
                Err(Error::Refused { code, message: why }) => {
                    tracing::error!(
                        session,
                        gw_seq = r.gw_seq,
                        code,
                        why,
                        "a gateway report the ledger refused was passed over"
                    );
                }
            }
        }
    }
    if r.status == UpstreamStatus::AuthFailed {
        sqlx::query(
            "INSERT INTO core_account_auth_signals (account_id, session, gw_key, seen_at) \
             VALUES (?, ?, ?, ?) ON CONFLICT (gw_key) DO NOTHING",
        )
        .bind(account)
        .bind(session)
        .bind(&key)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// A gateway session's usage columns are the ledger's, not its harness's meter.
async fn refresh_usage(conn: &mut SqliteConnection, session: &str) -> Result<(), sqlx::Error> {
    let [input, output, cache, _] = costs::session_totals(conn, session).await?;
    let cost = costs::session_cost(conn, session).await?;
    sqlx::query(
        "UPDATE core_agent_sessions SET tokens_in = ?, tokens_out = ?, cache_read = ?, \
         cache_write = 0, cost_usd_micros = ? WHERE id = ?",
    )
    .bind(input)
    .bind(output)
    .bind(cache)
    .bind(cost)
    .bind(session)
    .execute(conn)
    .await
    .map(drop)
}

/// The newest gateway report of `session` the ledger holds (what the next read acknowledges).
pub async fn acked(pool: &SqlitePool, session: &str) -> Result<u64, sqlx::Error> {
    let n: Option<i64> = sqlx::query_scalar("SELECT gw_seq FROM core_agent_sessions WHERE id = ?")
        .bind(session)
        .fetch_optional(pool)
        .await?;
    Ok(u64::try_from(n.unwrap_or(0)).unwrap_or(0))
}

/// The Core told the runner to stop the session at `at` (unix seconds): once, until a reserve.
pub async fn mark_stopped(pool: &SqlitePool, session: &str, at: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_agent_sessions SET gw_stopped_at = ? WHERE id = ? AND gw_stopped_at IS NULL",
    )
    .bind(at)
    .bind(session)
    .execute(pool)
    .await
    .map(drop)
}

/// The pending auth signal of `account` and how often it was tried, oldest first.
pub async fn pending_auth(
    pool: &SqlitePool,
    account: i64,
) -> Result<Option<(i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, tries FROM core_account_auth_signals WHERE account_id = ? AND state = 'pending' \
         ORDER BY id LIMIT 1",
    )
    .bind(account)
    .fetch_optional(pool)
    .await
}

/// One more test of the pending signal came back without an answer; after
/// [`MAX_CONFIRM_TRIES`] it is `inconclusive` and nothing more is asked.
pub async fn tried(pool: &SqlitePool, signal: i64, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_account_auth_signals SET tries = tries + 1, \
         state = iif(tries + 1 >= ?, 'inconclusive', state), \
         decided_at = iif(tries + 1 >= ?, ?, decided_at) WHERE id = ?",
    )
    .bind(MAX_CONFIRM_TRIES)
    .bind(MAX_CONFIRM_TRIES)
    .bind(now)
    .bind(signal)
    .execute(pool)
    .await
    .map(drop)
}

/// Settles every pending signal of `account` as `state` (`confirmed` or `cleared`).
pub async fn decide(
    pool: &SqlitePool,
    account: i64,
    state: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_account_auth_signals SET state = ?, decided_at = ? \
         WHERE account_id = ? AND state = 'pending'",
    )
    .bind(state)
    .bind(now)
    .bind(account)
    .execute(pool)
    .await
    .map(drop)
}

/// The details an `agent.cancelled` audit row of a budget stop carries.
pub fn stop_details(why: &str) -> serde_json::Value {
    json!({"reason": "budget", "detail": why})
}
