//! What a session's gateway reported, and what the Core does with it (KAN-435 G5): recorded into the
//! ledger inside the transaction that stores the answer, the cursor that is acknowledged, the stop a
//! budget orders and the auth failures kept for a check. See [`super`] for the rules.

use ainkrad_proto::v2::{GatewayReport, GatewayReportKind, UpstreamStatus, ceiling_tokens};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::super::agents::SessionSecret;
use super::super::budgets::guard;
use super::super::costs::{self, NewCost, Pricing};
use super::super::prices;
use super::super::prices::Rates;
use super::super::secrets::Error;
use super::ceiling::snapshot_rates;
use super::{account_secret, gateway_secret, refs, subjects_of};

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
        "SELECT gateway_account_id, gw_seq, gw_epoch, harness, secrets, gw_stop, gw_prices \
         FROM core_agent_sessions WHERE id = ?",
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
    let snapshot = snapshot_rates(row.try_get::<Option<String>, _>("gw_prices")?.as_deref());
    let mut cursor = u64::try_from(seq).unwrap_or(0);
    let mut epoch = u32::try_from(row.try_get::<i64, _>("gw_epoch")?).unwrap_or(0);
    let (start, start_epoch) = (cursor, epoch);
    let mut ordered: Vec<&GatewayReport> = reports.iter().collect();
    ordered.sort_by_key(|r| (r.epoch, r.gw_seq));
    for r in ordered {
        if r.epoch < epoch {
            continue; // an older epoch's report, held already
        }
        if r.epoch > epoch && r.gw_seq <= cursor {
            // A newer epoch numbering at or below the cursor: the runner lost its state and began
            // again from 1. It is not a resend, so the cursor starts over under the new epoch.
            cursor = 0;
        }
        if r.epoch == epoch && r.gw_seq <= cursor {
            continue; // held already: a resend, still acknowledged
        }
        if r.gw_seq != cursor + 1 {
            break; // a hole: the rest waits for the next read, from the cursor
        }
        let bound = Bound {
            session,
            account,
            provider,
            harness: &harness,
            snapshot: &snapshot,
        };
        record(conn, &bound, r, now).await?;
        cursor = r.gw_seq;
        epoch = r.epoch;
    }
    if cursor != start || epoch != start_epoch {
        sqlx::query("UPDATE core_agent_sessions SET gw_seq = ?, gw_epoch = ? WHERE id = ?")
            .bind(i64::try_from(cursor).unwrap_or(i64::MAX))
            .bind(i64::from(epoch))
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

/// What a report is recorded against: the Core's own row, never the report.
struct Bound<'a> {
    session: &'a str,
    account: i64,
    provider: &'a str,
    harness: &'a str,
    /// The grant's prices, for a model the book has lost.
    snapshot: &'a [(String, Rates)],
}

/// One report, in order.
async fn record(
    conn: &mut SqliteConnection,
    b: &Bound<'_>,
    r: &GatewayReport,
    now: &str,
) -> Result<(), sqlx::Error> {
    let Bound {
        session,
        account,
        provider,
        harness,
        snapshot,
    } = *b;
    let key = format!("gw:{session}:{}:{}", r.epoch, r.gw_seq);
    if r.kind == GatewayReportKind::Usage {
        let cache = r.cache_read.saturating_add(r.cache_write);
        if ceiling_tokens(r.input, r.output, cache, 0) > 0 {
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
                // The runner's own figure for the cost is never taken: what a request costs is the
                // Core's price book (or the grant's snapshot of it), not a runner's say-so.
                reported_usd_micros: None,
                approximate: r.approximate,
                subjects: &[],
                idempotency_key: &key,
                occurred_at: now,
            };
            let pricing = match prices::rates_in(conn, provider, model).await? {
                Some(_) => Pricing::Book,
                None => snapshot
                    .iter()
                    .find(|(m, _)| m == model)
                    .map_or(Pricing::Unpriced, |(_, r)| Pricing::Own(r.clone())),
            };
            match costs::record_priced_in(conn, &cost, pricing, now).await {
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
        super::signals::record(conn, account, session, &key, now).await?;
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

/// A reason to stop the session, set once (the supervisor cancels it, as for a budget that ran out).
pub async fn stop(pool: &SqlitePool, session: &str, why: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_agent_sessions SET gw_stop = ? WHERE id = ? AND gw_stop IS NULL \
         AND state NOT IN ('ended', 'lost')",
    )
    .bind(why)
    .bind(session)
    .execute(pool)
    .await
    .map(drop)
}

/// The details an `agent.cancelled` audit row of a budget stop carries.
pub fn stop_details(why: &str) -> serde_json::Value {
    json!({"reason": "budget", "detail": why})
}
