//! An agent's stats for its page (parity API B2): runs per day, success per week, the average
//! cost of a run, when it works, and its spend through the month. All from the runs and the
//! ledger, as of `now` (UTC): nothing is stored.

use ainkrad_core::org::AgentId;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStats {
    /// The last 7 days, oldest first: (day, runs started that day).
    pub runs_by_day: Vec<(String, i64)>,
    /// The last 8 weeks, oldest first: (the week's Monday, finished runs, of which succeeded).
    pub success_by_week: Vec<(String, i64, i64)>,
    /// The mean dollars of its priced runs of the last 8 weeks; `None` when it has none.
    pub avg_cost_micros: Option<i64>,
    /// Runs started in the last 28 days by weekday (Monday first) and 4-hour slot (00, 04 … 20).
    pub heatmap: [[i64; 6]; 7],
    /// Each day of the current month so far: (day, priced dollars, tokens).
    pub daily_spend: Vec<(String, i64, i64)>,
}

/// When a run started (queued, if it never did).
macro_rules! at {
    () => {
        "coalesce(started_at, queued_at)"
    };
}

pub async fn agent_stats(
    pool: &SqlitePool,
    agent: AgentId,
    now: &str,
) -> Result<AgentStats, Error> {
    let days = sqlx::query(concat!(
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 6) \
         SELECT date(?1, '-' || (6 - i) || ' days') AS day, (SELECT count(*) FROM runs \
             WHERE agent_id = ?2 AND date(",
        at!(),
        ") = date(?1, '-' || (6 - i) || ' days')) AS runs \
         FROM n ORDER BY i"
    ))
    .bind(now)
    .bind(agent.0)
    .fetch_all(pool)
    .await?;
    let weeks = sqlx::query(concat!(
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 7) \
         SELECT date(?1, '-6 days', 'weekday 1', '-' || (7 * (7 - i)) || ' days') AS week, \
             (SELECT count(*) FROM runs WHERE agent_id = ?2 AND state IN ('succeeded', 'failed', \
                 'cancelled', 'timed_out', 'runner_lost') AND date(",
        at!(),
        ", '-6 days', 'weekday 1') \
                 = date(?1, '-6 days', 'weekday 1', '-' || (7 * (7 - i)) || ' days')) AS runs, \
             (SELECT count(*) FROM runs WHERE agent_id = ?2 AND state = 'succeeded' \
                 AND date(",
        at!(),
        ", '-6 days', 'weekday 1') \
                 = date(?1, '-6 days', 'weekday 1', '-' || (7 * (7 - i)) || ' days')) AS ok \
         FROM n ORDER BY i"
    ))
    .bind(now)
    .bind(agent.0)
    .fetch_all(pool)
    .await?;
    let avg: Option<f64> = sqlx::query_scalar(concat!(
        "SELECT avg(cost_usd_micros) FROM runs WHERE agent_id = ? AND priced = 1 \
         AND date(",
        at!(),
        ") > date(?, '-56 days')"
    ))
    .bind(agent.0)
    .bind(now)
    .fetch_one(pool)
    .await?;
    let slots = sqlx::query(concat!(
        "SELECT (CAST(strftime('%w', ",
        at!(),
        ") AS INTEGER) + 6) % 7 AS dow, \
         CAST(strftime('%H', ",
        at!(),
        ") AS INTEGER) / 4 AS slot, count(*) AS n FROM runs \
         WHERE agent_id = ? AND date(",
        at!(),
        ") > date(?, '-28 days') GROUP BY dow, slot"
    ))
    .bind(agent.0)
    .bind(now)
    .fetch_all(pool)
    .await?;
    let mut heatmap = [[0; 6]; 7];
    for r in slots {
        let (d, s): (i64, i64) = (r.try_get("dow")?, r.try_get("slot")?);
        heatmap[d as usize][s as usize] = r.try_get("n")?;
    }
    let spend = sqlx::query(
        "WITH RECURSIVE d(day) AS (SELECT date(?1, 'start of month') \
             UNION ALL SELECT date(day, '+1 day') FROM d WHERE day < date(?1)) \
         SELECT day, (SELECT coalesce(sum(cost_usd_micros), 0) FROM cost_events \
                 WHERE agent_id = ?2 AND date(created_at) = day) AS usd, \
             (SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) \
                 FROM cost_events WHERE agent_id = ?2 AND date(created_at) = day) AS tokens \
         FROM d ORDER BY day",
    )
    .bind(now)
    .bind(agent.0)
    .fetch_all(pool)
    .await?;
    Ok(AgentStats {
        runs_by_day: days
            .iter()
            .map(|r| Ok((r.try_get("day")?, r.try_get("runs")?)))
            .collect::<Result<_, Error>>()?,
        success_by_week: weeks
            .iter()
            .map(|r| Ok((r.try_get("week")?, r.try_get("runs")?, r.try_get("ok")?)))
            .collect::<Result<_, Error>>()?,
        avg_cost_micros: avg.map(|a| a.round() as i64),
        heatmap,
        daily_spend: spend
            .iter()
            .map(|r| Ok((r.try_get("day")?, r.try_get("usd")?, r.try_get("tokens")?)))
            .collect::<Result<_, Error>>()?,
    })
}

/// Pending wakes per agent of the company (agents with none are absent).
pub async fn queued_wakes(
    pool: &SqlitePool,
    company: ainkrad_core::org::CompanyId,
) -> Result<std::collections::HashMap<i64, i64>, Error> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT w.agent_id, count(*) FROM wake_requests w JOIN agents a ON a.id = w.agent_id \
         WHERE a.company_id = ? AND w.status = 'pending' GROUP BY w.agent_id",
    )
    .bind(company.0)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}
