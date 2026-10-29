//! The per-task cost report (E15.5, pain #1): what each issue's runs used, so a small task that
//! burns big-model tokens shows. The same three kinds of spend as `cost_report`, never mixed:
//! dollars for priced metered runs, tokens for unpriced and for subscription runs.

use ainkrad_core::org::CompanyId;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row};

/// One issue's runs and what they used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskCost {
    pub issue_id: i64,
    /// `CIT-42`.
    pub key: String,
    pub title: String,
    pub points: Option<i64>,
    /// The tier its latest run was routed to.
    pub tier: Option<String>,
    pub runs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    /// The priced metered runs' dollars only, in millionths.
    pub cost_usd_micros: i64,
    pub priced_runs: i64,
    pub unpriced_runs: i64,
    pub subscription_runs: i64,
    pub unpriced_tokens: i64,
    pub subscription_tokens: i64,
    /// The largest context a run started with.
    pub context_tokens: Option<i64>,
    /// Seconds its runs worked (start to end; a live run up to `now`).
    pub secs: i64,
}

/// Every issue of `company` with a run queued at or after `since` (all, with none), most
/// tokens first; its runs' use counts only those runs. A `since` that is no timestamp is
/// `InvalidArgument`.
pub async fn task_costs(
    pool: &SqlitePool,
    company: CompanyId,
    since: Option<&str>,
    now: &str,
) -> Result<Vec<TaskCost>, Error> {
    if let Some(since) = since {
        let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
            .bind(since)
            .fetch_one(pool)
            .await?;
        if !valid {
            return Err(Error::InvalidArgument(format!("bad timestamp `{since}`")));
        }
    }
    let rows = sqlx::query(
        "WITH r AS (SELECT r.*, r.input_tokens + r.output_tokens + r.cache_tokens AS tokens, \
             EXISTS (SELECT 1 FROM cost_events c WHERE c.run_id = r.id) AS costed, \
             EXISTS (SELECT 1 FROM cost_events c WHERE c.run_id = r.id \
                 AND c.billing = 'subscription') AS sub \
             FROM runs r JOIN agents a ON a.id = r.agent_id \
             WHERE a.company_id = ?1 AND r.issue_id IS NOT NULL \
             AND (?2 IS NULL OR julianday(r.queued_at) >= julianday(?2))) \
         SELECT r.issue_id, p.key || '-' || i.number AS key, i.title, i.points, \
             (SELECT x.tier FROM runs x WHERE x.issue_id = r.issue_id AND x.tier IS NOT NULL \
                 ORDER BY x.id DESC LIMIT 1) AS tier, \
             count(*) AS runs, sum(r.input_tokens) AS input, sum(r.output_tokens) AS output, \
             sum(r.cache_tokens) AS cache, \
             sum(iif(costed AND NOT sub AND priced = 1, r.cost_usd_micros, 0)) AS cost, \
             sum(costed AND NOT sub AND priced = 1) AS priced_runs, \
             sum(costed AND NOT sub AND priced = 0) AS unpriced_runs, \
             sum(sub) AS subscription_runs, \
             sum(iif(costed AND NOT sub AND priced = 0, tokens, 0)) AS unpriced_tokens, \
             sum(iif(sub, tokens, 0)) AS subscription_tokens, \
             max(r.context_tokens) AS context_tokens, \
             CAST(round(sum(coalesce((julianday(coalesce(r.ended_at, ?3)) \
                 - julianday(r.started_at)) * 86400, 0))) AS INTEGER) AS secs \
         FROM r JOIN issues i ON i.id = r.issue_id JOIN projects p ON p.id = i.project_id \
         GROUP BY r.issue_id ORDER BY sum(tokens) DESC, r.issue_id",
    )
    .bind(company.0)
    .bind(since)
    .bind(now)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(TaskCost {
                issue_id: row.try_get("issue_id")?,
                key: row.try_get("key")?,
                title: row.try_get("title")?,
                points: row.try_get("points")?,
                tier: row.try_get("tier")?,
                runs: row.try_get("runs")?,
                input_tokens: row.try_get("input")?,
                output_tokens: row.try_get("output")?,
                cache_tokens: row.try_get("cache")?,
                cost_usd_micros: row.try_get("cost")?,
                priced_runs: row.try_get("priced_runs")?,
                unpriced_runs: row.try_get("unpriced_runs")?,
                subscription_runs: row.try_get("subscription_runs")?,
                unpriced_tokens: row.try_get("unpriced_tokens")?,
                subscription_tokens: row.try_get("subscription_tokens")?,
                context_tokens: row.try_get("context_tokens")?,
                secs: row.try_get("secs")?,
            })
        })
        .collect()
}

/// One task as JSON, dollars as an exact decimal string as in `cost_json`.
pub fn task_json(t: &TaskCost) -> Value {
    let usd = format!(
        "{}.{:06}",
        t.cost_usd_micros / 1_000_000,
        t.cost_usd_micros % 1_000_000
    );
    json!({"issue": t.issue_id, "key": t.key, "title": t.title, "points": t.points,
           "tier": t.tier, "runs": t.runs, "cost_usd": usd, "cost_usd_micros": t.cost_usd_micros,
           "priced_runs": t.priced_runs, "unpriced_runs": t.unpriced_runs,
           "unpriced_tokens": t.unpriced_tokens, "subscription_runs": t.subscription_runs,
           "subscription_tokens": t.subscription_tokens, "context_tokens": t.context_tokens,
           "secs": t.secs,
           "tokens": {"input": t.input_tokens, "output": t.output_tokens,
                      "cache": t.cache_tokens}})
}
