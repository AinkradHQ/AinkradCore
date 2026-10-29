//! Company-wide reads for the app's screens (E11.3–E11.5, E11.7): runs filtered and paged, an
//! issue's diff per repo, and a company's spend by the hour or day, by agent and by department.

use ainkrad_core::org::CompanyId;
use ainkrad_proto::runner::RepoDiff;

use super::*;

/// Which of a company's runs to list.
#[derive(Debug, Clone, Default)]
pub struct RunFilter {
    /// Only live runs (queued, claimed, running), or only ended ones.
    pub live: Option<bool>,
    pub state: Option<String>,
    pub agent: Option<AgentId>,
    pub issue: Option<IssueId>,
    /// Older than this run id.
    pub before: Option<i64>,
}

/// The company's runs matching `f`, newest first, at most `limit`.
pub async fn list_company_runs(
    pool: &SqlitePool,
    company: CompanyId,
    f: &RunFilter,
    limit: u32,
) -> Result<Vec<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE agent_id IN (SELECT id FROM agents WHERE company_id = ?1) \
         AND (?2 IS NULL OR (state IN ('queued', 'claimed', 'running')) = ?2) \
         AND (?3 IS NULL OR state = ?3) AND (?4 IS NULL OR agent_id = ?4) \
         AND (?5 IS NULL OR issue_id = ?5) AND (?6 IS NULL OR id < ?6) \
         ORDER BY id DESC LIMIT ?7"
    ))
    .bind(company.0)
    .bind(f.live)
    .bind(&f.state)
    .bind(f.agent.map(|a| a.0))
    .bind(f.issue.map(|i| i.0))
    .bind(f.before)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(run)
    .collect()
}

/// The issue's worktrees as last measured (protocol 1.18): the run that measured them, when it
/// last progressed, and each repo's diff against its base; `None` before any run measured one.
pub async fn issue_diff(
    pool: &SqlitePool,
    issue: IssueId,
) -> Result<Option<(RunId, Option<String>, Vec<RepoDiff>)>, Error> {
    let row: Option<(i64, Option<String>, Json<Vec<RepoDiff>>)> = sqlx::query_as(
        "SELECT id, last_progress_at, diff_repos FROM runs WHERE issue_id = ? \
         AND diff_repos IS NOT NULL ORDER BY id DESC LIMIT 1",
    )
    .bind(issue.0)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(run, at, Json(repos))| (RunId(run), at, repos)))
}

/// SQL: a cost event's tokens.
macro_rules! tokens {
    () => {
        "(c.input_tokens + c.output_tokens + c.cache_tokens)"
    };
}

/// SQL: the spend columns of the cost events `c` (grouped): priced dollars, priced tokens,
/// unpriced (metered, no price) tokens and runs, subscription tokens and runs.
macro_rules! spend_columns {
    () => {
        concat!(
            "coalesce(sum(c.cost_usd_micros), 0), \
             coalesce(sum(CASE WHEN c.priced = 1 THEN ", tokens!(), " END), 0), \
             coalesce(sum(CASE WHEN c.priced = 0 AND c.billing = 'metered' THEN ", tokens!(),
            " END), 0), \
             count(DISTINCT CASE WHEN c.priced = 0 AND c.billing = 'metered' THEN c.run_id END), \
             coalesce(sum(CASE WHEN c.billing = 'subscription' THEN ", tokens!(), " END), 0), \
             count(DISTINCT CASE WHEN c.billing = 'subscription' THEN c.run_id END)"
        )
    };
}

/// What a set of cost events spent. Dollars are the priced events' only: an unpriced event is
/// counted in tokens and runs, never as $0 (#15).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spend {
    pub cost_usd_micros: i64,
    pub priced_tokens: i64,
    pub unpriced_tokens: i64,
    pub unpriced_runs: i64,
    pub subscription_tokens: i64,
    pub subscription_runs: i64,
}

fn spend(row: &SqliteRow, from: usize) -> Result<Spend, Error> {
    Ok(Spend {
        cost_usd_micros: row.try_get(from)?,
        priced_tokens: row.try_get(from + 1)?,
        unpriced_tokens: row.try_get(from + 2)?,
        unpriced_runs: row.try_get(from + 3)?,
        subscription_tokens: row.try_get(from + 4)?,
        subscription_runs: row.try_get(from + 5)?,
    })
}

/// A bucket of a spend series: an hour or a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Hour,
    Day,
}

/// The company's spend per bucket from `since` to `until` (the cost ledger), oldest first, every
/// bucket present (an empty one all zero); each bucket's start as `YYYY-MM-DDTHH:00:00.000Z`.
// ponytail: one pass over the company's events per bucket (a function join); an index on
// cost_events (created_at) and a range join when ledgers grow large.
pub async fn spend_series(
    pool: &SqlitePool,
    company: CompanyId,
    bucket: Bucket,
    since: &str,
    until: &str,
) -> Result<Vec<(String, Spend)>, Error> {
    let (fmt, step) = match bucket {
        Bucket::Hour => ("%Y-%m-%dT%H:00:00.000Z", "+1 hour"),
        Bucket::Day => ("%Y-%m-%dT00:00:00.000Z", "+1 day"),
    };
    let rows = sqlx::query(concat!(
        "WITH RECURSIVE buckets (b) AS ( \
             SELECT strftime(?4, ?2) \
             UNION ALL SELECT strftime(?4, b, ?5) FROM buckets \
             WHERE julianday(b, ?5) <= julianday(?3)) \
         SELECT b, ",
        spend_columns!(),
        " FROM buckets LEFT JOIN cost_events c ON strftime(?4, c.created_at) = b \
             AND c.agent_id IN (SELECT id FROM agents WHERE company_id = ?1) \
         GROUP BY b ORDER BY b"
    ))
    .bind(company.0)
    .bind(since)
    .bind(until)
    .bind(fmt)
    .bind(step)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| Ok((row.try_get(0)?, spend(row, 1)?)))
        .collect()
}

/// The company's spend from `since` to `until` by agent (every agent, idle ones all zero), and by
/// department: an agent's department is its first team's (by team id), `None` for one in no team.
pub async fn spend_breakdown(
    pool: &SqlitePool,
    company: CompanyId,
    since: &str,
    until: &str,
) -> Result<(Vec<(AgentId, Spend)>, Vec<(Option<i64>, Spend)>), Error> {
    let home = "(SELECT t.department_id FROM team_memberships m JOIN teams t ON t.id = m.team_id \
                WHERE m.agent_id = a.id ORDER BY m.team_id LIMIT 1)";
    let window = "c.agent_id = a.id AND julianday(c.created_at) >= julianday(?2) \
                  AND julianday(c.created_at) <= julianday(?3)";
    let by_agent = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT a.id, {} FROM agents a LEFT JOIN cost_events c ON {window} \
         WHERE a.company_id = ?1 GROUP BY a.id ORDER BY a.id",
        spend_columns!()
    )))
    .bind(company.0)
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    let by_department = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {home} AS d, {} FROM agents a LEFT JOIN cost_events c ON {window} \
         WHERE a.company_id = ?1 GROUP BY d ORDER BY d IS NULL, d",
        spend_columns!()
    )))
    .bind(company.0)
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    let agents = by_agent
        .iter()
        .map(|row| Ok((AgentId(row.try_get(0)?), spend(row, 1)?)))
        .collect::<Result<_, Error>>()?;
    let departments = by_department
        .iter()
        .map(|row| Ok((row.try_get(0)?, spend(row, 1)?)))
        .collect::<Result<_, Error>>()?;
    Ok((agents, departments))
}
