//! A project's AI usage (Core 0.10, E11-3): the cost ledger (`core_cost_events`) joined to agent
//! sessions by their project. Money is what the ledger stores: USD micros (millionths), a
//! `billing_corrected` row may be negative, an `unpriced` row has no cost and adds nothing.

use std::collections::BTreeMap;

use sqlx::sqlite::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUsage {
    pub id: String,
    pub title: Option<String>,
    pub state: String,
    /// All-time cost in USD micros.
    pub cost: i64,
    /// Cost per day over the last 7 days, oldest first.
    pub spark: [i64; 7],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Usage {
    pub week_cost: i64,
    pub prev_week_cost: i64,
    pub sessions_week: i64,
    pub by_day: [i64; 7],
    pub sessions: Vec<SessionUsage>,
}

/// Folds `(session, days ago, micros)` rows (days ago 0 is today, 0-13 kept) into the week
/// totals and per-session sparks. Pure.
pub fn fold(rows: &[(String, i64, i64)]) -> (i64, i64, [i64; 7], BTreeMap<String, [i64; 7]>) {
    let (mut week, mut prev, mut days) = (0, 0, [0; 7]);
    let mut spark: BTreeMap<String, [i64; 7]> = BTreeMap::new();
    for (s, ago, micros) in rows {
        match *ago {
            0..=6 => {
                let i = (6 - ago) as usize;
                week += micros;
                days[i] += micros;
                spark.entry(s.clone()).or_default()[i] += micros;
            }
            7..=13 => prev += micros,
            _ => {}
        }
    }
    (week, prev, days, spark)
}

/// `now` is the stored ISO time the days are counted from.
pub async fn usage(pool: &SqlitePool, project: i64, now: &str) -> Result<Usage, sqlx::Error> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT e.session, CAST(julianday(?1) - julianday(e.occurred_at) AS INTEGER), \
                COALESCE(e.cost_usd_micros, 0) \
         FROM core_cost_events e JOIN core_agent_sessions s ON s.id = e.session \
         WHERE s.project_id = ?2 AND julianday(e.occurred_at) > julianday(?1) - 14",
    )
    .bind(now)
    .bind(project)
    .fetch_all(pool)
    .await?;
    let (week_cost, prev_week_cost, by_day, spark) = fold(&rows);
    let sessions_week: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions \
         WHERE project_id = ?1 AND julianday(created_at) > julianday(?2) - 7",
    )
    .bind(project)
    .bind(now)
    .fetch_one(pool)
    .await?;
    let list: Vec<(String, Option<String>, String, i64)> = sqlx::query_as(
        "SELECT s.id, s.title, s.state, COALESCE((SELECT SUM(e.cost_usd_micros) \
            FROM core_cost_events e WHERE e.session = s.id), 0) \
         FROM core_agent_sessions s WHERE s.project_id = ? \
         ORDER BY s.created_at DESC, s.id LIMIT 30",
    )
    .bind(project)
    .fetch_all(pool)
    .await?;
    let sessions = list
        .into_iter()
        .map(|(id, title, state, cost)| SessionUsage {
            spark: spark.get(&id).copied().unwrap_or_default(),
            id,
            title,
            state,
            cost,
        })
        .collect();
    Ok(Usage {
        week_cost,
        prev_week_cost,
        sessions_week,
        by_day,
        sessions,
    })
}

/// A file a session of the project edited in the last 7 days: `(session id, session title, unix
/// ms, path)`, newest first, one row per (session, path) with its newest time (at most 100). Read
/// from the transcript's `tool_use` entries that carry an `edit` (the harness's Edit, Write and
/// MultiEdit); only the path is read, never the old or new text.
pub async fn recent_edits(
    pool: &SqlitePool,
    project: i64,
    since_ms: i64,
) -> Result<Vec<(String, Option<String>, i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT s.id, s.title, max(t.at) AS at, json_extract(c.value, '$.path') AS path \
         FROM core_agent_transcript t JOIN core_agent_sessions s ON s.id = t.session, \
              json_each(t.body, '$.edit.changes') c \
         WHERE s.project_id = ?1 AND t.at > ?2 AND json_extract(t.body, '$.type') = 'tool_use' \
           AND json_extract(c.value, '$.path') IS NOT NULL \
         GROUP BY s.id, path ORDER BY at DESC LIMIT 100",
    )
    .bind(project)
    .bind(since_ms)
    .fetch_all(pool)
    .await
}

/// A path as a short line: its last two parts (`src/login.swift`). Pure.
pub fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    parts[parts.len().saturating_sub(2)..].join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_cut_to_its_last_two_parts() {
        assert_eq!(short_path("/w/app/src/login.swift"), "src/login.swift");
        assert_eq!(short_path("a.rs"), "a.rs");
        assert_eq!(short_path(""), "");
    }

    #[test]
    fn rows_fold_into_the_week_the_week_before_and_a_spark_per_session() {
        let rows = vec![
            ("a".to_owned(), 0, 5),
            ("a".to_owned(), 0, 2),
            ("a".to_owned(), 6, 1),
            ("b".to_owned(), 3, 4),
            ("b".to_owned(), 7, 10),
            ("b".to_owned(), 13, -1),
            ("b".to_owned(), 14, 99),
        ];
        let (week, prev, days, spark) = fold(&rows);
        assert_eq!((week, prev), (12, 9));
        assert_eq!(days, [1, 0, 0, 4, 0, 0, 7]);
        assert_eq!(spark["a"], [1, 0, 0, 0, 0, 0, 7]);
        assert_eq!(spark["b"][3], 4);
    }
}
