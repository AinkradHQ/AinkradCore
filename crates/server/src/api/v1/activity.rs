//! What the Activity app draws over time (E2-6): the Core's readings for the last day, and the
//! audit log counted by hour, day and kind. Both are `admin`, like the metrics and the audit log
//! they summarise, and carry counts and readings only: no id, name, path or content.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::scheduler::iso_of_unix;

/// Seconds between two samples.
const INTERVAL_SECS: i64 = 60;

/// Which stretch of history.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// How many hours back, 1 to 24 (default 24).
    pub hours: Option<u32>,
}

/// One minute of the Core's readings.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpsSample {
    pub at: Timestamp,
    /// The Core process's CPU, as a percent of one core; absent for the first sample after a start.
    #[schema(required = false)]
    pub cpu_pct: Option<f64>,
    /// The Core process's resident memory in bytes.
    #[schema(required = false)]
    pub memory_bytes: Option<u64>,
    /// Share of the data disk in use, 0 to 100.
    #[schema(required = false)]
    pub disk_used_pct: Option<i64>,
}

/// The Core's readings, oldest first, one a minute. Kept in memory: a restart empties it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpsHistory {
    pub interval_secs: i64,
    pub samples: Vec<OpsSample>,
}

#[utoipa::path(get, path = "/api/v1/ops/history", operation_id = "getOpsHistory", tag = "ops",
    params(HistoryQuery),
    responses((status = 200, description = "The Core's CPU, memory and disk readings for the \
        last `hours` (at most 24), one per minute, oldest first. In memory: a restart starts \
        the series again. Needs `admin`", body = OpsHistory)))]
pub async fn ops_history(
    State(app): State<App>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<OpsHistory> {
    let hours = i64::from(q.hours.unwrap_or(24).clamp(1, 24));
    let from = app.clock.unix() - hours * 3_600;
    let samples = app
        .health
        .history()
        .since(from)
        .into_iter()
        .map(|s| OpsSample {
            at: ts(&iso_of_unix(s.at)),
            cpu_pct: s.cpu_pct,
            memory_bytes: s.memory_bytes,
            disk_used_pct: s.disk_used_pct,
        })
        .collect();
    Ok(Json(OpsHistory {
        interval_secs: INTERVAL_SECS,
        samples,
    }))
}

/// Which query the stats are for.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    /// How many days, today included, 1 to 14 (default 7).
    pub days: Option<u32>,
    /// The client's offset from UTC in minutes (`-300`, `120`), so hours and days fall where the
    /// person lives; default 0.
    pub tz_offset_mins: Option<i32>,
}

/// Rows of one kind.
#[derive(Debug, Serialize, ToSchema)]
pub struct KindCount {
    /// `sessions`, `terminals`, `devices`, `secrets`, `updates` or `other`.
    pub kind: String,
    pub count: i64,
}

/// One day of the audit log.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditDay {
    /// `YYYY-MM-DD` in the client's offset.
    pub date: String,
    /// Rows per hour of that day, 24 numbers.
    pub hours: Vec<i64>,
    pub total: i64,
    /// Rows per kind (every kind, zero included).
    pub kinds: Vec<KindCount>,
    /// Rows that need a look: failures, refusals, lockouts, raised alarms.
    pub needs_attention: i64,
}

/// The audit log counted, newest day first.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditStats {
    pub days: Vec<AuditDay>,
}

pub const KINDS: [&str; 6] = [
    "sessions",
    "terminals",
    "devices",
    "secrets",
    "updates",
    "other",
];

/// The kind an audit action counts under.
pub fn kind_of(action: &str) -> &'static str {
    let head = action.split('.').next().unwrap_or_default();
    match head {
        "agent" | "session" | "account" => "sessions",
        "terminal" => "terminals",
        "device" | "pairing" | "auth" => "devices",
        "secret" => "secrets",
        "update" => "updates",
        "core" if action.contains("update") => "updates",
        _ => "other",
    }
}

/// Whether an action is one the person should look at.
pub fn needs_attention(action: &str) -> bool {
    action.contains("failed")
        || action.contains("refused")
        || action == "alarm.raised"
        || action == "auth.lockout"
        || action == "runner.degraded"
}

/// Folds `(date, hour, action, count)` rows into the days named by `dates` (newest first).
pub fn fold(rows: &[(String, i64, String, i64)], dates: &[String]) -> Vec<AuditDay> {
    let mut by: BTreeMap<&str, AuditDay> = dates
        .iter()
        .map(|d| {
            let day = AuditDay {
                date: d.clone(),
                hours: vec![0; 24],
                total: 0,
                kinds: KINDS
                    .iter()
                    .map(|k| KindCount {
                        kind: (*k).to_owned(),
                        count: 0,
                    })
                    .collect(),
                needs_attention: 0,
            };
            (d.as_str(), day)
        })
        .collect();
    for (date, hour, action, n) in rows {
        let Some(day) = by.get_mut(date.as_str()) else {
            continue;
        };
        if let Some(h) = usize::try_from(*hour)
            .ok()
            .and_then(|h| day.hours.get_mut(h))
        {
            *h += n;
        }
        day.total += n;
        if let Some(k) = day.kinds.iter_mut().find(|k| k.kind == kind_of(action)) {
            k.count += n;
        }
        if needs_attention(action) {
            day.needs_attention += n;
        }
    }
    dates.iter().filter_map(|d| by.remove(d.as_str())).collect()
}

#[utoipa::path(get, path = "/api/v1/audit/stats", operation_id = "getAuditStats", tag = "events",
    params(StatsQuery),
    responses((status = 200, description = "Audit rows counted per hour, per day and per kind \
        for the last `days` days in the client's time zone, newest day first. Needs `admin`",
        body = AuditStats)))]
pub async fn audit_stats(
    State(app): State<App>,
    Query(q): Query<StatsQuery>,
) -> ApiResult<AuditStats> {
    let days = i64::from(q.days.unwrap_or(7).clamp(1, 14));
    let off = i64::from(q.tz_offset_mins.unwrap_or(0));
    if !(-14 * 60..=14 * 60).contains(&off) {
        return Err(ApiError::bad_request(
            "tz_offset_mins is within 14 hours of UTC",
        ));
    }
    let today = (app.clock.unix() + off * 60).div_euclid(86_400) * 86_400;
    let dates: Vec<String> = (0..days)
        .map(|i| iso_of_unix(today - i * 86_400)[..10].to_owned())
        .collect();
    let from = iso_of_unix(today - (days - 1) * 86_400 - off * 60);
    let shift = format!("{off:+} minutes");
    let rows: Vec<(String, i64, String, i64)> = sqlx::query_as(
        "SELECT date(at, ?), CAST(strftime('%H', at, ?) AS INTEGER), action, count(*) \
         FROM audit_events WHERE at >= ? GROUP BY 1, 2, 3",
    )
    .bind(&shift)
    .bind(&shift)
    .bind(&from)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(AuditStats {
        days: fold(&rows, &dates),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_fold_into_hours_kinds_and_attention() {
        let rows = vec![
            ("2026-11-19".to_owned(), 10, "secret.revealed".to_owned(), 2),
            ("2026-11-19".to_owned(), 10, "terminal.opened".to_owned(), 1),
            ("2026-11-19".to_owned(), 23, "agent.failed".to_owned(), 1),
            ("2026-11-18".to_owned(), 0, "setting.set".to_owned(), 4),
            ("2026-01-01".to_owned(), 0, "setting.set".to_owned(), 9),
        ];
        let dates = vec!["2026-11-19".to_owned(), "2026-11-18".to_owned()];
        let days = fold(&rows, &dates);
        assert_eq!(days.len(), 2, "a row outside the days is dropped");
        let d = &days[0];
        assert_eq!((d.hours[10], d.hours[23], d.total), (3, 1, 4));
        assert_eq!(d.needs_attention, 1);
        let count = |kind: &str| d.kinds.iter().find(|k| k.kind == kind).unwrap().count;
        assert_eq!(
            (count("secrets"), count("terminals"), count("sessions")),
            (2, 1, 1)
        );
        assert_eq!(days[1].total, 4);
        assert_eq!(
            days[1]
                .kinds
                .iter()
                .find(|k| k.kind == "other")
                .unwrap()
                .count,
            4
        );
    }
}
