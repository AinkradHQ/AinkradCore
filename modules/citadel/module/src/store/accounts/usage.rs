//! Account usage report (S9, E15.2): rolling 5-hour and 7-day tokens, messages and cost,
//! per-company split, configured limit standings, and recent provider drops.

use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnection, SqlitePool};
use sqlx::{Error, Row};

use super::limits::{LimitStanding, drops_in, refresh_in, used_in, utilisation_in};
use super::{Account, account_columns, account_row, companies_in};
use crate::domain::gov::{AccountId, LimitUnit};
use crate::domain::org::CompanyId;

pub const FIVE_HOURS: i64 = 5 * 3600;
pub const SEVEN_DAYS: i64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub total_tokens: i64,
    pub messages: i64,
    pub cost_usd_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyAccountSlice {
    pub company_id: CompanyId,
    pub five_hours: WindowUsage,
    pub seven_days: WindowUsage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUsage {
    pub account: Account,
    pub five_hours: WindowUsage,
    pub seven_days: WindowUsage,
    pub limits: Vec<LimitStanding>,
    pub max_utilisation_bps: u32,
    pub recent_drops: i64,
    pub by_company: Vec<CompanyAccountSlice>,
}

async fn window_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    company: Option<CompanyId>,
    window_secs: i64,
    now: &str,
) -> Result<WindowUsage, Error> {
    let win = format!("-{window_secs} seconds");
    let (input, output, cache, cost): (i64, i64, i64, i64) = match company {
        None => {
            sqlx::query_as(
                "SELECT coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), \
                 coalesce(sum(cache_tokens), 0), coalesce(sum(cost_usd_micros), 0) \
                 FROM citadel_cost_events WHERE account_id = ? \
                 AND julianday(created_at) > julianday(?, ?) \
                 AND julianday(created_at) <= julianday(?)",
            )
            .bind(account.0)
            .bind(now)
            .bind(&win)
            .bind(now)
            .fetch_one(&mut *conn)
            .await?
        }
        Some(c) => {
            sqlx::query_as(
                "SELECT coalesce(sum(c.input_tokens), 0), coalesce(sum(c.output_tokens), 0), \
                 coalesce(sum(c.cache_tokens), 0), coalesce(sum(c.cost_usd_micros), 0) \
                 FROM citadel_cost_events c JOIN citadel_agents a ON a.id = c.agent_id \
                 WHERE c.account_id = ? AND a.company_id = ? \
                 AND julianday(c.created_at) > julianday(?, ?) \
                 AND julianday(c.created_at) <= julianday(?)",
            )
            .bind(account.0)
            .bind(c.0)
            .bind(now)
            .bind(&win)
            .bind(now)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    let messages = match company {
        None => used_in(conn, account, LimitUnit::Messages, window_secs, now).await?,
        Some(_) => 0,
    };
    Ok(WindowUsage {
        input_tokens: input,
        output_tokens: output,
        cache_tokens: cache,
        total_tokens: input + output + cache,
        messages,
        cost_usd_micros: cost,
    })
}

pub async fn account_usage(
    pool: &SqlitePool,
    company: Option<CompanyId>,
    now: &str,
) -> Result<Vec<AccountUsage>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    refresh_in(&mut tx, now).await?;
    let rows = sqlx::query(concat!(
        "SELECT ",
        account_columns!(),
        " FROM citadel_accounts WHERE ?1 IS NULL \
         OR id IN (SELECT account_id FROM citadel_account_companies WHERE company_id = ?1) \
         OR id IN (SELECT c.account_id FROM citadel_cost_events c \
                   JOIN citadel_agents a ON a.id = c.agent_id \
                   WHERE a.company_id = ?1 AND c.account_id IS NOT NULL) \
         ORDER BY id"
    ))
    .bind(company.map(|c| c.0))
    .fetch_all(&mut *tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id = AccountId(row.try_get("id")?);
        let companies = companies_in(&mut tx, id).await?;
        let mut account = account_row(row, companies)?;
        let broker: Option<(String, String)> =
            sqlx::query_as("SELECT delivery, runners FROM core_secrets WHERE name = ?")
                .bind(&account.secret_name)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some((delivery, runners)) = broker {
            account.delivery = delivery;
            account.runners = serde_json::from_str(&runners).unwrap_or_default();
        }
        let (limits, max_utilisation_bps) = utilisation_in(&mut tx, id, now).await?;
        let recent_drops = drops_in(&mut tx, id, now).await?;
        let mut by_company = Vec::new();
        let slice_companies: Vec<CompanyId> = match company {
            Some(c) => vec![c],
            None => {
                let ids: Vec<i64> = sqlx::query_scalar(
                    "SELECT company_id FROM citadel_account_companies WHERE account_id = ?1 \
                     UNION SELECT a.company_id FROM citadel_cost_events c \
                         JOIN citadel_agents a ON a.id = c.agent_id WHERE c.account_id = ?1 \
                     ORDER BY 1",
                )
                .bind(id.0)
                .fetch_all(&mut *tx)
                .await?;
                ids.into_iter().map(CompanyId).collect()
            }
        };
        for c in slice_companies {
            by_company.push(CompanyAccountSlice {
                company_id: c,
                five_hours: window_in(&mut tx, id, Some(c), FIVE_HOURS, now).await?,
                seven_days: window_in(&mut tx, id, Some(c), SEVEN_DAYS, now).await?,
            });
        }
        out.push(AccountUsage {
            account,
            five_hours: window_in(&mut tx, id, None, FIVE_HOURS, now).await?,
            seven_days: window_in(&mut tx, id, None, SEVEN_DAYS, now).await?,
            limits,
            max_utilisation_bps,
            recent_drops,
            by_company,
        });
    }
    tx.commit().await?;
    Ok(out)
}

fn window_json(w: &WindowUsage) -> Value {
    json!({
        "input_tokens": w.input_tokens,
        "output_tokens": w.output_tokens,
        "cache_tokens": w.cache_tokens,
        "total_tokens": w.total_tokens,
        "messages": w.messages,
        "cost_usd_micros": w.cost_usd_micros,
    })
}

pub fn usage_json(all: &[AccountUsage]) -> Value {
    Value::Array(
        all.iter()
            .map(|u| {
                let a = &u.account;
                json!({
                    "id": a.id.0,
                    "harness": a.harness.as_str(),
                    "label": a.label,
                    "secret_name": a.secret_name,
                    "delivery": a.delivery,
                    "runners": a.runners,
                    "billing": a.billing.as_str(),
                    "status": a.status.as_str(),
                    "status_reason": a.status_reason,
                    "status_until": a.status_until,
                    "last_used_at": a.last_used_at,
                    "plan_tier": a.plan_tier.map(|t| t.as_str()),
                    "signal": a.signal,
                    "company_ids": a.company_ids.iter().map(|c| c.0).collect::<Vec<_>>(),
                    "five_hours": window_json(&u.five_hours),
                    "seven_days": window_json(&u.seven_days),
                    "max_utilisation_bps": u.max_utilisation_bps,
                    "recent_drops": u.recent_drops,
                    "limits": u.limits.iter().map(|l| json!({
                        "unit": l.unit.as_str(),
                        "window_secs": l.window_secs,
                        "cap": l.cap,
                        "used": l.used,
                        "warn_percent": l.warn_percent,
                        "exhausted": l.exhausted,
                    })).collect::<Vec<_>>(),
                    "by_company": u.by_company.iter().map(|s| json!({
                        "company_id": s.company_id.0,
                        "five_hours": window_json(&s.five_hours),
                        "seven_days": window_json(&s.seven_days),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}
