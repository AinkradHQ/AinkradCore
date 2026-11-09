//! The account usage report (E15.2, decision #41): per account, each limit's use in its
//! current window, the harness's latest plan-limit report, and what each company used of it
//! (tokens from the cost ledger, prompts from `account_events`, runs), all time.

use citadel_core::gov::{Account, AccountLimit};
use serde_json::{Value, json};
use sqlx::Error;
use sqlx::sqlite::SqlitePool;

use super::{drops_over_in, limits_in, list_accounts, used_in};
use citadel_core::settings::Key;

#[derive(Debug, Clone, PartialEq)]
pub struct LimitUsage {
    pub limit: AccountLimit,
    /// Used in the window ending now.
    pub used: i64,
}

/// What one company used of one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyUsage {
    pub company_id: i64,
    pub tokens: i64,
    pub messages: i64,
    pub runs: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AccountUsage {
    pub account: Account,
    pub limits: Vec<LimitUsage>,
    /// By company id.
    pub companies: Vec<CompanyUsage>,
    /// The harness's latest plan-limit report, if it sends one (Claude).
    pub signal: Option<Value>,
    /// Provider drops in the account's last `account.drop_window_secs` (E15.4), that window.
    pub drops: i64,
    pub drops_window_secs: i64,
    /// Provider drops in its last `account.drop_display_window_secs`, for the app, and that
    /// window.
    pub recent_drops: i64,
    pub recent_drops_window_secs: i64,
}

/// Every account's usage at `now`, by account id.
pub async fn account_usage(pool: &SqlitePool, now: &str) -> Result<Vec<AccountUsage>, Error> {
    let mut conn = pool.acquire().await?;
    let mut out = vec![];
    for account in list_accounts(pool).await? {
        let mut limits = vec![];
        for limit in limits_in(&mut conn, account.id).await? {
            let used = used_in(&mut conn, account.id, limit.window_secs, limit.unit, now).await?;
            limits.push(LimitUsage { limit, used });
        }
        let companies: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
            "WITH t AS (SELECT g.company_id, sum(c.input_tokens + c.output_tokens \
                 + c.cache_tokens) AS tokens, count(DISTINCT c.run_id) AS runs \
                 FROM cost_events c JOIN agents g ON g.id = c.agent_id \
                 WHERE c.account_id = ?1 GROUP BY g.company_id), \
             m AS (SELECT g.company_id, count(*) AS messages, count(DISTINCT e.run_id) AS runs \
                 FROM account_events e JOIN runs r ON r.id = e.run_id \
                 JOIN agents g ON g.id = r.agent_id \
                 WHERE e.account_id = ?1 AND e.kind = 'message' GROUP BY g.company_id) \
             SELECT company_id, coalesce(t.tokens, 0), coalesce(m.messages, 0), \
                 max(coalesce(t.runs, 0), coalesce(m.runs, 0)) \
             FROM (SELECT company_id FROM t UNION SELECT company_id FROM m) \
             LEFT JOIN t USING (company_id) LEFT JOIN m USING (company_id) ORDER BY company_id",
        )
        .bind(account.id.0)
        .fetch_all(&mut *conn)
        .await?;
        let signal: Option<String> = sqlx::query_scalar("SELECT signal FROM accounts WHERE id = ?")
            .bind(account.id.0)
            .fetch_one(&mut *conn)
            .await?;
        let (drops, drops_window_secs) =
            drops_over_in(&mut conn, account.id, Key::DropWindowSecs, now).await?;
        let (recent_drops, recent_drops_window_secs) =
            drops_over_in(&mut conn, account.id, Key::DropDisplayWindowSecs, now).await?;
        out.push(AccountUsage {
            account,
            limits,
            companies: companies
                .into_iter()
                .map(|(company_id, tokens, messages, runs)| CompanyUsage {
                    company_id,
                    tokens,
                    messages,
                    runs,
                })
                .collect(),
            signal: signal.and_then(|s| serde_json::from_str(&s).ok()),
            drops,
            drops_window_secs,
            recent_drops,
            recent_drops_window_secs,
        });
    }
    Ok(out)
}

/// The report of one account as JSON, for the CLI.
pub fn usage_json(u: &AccountUsage) -> Value {
    let a = &u.account;
    let limits: Vec<Value> = u
        .limits
        .iter()
        .map(|l| {
            json!({"window_secs": l.limit.window_secs, "unit": l.limit.unit.as_str(),
                   "max": l.limit.max, "used": l.used, "warn_percent": l.limit.warn_percent})
        })
        .collect();
    let companies: Vec<Value> = u
        .companies
        .iter()
        .map(|c| {
            json!({"company_id": c.company_id, "tokens": c.tokens, "messages": c.messages,
                   "runs": c.runs})
        })
        .collect();
    json!({"id": a.id.0, "label": a.label, "harness": a.harness.as_str(),
           "status": a.status.as_str(), "status_reason": a.status_reason,
           "status_until": a.status_until, "billing": a.billing.as_str(),
           "limits": limits, "companies": companies, "signal": u.signal,
           "drops": u.drops, "recent_drops": u.recent_drops,
           "recent_drops_window_secs": u.recent_drops_window_secs, "plan_tier": a.plan_tier})
}
