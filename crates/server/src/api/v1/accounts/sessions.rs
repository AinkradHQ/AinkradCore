//! An account's latest AI sessions (0.10.4, the account details page): one read instead of joining
//! the cost ledger to `/agents/sessions`. `read`, like the other account reads; dollars only to an
//! `admin` device, as the month spend.

use axum::extract::Query;
use sqlx::Row;
use utoipa::IntoParams;

use super::*;

/// One AI session that ran on the account.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountSession {
    pub session_id: String,
    /// The session's title, else its first message's start; empty when it has neither.
    pub title: String,
    /// The model it ran: what the harness said it runs, else what the session asked for. Absent
    /// when neither is known (the harness default, not reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub model: Option<String>,
    /// The runner device it ran on, and that runner's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub runner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub runner_name: Option<String>,
    /// Input, output and cache tokens.
    pub tokens: i64,
    /// What it cost, in millionths of a dollar; absent for a plan (unpriced) and for a device that
    /// is not `admin`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub usd_micros: Option<i64>,
    pub started_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub ended_at: Option<Timestamp>,
    /// The account (its id) the run moved to when this session failed over; absent when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub moved_to_account: Option<String>,
    /// Set when this row is not an AI session but a tool typed in a terminal (its id, also in
    /// `session_id`) that signed in with the account: `title` names the tool, and no transcript,
    /// tokens or dollars exist for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub terminal: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AccountSessionsQuery {
    /// At most this many, newest first (default 10, most 50).
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/accounts/{id}/sessions", operation_id = "listAccountSessions",
    tag = "accounts",
    params(("id" = String, Path, description = "The account's id"), AccountSessionsQuery),
    responses((status = 200, description = "The latest AI sessions that ran on the account, newest \
        first, with their title, model, runner, tokens and (for an `admin` device) dollars, and the \
        account a failed-over session moved to. 404 for no such account", body = Vec<AccountSession>)))]
pub async fn list_sessions(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<AccountSessionsQuery>,
) -> ApiResult<Vec<AccountSession>> {
    let a = acc::get(&app.pool, num(&id, "account")?)
        .await
        .map_err(err)?;
    let admin = me.device.scopes.iter().any(|s| s == "admin");
    let limit = q.limit.unwrap_or(10).clamp(1, 50);
    let rows = sqlx::query(
        "SELECT s.id, s.title, s.prompt, coalesce(s.harness_model, s.model) AS model, s.runner, \
         d.name AS runner_name, s.tokens_in + s.tokens_out + s.cache_read + s.cache_write AS tokens, \
         s.cost_usd_micros, s.created_at, s.ended_at, \
         (SELECT x.account_id FROM core_agent_sessions x WHERE x.failover_of = s.id) AS moved_to \
         FROM core_agent_sessions s LEFT JOIN core_devices d ON d.id = s.runner \
         WHERE s.account_id = ? ORDER BY s.created_at DESC, s.n DESC LIMIT ?",
    )
    .bind(a.id)
    .bind(limit)
    .fetch_all(&app.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let prompt: Option<String> = r.try_get("prompt")?;
        let title: Option<String> = r.try_get("title")?;
        let ended: Option<String> = r.try_get("ended_at")?;
        out.push(AccountSession {
            session_id: r.try_get("id")?,
            title: title
                .or_else(|| prompt.as_deref().and_then(crate::store::agents::title_of))
                .unwrap_or_default(),
            model: r
                .try_get::<Option<String>, _>("model")?
                .filter(|m| !m.is_empty()),
            runner_id: Some(r.try_get::<String, _>("runner")?).filter(|r| !r.is_empty()),
            runner_name: r.try_get("runner_name")?,
            tokens: r.try_get("tokens")?,
            usd_micros: r
                .try_get::<Option<i64>, _>("cost_usd_micros")?
                .filter(|_| admin),
            started_at: ts(&r.try_get::<String, _>("created_at")?),
            ended_at: opt_ts(ended.as_deref()),
            moved_to_account: r
                .try_get::<Option<i64>, _>("moved_to")?
                .map(|n| n.to_string()),
            terminal: None,
        });
    }
    // A tool typed in a terminal (0.10.5), between the sessions by when it signed in.
    let uses = sqlx::query_as::<_, (String, String, String, String, Option<String>)>(
        "SELECT u.terminal, u.tool, u.runner, u.created_at, d.name FROM core_terminal_account_uses u \
         LEFT JOIN core_devices d ON d.id = u.runner WHERE u.account_id = ? \
         ORDER BY u.created_at DESC, u.id DESC LIMIT ?",
    )
    .bind(a.id)
    .bind(limit)
    .fetch_all(&app.pool)
    .await?;
    for (terminal, tool, runner, at, runner_name) in uses {
        out.push(AccountSession {
            session_id: terminal.clone(),
            title: format!("{tool} in a terminal"),
            model: None,
            runner_id: Some(runner),
            runner_name,
            tokens: 0,
            usd_micros: None,
            started_at: ts(&at),
            ended_at: None,
            moved_to_account: None,
            terminal: Some(terminal),
        });
    }
    // Timestamps of one format sort as text; newest first, stable for equal times.
    out.sort_by(|x, y| y.started_at.cmp(&x.started_at));
    out.truncate(usize::try_from(limit).unwrap_or(10));
    Ok(Json(out))
}
