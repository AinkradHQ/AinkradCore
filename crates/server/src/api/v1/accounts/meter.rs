//! The usage meter of an account row (E7-2): how much of its plan or budget is used, and whether it
//! can take work now. Built from what the Core already keeps: a subscription's plan-limit snapshot
//! (`health.plan_limit`), the account's budgets (`core_budgets`) and its health state. Nothing is
//! tracked for it. `admin` devices only, like the health it reads.

use std::collections::HashMap;

use super::*;
use crate::store::budgets::{self, Standing};

/// One row's meter: `fraction` of the most binding limit, in words of `used` of `limit` per `window`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountMeter {
    /// `ready`; `limit_hit` (a limit or quota stops it until `state_until`); or `unavailable`
    /// (cooling after errors, unhealthy or disabled: see the account's `state_reason`).
    pub state: String,
    /// When a `limit_hit` account is usable again; absent when unknown (a `total` budget).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub state_until: Option<Timestamp>,
    /// Used over the limit, 0 to 1 (1 at or past it), of the most used limit; absent when the
    /// account has no limit and no plan snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub fraction: Option<f64>,
    /// With `limit` and `unit`: `38` of `100` `percent`; `12000000` of `50000000` `usd_micros`;
    /// `60` of `900` `messages`; or `tokens`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub used: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub unit: Option<String>,
    /// `five_hours`, `day`, `week`, `month` or `total`; a plan window the Core does not know keeps
    /// the harness's own name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub window: Option<String>,
    /// When that window starts over; absent for `total`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub resets_at: Option<Timestamp>,
    /// Where the number comes from: `plan` (the harness's snapshot) or `budget`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub source: Option<String>,
}

struct Pick {
    fraction: f64,
    used: f64,
    limit: f64,
    unit: &'static str,
    window: String,
    resets_at: Option<String>,
    source: &'static str,
}

fn window_name(period: &str) -> String {
    match period {
        "hour5" => "five_hours",
        p => p,
    }
    .to_owned()
}

/// The most used limit a budget has, of its tokens, dollars and messages.
fn of_budget(s: &Standing) -> Option<Pick> {
    let b = &s.budget;
    let dims = [
        (b.token_cap > 0).then(|| (s.spent, b.token_cap + s.raised, "tokens")),
        b.usd_cap_micros
            .map(|c| (s.usd_spent, c + s.raised_usd, "usd_micros")),
        b.message_cap.map(|c| (s.messages, c, "messages")),
    ];
    dims.into_iter()
        .flatten()
        .filter(|(_, cap, _)| *cap > 0)
        .map(|(used, cap, unit)| Pick {
            fraction: (used as f64 / cap as f64).clamp(0.0, 1.0),
            used: used as f64,
            limit: cap as f64,
            unit,
            window: window_name(&b.period),
            resets_at: budgets::period_end(&b.period, &s.period_start()),
            source: "budget",
        })
        .max_by(|a, b| a.fraction.total_cmp(&b.fraction))
}

/// The most used window of a subscription's plan snapshot.
fn of_plan(p: &AccountPlanLimit) -> Option<Pick> {
    p.windows
        .iter()
        .max_by(|a, b| a.utilization.total_cmp(&b.utilization))
        .map(|w| Pick {
            fraction: w.utilization.clamp(0.0, 1.0),
            used: (w.utilization * 100.0).round(),
            limit: 100.0,
            unit: "percent",
            window: match w.name.as_str() {
                "five_hour" => "five_hours".to_owned(),
                "seven_day" => "week".to_owned(),
                n => n.to_owned(),
            },
            resets_at: w.resets_at.as_ref().map(|t| t.as_str().to_owned()),
            source: "plan",
        })
}

/// The meter of an account in `state` (`state_reason`, `state_until`) with its plan snapshot and
/// budgets (as they stand at `now`).
pub(super) fn meter_of(
    state: &str,
    reason: Option<&str>,
    until: Option<&Timestamp>,
    plan: Option<&AccountPlanLimit>,
    standings: &[Standing],
) -> AccountMeter {
    let mut picks: Vec<Pick> = plan.and_then(of_plan).into_iter().collect();
    picks.extend(standings.iter().filter_map(of_budget));
    // The most used wins; on a tie the earlier (the plan) stays.
    let best = picks
        .into_iter()
        .reduce(|a, b| if b.fraction > a.fraction { b } else { a });
    // A hard-stop budget that ran out blocks until the last of those periods starts over.
    let blocked: Vec<Option<String>> = standings
        .iter()
        .filter(|s| s.budget.hard_stop && s.exhausted())
        .map(|s| budgets::period_end(&s.budget.period, &s.period_start()))
        .collect();
    let quota =
        matches!(reason, Some("rate_limited" | "quota" | "plan_limit")) || state == "limited";
    let rejected = plan.is_some_and(|p| p.status == "rejected");
    let (state, until) = if matches!(state, "cooling" | "limited") && quota {
        ("limit_hit", until.map(|t| t.as_str().to_owned()))
    } else if !blocked.is_empty() {
        let end = blocked.iter().cloned().collect::<Option<Vec<_>>>();
        ("limit_hit", end.and_then(|e| e.into_iter().max()))
    } else if rejected && state == "active" {
        ("limit_hit", best.as_ref().and_then(|p| p.resets_at.clone()))
    } else if state == "active" {
        ("ready", None)
    } else {
        ("unavailable", None)
    };
    AccountMeter {
        state: state.to_owned(),
        state_until: until.map(|t| ts(&t)),
        fraction: best.as_ref().map(|p| p.fraction),
        used: best.as_ref().map(|p| p.used),
        limit: best.as_ref().map(|p| p.limit),
        unit: best.as_ref().map(|p| p.unit.to_owned()),
        window: best.as_ref().map(|p| p.window.clone()),
        resets_at: best.as_ref().and_then(|p| p.resets_at.as_deref().map(ts)),
        source: best.as_ref().map(|p| p.source.to_owned()),
    }
}

/// Every account's budgets as they stand at `now`, by account id; for an `admin` device only.
pub(super) async fn standings(
    app: &App,
    me: &Caller,
) -> Result<Option<HashMap<i64, Vec<Standing>>>, ApiError> {
    if !me.device.scopes.iter().any(|s| s == "admin") {
        return Ok(None);
    }
    let mut all: HashMap<i64, Vec<Standing>> = HashMap::new();
    for s in budgets::list(&app.pool, Some("account"), None, None, &app.clock.now()).await? {
        if let Ok(id) = s.budget.subject.parse() {
            all.entry(id).or_default().push(s);
        }
    }
    Ok(Some(all))
}

impl ProviderAccount {
    /// With its usage meter, from [`standings`]; `None` (not an admin) adds nothing.
    pub(super) fn with_meter(mut self, m: Option<&HashMap<i64, Vec<Standing>>>) -> Self {
        if let Some(m) = m {
            let own = m.get(&self.id).map(Vec::as_slice).unwrap_or_default();
            let plan = self.health.as_ref().and_then(|h| h.plan_limit.as_ref());
            self.usage = Some(meter_of(
                &self.state,
                self.state_reason.as_deref(),
                self.state_until.as_ref(),
                plan,
                own,
            ));
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::budgets::Budget;

    fn standing(
        period: &str,
        key: &str,
        tokens: i64,
        usd: Option<i64>,
        msgs: Option<i64>,
    ) -> Standing {
        Standing {
            budget: Budget {
                id: 1,
                kind: "account".into(),
                subject: "1".into(),
                company: None,
                period: period.into(),
                token_cap: tokens,
                usd_cap_micros: usd,
                message_cap: msgs,
                warn_at_percent: 80,
                hard_stop: true,
                created_at: String::new(),
                updated_at: String::new(),
            },
            period_key: key.into(),
            spent: 0,
            raised: 0,
            usd_spent: 0,
            raised_usd: 0,
            held: 0,
            held_usd: 0,
            messages: 0,
        }
    }

    #[test]
    fn a_subscription_reads_its_plan_window() {
        let plan = AccountPlanLimit {
            at: ts("2026-11-19T10:00:00.000Z"),
            status: "allowed".into(),
            windows: vec![
                AccountPlanWindow {
                    name: "five_hour".into(),
                    utilization: 0.1,
                    resets_at: None,
                },
                AccountPlanWindow {
                    name: "seven_day".into(),
                    utilization: 0.38,
                    resets_at: Some(ts("2026-11-23T09:00:00.000Z")),
                },
            ],
        };
        let m = meter_of("active", None, None, Some(&plan), &[]);
        assert_eq!(
            (m.state.as_str(), m.unit.as_deref()),
            ("ready", Some("percent"))
        );
        assert_eq!(
            (m.used, m.limit, m.window.as_deref()),
            (Some(38.0), Some(100.0), Some("week"))
        );
        assert!((m.fraction.unwrap() - 0.38).abs() < 1e-9);
    }

    #[test]
    fn an_api_key_reads_its_dollar_budget() {
        let mut s = standing("month", "2026-11", 0, Some(50_000_000), None);
        s.usd_spent = 12_000_000;
        let m = meter_of("active", None, None, None, &[s]);
        assert_eq!(m.unit.as_deref(), Some("usd_micros"));
        assert_eq!(
            (m.used, m.limit, m.window.as_deref()),
            (Some(12e6), Some(50e6), Some("month"))
        );
        assert_eq!(m.resets_at.unwrap().as_str(), "2026-12-01T00:00:00.000Z");
    }

    #[test]
    fn a_full_message_cap_is_a_limit_hit_until_the_window_starts_over() {
        let mut s = standing("hour5", "2026-11-19T10:00Z", 0, None, Some(60));
        s.messages = 60;
        let m = meter_of("active", None, None, None, &[s]);
        assert_eq!(m.state, "limit_hit");
        assert_eq!(
            (m.fraction, m.unit.as_deref()),
            (Some(1.0), Some("messages"))
        );
        assert_eq!(m.window.as_deref(), Some("five_hours"));
        assert!(m.state_until.is_some());
    }

    #[test]
    fn a_cooled_quota_is_a_limit_hit_with_its_end_and_an_unhealthy_account_is_unavailable() {
        let until = ts("2026-11-21T09:00:00.000Z");
        let m = meter_of("cooling", Some("plan_limit"), Some(&until), None, &[]);
        assert_eq!(m.state, "limit_hit");
        assert_eq!(m.state_until.unwrap().as_str(), until.as_str());
        assert_eq!(
            meter_of("unhealthy", None, None, None, &[]).state,
            "unavailable"
        );
    }
}
