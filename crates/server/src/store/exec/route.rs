//! Which (harness, model, account) a run works on (E15.1, E15.3). An agent's chain is its own
//! (harness, model), then its fallbacks in order. A new run starts on the first entry this
//! runner can work (its harness offered) with an account the run's company may use (or no
//! pool for that harness); every entry passed over is a reason on the run. The rest of the
//! chain goes to the runner, each entry with its account, to move to when a turn fails as
//! unavailable, rate-limited or out of quota (`switch_route`).
//!
//! Tiers (E15.5): a run's task tier puts its agent's model for that tier, when it has one, at
//! the head of the chain; the agent's own entry and its fallbacks follow, so a refused small
//! model still falls back.
//!
//! Project profile (E15.13): an agent with no model of its own runs on its project's model for
//! its role, and a tier it has no model for on the role's model for that tier, on its harness.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::gov::{Account, AccountId, AccountStatus};
use ainkrad_core::org::{AgentId, CompanyId, Harness, ModelRoute, Tier};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::ProjectId;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::gov::{Mark, Pick, get_account, mark_in, pick_account_in, use_account_in};
use crate::store::org::{fallbacks_in, tier_route_in};
use crate::store::settings::value_in;

/// Where a new run starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Start {
    pub harness: Harness,
    pub model: String,
    pub account: Option<AccountId>,
    /// Why each entry before it was passed over.
    pub skipped: Vec<String>,
}

/// The agent's whole chain for a task of `tier` on `issue`: its model for the tier (else its
/// project profile's for its role), its own entry (its model, else the profile's for its role),
/// then its fallbacks, each once.
async fn chain_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    tier: Option<Tier>,
    issue: Option<IssueId>,
) -> Result<(CompanyId, Vec<ModelRoute>), Error> {
    let (company, harness, model, role): (i64, String, String, String) =
        sqlx::query_as("SELECT company_id, harness, model, role FROM agents WHERE id = ?")
            .bind(agent.0)
            .fetch_one(&mut *conn)
            .await?;
    let harness: Harness = harness.parse().map_err(|e| Error::Decode(Box::new(e)))?;
    let role_model = match issue {
        Some(issue) => role_model_in(conn, issue, &role).await?,
        None => None,
    };
    let model = match &role_model {
        Some(m) if model.trim().is_empty() => m.model.clone(),
        _ => model,
    };
    let own = ModelRoute { harness, model };
    let mut chain = vec![];
    if let Some(tier) = tier {
        let profile_tier = role_model.as_ref().and_then(|m| match tier {
            Tier::Small => m.small.clone(),
            Tier::Large => m.large.clone(),
            Tier::Standard => None,
        });
        match tier_route_in(conn, agent, tier).await? {
            Some(r) => chain.push(r),
            None => chain.extend(profile_tier.map(|model| ModelRoute { harness, model })),
        }
    }
    for r in [own].into_iter().chain(fallbacks_in(conn, agent).await?) {
        if !chain.contains(&r) {
            chain.push(r);
        }
    }
    Ok((CompanyId(company), chain))
}

/// The issue's project profile's models for `role`, if it names it.
async fn role_model_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
    role: &str,
) -> Result<Option<crate::profile::RoleModel>, Error> {
    let project: Option<i64> = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(issue.0)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(project) = project else {
        return Ok(None);
    };
    let profile = crate::store::work::profile_in(conn, ProjectId(project)).await?;
    Ok(profile.and_then(|p| p.profile.role_model(role).cloned()))
}

fn named(r: &ModelRoute) -> String {
    format!("{}/{}", r.harness.as_str(), r.model)
}

/// Where a new run of `agent` on a task of `tier` starts on a runner offering `harnesses`;
/// `None` when no entry has an account its company may use (the wake waits).
pub(crate) async fn start_route_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    (tier, issue): (Tier, Option<IssueId>),
    harnesses: &[Harness],
    now: &str,
) -> Result<Option<Start>, Error> {
    let (company, chain) = chain_in(conn, agent, Some(tier), issue).await?;
    let wait = value_in(conn, Key::AccountAtLimit, Scope::Company(company)).await? == 1;
    let mut skipped = vec![];
    for r in chain {
        if !harnesses.contains(&r.harness) {
            skipped.push(format!("{}: not on this runner", named(&r)));
            continue;
        }
        let account = match pick_account_in(conn, company, r.harness, now).await? {
            // `account.at_limit` 1: wait for this entry's accounts, not the next entry.
            Pick::Unavailable if wait => return Ok(None),
            Pick::Unavailable => {
                skipped.push(format!("{}: no_account: no active account", named(&r)));
                continue;
            }
            Pick::NoPool => None,
            Pick::Account(a) => Some(a),
        };
        return Ok(Some(Start {
            harness: r.harness,
            model: r.model,
            account,
            skipped,
        }));
    }
    Ok(None)
}

/// The chain after `run`'s entry that a runner offering `harnesses` can work, each with the
/// account it would use now (not marked used until the run moves to it). Entries with no
/// account for the run's company are left out.
// ponytail: an account picked here may be limited by the time the runner falls back to it; it
// is used once anyway. Asking the server at fallback time is the upgrade.
pub async fn fallback_routes(
    pool: &SqlitePool,
    run: &Run,
    harnesses: &[Harness],
    now: &str,
) -> Result<Vec<(ModelRoute, Option<Account>)>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, chain) = chain_in(&mut tx, run.agent_id, run.tier, run.issue_id).await?;
    let model = run.model_used.clone().unwrap_or_default();
    let at = chain
        .iter()
        .position(|r| r.harness == run.harness && r.model == model);
    let mut out = vec![];
    for r in chain.into_iter().skip(at.map_or(usize::MAX, |i| i + 1)) {
        if !harnesses.contains(&r.harness) {
            continue;
        }
        match pick_account_in(&mut tx, company, r.harness, now).await? {
            Pick::Unavailable => {}
            Pick::NoPool => out.push((r, None)),
            Pick::Account(a) => out.push((r, Some(a))),
        }
    }
    tx.commit().await?;
    let mut routes = vec![];
    for (r, a) in out {
        let account = match a {
            Some(a) => get_account(pool, a).await?,
            None => None,
        };
        routes.push((r, account));
    }
    Ok(routes)
}

/// Why a `switch_route` was refused.
#[derive(Debug)]
pub enum SwitchError {
    /// Not an entry of the run's agent's chain, or an account it may not use.
    Refused(String),
    Db(Error),
}

impl From<Error> for SwitchError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for SwitchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => f.write_str(why),
            Self::Db(e) => e.fmt(f),
        }
    }
}

/// A run moving to another entry of its chain, as its runner reports it.
#[derive(Debug, Clone, Copy)]
pub struct Fallback<'a> {
    pub to: &'a ModelRoute,
    pub account: Option<AccountId>,
    /// `model_unavailable`, `rate_limited`, `quota`, `no_account`, …
    pub class: &'a str,
    /// The harness's words.
    pub reason: &'a str,
}

/// Moves `run` to `to` (an entry of its agent's chain) working as `account`, because of
/// `class` (`reason`): records the model and appends the reason on the run, counts the prompt
/// against the account's limits, and appends `run.fallback`. An account a turn found
/// rate-limited or out of quota is limited for its `account.refusal_cooloff_secs` (E15.17). Moving to where the run already is
/// does nothing (a resent message).
pub async fn switch_route(
    pool: &SqlitePool,
    run: RunId,
    fallback: &Fallback<'_>,
    actor: AuditActor,
    now: &str,
) -> Result<Run, SwitchError> {
    let Fallback {
        to,
        account,
        class,
        reason,
    } = *fallback;
    let mut tx = crate::store::begin_write(pool).await?;
    let current = sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE id = ?"
    ))
    .bind(run.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(super::run)?;
    let same = current.harness == to.harness
        && current.model_used.as_deref() == Some(to.model.as_str())
        && current.account_id == account;
    if same {
        return Ok(current);
    }
    let (agent, tier, issue) = (current.agent_id, current.tier, current.issue_id);
    let (_, chain) = chain_in(&mut tx, agent, tier, issue).await?;
    if !chain.contains(to) {
        return Err(SwitchError::Refused(format!(
            "{} is not in the agent's chain",
            named(to)
        )));
    }
    let entry = format!(
        "{}/{}: {class}: {reason}",
        current.harness.as_str(),
        current.model_used.as_deref().unwrap_or("")
    );
    let moved = sqlx::query(
        "UPDATE runs SET harness = ?1, model_used = ?2, account_id = ?3, \
         fallback_reason = iif(fallback_reason IS NULL, ?4, fallback_reason || '; ' || ?4) \
         WHERE id = ?5",
    )
    .bind(to.harness.as_str())
    .bind(&to.model)
    .bind(account.map(|a| a.0))
    .bind(&entry)
    .bind(run.0)
    .execute(&mut *tx)
    .await;
    if let Err(Error::Database(e)) = &moved {
        return Err(SwitchError::Refused(e.message().to_owned()));
    }
    moved?;
    if let Some(a) = account {
        use_account_in(&mut tx, run.0, a, now).await?;
    }
    if let (Some(old), "rate_limited" | "quota") = (current.account_id, class) {
        let cool_off = value_in(&mut tx, Key::RefusalCoolOffSecs, Scope::Account(old)).await?;
        let until: String =
            sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', julianday(?) + ? / 86400.0)")
                .bind(now)
                .bind(cool_off)
                .fetch_one(&mut *tx)
                .await?;
        let why = format!("a turn was refused: {class}");
        let mark = Mark {
            to: AccountStatus::Limited,
            reason: Some(&why),
            until: Some(&until),
            action: "account.limited",
            details: json!({"source": "turn", "class": class, "until": until, "run": run.0}),
        };
        mark_in(&mut tx, old, &[AccountStatus::Active], mark).await?;
    }
    let details = json!({"from": {"harness": current.harness.as_str(),
                                  "model": current.model_used, "account": current.account_id.map(|a| a.0)},
                         "to": {"harness": to.harness.as_str(), "model": to.model,
                                "account": account.map(|a| a.0)},
                         "class": class, "reason": reason});
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(current.agent_id.0)
        .fetch_one(&mut *tx)
        .await?;
    audit::append(
        &mut *tx,
        &NewAuditEvent {
            actor,
            action: "run.fallback".to_owned(),
            entity: Some(AuditEntity {
                kind: "run".to_owned(),
                id: run.0,
            }),
            company_id: Some(CompanyId(company)),
            run_id: Some(run),
            details: details.to_string(),
        },
    )
    .await?;
    let moved = sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE id = ?"
    ))
    .bind(run.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(super::run)?;
    tx.commit().await?;
    Ok(moved)
}
