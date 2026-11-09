//! The provider account pool (E15.1) and its usage limits (E15.2), as the admin, through the audited store calls. `add`
//! prints the new account's id; `list` one tab-separated row per account.

use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::gov::{Account, AccountStatus, LimitUnit, NewAccountLimit, window_secs};
use citadel_core::org::{AgentId, CompanyId, ModelRoute};
use citadel_server::scheduler::{Clock, SystemClock};
use citadel_server::store::{self, gov, org};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  citadel-server account add <db> <harness> <label> [--credential <file>] [--env <VAR>]
                 [--config-dir <dir>] [--billing <metered|subscription>]
  citadel-server account list <db>
  citadel-server account assign <db> <label> <company-id>
  citadel-server account unassign <db> <label> <company-id>
  citadel-server account disable <db> <label> [--reason <text>]
  citadel-server account enable <db> <label>
  citadel-server account limit set <db> <label> <window> <max> <tokens|messages> [--warn <percent>]
  citadel-server account limit clear <db> <label> <window> <tokens|messages>
  citadel-server account usage <db> [--company <company-id>]
  citadel-server agent fallback set <db> <agent-id> [<harness>/<model> …]
  citadel-server agent fallback list <db> <agent-id>
One pool of provider accounts, assigned to companies; each run gets an active account of
its harness assigned to its company, the least recently used first. Once a harness has an
account in the pool, its runs wait for one. No secret is stored: --credential is a file
name under each runner's credentials dir (<config-root>/credentials) holding the token,
read when a run starts and put in --env (default: the harness's first auth variable, e.g.
CLAUDE_CODE_OAUTH_TOKEN). Without --credential the account logs in through its own config
dir, <config-root>/<config-dir> on each runner (default accounts/<label>). --billing
defaults to the harness's (billing set).
A limit caps an account over a rolling window (`5h`, `7d`, `30m`, `90s`): its tokens, or
its messages (prompts sent as it). The admin is warned at --warn percent (default: the
account.warn_percent setting, 80 unless set), once per window; at the limit the account is limited and skipped until the window rolls below
it. Claude's own plan-limit reports also limit it until the reset Claude gives. usage prints
JSON: each account's limits and use, and what each company used of it.
An agent's fallback chain is tried in order after its own harness and model when a turn
finds the model unavailable, rate-limited or out of quota, or when no account is free for an
entry; the run records the model it used and why. fallback set with no entries clears it.
A turn the provider drops (network, 5xx, overloaded, a reset stream) is resumed in the same
session inside the run; account.drop_threshold drops (3) within account.drop_window_secs
(10 min) make it unhealthy for account.unhealthy_secs (10 min), and its runs fall back
meanwhile (settings; see `setting list`). usage shows each account's recent drops.";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs an account command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["account", "add", db, harness, label, rest @ ..] => {
            let f = flags(
                rest,
                &["--credential", "--env", "--config-dir", "--billing"],
            )?;
            let billing = match f.get("--billing") {
                Some(b) => Some(b.parse().ok()?),
                None => None,
            };
            let owned = |name| f.get(name).map(|v: &&str| v.to_string());
            let (credential, env) = (owned("--credential"), owned("--env"));
            let dir = owned("--config-dir");
            add(Path::new(db), harness, label, credential, env, dir, billing).await
        }
        ["account", "list", db] => list(Path::new(db)).await,
        [
            "account",
            verb @ ("assign" | "unassign"),
            db,
            label,
            company,
        ] => {
            let company = CompanyId(id(company).ok()?);
            assign(Path::new(db), label, company, *verb == "assign").await
        }
        ["account", "disable", db, label, rest @ ..] => {
            let f = flags(rest, &["--reason"])?;
            let reason = f
                .get("--reason")
                .copied()
                .unwrap_or("disabled by the admin");
            status(Path::new(db), label, AccountStatus::Disabled, Some(reason)).await
        }
        ["account", "enable", db, label] => {
            status(Path::new(db), label, AccountStatus::Active, None).await
        }
        [
            "account",
            "limit",
            "set",
            db,
            label,
            window,
            max,
            unit,
            rest @ ..,
        ] => {
            let f = flags(rest, &["--warn"])?;
            let limit = NewAccountLimit {
                window_secs: window_secs(window)?,
                unit: unit.parse().ok()?,
                max: max.parse().ok()?,
                warn_percent: match f.get("--warn") {
                    Some(w) => Some(w.parse().ok()?),
                    None => None,
                },
            };
            limit_set(Path::new(db), label, limit).await
        }
        ["account", "limit", "clear", db, label, window, unit] => {
            let (window, unit) = (window_secs(window)?, unit.parse().ok()?);
            limit_clear(Path::new(db), label, window, unit).await
        }
        ["account", "usage", db, rest @ ..] => {
            let company = match rest {
                [] => None,
                ["--company", c] => Some(id(c).ok()?),
                _ => return None,
            };
            usage(Path::new(db), company).await
        }
        ["agent", "fallback", "set", db, agent, entries @ ..] => {
            let mut chain = vec![];
            for e in entries {
                let (harness, model) = e.split_once('/')?;
                let harness = harness.parse().ok()?;
                let model = model.to_owned();
                chain.push(ModelRoute { harness, model });
            }
            fallback_set(Path::new(db), AgentId(id(agent).ok()?), &chain).await
        }
        ["agent", "fallback", "list", db, agent] => {
            fallback_list(Path::new(db), AgentId(id(agent).ok()?)).await
        }
        _ => return None,
    })
}

async fn fallback_set(db: &Path, agent: AgentId, chain: &[ModelRoute]) -> Result_ {
    let pool = store::connect(db).await?;
    if !org::set_fallbacks(&pool, agent, chain, BY).await? {
        return Err(format!("no agent {}", agent.0).into());
    }
    eprintln!("agent {}: {} fallbacks", agent.0, chain.len());
    println!("{}", agent.0);
    Ok(())
}

/// One `<harness>/<model>` per line, in order.
async fn fallback_list(db: &Path, agent: AgentId) -> Result_ {
    let pool = store::connect(db).await?;
    for r in org::list_fallbacks(&pool, agent).await? {
        println!("{}/{}", r.harness.as_str(), r.model);
    }
    Ok(())
}

async fn limit_set(db: &Path, label: &str, limit: NewAccountLimit) -> Result_ {
    let pool = store::connect(db).await?;
    let a = by_label(&pool, label).await?;
    let l = gov::set_account_limit(&pool, a.id, limit, BY, &SystemClock.now()).await?;
    eprintln!(
        "account {}: at most {} {} per {}s, warned at {}%",
        a.label,
        l.max,
        l.unit.as_str(),
        l.window_secs,
        l.warn_percent
    );
    println!("{}", l.id);
    Ok(())
}

async fn limit_clear(db: &Path, label: &str, window: i64, unit: LimitUnit) -> Result_ {
    let pool = store::connect(db).await?;
    let a = by_label(&pool, label).await?;
    if !gov::clear_account_limit(&pool, a.id, window, unit, BY).await? {
        return Err(format!("account {} has no such limit", a.label).into());
    }
    println!("{}", a.id.0);
    Ok(())
}

/// The usage report as JSON; with a company, only what it used, of the accounts it used.
async fn usage(db: &Path, company: Option<i64>) -> Result_ {
    let pool = store::connect(db).await?;
    let mut all = gov::account_usage(&pool, &SystemClock.now()).await?;
    if let Some(c) = company {
        for u in &mut all {
            u.companies.retain(|cu| cu.company_id == c);
        }
        all.retain(|u| !u.companies.is_empty() || u.account.companies.contains(&c));
    }
    let report: Vec<_> = all.iter().map(gov::usage_json).collect();
    println!("{}", serde_json::Value::from(report));
    Ok(())
}

async fn add(
    db: &Path,
    harness: &str,
    label: &str,
    credential: Option<String>,
    env: Option<String>,
    dir: Option<String>,
    billing: Option<citadel_core::gov::Billing>,
) -> Result_ {
    let harness = harness.parse().map_err(|e| format!("harness: {e}"))?;
    let pool = store::connect(db).await?;
    let new = gov::new_account(&pool, harness, label, credential, env, dir, billing).await?;
    let a = gov::create_account(&pool, &new, BY).await?;
    eprintln!(
        "account {} (id {}) on {}, config dir {}, billed {}; assign it to a company",
        a.label,
        a.id.0,
        a.harness.as_str(),
        a.config_dir,
        a.billing.as_str()
    );
    println!("{}", a.id.0);
    Ok(())
}

async fn by_label(pool: &sqlx::SqlitePool, label: &str) -> Result<Account, String> {
    match gov::account_by_label(pool, label).await {
        Ok(Some(a)) => Ok(a),
        Ok(None) => Err(format!("no account {label:?}")),
        Err(e) => Err(e.to_string()),
    }
}

/// id, harness, label, status, billing, config dir, credential file, variable, companies,
/// last used, status reason.
async fn list(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for a in gov::list_accounts(&pool).await? {
        let companies: Vec<String> = a.companies.iter().map(i64::to_string).collect();
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            a.id.0,
            a.harness.as_str(),
            a.label,
            a.status.as_str(),
            a.billing.as_str(),
            a.config_dir,
            a.credential_ref.as_deref().unwrap_or("-"),
            a.credential_env.as_deref().unwrap_or("-"),
            companies.join(","),
            a.last_used_at.as_deref().unwrap_or("-"),
            a.status_reason.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

async fn assign(db: &Path, label: &str, company: CompanyId, on: bool) -> Result_ {
    let pool = store::connect(db).await?;
    let a = by_label(&pool, label).await?;
    if !gov::assign_account(&pool, a.id, company, on, BY).await? && on {
        let held = a.companies.contains(&company.0);
        if !held {
            return Err(format!("no company {}", company.0).into());
        }
    }
    let verb = if on { "assigned to" } else { "unassigned from" };
    eprintln!("account {} {verb} company {}", a.label, company.0);
    println!("{}", a.id.0);
    Ok(())
}

async fn status(db: &Path, label: &str, to: AccountStatus, reason: Option<&str>) -> Result_ {
    let pool = store::connect(db).await?;
    let a = by_label(&pool, label).await?;
    gov::set_account_status(&pool, a.id, to, reason, BY).await?;
    eprintln!("account {} is {}", a.label, to.as_str());
    println!("{}", a.id.0);
    Ok(())
}
