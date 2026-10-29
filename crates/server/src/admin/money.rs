//! Governance commands (E7): budgets and their spend, prices, billing and cost reports, as
//! the admin, through the audited services. `set` prints the new row's id; `list` one
//! tab-separated row per item; `cost report` JSON.

use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{Billing, BudgetPeriod, BudgetScope, NewBudget};
use ainkrad_core::org::{AgentId, CompanyId, DepartmentId, Harness};
use ainkrad_core::work::{ProjectId, SprintId};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, gov};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  ainkrad-core-server budget set <db> <company|department|project|agent|sprint> <id>
                 <day|week|month|total> <token-cap> [--warn <percent>] [--soft <yes|no>]
  ainkrad-core-server budget list <db> <company-id>
  ainkrad-core-server budget recompute <db>
  ainkrad-core-server price set <db> <harness> <model> <input> <output> <cache>
  ainkrad-core-server price list <db>
  ainkrad-core-server billing set <db> <harness> <metered|subscription>
  ainkrad-core-server cost report <db> <company-id> [--sprint <sprint-id>]
  ainkrad-core-server cost tasks <db> <company-id> [--since <timestamp>]
A budget counts tokens over a calendar period (UTC; a week starts Monday). It warns its
scope's product owner at --warn percent (default: its company's budget.warn_percent setting,
80 unless set) once a period; unless --soft yes, no new
run starts once it is spent, and a budget_overrun approval asks for more
(`approval approve <id> --raise <tokens>`). recompute rebuilds the spend counters from the
ledger. A price is US dollars per million tokens (e.g. 3 15 0.3); each set is a new
version, used from then on. A run whose harness reports no cost and whose harness and model
have no price is unpriced: reported as such, never as $0. A subscription harness's runs are
counted in tokens only. cost tasks prints one JSON line per issue, most tokens first: its
runs, tokens, dollars (priced runs only), unpriced and subscription tokens, largest context
and seconds worked (E15.5).";

const BY: AuditActor = AuditActor::User(ADMIN);

/// Runs a governance command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["budget", "set", db, scope, scope_id, period, cap, rest @ ..] => {
            let f = flags(rest, &["--warn", "--soft"])?;
            let n = id(scope_id).ok()?;
            let scope = match *scope {
                "company" => BudgetScope::Company(CompanyId(n)),
                "department" => BudgetScope::Department(DepartmentId(n)),
                "project" => BudgetScope::Project(ProjectId(n)),
                "agent" => BudgetScope::Agent(AgentId(n)),
                "sprint" => BudgetScope::Sprint(SprintId(n)),
                "issue" => BudgetScope::Issue(ainkrad_core::work::IssueId(n)),
                _ => return None,
            };
            let soft = match f.get("--soft").copied() {
                None | Some("no") => false,
                Some("yes") => true,
                Some(_) => return None,
            };
            let warn = match f.get("--warn") {
                Some(w) => Some(w.parse().ok()?),
                None => None,
            };
            let b = NewBudget {
                scope,
                period: period.parse::<BudgetPeriod>().ok()?,
                token_cap: cap.parse().ok()?,
                usd_cap_micros: None,
                warn_at_percent: 0,
                hard_stop: !soft,
            };
            set(Path::new(db), b, warn).await
        }
        ["budget", "list", db, company] => list(Path::new(db), CompanyId(id(company).ok()?)).await,
        ["budget", "recompute", db] => recompute(Path::new(db)).await,
        ["price", "set", db, harness, model, rates @ ..] => {
            let [input, output, cache] = rates else {
                return None;
            };
            let micros = |usd: &str| -> Option<i64> {
                let usd: f64 = usd
                    .parse()
                    .ok()
                    .filter(|u: &f64| u.is_finite() && *u >= 0.0)?;
                Some((usd * 1e6).round() as i64)
            };
            let rates = [micros(input)?, micros(output)?, micros(cache)?];
            price(Path::new(db), harness.parse().ok()?, model, rates).await
        }
        ["price", "list", db] => prices(Path::new(db)).await,
        ["billing", "set", db, harness, billing] => {
            billing_set(Path::new(db), harness.parse().ok()?, billing.parse().ok()?).await
        }
        ["cost", "report", db, company, rest @ ..] => {
            let scope = match rest {
                [] => gov::CostScope::Company(CompanyId(id(company).ok()?)),
                ["--sprint", s] => gov::CostScope::Sprint(SprintId(id(s).ok()?)),
                _ => return None,
            };
            cost(Path::new(db), scope).await
        }
        ["cost", "tasks", db, company, rest @ ..] => {
            let since = match rest {
                [] => None,
                ["--since", s] => Some(*s),
                _ => return None,
            };
            tasks(Path::new(db), CompanyId(id(company).ok()?), since).await
        }
        _ => return None,
    })
}

/// Sets `b`, warning at `warn` percent or else the `budget.warn_percent` setting.
async fn set(db: &Path, mut b: NewBudget, warn: Option<u8>) -> Result_ {
    let pool = store::connect(db).await?;
    b.warn_at_percent = match warn {
        Some(w) => w,
        None => gov::default_warn_percent(&pool, &b.scope).await?,
    };
    let set = gov::set_budget(&pool, &b, BY).await?;
    eprintln!(
        "budget {}: {} tokens a {}",
        set.id.0,
        set.token_cap,
        set.period.as_str()
    );
    println!("{}", set.id.0);
    Ok(())
}

/// id, scope, scope id, period, current period, cap, raised, spent, left, warn %, hard stop.
async fn list(db: &Path, company: CompanyId) -> Result_ {
    let pool = store::connect(db).await?;
    for s in gov::company_budgets(&pool, company, &SystemClock.now()).await? {
        let (scope, scope_id) = match s.budget.scope {
            BudgetScope::Company(i) => ("company", i.0),
            BudgetScope::Department(i) => ("department", i.0),
            BudgetScope::Project(i) => ("project", i.0),
            BudgetScope::Agent(i) => ("agent", i.0),
            BudgetScope::Sprint(i) => ("sprint", i.0),
            BudgetScope::Issue(i) => ("issue", i.0),
        };
        println!(
            "{}\t{scope}\t{scope_id}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.budget.id.0,
            s.budget.period.as_str(),
            s.period_key,
            s.budget.token_cap,
            s.raised,
            s.spent,
            s.left(),
            s.budget.warn_at_percent,
            if s.budget.hard_stop { "hard" } else { "soft" },
        );
    }
    Ok(())
}

async fn recompute(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    let n = gov::recompute_budget_spend(&pool, BY).await?;
    eprintln!("{n} budget spend counters rebuilt from the ledger");
    println!("{n}");
    Ok(())
}

async fn price(db: &Path, harness: Harness, model: &str, rates: [i64; 3]) -> Result_ {
    let pool = store::connect(db).await?;
    let p = gov::set_price(&pool, harness, model, rates, BY, &SystemClock.now()).await?;
    eprintln!("{} {} price v{}", harness.as_str(), p.model, p.version);
    println!("{}", p.id.0);
    Ok(())
}

/// harness, model, version, then input, output and cache in millionths of a dollar per Mtok.
async fn prices(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for p in gov::list_prices(&pool).await? {
        println!(
            "{}\t{}\tv{}\t{}\t{}\t{}",
            p.harness.as_str(),
            p.model,
            p.version,
            p.input_micros_per_mtok,
            p.output_micros_per_mtok,
            p.cache_micros_per_mtok
        );
    }
    Ok(())
}

async fn billing_set(db: &Path, harness: Harness, billing: Billing) -> Result_ {
    let pool = store::connect(db).await?;
    gov::set_billing(&pool, harness, billing, BY).await?;
    eprintln!("{} runs are billed {}", harness.as_str(), billing.as_str());
    println!("{}", harness.as_str());
    Ok(())
}

async fn cost(db: &Path, scope: gov::CostScope) -> Result_ {
    let pool = store::connect(db).await?;
    let r = gov::cost_report(&pool, scope).await?;
    if r.unpriced_runs > 0 {
        eprintln!(
            "unpriced {} runs: their dollars are not in the total",
            r.unpriced_runs
        );
    }
    println!("{}", gov::cost_json(&r));
    Ok(())
}

async fn tasks(db: &Path, company: CompanyId, since: Option<&str>) -> Result_ {
    let pool = store::connect(db).await?;
    for t in gov::task_costs(&pool, company, since, &SystemClock.now()).await? {
        println!("{}", gov::task_json(&t));
    }
    Ok(())
}
