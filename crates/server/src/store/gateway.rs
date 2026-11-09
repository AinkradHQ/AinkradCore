//! The Core's side of the auth gateway's money (KAN-435 G5; design `2026-11-04-kan-435-auth-gateway`
//! §4.6, §4.7): what a gateway session may spend, what its gateway reported it spent, and what to do
//! when the budgets say stop. Everything here is a row operation; the service that talks to runners
//! is `agents::gateway`.
//!
//! - **One writer per session.** A session whose account is served by a gateway
//!   (`core_agent_sessions.gateway_account_id`) is recorded into the ledger from its gateway's
//!   reports and from nothing else: its harness meter is display-only, so a session is never counted
//!   twice (the Citadel reconcile skips such a session).
//! - **Trust.** The account, the provider and the harness come from the Core's own session row. A
//!   report names none of them, and whatever else it says (a model, a count) is validated and
//!   clamped before the ledger sees it.
//! - **Acknowledge only what committed.** [`absorb`] runs inside the transaction that stores the
//!   transcript (`store::agents::apply`). It advances `gw_seq` only past reports it has recorded in
//!   that same transaction, and the Core's next `agent.read` carries that number as `gw_after`: a
//!   ledger write that fails rolls the cursor back with it, so nothing is ever acknowledged that the
//!   ledger does not hold.
//! - **The hold is the ceiling.** [`reserve`] takes what the session may spend from every hard-stop
//!   budget of its account and pools (KAN-448 `reserve_in`) and returns it as the grant's ceiling.

use ainkrad_proto::v2::{Ceiling, ModelPrice};
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::agents::SessionSecret;
use super::budgets::{
    Standing,
    guard::{self, Reservation},
};
use super::secrets::{ACCOUNT_PREFIX, Error};

/// The most a Claude turn may ask to write (`max_tokens`).
pub const MAX_OUTPUT_TOKENS: u64 = 128_000;
/// The context a turn may need to read: a standard window.
pub const MIN_CONTEXT_TOKENS: u64 = 200_000;
/// The least a ceiling may be and still let one turn through: the gateway reserves a request's
/// input and its `max_tokens` before it sends it, so a smaller ceiling refuses every request.
pub const MIN_CEILING_TOKENS: u64 = MAX_OUTPUT_TOKENS + MIN_CONTEXT_TOKENS;
/// The most tokens one session holds from a budget. The design leaves the default budget cap
/// undecided (it sets the default ceiling too); until it is, a session takes the headroom up to this
/// much, so one session cannot starve a second one on the same budget.
pub const HOLD_TOKENS: u64 = 20_000_000;
/// The most micro-dollars one session holds from a budget (US$50), see [`HOLD_TOKENS`].
pub const HOLD_USD_MICROS: u64 = 50_000_000;
/// A hold lapses after a week if nobody released it (the longest the budget engine allows).
const HOLD_TTL_SECS: i64 = 7 * 24 * 3600;
/// Gateway status reports with `auth_failed` are confirmed by a test this many times at most.
pub const MAX_CONFIRM_TRIES: i64 = 3;

/// The account an `acct.<provider>.<id>` secret names, when the name is the account model's own
/// (a provider id, a built-in or a user definition's, and the account row's id, a plain number): an
/// API-key account, served by the gateway (a subscription's `acct.claude-sub.<id>` parses too: callers
/// refuse it, `agents::gateway::secrets_problem`). Whether such a row exists, and is of that provider, is
/// the launch's to check. A secret of any other label (`acct.anthropic.main`) is not one, and a
/// session may not name it (`agents::non_gateway_account`): an API-key account is never an env secret.
pub fn account_secret(name: &str) -> Option<(&str, i64)> {
    let (provider, id) = name.strip_prefix(ACCOUNT_PREFIX)?.split_once('.')?;
    let shaped = (1..=32).contains(&provider.len())
        && provider.as_bytes()[0].is_ascii_lowercase()
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let plain = !id.is_empty() && id.len() <= 18 && !id.starts_with('0');
    (shaped && plain && id.bytes().all(|b| b.is_ascii_digit()))
        .then(|| id.parse().ok())
        .flatten()
        .map(|id| (provider, id))
}

/// The secret of `secrets` that a gateway serves, if any.
pub fn gateway_secret(secrets: &[SessionSecret]) -> Option<&SessionSecret> {
    secrets
        .iter()
        .find(|s| super::account_keys::gateway_served(&s.name))
}

/// What the session's own `model` (the cheapest priced one when it names none) needs for one turn to be admitted: `MIN_CONTEXT_TOKENS` of input
/// and `MAX_OUTPUT_TOKENS` of output at its list price, rounded up as the gateway rounds. 0 with
/// no prices.
pub fn min_turn_usd(prices: &[ModelPrice], model: Option<&str>) -> u64 {
    prices
        .iter()
        .filter(|p| model.is_none_or(|m| p.model == m))
        .map(|p| {
            let sum = u128::from(MIN_CONTEXT_TOKENS) * u128::from(p.input)
                + u128::from(MAX_OUTPUT_TOKENS) * u128::from(p.output);
            u64::try_from(sum.div_ceil(1_000_000)).unwrap_or(u64::MAX)
        })
        .min()
        .unwrap_or(0)
}

mod ceiling;
mod reports;
mod signals;
pub use ceiling::*;
pub use reports::*;
pub use signals::*;

/// The budgets' subjects of an account: itself and every pool it is in.
pub(super) async fn subjects_of(
    conn: &mut SqliteConnection,
    account: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let pools: Vec<i64> = sqlx::query_scalar(
        "SELECT pool_id FROM core_pool_members WHERE account_id = ? ORDER BY pool_id",
    )
    .bind(account)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = vec![("account".to_owned(), account.to_string())];
    out.extend(
        pools
            .into_iter()
            .map(|p| ("pool".to_owned(), p.to_string())),
    );
    Ok(out)
}

pub(super) fn refs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// What is left to spend across `standings`: `None` in a dimension no budget limits.
pub(super) fn room(standings: &[Standing]) -> (Option<u64>, Option<u64>) {
    let (mut tokens, mut usd): (Option<u64>, Option<u64>) = (None, None);
    let least = |so_far: Option<u64>, n: i64| {
        let n = u64::try_from(n.max(0)).unwrap_or(0);
        Some(so_far.map_or(n, |c| c.min(n)))
    };
    for s in standings {
        if !s.dollars_only() {
            tokens = least(tokens, s.left().saturating_sub(s.held));
        }
        if let Some(left) = s.usd_left() {
            usd = least(usd, left.saturating_sub(s.held_usd));
        }
    }
    (tokens, usd)
}

/// What [`reserve`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hold {
    /// The hold is written; its size is the ceiling (`u64::MAX` where nothing limits).
    Granted(Ceiling),
    /// The session may not start: why, in words the operator can act on.
    Denied(String),
}

/// Reserves what `session`, served by `account`, may spend: the headroom of every hard-stop budget
/// of the account and its pools, at most [`HOLD_TOKENS`] and [`HOLD_USD_MICROS`], in one write
/// transaction (so two sessions cannot both take the last of it). The account's session limits
/// (`core_accounts.session_max_*`, less what this session has already spent) cap the hold too. A second reserve for the same
/// session (a resume) replaces its own hold and is not counted against itself, and lifts a stop the
/// budgets had set (what is left now is what it may spend). Denied, nothing is held, and a ceiling
/// that cannot admit one turn is a denial that says so: a session that starts but is refused at
/// every request would only look broken.
pub async fn reserve(
    pool: &SqlitePool,
    session: &str,
    account: i64,
    min_usd: u64,
    now: &str,
) -> Result<Hold, Error> {
    let mut tx = super::begin_write(pool).await?;
    // A denial drops `tx` unwritten: what `reserve_in` released first comes back with it.
    let hold = reserve_in(&mut tx, session, account, min_usd, now).await?;
    if matches!(hold, Hold::Granted(_)) {
        tx.commit().await?;
    }
    Ok(hold)
}

/// [`reserve`] in the caller's write transaction (the allocator's pick and its hold are one
/// write). A denial can leave the session's own earlier hold released in the transaction: the
/// caller rolls back, or (the allocator) has none to lose.
pub async fn reserve_in(
    tx: &mut SqliteConnection,
    session: &str,
    account: i64,
    min_usd: u64,
    now: &str,
) -> Result<Hold, Error> {
    let owned = subjects_of(tx, account).await?;
    let subjects = refs(&owned);
    let standings = guard::standings_for(tx, &subjects, now, session, true).await?;
    let (tokens, usd) = room(&standings);
    let tokens = tokens.map(|r| r.min(HOLD_TOKENS));
    let usd = usd.map(|r| r.min(HOLD_USD_MICROS));
    if let Some(t) = tokens.filter(|t| *t < MIN_CEILING_TOKENS) {
        return Ok(Hold::Denied(format!(
            "the budgets leave {t} tokens, and one turn needs at least {MIN_CEILING_TOKENS} \
             (up to {MAX_OUTPUT_TOKENS} written and {MIN_CONTEXT_TOKENS} read)"
        )));
    }
    if let Some(u) = usd.filter(|u| *u < min_usd) {
        return Ok(Hold::Denied(format!(
            "the budgets leave {u} micro-dollars, and one turn of the cheapest priced model \
             needs at least {min_usd}"
        )));
    }
    // The account's session limits cap what the hold may be, and are the ceiling alone where no
    // budget limits a dimension (nothing is held then, there is nothing to hold it from).
    let (left_t, left_u) = ceiling::session_left(tx, account, session).await?;
    if let Some(t) = left_t.filter(|t| *t < MIN_CEILING_TOKENS) {
        return Ok(Hold::Denied(format!(
            "the account's session limit leaves {t} tokens, and one turn needs at least \
             {MIN_CEILING_TOKENS}"
        )));
    }
    if let Some(u) = left_u.filter(|u| *u < min_usd) {
        return Ok(Hold::Denied(format!(
            "the account's session limit leaves {u} micro-dollars, and one turn of the cheapest \
             priced model needs at least {min_usd}"
        )));
    }
    let capped = |hold: Option<u64>, left: Option<u64>| hold.map(|h| left.map_or(h, |l| h.min(l)));
    let (tokens_held, usd_held) = (capped(tokens, left_t), capped(usd, left_u));
    let held = |n: Option<u64>| i64::try_from(n.unwrap_or(0)).unwrap_or(i64::MAX);
    // The old hold goes first, in this transaction: `reserve_in` only replaces the holds of the
    // budgets that apply now, so one on a pool the account has left would otherwise stay until it
    // lapses (a hold lasts a week; a session that outlives it is counted by its spend alone).
    guard::release_in(tx, session).await?;
    let granted = guard::reserve_in(
        tx,
        session,
        &subjects,
        held(tokens_held),
        held(usd_held),
        HOLD_TTL_SECS,
        now,
    )
    .await?;
    if let Reservation::Denied(budgets) = granted {
        let named: Vec<String> = budgets
            .iter()
            .map(|b| {
                format!(
                    "{} {} ({})",
                    b.budget.kind, b.budget.subject, b.budget.period
                )
            })
            .collect();
        return Ok(Hold::Denied(format!(
            "a hard-stop budget has no room left: {}",
            named.join(", ")
        )));
    }
    sqlx::query("UPDATE core_agent_sessions SET gw_stop = NULL, gw_stop_budget = NULL, gw_stopped_at = NULL WHERE id = ?")
        .bind(session)
        .execute(tx)
        .await?;
    Ok(Hold::Granted(Ceiling {
        tokens: tokens_held.or(left_t).unwrap_or(u64::MAX),
        usd_micros: usd_held.or(left_u).unwrap_or(u64::MAX),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_account_models_own_names_are_gateway_secrets() {
        assert_eq!(account_secret("acct.anthropic.7"), Some(("anthropic", 7)));
        assert_eq!(account_secret("acct.openai.120"), Some(("openai", 120)));
        assert_eq!(account_secret("acct.google.3"), Some(("google", 3)));
        // A user definition's id is a provider too (its account row decides if it exists).
        assert_eq!(
            account_secret("acct.openrouter.12"),
            Some(("openrouter", 12))
        );
        for env in [
            "acct.anthropic.main",
            "acct.anthropic.07",
            "acct.anthropic.0",
            "acct.anthropic.",
            "acct.anthropic.1.2",
            "acct.Nobody.1",
            "acct.-x.1",
            "acct..1",
            "acct.1",
            "git.token",
            "acct.anthropic.99999999999999999999",
        ] {
            assert_eq!(account_secret(env), None, "{env}");
        }
    }

    #[test]
    fn a_turn_costs_its_input_and_its_longest_output_at_the_cheapest_price() {
        let p = |input, output| ModelPrice {
            model: if input == 1_000_000 { "cheap" } else { "dear" }.to_owned(),
            input,
            output,
            cache_read: 0,
            cache_write: 0,
        };
        assert_eq!(min_turn_usd(&[], None), 0);
        // 0.2 Mtok in at $3 and 0.128 Mtok out at $15, in micro-dollars: 600000 + 1920000.
        assert_eq!(min_turn_usd(&[p(3_000_000, 15_000_000)], None), 2_520_000);
        let both = [p(3_000_000, 15_000_000), p(1_000_000, 5_000_000)];
        assert_eq!(min_turn_usd(&both, None), 840_000);
        // A session that pins its model is held to that model's turn, not the cheapest one's.
        assert_eq!(min_turn_usd(&both, Some("dear")), 2_520_000);
        assert_eq!(min_turn_usd(&both, Some("cheap")), 840_000);
    }
}
