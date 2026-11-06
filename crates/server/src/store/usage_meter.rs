//! Usage per attempt for a session no gateway serves (KAN-436 S1; design
//! `2026-11-06-core-account-scheduler` §6): the harness meter of a subscription session, turned
//! into ledger deltas.
//!
//! - **One writer per session.** This one writes only for a session that names a subscription
//!   account, has no gateway (`store::gateway::absorb` answered false) and no module owner. A
//!   gateway session keeps its reports; a module session keeps the Citadel reconcile; a session
//!   with no account has nobody (the `max()` columns only).
//! - **A delta from a running total.** `AgentEvents.usage` is the running total of one epoch
//!   (`resumes`: the harness restarts its meter at each start). The row is the total over the
//!   mark `hm_*`; a total at or below the mark records nothing; a new epoch starts the mark at 0.
//! - **The key** `hm:<session>:<epoch>:<in>.<out>.<cache>` carries the three cumulative counts,
//!   never their sum, so a resend is the same key and two snapshots with one sum but another
//!   split cannot collide as a ledger `conflict`.
//! - **Trust.** The account comes from the session's own secret (`acct.claude-sub.<id>`), never
//!   from anything the runner says. The row is unpriced (NULL cost: the plan bills nothing, and
//!   the harness's own figure is notional): tokens count against token budgets, no dollars.
//! - **One transaction** with the transcript cursor, as `absorb` does: nothing is acknowledged
//!   that the ledger does not hold.

use ainkrad_proto::runner::Tokens;
use sqlx::{Row, SqliteConnection};

use super::agents::SessionSecret;
use super::costs::{self, NewCost, Pricing};
use super::{account_keys::subscription_provider, gateway::account_secret, prices, secrets::Error};

/// The largest cumulative count taken (a runner's number is not trusted to be sane).
const MAX_COUNT: u64 = 1 << 40;

fn clamp(n: u64) -> i64 {
    i64::try_from(n.min(MAX_COUNT)).unwrap_or(i64::MAX)
}

/// Records what the harness meter `usage` adds to the ledger for `session`, in the caller's
/// transaction. `gateway`: a gateway serves the session (what `absorb` answered).
pub async fn record(
    conn: &mut SqliteConnection,
    session: &str,
    usage: Option<Tokens>,
    gateway: bool,
    now: &str,
) -> Result<(), sqlx::Error> {
    let (Some(u), false) = (usage, gateway) else {
        return Ok(());
    };
    let Some(row) = sqlx::query(
        "SELECT harness, model, secrets, resumes, owner_module, hm_epoch, hm_in, hm_out, hm_cache \
         FROM core_agent_sessions WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(());
    };
    if row.try_get::<Option<String>, _>("owner_module")?.is_some() {
        return Ok(());
    }
    let secrets: Vec<SessionSecret> =
        serde_json::from_str(&row.try_get::<String, _>("secrets")?).unwrap_or_default();
    let Some((provider, account)) = secrets
        .iter()
        .filter_map(|s| account_secret(&s.name))
        .find(|(p, _)| subscription_provider(p))
    else {
        return Ok(());
    };
    let epoch: i64 = row.try_get("resumes")?;
    let same = row.try_get::<i64, _>("hm_epoch")? == epoch;
    let mark =
        |col: &str| -> Result<i64, sqlx::Error> { Ok(if same { row.try_get(col)? } else { 0 }) };
    let old = [mark("hm_in")?, mark("hm_out")?, mark("hm_cache")?];
    let total = [
        clamp(u.input),
        clamp(u.output),
        clamp(u.cache_read.saturating_add(u.cache_write)),
    ];
    // Per count, never backwards: a total at or below the mark adds nothing.
    let new: [i64; 3] = std::array::from_fn(|i| total[i].max(old[i]));
    if new == old {
        return Ok(());
    }
    let key = format!("hm:{session}:{epoch}:{}.{}.{}", new[0], new[1], new[2]);
    let model = row.try_get::<Option<String>, _>("model")?;
    let harness: String = row.try_get("harness")?;
    let cost = NewCost {
        session,
        epoch,
        account_id: Some(account),
        legacy_account_id: None,
        provider,
        harness: &harness,
        model: model
            .as_deref()
            .filter(|m| prices::valid_model(m))
            .unwrap_or("unknown"),
        input_tokens: new[0] - old[0],
        output_tokens: new[1] - old[1],
        cache_tokens: new[2] - old[2],
        reported_usd_micros: None,
        approximate: false,
        subjects: &[],
        idempotency_key: &key,
        occurred_at: now,
    };
    match costs::record_priced_in(conn, &cost, Pricing::Unpriced, now).await {
        Ok(_) => {}
        Err(Error::Db(e)) => return Err(e),
        // Refused for good (a harness the ledger does not take): passed over, the mark moves on,
        // so the cursor is never held back by it.
        Err(Error::Refused { code, message }) => {
            tracing::error!(session, code, message, "a meter reading the ledger refused");
        }
    }
    sqlx::query(
        "UPDATE core_agent_sessions SET hm_epoch = ?, hm_in = ?, hm_out = ?, hm_cache = ? \
         WHERE id = ?",
    )
    .bind(epoch)
    .bind(new[0])
    .bind(new[1])
    .bind(new[2])
    .bind(session)
    .execute(conn)
    .await
    .map(drop)
}
