//! Accounts on the Core (2026-11-23, plan `2026-11-23-accounts-on-core-only`): every plan account's
//! login lives in the Core's vault and is lent to whichever runner runs a session, as a Claude plan's
//! token always was. For Codex and OpenCode the login is files (`auth.json`):
//!
//! - [`move_to_core`]: the runner that holds a bound home hands its credential files over
//!   (`login.export`); the Core seals them, scopes them to every runner, drops the bound record and
//!   owes the home a wipe. A new sign-in does this as soon as it finishes; an older account does it
//!   on "Move to Core". Any failure before the seal leaves the account as it was.
//! - [`take_back`]: a session's runner returns a login the harness refreshed
//!   (`POST /runner/sessions/{id}/credential`), checked to be the same account and resealed.
//! - [`widen`]: each runner that connects joins the scope of every Core-held login.
//!
//! Antigravity's login is in the OS keyring, not a file: it stays on its runner ([`NOT_PORTABLE`]).
//! No value is logged or put in an audit row or an error.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::v2::{
    AGENT_DRIVER, Body, Bundle, CAP_LOGIN_EXPORT, Command, LoginExport, Reply, bound_harness,
    bound_problem, is_bound_secret, lendable, parse_bundle, same_lent_account,
};
use zeroize::{Zeroize, Zeroizing};

/// How long after its session ended a refreshed login is still taken back (review item 4): the
/// runner sends it before it reports the end, so this only covers a slow link.
pub const RETURN_GRACE_SECS: i64 = 120;

use crate::api::App;
use crate::store::secrets::Error;
use crate::store::{accounts, bound, gateway};

/// Why an Antigravity account cannot move.
pub const NOT_PORTABLE: &str = "Antigravity keeps its login in that machine's keychain, which Ainkrad cannot \
     move: this account stays on the runner it signed in on";

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// Moves account `id`'s login from its runner to the Core's vault.
pub async fn move_to_core(
    app: &App,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<accounts::Account, Error> {
    let a = accounts::get(&app.pool, id).await?;
    let Some(harness) = bound_harness(&a.provider) else {
        return refused(
            "bad_request",
            "only a ChatGPT or OpenCode plan signs in on a runner",
        );
    };
    if !lendable(&a.provider) {
        return refused("not_portable", NOT_PORTABLE);
    }
    let mut conn = app.pool.acquire().await?;
    let Some(b) = bound::of(&mut conn, id).await? else {
        return refused("bad_request", "the account is already on the Core");
    };
    // Never under a running session (review item 7): it refreshes the copy on the runner, which the
    // move would leave behind for the wipe.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_agent_sessions s WHERE s.state IN ('starting', 'running', 'interrupted') \
         AND (s.account_id = ? OR EXISTS (SELECT 1 FROM json_each(s.secrets) j \
              WHERE json_extract(j.value, '$.name') = ?))",
    )
    .bind(id)
    .bind(&a.secret_name)
    .fetch_one(&mut *conn)
    .await?;
    if live > 0 {
        return refused(
            "account_busy",
            "a session is using this account: move it once that session has ended",
        );
    }
    drop(conn);
    let Some(sealer) = app.secrets.as_deref() else {
        return refused("secrets_unavailable", "this Core has no master key loaded");
    };
    let live = app.hub.runners();
    let Some(r) = live.get(&b.runner).filter(|r| r.online) else {
        return refused(
            "runner_offline",
            "the runner this account signed in on is offline: turn it on, or sign in again",
        );
    };
    if !r
        .drivers
        .iter()
        .filter(|d| d.name == AGENT_DRIVER)
        .any(|d| d.commands.iter().any(|c| c == CAP_LOGIN_EXPORT))
    {
        return refused(
            "runner_too_old",
            "the runner this account signed in on needs the newest ainkrad-runner to hand its login over",
        );
    }
    let cmd = Command::LoginExport(LoginExport {
        home: b.home.clone(),
        harness: harness.to_owned(),
    });
    let sent = app
        .hub
        .dispatch_login(&b.runner, cmd)
        .or_else(|e| refused("runner_failed", e.message))?;
    let answer = tokio::time::timeout(Duration::from_secs(15), sent.outcome()).await;
    let token = match answer {
        Ok(Ok(Body::Result(Reply::LoginResult(mut r)))) if r.done && r.error.is_none() => {
            r.token.take().map(Zeroizing::new)
        }
        Ok(Ok(Body::Result(Reply::LoginResult(mut r)))) => {
            // An answer with an error never keeps a login it may carry (review item 14).
            if let Some(t) = r.token.as_mut() {
                t.zeroize();
            }
            return refused(
                "runner_failed",
                r.error
                    .unwrap_or_else(|| "the runner handed no login over".to_owned()),
            );
        }
        Ok(Ok(_)) => return refused("runner_failed", "the runner answered something else"),
        Ok(Err(e)) => return refused("runner_failed", e.message),
        Err(_) => return refused("runner_failed", "the runner did not answer in time"),
    };
    let Some(token) = token else {
        return refused("runner_failed", "the runner handed no login over");
    };
    if let Err(why) = parse_bundle(harness, &token) {
        return refused("runner_failed", why);
    }
    // The login goes into the vault and the runner's copy is owed a wipe, in one transaction.
    bound::hold(
        &app.pool,
        sealer,
        &a,
        &token,
        None,
        by_device,
        actor,
        &app.clock.now(),
    )
    .await?;
    drop(token);
    accounts::get(&app.pool, id).await
}

/// Takes back the login the harness of session `session` refreshed, sent by `runner`. Only the
/// session's own runner, for the Core-held plan account the session holds, while it runs or within
/// [`RETURN_GRACE_SECS`] of its end, once per lease, against the version it was lent, the
/// harness's own credential files, and the same account by the strict lent rule
/// (`same_lent_account`).
pub async fn take_back(
    app: &App,
    runner: &str,
    session: &str,
    files: &Bundle,
) -> Result<(), Error> {
    let gone = || refused("not_found", "no such session on this runner");
    let Some(s) = crate::store::agents::get(&app.pool, session).await? else {
        return gone();
    };
    if s.runner != runner {
        return gone();
    }
    let late = s
        .ended_at
        .as_deref()
        .and_then(crate::scheduler::unix_secs)
        .is_some_and(|end| app.clock.unix() - end > RETURN_GRACE_SECS);
    if late {
        return refused(
            "conflict",
            "the session ended too long ago to send its login back",
        );
    }
    let Some(secret) = s.secrets.iter().find(|x| is_bound_secret(&x.name)) else {
        return gone();
    };
    let Some((provider, id)) = gateway::account_secret(&secret.name) else {
        return gone();
    };
    let a = accounts::get(&app.pool, id).await?;
    if a.secret_name != secret.name || a.provider != provider {
        return gone();
    }
    let harness = bound_harness(provider).unwrap_or_default();
    if bound_problem(harness, false, [secret.name.as_str()]).is_some() {
        return gone();
    }
    let mut conn = app.pool.acquire().await?;
    if !bound::held_by_core(&mut conn, provider, id).await? {
        return refused("bad_request", "the account's login is not held by the Core");
    }
    drop(conn);
    if let Some(why) = ainkrad_proto::v2::bundle_problem(harness, files) {
        return refused("bad_request", why);
    }
    let Some(sealer) = app.secrets.as_deref() else {
        return refused("secrets_unavailable", "this Core has no master key loaded");
    };
    let stored = crate::store::secrets::open_value(&app.pool, sealer, &a.secret_name).await?;
    let plain = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(stored.as_bytes())
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .map(Zeroizing::new)
    };
    let Some(mut held) = plain.and_then(|p| parse_bundle(harness, &p).ok()) else {
        return refused(
            "secrets_unavailable",
            "the account's login on file did not open",
        );
    };
    for (rel, new) in files {
        let same = held
            .get(rel)
            .is_some_and(|old| same_lent_account(harness, old.as_bytes(), new.as_bytes()));
        if !same {
            return refused(
                "bad_request",
                "the login sent back is not the same account's",
            );
        }
    }
    if files.iter().all(|(rel, new)| held.get(rel) == Some(new)) {
        return Ok(());
    }
    held.extend(files.iter().map(|(k, v)| (k.clone(), v.clone())));
    let text = Zeroizing::new(serde_json::to_string(&held).unwrap_or_default());
    held.values_mut().for_each(zeroize::Zeroize::zeroize);
    bound::hold(
        &app.pool,
        sealer,
        &a,
        &text,
        Some(bound::Return { session }),
        runner,
        AuditActor::System,
        &app.clock.now(),
    )
    .await
    .map(drop)
}

/// Adds every online runner to the scope of each Core-held login (one pass).
pub async fn widen(app: &App) {
    let online: Vec<String> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| r.online)
        .map(|(id, _)| id)
        .collect();
    if let Err(e) = bound::widen(&app.pool, &online, &app.clock.now()).await {
        tracing::warn!(error = %e, "lending Core-held logins to the runners");
    }
}
