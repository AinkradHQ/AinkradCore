//! Subscription sign-in as the Core drives it (KAN-441 L1; plan
//! `2026-11-05-claude-subscription-sign-in`). The Core never runs the vendor CLI (design §11b.8):
//! it asks a runner for a one-shot sign-in and moves the login (`store::logins`) as the runner
//! answers.
//!
//! 1. [`start`]: `login.start` to the runner; its `login.url` answer makes the login `open_url`.
//! 2. [`code`]: the user's approval code goes to the runner (`login.code`, never stored, never
//!    logged, dropped after the send); its `login.result` carries the token, once.
//! 3. The token is stored through the account path (`accounts::create_by`, the broker's own
//!    gates: `secrets.mode`, `secrets.provider_accounts`) and zeroized; `account.created` is audited
//!    with the method `subscription`; the login is `done`.
//!
//! Every ending is a `failed` or `cancelled` login with a plain reason, and the runner is told
//! `login.cancel` (best effort). A login open past ten minutes fails by itself (not while storing).
//!
//! **The runner side** (L2, `ainkrad-runner`'s `v2::login`): a runner lists [`CAP_LOGIN`] among its
//! agent driver's commands only while its `claude` is a version it can drive. Without one, [`start`]
//! answers 409 `no_runner`: nothing here is sent to a runner that cannot take it.

use std::time::Duration;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{
    AGENT_DRIVER, Body, CAP_LOGIN, Command, LoginCancel, LoginCode, LoginStart, OP_LOGIN_START,
    Reply,
};
use zeroize::Zeroizing;

use crate::api::App;
use crate::api::v1::{BY, Caller};
use crate::hub::RunnerState;
use crate::store::logins::{self, Change, Login};
use crate::store::secrets::Error;
use crate::store::{account_keys, accounts, providers, secrets, settings};

/// How long the runner may take to show a sign-in URL.
const URL_WAIT: Duration = Duration::from_secs(90);
/// The approval code's length and alphabet (what Claude shows; nothing else gets to a PTY).
const CODE_LEN: std::ops::RangeInclusive<usize> = 8..=512;
const CODE_EXTRA: &[u8] = b"-_.~#:+/=";
/// A sign-in URL is https on one of these hosts (or a subdomain), so the app never opens a stray one.
const URL_HOSTS: [&str; 3] = ["claude.ai", "claude.com", "anthropic.com"];

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

fn now(app: &App) -> i64 {
    app.clock.unix()
}

/// Whether `r` may take a sign-in for `harness`: online, not silent, a slot for the harness, and
/// the `login` command listed beside its agent driver's ops.
fn ready(r: &RunnerState, harness: &str) -> bool {
    r.online
        && !r.degraded
        && r.drivers.iter().any(|d| {
            d.name == AGENT_DRIVER
                && (d.slots.is_empty() || d.slots.contains_key(harness))
                && d.commands
                    .iter()
                    .any(|c| c == CAP_LOGIN || c == OP_LOGIN_START)
        })
}

/// The runner a sign-in goes to: `asked`, or the least loaded ready one.
fn pick(app: &App, harness: &str, asked: Option<&str>) -> Result<String, Error> {
    let live = app.hub.runners();
    let mut ok: Vec<_> = live.iter().filter(|(_, r)| ready(r, harness)).collect();
    ok.sort_by_key(|(id, r)| (r.load, (*id).clone()));
    match (asked, ok.first()) {
        (Some(a), _) if ok.iter().any(|(id, _)| *id == a) => Ok(a.to_owned()),
        (Some(_), _) => refused(
            "no_runner",
            "that runner is not online, or cannot run a sign-in for this provider",
        ),
        (None, Some((id, _))) => Ok((*id).clone()),
        (None, None) => refused(
            "no_runner",
            format!("no runner is ready with {harness} installed and sign-in support"),
        ),
    }
}

/// The gates a stored token will meet, checked before the user signs in so the sign-in is not
/// wasted (the broker applies them again at the store: this weakens nothing). A subscription
/// token is a real credential: it needs `secrets.provider_accounts` (or mode 2).
async fn gate(app: &App) -> Result<(), Error> {
    secrets::require_enabled(&app.pool).await?;
    let get = |k| settings::value(&app.pool, k, Scope::Server);
    let (mode, narrow) = (
        get(Key::SecretsMode).await.map_err(db)?,
        get(Key::SecretsProviderAccounts).await.map_err(db)?,
    );
    match mode >= 2 || narrow == 1 {
        true => Ok(()),
        false => refused(
            "real_secret_refused",
            "a subscription token is a real credential and secrets.provider_accounts is off",
        ),
    }
}

fn db(e: impl std::fmt::Display) -> Error {
    Error::Db(sqlx::Error::Protocol(e.to_string()))
}

/// Starts a sign-in of `provider` for account `label` on a runner (`runner`, or the best one).
pub async fn start(
    app: &App,
    caller: &Caller,
    provider: &str,
    label: &str,
    runner: Option<&str>,
) -> Result<Login, Error> {
    let def = match providers::get(&app.pool, provider).await {
        Ok(d) if account_keys::is_subscription(&d) => d,
        Ok(_) | Err(Error::Refused { .. }) => {
            return refused("bad_request", "that provider has no browser sign-in");
        }
        Err(e) => return Err(e),
    };
    if !accounts::valid_label(label) {
        return refused("bad_request", "a label is [a-z][a-z0-9._-]{0,63}");
    }
    if app.secrets.is_none() {
        return refused("secrets_unavailable", "this Core has no master key loaded");
    }
    gate(app).await?;
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_accounts WHERE label = ?")
        .bind(label)
        .fetch_one(&app.pool)
        .await?;
    if taken > 0 {
        return refused("conflict", "an account of that label exists");
    }
    let runner = pick(app, &def.harness, runner)?;
    let l = logins::create(
        &app.pool,
        (provider, label, &runner),
        &caller.device.id,
        BY,
        now(app),
    )
    .await?;
    tokio::spawn(run_start(app.clone(), l.clone(), def.harness));
    Ok(l)
}

/// `login.start`, its URL, then a watchdog that fails the login at its expiry.
async fn run_start(app: App, l: Login, harness: String) {
    let cmd = Command::LoginStart(LoginStart {
        login_id: l.id.clone(),
        harness,
    });
    let asked = async {
        let sent = app.hub.dispatch_login(&l.runner, cmd)?;
        match tokio::time::timeout(URL_WAIT, sent.outcome()).await {
            Ok(r) => r,
            Err(_) => Err(ainkrad_proto::v2::StreamError::new(
                ainkrad_proto::v2::ErrorCode::Lost,
                "the runner showed no sign-in URL in time",
            )),
        }
    }
    .await;
    match asked {
        Ok(Body::Result(Reply::LoginUrl(u))) if u.login_id == l.id && url_ok(&u.url) => {
            let change = Change {
                url: Some(&u.url),
                ..Change::default()
            };
            let moved = logins::step(
                &app.pool,
                &l.id,
                &["starting"],
                "open_url",
                &change,
                BY,
                now(&app),
            )
            .await;
            if !matches!(moved, Ok(Some(_))) {
                return; // cancelled or failed meanwhile: that already told the runner
            }
        }
        Ok(Body::Result(Reply::LoginUrl(_))) => {
            return fail(
                &app,
                &l,
                "the runner sent a sign-in URL that is not Claude's",
            )
            .await;
        }
        Ok(_) => return fail(&app, &l, "the runner answered something else").await,
        Err(e) => {
            return fail(
                &app,
                &l,
                &format!("the runner could not start it: {}", e.message),
            )
            .await;
        }
    }
    tokio::time::sleep(Duration::from_secs(logins::TTL_SECS as u64)).await;
    // Not `storing`: that one ends in `done` or `failed` by its own store.
    fail_from(
        &app,
        &l,
        "expired",
        &["starting", "open_url", "waiting_code"],
    )
    .await;
}

fn url_ok(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    // The host is what is before the first `/ ? #`: letters, digits, `.` and `-` only, so no
    // userinfo, port, backslash or other trick can make it read as another host.
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let shaped = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with('.')
        && !host.contains("..");
    let host = host.to_ascii_lowercase();
    url.len() <= 2048
        && url.bytes().all(|b| b.is_ascii_graphic())
        && shaped
        && URL_HOSTS
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// Ends an open login as failed and tells its runner to drop the sign-in. A login that already
/// ended is left alone.
async fn fail(app: &App, l: &Login, reason: &str) {
    fail_from(app, l, reason, &[]).await;
}

/// [`fail`] from the states `from` only (any open state when empty).
async fn fail_from(app: &App, l: &Login, reason: &str, from: &[&str]) {
    let change = Change {
        reason: Some(reason),
        ..Change::default()
    };
    if let Ok(Some(_)) = logins::step(&app.pool, &l.id, from, "failed", &change, BY, now(app)).await
    {
        tell_cancel(app, l);
    }
}

fn tell_cancel(app: &App, l: &Login) {
    let cmd = Command::LoginCancel(LoginCancel {
        login_id: l.id.clone(),
    });
    // Best effort: a runner that is gone has nothing left to cancel, and its own timeout wipes it.
    let _ = app.hub.dispatch_login(&l.runner, cmd);
}

/// Whether `code` has the shape of what Claude shows. Never echoed back.
fn code_ok(code: &str) -> bool {
    CODE_LEN.contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || CODE_EXTRA.contains(&b))
}

/// The login `id` as `caller` may see it: its own requester's only, else it does not exist.
pub async fn get(app: &App, caller: &Caller, id: &str) -> Result<Login, Error> {
    match logins::get(&app.pool, id, BY, now(app)).await? {
        Some(l) if l.device == caller.device.id => Ok(l),
        _ => refused("not_found", "no such sign-in"),
    }
}

/// Hands the approval code to the runner. Only from `open_url`, once.
pub async fn code(
    app: &App,
    caller: &Caller,
    id: &str,
    code: Zeroizing<String>,
) -> Result<Login, Error> {
    let l = get(app, caller, id).await?;
    if !code_ok(&code) {
        return refused("bad_request", "that is not the shape of an approval code");
    }
    let change = Change::default();
    let moved = logins::step(
        &app.pool,
        id,
        &["open_url"],
        "waiting_code",
        &change,
        BY,
        now(app),
    )
    .await?;
    let Some(moved) = moved else {
        return refused(
            "login_state",
            format!(
                "the sign-in is {}: a code is taken once its URL is shown",
                l.state
            ),
        );
    };
    tokio::spawn(run_code(app.clone(), moved.clone(), code));
    Ok(moved)
}

async fn run_code(app: App, l: Login, code: Zeroizing<String>) {
    let cmd = Command::LoginCode(LoginCode {
        login_id: l.id.clone(),
        code: code.to_string(),
    });
    drop(code);
    let left = remaining(&app, &l);
    let asked = async {
        let sent = app.hub.dispatch_login(&l.runner, cmd)?;
        match tokio::time::timeout(left, sent.outcome()).await {
            Ok(r) => r,
            Err(_) => Err(ainkrad_proto::v2::StreamError::new(
                ainkrad_proto::v2::ErrorCode::Lost,
                "nothing happened before the sign-in expired",
            )),
        }
    }
    .await;
    let mut result = match asked {
        Ok(Body::Result(Reply::LoginResult(r))) if r.login_id == l.id => r,
        Ok(_) => return fail(&app, &l, "the runner answered something else").await,
        Err(e) => return fail(&app, &l, &format!("the runner failed: {}", e.message)).await,
    };
    let token = result.token.take().map(Zeroizing::new);
    match (token, result.error) {
        (Some(token), None) => store(&app, &l, token).await,
        (_, Some(why)) => fail(&app, &l, &why).await,
        (None, None) => fail(&app, &l, "the runner returned no token").await,
    }
}

fn remaining(app: &App, l: &Login) -> Duration {
    let until = crate::scheduler::unix_secs(&l.expires_at).unwrap_or(0);
    Duration::from_secs((until - now(app)).max(1) as u64)
}

/// The token into the broker as the account's secret, then the login is `done`.
async fn store(app: &App, l: &Login, token: Zeroizing<String>) {
    let change = Change::default();
    match logins::step(
        &app.pool,
        &l.id,
        &["waiting_code"],
        "storing",
        &change,
        BY,
        now(app),
    )
    .await
    {
        Ok(Some(_)) => {}
        _ => return, // ended meanwhile (cancelled or expired): the token is dropped here
    }
    let Some(sealer) = app.secrets.as_deref() else {
        return fail(app, l, "this Core has no master key loaded").await;
    };
    // Usable on every allowed runner (spec 12e), as the broker's scope is an explicit list: every
    // active runner now. (A Claude token is a bearer env variable; a Codex `auth.json` is bound to
    // one runner and would not do this.)
    let Ok(runners) = logins::active_runners(&app.pool).await else {
        return fail(app, l, "the Core could not list its runners").await;
    };
    let new = accounts::NewAccount {
        provider: &l.provider,
        label: &l.label,
        value: &token,
        runners: &runners,
        cap: None,
    };
    let user = crate::store::chains::user_of(&app.pool, &l.device)
        .await
        .unwrap_or(1);
    let made = accounts::create_placed(
        &app.pool,
        sealer,
        &new,
        "subscription",
        &l.device,
        BY,
        &app.clock.now(),
        &crate::store::placement::Placement {
            user,
            ..Default::default()
        },
    )
    .await
    .map(|(a, _)| a);
    drop(token);
    match made {
        Ok(a) => {
            let change = Change {
                account_id: Some(a.id),
                ..Change::default()
            };
            let _ = logins::step(
                &app.pool,
                &l.id,
                &["storing"],
                "done",
                &change,
                BY,
                now(app),
            )
            .await;
        }
        Err(Error::Refused { message, .. }) => fail(app, l, &message).await,
        Err(Error::Db(_)) => fail(app, l, "the Core could not store the account").await,
    }
}

/// Cancels the sign-in; one that already ended is returned as it is.
pub async fn cancel(app: &App, caller: &Caller, id: &str) -> Result<Login, Error> {
    let l = get(app, caller, id).await?;
    match logins::step(
        &app.pool,
        id,
        // Not while its token is being stored: that ends in `done` or `failed`.
        &["starting", "open_url", "waiting_code"],
        "cancelled",
        &Change::default(),
        BY,
        now(app),
    )
    .await?
    {
        Some(done) => {
            tell_cancel(app, &done);
            Ok(done)
        }
        None => Ok(l),
    }
}

#[cfg(test)]
mod tests {
    use super::url_ok;

    /// Userinfo marker, built apart so no source line reads as an email address.
    const AT: char = '@';

    #[test]
    fn a_sign_in_url_is_https_on_claudes_own_hosts_only() {
        for ok in [
            "https://claude.ai/oauth/authorize?state=x",
            "https://console.anthropic.com/a#b",
            "https://CLAUDE.AI/x",
            "https://claude.com",
            "https://claude.ai?x=1",
        ] {
            assert!(url_ok(ok), "{ok}");
        }
        for bad in [
            r"https://evil.com\.claude.ai/x",
            &format!("https://evil.com{AT}claude.ai/x"),
            &format!("https://claude.ai{AT}evil.com/x"),
            "https://claude.ai:443/x",
            "http://claude.ai/x",
            "https://evil.com/x",
            "https://evilclaude.ai/x",
            "https://claude.ai.evil.com/x",
            "https://claude.ai./x",
            "https://.claude.ai/x",
            "https://a..claude.ai/x",
            "https:///x",
            "https://claude.ai/a b",
            "https://claude.ai/a\nb",
            "https://claude.ai\t/x",
        ] {
            assert!(!url_ok(bad), "{bad:?}");
        }
    }
}
