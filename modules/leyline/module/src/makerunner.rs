//! Make a host a runner (Y8-01, plan T12): one action installs the existing runner on a Leyline
//! host over SSH, through the gate, and pairs it, using the Core's own runner invite and the
//! existing `get.sh --runner` installer unchanged.
//!
//! Security model.
//! - Person only: the gate's `MakeRunner` action is denied to every AI session and to health, on
//!   every rule. The route also needs the step-up and the `admin`, `runner` and `terminal` scopes
//!   (the invite is made as the caller, who must hold what it grants).
//! - The invite (a single-use secret, 15 minutes) is never in argv, an environment, the Core's
//!   logs or any audit row. It goes to the host as one SFTP file, created `0600` before its first
//!   byte (the mode rides the SFTP open itself, so there is no umask window), straight in the
//!   user's home as `.ainkrad-invite-<pairing>` (no directory to create or trust, one file per
//!   install that only its own watcher removes); the command run on the host names only
//!   that file. The root shell reads it into the installer's environment and deletes it
//!   first. In the Core it lives in a `Zeroizing` buffer for the length of one call and rides one
//!   SFTP frame that the hub does not keep for a resend.
//! - Nothing is typed by the person (E8). The installer runs as ONE non-interactive `ssh.exec`, through
//!   the gate. If the SSH user has passwordless sudo (`sudo -n`), the same `get.sh --runner` runs as root and
//!   installs the system service, with agents. If not, `get.sh --runner --user` installs a runner for that
//!   user only (systemd --user with linger, else a user crontab `@reboot`). A password is never asked for,
//!   read or stored, and `sudo` is only ever used with `-n`.
//! - The user-level runner is the same unprivileged program but has no root firewall, so it offers
//!   terminals and keeps AI sessions off (they need the egress filter). It is not a weaker door: it can do
//!   only what that user's SSH login could already do.
//! - Nothing is trusted on first sight: every host on the path needs a pinned host key already.
//! - Failure leaves nothing behind: a failed upload, terminal or typing withdraws the invite and
//!   removes the file (best effort), and an invite that is not claimed in its 15 minutes is
//!   withdrawn and its file removed as well, with a `leyline.host` event so the app can say "try
//!   again". The runner it pairs is set as `runner_device` only from the pairing's own record.
// ponytail: the waiting task lives in the process: a Core restart inside the 15 minutes forgets it
// (the invite still expires on its own; the 0600 file stays until the next make-runner replaces
// it). Rebuild the wait from `core_pairings` at start when that matters.

use std::time::Duration;

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{
    ApiError, ApiResult, BY, Caller, SftpJob, TerminalSize, sftp_job,
};
use ainkrad_core_server::store::gov::{self, Created, Decider, NewPairing};
use ainkrad_core_server::store::{audit, begin_write, events};
use ainkrad_proto::v2::{OP_SFTP_WRITE, SshRoute};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::exec;
use crate::gate::{self, Action, Authorized, Principal};
use crate::hostkeys;
use crate::hosts::{In, find};
use crate::terminal::{self, NewSession, SessionView};

/// The release this Core is: the installer and the runner it installs are this version's, not
/// whatever `latest` is by then. A tag that does not exist fails the `curl -f`, it never falls back.
const RELEASE: &str = concat!(
    "https://github.com/AinkradHQ/AinkradCore/releases/download/v",
    env!("CARGO_PKG_VERSION")
);
/// Where the invite of one install waits on the host, relative to the user's home (SFTP starts
/// there). A pairing id is `p_` and Crockford base32: safe in a path and in the typed line.
fn file(pairing: &str) -> String {
    format!(".ainkrad-invite-{pairing}")
}
/// How often the wait looks at the pairing.
const POLL: Duration = Duration::from_secs(3);
/// How long past the invite's end the wait gives the Core's own expiry sweep before it acts.
const GRACE: i64 = 60;

/// The runner install started on the host by itself. Watch the host's `runner_install` (and its
/// `runner_device` once it pairs).
#[derive(Serialize, ToSchema)]
pub struct Install {
    /// Always absent now: the install runs by itself, no terminal opens (kept for an older app).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionView>,
    /// The invite's pairing id (`p_...`), never its secret.
    pub pairing: String,
    /// When the invite ends (15 minutes): after it the person starts again.
    pub expires_at: String,
}

fn refuse(code: &'static str, why: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, why)
}

fn forbidden() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden_scope",
        "this device's scopes do not allow that",
    )
}

/// How Make runner stands on a host, as `HostView.runner_install`.
#[derive(Serialize, ToSchema)]
pub struct InstallState {
    /// `installing`, `failed` or `paired`.
    pub state: String,
    /// `system` (passwordless sudo: the system service, with AI sessions) or `user` (this user only, terminals).
    pub mode: Option<String>,
    /// In words, when it failed.
    pub reason: Option<String>,
}

pub(crate) async fn states(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(String, InstallState)>, sqlx::Error> {
    use sqlx::Row;
    sqlx::query("SELECT host_id, state, mode, reason FROM leyline_runner_install")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| {
            Ok((
                r.try_get("host_id")?,
                InstallState {
                    state: r.try_get("state")?,
                    mode: r.try_get("mode")?,
                    reason: r.try_get("reason")?,
                },
            ))
        })
        .collect()
}

/// What the host is asked to run. `sudo -n` never prompts; the invite is read from its 0600 file by
/// the shell that runs the installer (as root with `sudo`), never put in argv.
fn command_line(pairing: &str, system: bool) -> String {
    format!(
        "{} sh -c 'AINKRAD_PAIR_INVITE=$(cat \"$0\"); rm -f \"$0\"; export AINKRAD_PAIR_INVITE \
         AINKRAD_RELEASE_URL={RELEASE}; curl -fsSL --proto =https --tlsv1.3 {RELEASE}/get.sh \
         | sh -s -- --runner{}' \"$HOME/{}\"",
        if system { "sudo -n" } else { "" },
        if system { "" } else { " --user" },
        file(pairing)
    )
}

/// Asks the host whether its SSH user can use sudo without a password.
const CAN_SUDO: &str = "sh -c 'if sudo -n true 2>/dev/null; then echo system; else echo user; fi'";

#[utoipa::path(post, path = "/hosts/{host}/runner", operation_id = "leylineMakeRunner", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = NewSession,
    responses((status = 200, description = "A runner invite is on the host and the installer runs there by itself, with nothing to type: the system service when the SSH user has passwordless sudo, else a runner for that user only (systemd --user with linger, or a user crontab @reboot). Follow `runner_install` on the host (`installing`, `failed` with a reason, `paired`); it shows as a paired runner (`runner_device`) when done. 403 `gate_refused` (person only) or `forbidden_scope`; 409 `already_runner`, `host_not_trusted` (every host on the path needs a pinned key), `runner_cannot_ssh`, `runner_cannot_sftp`, `host_needs_key`, `no_runner`; 502 `sftp_failed` (nothing is left behind). Needs a step-up", body = Install)))]
pub(crate) async fn make(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<NewSession>,
) -> ApiResult<Install> {
    for s in ["admin", "runner", "terminal"] {
        if !me.device.scopes.iter().any(|d| d == s) {
            return Err(forbidden());
        }
    }
    let size = TerminalSize {
        rows: req.rows,
        cols: req.cols,
    };
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, &host).await?
    };
    let auth = gate::authorize(&app, &Principal::of(&me), &id, &Action::MakeRunner).await?;
    let _ = size;
    match prepare(&app, &me, &auth).await {
        Ok(p) => {
            let out = Install {
                session: None,
                pairing: p.pairing.clone(),
                expires_at: p.expires_at.clone(),
            };
            // The gate's run stays open until the install ends: every step re-checks it.
            tokio::spawn(install(app.clone(), me.clone(), auth, p));
            Ok(Json(out))
        }
        Err(e) => {
            gate::finish(&app, auth, false).await?;
            Err(e)
        }
    }
}

/// One SFTP job on the host with leases of its own (a lease is redeemed once).
async fn job(
    app: &App,
    me: &Caller,
    runner: &str,
    chain: &[String],
    j: SftpJob<'_>,
) -> Result<(), ApiError> {
    let ssh = terminal::leased(app, me, runner, chain).await?;
    let route = SshRoute {
        target: ssh.target.clone(),
        hops: ssh.hops.clone(),
    };
    let done = sftp_job(app, me, runner, route, j).await;
    if done.is_err() {
        terminal::unlease(app, &ssh).await;
    }
    done
}

/// Ends an invite nobody will use (a no-op once it is claimed or over).
async fn withdraw(app: &App, me: &Caller, pairing: &str) {
    let by = Decider {
        actor: BY,
        device: Some(me.device.id.as_str()),
        scopes: None,
    };
    let _ = gov::reject_pairing(&app.pool, pairing, by, app.clock.unix()).await;
}

/// Everything a failed or lapsed install must undo: the invite and the file.
async fn undo(app: &App, me: &Caller, runner: &str, chain: &[String], pairing: &str) {
    withdraw(app, me, pairing).await;
    let _ = job(app, me, runner, chain, SftpJob::Remove(&file(pairing))).await;
}

/// What `install` needs after the checks, the invite and its file are in place.
struct Prepared {
    host: String,
    runner: String,
    chain: Vec<String>,
    pairing: String,
    expires: i64,
    expires_at: String,
}

async fn prepare(app: &App, me: &Caller, auth: &Authorized) -> Result<Prepared, ApiError> {
    let size = TerminalSize { rows: 24, cols: 80 };
    let id = auth.host_id();
    let (name, device): (String, Option<String>) =
        sqlx::query_as("SELECT name, runner_device FROM leyline_hosts WHERE id = ?")
            .bind(id)
            .fetch_one(&app.pool)
            .await?;
    if let Some(d) = device
        && gov::get_device(&app.pool, &d)
            .await?
            .is_some_and(|d| d.usable())
    {
        return Err(refuse("already_runner", "the host is a runner already"));
    }
    // Every refusal the Core can know of, before an invite or a lease exists.
    let (runner, chain) = terminal::reach(app, me, id, size).await?;
    let can_sftp = app.hub.runners().get(&runner).is_some_and(|r| {
        r.drivers
            .iter()
            .any(|d| d.commands.iter().any(|c| c == OP_SFTP_WRITE))
    });
    if !can_sftp {
        return Err(refuse(
            "runner_cannot_sftp",
            "the runner is too old to copy files to a host",
        ));
    }
    {
        let mut conn = app.pool.acquire().await?;
        for h in &chain {
            if hostkeys::trusted(&mut conn, h).await?.is_empty() {
                return Err(refuse(
                    "host_not_trusted",
                    "trust the host key of every host on the path first",
                ));
            }
        }
    }
    let scopes = vec!["runner".to_owned()];
    let new = NewPairing {
        kind: "runner",
        name: &name,
        scopes: &scopes,
        created_by: Some(me.device.id.as_str()),
        bootstrap: false,
        recovery: false,
        invite: true,
    };
    let Created {
        id: pairing,
        secret,
        expires,
        ..
    } = gov::create_pairing(&app.pool, &new, BY, app.clock.unix())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::conflict(why),
            e => e.into(),
        })?;
    // `<host>/<core fingerprint>.<secret>`: what `get.sh --runner` takes. Only in this buffer.
    let token = Zeroizing::new(format!("{}/{}.{secret}", app.host, app.auth.identity.fp));
    drop(Zeroizing::new(secret));
    let put = job(
        app,
        me,
        &runner,
        &chain,
        SftpJob::Put {
            path: &file(&pairing),
            mode: 0o600,
            bytes: token.as_bytes(),
        },
    )
    .await;
    drop(token);
    if let Err(e) = put {
        withdraw(app, me, &pairing).await;
        return Err(e);
    }
    let expires_at = gov::get_pairing(&app.pool, &pairing)
        .await?
        .map(|p| p.expires_at)
        .unwrap_or_default();
    Ok(Prepared {
        host: id.to_owned(),
        runner,
        chain,
        pairing,
        expires,
        expires_at,
    })
}

/// Runs the installer on the host, then waits for the pairing. Ends the gate's run last.
async fn install(app: App, me: Caller, auth: Authorized, p: Prepared) {
    let Prepared {
        host,
        runner,
        chain,
        pairing,
        expires,
        ..
    } = p;
    let _ = state(&app, &host, "installing", None, None).await;
    let result = async {
        let sudo = exec::once(&app, &auth, CAN_SUDO).await?;
        let system = sudo.stdout.text.trim() == "system";
        let _ = state(
            &app,
            &host,
            "installing",
            Some(if system { "system" } else { "user" }),
            None,
        )
        .await;
        let r = exec::once(&app, &auth, &command_line(&pairing, system)).await?;
        if r.exit_code == Some(0) && !r.timed_out {
            Ok(system)
        } else {
            let tail: String = r
                .stderr
                .text
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" ");
            Err(if r.timed_out {
                "the install took too long".to_owned()
            } else if tail.trim().is_empty() {
                "the installer on the host failed".to_owned()
            } else {
                crate::gate::redact_text(&tail).chars().take(300).collect()
            })
        }
    }
    .await;
    let ok = result.is_ok();
    match result {
        Ok(system) => {
            let mode = if system { "system" } else { "user" };
            let _ = state(&app, &host, "installing", Some(mode), None).await;
            watch(
                app.clone(),
                me.clone(),
                (host.clone(), runner, chain),
                pairing,
                expires,
                mode,
            )
            .await;
        }
        Err(why) => {
            undo(&app, &me, &runner, &chain, &pairing).await;
            let _ = state(&app, &host, "failed", None, Some(&why)).await;
            let _ = record(&app, &host, "failed", None).await;
        }
    }
    if let Err(e) = gate::finish(&app, auth, ok).await {
        tracing::error!(error = %e.message, "closing a make-runner run failed");
    }
}

/// How the install stands, kept for the host's `runner_install`.
async fn state(
    app: &App,
    host: &str,
    what: &str,
    mode: Option<&str>,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO leyline_runner_install (host_id, state, mode, reason, at) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(host_id) DO UPDATE SET state = ?2, mode = COALESCE(?3, mode), reason = ?4, at = ?5",
    )
    .bind(host)
    .bind(what)
    .bind(mode)
    .bind(reason)
    .bind(app.clock.unix())
    .execute(&app.pool)
    .await?;
    Ok(())
}

/// Waits for the invite to be claimed. Claimed: the new runner is the host's `runner_device`.
/// Lapsed, refused or withdrawn: the file goes and the app is told, so the person can start again.
async fn watch(
    app: App,
    me: Caller,
    (host, runner, chain): (String, String, Vec<String>),
    pairing: String,
    expires: i64,
    mode: &str,
) {
    loop {
        tokio::time::sleep(POLL).await;
        let p = match gov::get_pairing(&app.pool, &pairing).await {
            Ok(Some(p)) => p,
            Ok(None) => break, // gone: nothing left to wait for
            Err(_) => continue,
        };
        match (p.status.as_str(), p.device_id) {
            ("approved", Some(dev)) => {
                let _ = state(&app, &host, "paired", Some(mode), None).await;
                if record(&app, &host, "paired", Some(&dev)).await.is_err() {
                    tracing::warn!("a paired runner could not be linked to its host");
                }
                return;
            }
            ("live" | "claimed", _) if app.clock.unix() <= expires + GRACE => {}
            _ => break,
        }
    }
    undo(&app, &me, &runner, &chain, &pairing).await;
    let _ = state(
        &app,
        &host,
        "failed",
        None,
        Some("the runner did not pair in time"),
    )
    .await;
    if record(&app, &host, "expired", None).await.is_err() {
        tracing::warn!("a lapsed runner invite could not be recorded");
    }
}

/// The audit row and event of how an install ended; `paired` also sets `runner_device`. Ids only,
/// and for `paired` the claimer's own details (name, platform, fingerprint) so the person can see
/// that it is the machine they meant: the invite is its own approval, so this is the only check.
async fn record(app: &App, host: &str, what: &str, device: Option<&str>) -> Result<(), ApiError> {
    let claimer = match device {
        Some(d) => gov::get_device(&app.pool, d).await?.map(|d| {
            json!({"id": d.id, "name": d.name, "platform": d.platform, "fingerprint": d.fingerprint})
        }),
        None => None,
    };
    let mut tx = begin_write(&app.pool).await?;
    if let Some(d) = device {
        sqlx::query(
            "UPDATE leyline_hosts SET runner_device = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        )
        .bind(d)
        .bind(host)
        .execute(&mut *tx)
        .await?;
    }
    let row = NewAuditEvent {
        actor: BY,
        action: "leyline.host.changed".to_owned(),
        entity: None,
        details: json!({"host": host, "runner_install": what, "runner_device": device,
            "claimer": claimer})
        .to_string(),
    };
    audit::append(&mut tx, &row).await?;
    events::append(
        &mut tx,
        "leyline.host",
        &json!({"op": "changed", "id": host, "runner_install": what, "claimer": claimer}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed line holds the file and the installer, never a secret; the file is read by the
    /// root shell (`$0`), whose home the outer shell expands.
    #[test]
    fn the_line_names_the_file_not_the_invite_and_never_prompts_for_sudo() {
        let sys = command_line("p_ABC", true);
        assert!(sys.starts_with("sudo -n sh -c '"));
        assert!(sys.contains("--runner' "));
        assert!(!sys.contains("--user"));
        let user = command_line("p_ABC", false);
        assert!(user.starts_with("sh -c '"));
        assert!(!user.contains("sudo"));
        assert!(user.contains("--runner --user'"));
        for l in [&sys, &user] {
            assert!(l.contains("\"$HOME/.ainkrad-invite-p_ABC\""));
            // https only, TLS 1.3, and this release's own installer and binaries, never `latest`.
            assert!(l.contains("--proto =https --tlsv1.3"));
            assert!(l.contains(&format!("{RELEASE}/get.sh")));
            assert!(l.contains(&format!("AINKRAD_RELEASE_URL={RELEASE}")));
            assert!(!l.contains("latest"));
            assert!(!l.contains("AINKRAD_PAIR_INVITE=ainkrad"));
            assert_eq!(l.matches('\n').count(), 0);
        }
        assert!(CAN_SUDO.contains("sudo -n true"));
    }
}
