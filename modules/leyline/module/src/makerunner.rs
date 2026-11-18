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
//!   byte (`SftpWrite::mode`), in the user's `~/.cache`; the command typed into the terminal names
//!   only that file. The root shell reads it into the installer's environment and deletes it
//!   first. In the Core it lives in a `Zeroizing` buffer for the length of one call and rides one
//!   SFTP frame that the hub does not keep for a resend.
//! - The installer is not touched: the same `get.sh --runner` and its own checks run, as root,
//!   after the person types their sudo password in the terminal (never read or stored here).
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
    ApiError, ApiResult, BY, Caller, SftpJob, TerminalSize, sftp_job, type_into,
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

use crate::gate::{self, Action, Authorized, Principal};
use crate::hostkeys;
use crate::hosts::{In, find};
use crate::terminal::{self, NewSession, SessionView};

/// Where the invite waits on the host, relative to the user's home (SFTP starts there).
const DIR: &str = ".cache";
const FILE: &str = ".cache/ainkrad-invite";
/// The installer, from the same signed release channel the app's own command shows.
const GET: &str = "https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh";
/// How often the wait looks at the pairing.
const POLL: Duration = Duration::from_secs(3);
/// How long past the invite's end the wait gives the Core's own expiry sweep before it acts.
const GRACE: i64 = 60;

/// The runner install started: attach to `session.terminal`, type the sudo password there, and
/// watch `leyline.host` events (or the host's `runner_device`) for the pairing.
#[derive(Serialize, ToSchema)]
pub struct Install {
    pub session: SessionView,
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

/// The one line typed in the terminal. The invite is not in it, only the file it is in.
fn command_line() -> String {
    format!(
        "sudo sh -c 'AINKRAD_PAIR_INVITE=$(cat \"$0\"); rm -f \"$0\"; export AINKRAD_PAIR_INVITE; \
         curl -fsSL {GET} | sh -s -- --runner' \"$HOME/{FILE}\"\n"
    )
}

#[utoipa::path(post, path = "/hosts/{host}/runner", operation_id = "leylineMakeRunner", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = NewSession,
    responses((status = 200, description = "A runner invite is on the host and a terminal is open with the installer's command typed in: the person types the sudo password there. The host shows as a paired runner (`runner_device`) when the installer is done. 403 `gate_refused` (person only) or `forbidden_scope`; 409 `already_runner`, `host_not_trusted` (every host on the path needs a pinned key), `runner_cannot_ssh`, `runner_cannot_sftp`, `host_needs_key`, `no_runner`; 502 `sftp_failed` (nothing is left behind). Needs a step-up", body = Install)))]
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
    let done = run(&app, &me, size, &auth).await;
    gate::finish(&app, auth, done.is_ok()).await?;
    Ok(Json(done?))
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
    let _ = job(app, me, runner, chain, SftpJob::Remove(FILE)).await;
}

async fn run(
    app: &App,
    me: &Caller,
    size: TerminalSize,
    auth: &Authorized,
) -> Result<Install, ApiError> {
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
    // The directory may exist already; a real failure shows at the put.
    let _ = job(app, me, &runner, &chain, SftpJob::Mkdir(DIR)).await;
    let put = job(
        app,
        me,
        &runner,
        &chain,
        SftpJob::Put {
            path: FILE,
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
    let session = match terminal::start(app, me, size, auth).await {
        Ok(s) => s,
        Err(e) => {
            undo(app, me, &runner, &chain, &pairing).await;
            return Err(e);
        }
    };
    // ponytail: typed at once; the pty holds it until the remote shell reads it. A shell that
    // drops typeahead at login leaves the person to paste the line: re-send on first output.
    if let Err(e) = type_into(app, me, &session.terminal, &command_line()).await {
        undo(app, me, &runner, &chain, &pairing).await;
        return Err(e);
    }
    let expires_at = gov::get_pairing(&app.pool, &pairing)
        .await?
        .map(|p| p.expires_at)
        .unwrap_or_default();
    tokio::spawn(watch(
        app.clone(),
        me.clone(),
        (id.to_owned(), runner, chain),
        pairing.clone(),
        expires,
    ));
    Ok(Install {
        session,
        pairing,
        expires_at,
    })
}

/// Waits for the invite to be claimed. Claimed: the new runner is the host's `runner_device`.
/// Lapsed, refused or withdrawn: the file goes and the app is told, so the person can start again.
async fn watch(
    app: App,
    me: Caller,
    (host, runner, chain): (String, String, Vec<String>),
    pairing: String,
    expires: i64,
) {
    loop {
        tokio::time::sleep(POLL).await;
        let Ok(Some(p)) = gov::get_pairing(&app.pool, &pairing).await else {
            continue;
        };
        match (p.status.as_str(), p.device_id) {
            ("approved", Some(dev)) => {
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
    if record(&app, &host, "expired", None).await.is_err() {
        tracing::warn!("a lapsed runner invite could not be recorded");
    }
}

/// The audit row and event of how an install ended; `paired` also sets `runner_device`. Ids only.
async fn record(app: &App, host: &str, what: &str, device: Option<&str>) -> Result<(), ApiError> {
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
        details: json!({"host": host, "runner_install": what, "runner_device": device}).to_string(),
    };
    audit::append(&mut tx, &row).await?;
    events::append(
        &mut tx,
        "leyline.host",
        &json!({"op": "changed", "id": host, "runner_install": what}),
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
    fn the_line_names_the_file_not_the_invite() {
        let l = command_line();
        assert!(l.starts_with("sudo sh -c '"));
        assert!(l.contains("--runner"));
        assert!(l.contains(&format!("\"$HOME/{FILE}\"")));
        assert!(!l.contains("AINKRAD_PAIR_INVITE=ainkrad"));
        assert!(l.ends_with('\n'));
        assert_eq!(l.matches('\n').count(), 1);
    }
}
