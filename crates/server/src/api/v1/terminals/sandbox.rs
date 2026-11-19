//! Where a new terminal's shell lives (D-17, E6-2): the Core's side of `PtyOpen::sandbox`.
//!
//! The default is a private root with the caller's persistent home on the runner. A project's or
//! session's folder is added only when the caller asks for that mode and may see it. `real` (the
//! runner's own host view) is allowed to exactly one caller: the Mac that owns a macOS runner.
//!
//! **How the Core proves "this Mac's bundled runner, from this Mac's app".** Every request is
//! signed by a paired device key (Secure Enclave on a Mac), so `me.device` is the app. The runner
//! is the bundled one when that same app device attested it (`attestBundledRunner`, which sets
//! `core_pairings.bundled`): the app reads the runner's own enrolment file on its local disk, which
//! only a runner on this Mac has, and says so under a step-up. The Core accepts the attestation
//! only from a macOS `device` that created the invite that enrolled the runner. A runner on another
//! machine (even one this same Mac paired through the Add-runner wizard) has no such file here, so
//! the app never attests it. On top of that, the runner's hello must say macOS and the caller must
//! be a macOS `device` with the `terminal` scope; the runner itself refuses `real` unless it was
//! started with `--bundled`, a flag only the app's LaunchAgent sets. A Core-local runner (no
//! creator), Linux, and a runner another device or the wizard paired all fail. The mode is never
//! a default: the app must ask for `real`.

use super::*;
use ainkrad_proto::v2::{SandboxMode, valid_sandbox_user};
use axum::http::StatusCode;

/// What `create` hands to the runner.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub sandbox: Option<String>,
    pub user: Option<String>,
    pub cwd: Option<String>,
    /// Only for `real` in a session folder (the host-view reveal).
    pub session: Option<String>,
}

fn refused(why: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "real_terminal_refused", why)
}

/// The rule for `real`, apart from the database: `owner` is the device that enrolled the runner.
pub(super) fn real_ok(
    owner: Option<&str>,
    bundled: bool,
    me: &gov::Device,
    runner_os: Option<&str>,
) -> Result<(), &'static str> {
    let mac = |p: Option<&str>| p.is_some_and(|p| p.eq_ignore_ascii_case("macos"));
    if me.kind != "device" || !mac(me.platform.as_deref()) {
        return Err("a real shell is only for the Mac's own app");
    }
    if !me.scopes.iter().any(|s| s == "terminal") {
        return Err("this device may not open terminals");
    }
    if !mac(runner_os) {
        return Err("a real shell is only for a macOS runner");
    }
    match owner {
        Some(o) if o == me.id && bundled => Ok(()),
        Some(o) if o == me.id => Err("this runner is not the one bundled with this Mac's app"),
        _ => Err("this runner was not enrolled by this Mac"),
    }
}

async fn real(app: &App, me: &Caller, runner: &str) -> Result<(), ApiError> {
    let (owner, bundled): (Option<String>, i64) = sqlx::query_as(
        "SELECT created_by, bundled FROM core_pairings WHERE kind = 'runner' AND device_id = ? \
         AND status = 'approved'",
    )
    .bind(runner)
    .fetch_optional(&app.pool)
    .await?
    .unwrap_or((None, 0));
    let os = app.hub.runners().get(runner).and_then(|r| r.os.clone());
    real_ok(owner.as_deref(), bundled == 1, &me.device, os.as_deref()).map_err(refused)
}

/// The newest live session of project `id` on `runner`: the folder a project terminal mounts.
async fn project_session(
    app: &App,
    me: &Caller,
    runner: &str,
    id: i64,
) -> Result<String, ApiError> {
    // Only the caller's own sessions: another device's worktree is not theirs to open a shell in.
    sqlx::query_scalar(
        "SELECT id FROM core_agent_sessions WHERE project_id = ? AND runner = ? AND created_by = ? \
         AND state IN ('starting', 'running', 'interrupted') AND folder IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .bind(runner)
    .bind(&me.device.id)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "project_folder_unknown",
            "the project has no live session folder on this runner",
        )
    })
}

/// Whether `runner` is connected with a hello that does NOT say it honours `PtyOpen::sandbox`.
/// A runner that is not connected has no hello to judge: the open stops later as unknown or offline.
fn runner_predates_sandboxes(app: &App, runner: &str) -> bool {
    app.hub.runners().get(runner).is_some_and(|r| {
        !r.drivers
            .iter()
            .any(|d| d.name == "pty" && d.slots.contains_key("sandbox"))
    })
}

pub(super) async fn plan(
    app: &App,
    me: &Caller,
    runner: &str,
    sandbox: Option<&str>,
    session: Option<&str>,
    cwd: Option<&str>,
    project: Option<i64>,
) -> Result<Plan, ApiError> {
    // A runner that predates sandboxes would ignore the fields and start a host-view shell: no
    // terminal opens on it, whatever was asked (E12 updates runners on its own).
    if runner_predates_sandboxes(app, runner) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "runner_update_required",
            "Update this runner to open terminals",
        ));
    }
    let default;
    let want = match (sandbox, session) {
        (Some(s), _) => s,
        (None, Some(id)) => {
            default = format!("session:{id}");
            &default
        }
        (None, None) => "home",
    };
    let mode = SandboxMode::parse(want).map_err(|m| ApiError::bad_request(&m))?;
    if mode == SandboxMode::Real {
        real(app, me, runner).await?;
        // The host view: a project's folder (a cwd, not a mount: the runner lets the shell into
        // that session folder), a session's, or a path.
        if let Some(p) = project {
            if session.is_some() || cwd.is_some() {
                return Err(ApiError::bad_request(
                    "give a project, a session or a cwd, not two",
                ));
            }
            let mut c = app.pool.acquire().await?;
            crate::store::projects::get(&mut c, p)
                .await
                .map_err(|_| ApiError::not_found("no such project"))?;
            drop(c);
            let sid = project_session(app, me, runner, p).await?;
            return Ok(Plan {
                sandbox: Some("real".into()),
                user: None,
                cwd: Some(super::super::agents::terminal_folder(app, me, runner, &sid).await?),
                session: Some(sid),
            });
        }
        return match (session, cwd) {
            (Some(id), None) => Ok(Plan {
                sandbox: Some("real".into()),
                user: None,
                cwd: Some(super::super::agents::terminal_folder(app, me, runner, id).await?),
                session: Some(id.to_owned()),
            }),
            (Some(_), Some(_)) => Err(ApiError::bad_request("give cwd or session, not both")),
            (None, cwd) => Ok(Plan {
                sandbox: Some("real".into()),
                user: None,
                cwd: cwd.map(str::to_owned),
                session: None,
            }),
        };
    }
    if project.is_some() {
        return Err(ApiError::bad_request(
            "project is for a real shell; a sandbox names it in `sandbox`",
        ));
    }
    if cwd.is_some() {
        return Err(ApiError::bad_request(
            "a sandboxed terminal takes no cwd: name a project or session in `sandbox`",
        ));
    }
    let folder_session = match &mode {
        SandboxMode::Home => None,
        SandboxMode::Session(id) => {
            if session.is_some_and(|s| s != id.as_str()) {
                return Err(ApiError::bad_request(
                    "sandbox and session name different sessions",
                ));
            }
            Some(id.clone())
        }
        SandboxMode::Project(p) => {
            let n: i64 = p
                .parse()
                .map_err(|_| ApiError::bad_request("a project id is a number"))?;
            let mut c = app.pool.acquire().await?;
            crate::store::projects::get(&mut c, n)
                .await
                .map_err(|_| ApiError::not_found("no such project"))?;
            Some(project_session(app, me, runner, n).await?)
        }
        SandboxMode::Real => unreachable!("handled above"),
    };
    let folder = match folder_session {
        Some(id) => Some(super::super::agents::terminal_folder(app, me, runner, &id).await?),
        None => None,
    };
    let uid: i64 = sqlx::query_scalar("SELECT user_id FROM core_devices WHERE id = ?")
        .bind(&me.device.id)
        .fetch_one(&app.pool)
        .await?;
    let user = format!("u{uid}");
    debug_assert!(valid_sandbox_user(&user));
    Ok(Plan {
        sandbox: Some(want.to_owned()),
        user: Some(user),
        cwd: folder,
        session: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(kind: &str, platform: Option<&str>, scopes: &[&str]) -> gov::Device {
        gov::Device {
            seq: 1,
            id: "d_me".into(),
            kind: kind.into(),
            name: "x".into(),
            routine_spki: vec![],
            fingerprint: String::new(),
            stepup_spki: None,
            platform: platform.map(str::to_owned),
            key_storage: None,
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            status: "active".into(),
            created_at: String::new(),
            last_used_at: None,
            revoked_at: None,
        }
    }

    /// `real` is refused unless every link of the proof holds: the caller is a macOS app device
    /// with the terminal scope, the runner is macOS, and that same device enrolled it.
    #[test]
    fn a_real_shell_needs_every_link_of_the_proof() {
        let me = dev("device", Some("macos"), &["terminal"]);
        assert!(real_ok(Some("d_me"), true, &me, Some("macos")).is_ok());
        // A remote Mac runner this same Mac paired through the wizard (not bundled).
        assert!(real_ok(Some("d_me"), false, &me, Some("macos")).is_err());
        // Another device's runner, a Core-local runner (no creator), a Linux runner.
        assert!(real_ok(Some("d_other"), true, &me, Some("macos")).is_err());
        assert!(real_ok(None, true, &me, Some("macos")).is_err());
        assert!(real_ok(Some("d_me"), true, &me, Some("linux")).is_err());
        assert!(real_ok(Some("d_me"), true, &me, None).is_err());
        // Not the Mac app: a runner, a passkey (browser), an iPhone, no terminal scope.
        for bad in [
            dev("runner", Some("macos"), &["terminal"]),
            dev("passkey", Some("macos"), &["terminal"]),
            dev("device", Some("ios"), &["terminal"]),
            dev("device", None, &["terminal"]),
            dev("device", Some("macos"), &["agent"]),
        ] {
            assert!(
                real_ok(Some("d_me"), true, &bad, Some("macos")).is_err(),
                "{bad:?}"
            );
        }
    }
}
