//! Where a new terminal's shell lives (D-17, E6-2): the Core's side of `PtyOpen::sandbox`.
//!
//! The default is a private root with the caller's persistent home on the runner. A project's or
//! session's folder is added only when the caller asks for that mode and may see it. `real` (the
//! runner's own host view) is allowed to exactly one caller: the Mac that owns a macOS runner.
//!
//! **How the Core proves "this Mac, from this Mac's app".** Every request is signed by a paired
//! device key (Secure Enclave on a Mac), so `me.device` is the app. The runner is "this Mac's"
//! when the pairing that enrolled it (`core_pairings.created_by`, the device that made the invite
//! the bundled runner redeemed) is that same device, the runner's hello says it runs on macOS, and
//! the caller is a `device` on macOS holding the `terminal` scope. A Core-local runner (enrolled on
//! the host socket, no creator), a Linux or Windows runner, and a runner another device paired
//! all fail. The mode is never a default: the app must ask for `real`.

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
        Some(o) if o == me.id => Ok(()),
        _ => Err("this runner was not enrolled by this Mac"),
    }
}

async fn real(app: &App, me: &Caller, runner: &str) -> Result<(), ApiError> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT created_by FROM core_pairings WHERE kind = 'runner' AND device_id = ? \
         AND status = 'approved'",
    )
    .bind(runner)
    .fetch_optional(&app.pool)
    .await?
    .flatten();
    let os = app.hub.runners().get(runner).and_then(|r| r.os.clone());
    real_ok(owner.as_deref(), &me.device, os.as_deref()).map_err(refused)
}

/// The newest live session of project `id` on `runner`: the folder a project terminal mounts.
async fn project_session(app: &App, runner: &str, id: i64) -> Result<String, ApiError> {
    sqlx::query_scalar(
        "SELECT id FROM core_agent_sessions WHERE project_id = ? AND runner = ? \
         AND state IN ('starting', 'running', 'interrupted') AND folder IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .bind(runner)
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

/// Whether `runner`'s hello says it honours `PtyOpen::sandbox`.
fn runner_supports(app: &App, runner: &str) -> bool {
    app.hub.runners().get(runner).is_some_and(|r| {
        r.drivers
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
) -> Result<Plan, ApiError> {
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
        // The host view as before: a folder by path, or a session's.
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
            Some(project_session(app, runner, n).await?)
        }
        SandboxMode::Real => unreachable!("handled above"),
    };
    let folder = match folder_session {
        Some(id) => Some(super::super::agents::terminal_folder(app, me, runner, &id).await?),
        None => None,
    };
    if !runner_supports(app, runner) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "sandbox_unsupported",
            "this runner predates terminal sandboxes; update it",
        ));
    }
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
        assert!(real_ok(Some("d_me"), &me, Some("macos")).is_ok());
        // Another device's runner, a Core-local runner (no creator), a Linux runner.
        assert!(real_ok(Some("d_other"), &me, Some("macos")).is_err());
        assert!(real_ok(None, &me, Some("macos")).is_err());
        assert!(real_ok(Some("d_me"), &me, Some("linux")).is_err());
        assert!(real_ok(Some("d_me"), &me, None).is_err());
        // Not the Mac app: a runner, a passkey (browser), an iPhone, no terminal scope.
        for bad in [
            dev("runner", Some("macos"), &["terminal"]),
            dev("passkey", Some("macos"), &["terminal"]),
            dev("device", Some("ios"), &["terminal"]),
            dev("device", None, &["terminal"]),
            dev("device", Some("macos"), &["agent"]),
        ] {
            assert!(
                real_ok(Some("d_me"), &bad, Some("macos")).is_err(),
                "{bad:?}"
            );
        }
    }
}
