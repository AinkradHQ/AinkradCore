//! The local terminal path (spec `Specs/2026-11-12-local-terminal-path.md`): the Core stays the
//! authority and the audit, an app on the runner's own Mac carries the bytes itself.
//!
//! `grantLocalTerminal` is the attach, for a client that will reach the host's Unix socket
//! directly: the same scope and step-up as `attachTerminal`, the same attach caps, an audit row
//! and event, and instead of a WebSocket a short-lived grant the Core signs for this device and
//! terminal. The app calls it again before each lease ends (a renewal, not a new attach); the
//! Core stops granting when the device is revoked or loses the scope, so a local connection
//! outlives that by one lease at most. `releaseLocalTerminal` is the detach.

use super::*;
use ainkrad_proto::v2::local::{
    GRANT_TTL_SECS, GRANT_VERSION, LEASE_SECS, LocalGrant, grant_message,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};

/// What the app needs to reach the host: present `grant` on `socket`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LocalTerminalGrant {
    pub terminal: String,
    /// The runner the terminal lives on: a grant is for that runner's hosts only.
    pub runner: String,
    /// The Core-signed grant, single-use; sign the host's challenge with the device key and send both.
    pub grant: String,
    pub expires_at: Timestamp,
    /// Seconds one authentication keeps the local connection open. Ask again before then.
    pub lease_secs: u64,
    /// The file name of the host's socket in the runner's terminal directory.
    pub socket: String,
}

impl Rooms {
    /// A lease for `device` on `terminal` until `until`, or `None` at a cap. `Some(true)` is a
    /// new lease, `Some(false)` a renewal. A lease that ran out counts for nothing here, and is
    /// removed (and audited) by `lapse`.
    fn lease(&self, terminal: &str, device: &str, until: i64, now: i64) -> Option<bool> {
        let mut m = self.leases.lock().unwrap();
        let key = (terminal.to_owned(), device.to_owned());
        let live = |u: &i64| *u > now;
        if m.get(&key).is_some_and(live) {
            m.insert(key, until);
            return Some(false);
        }
        let per_terminal = m.iter().filter(|(k, u)| k.0 == terminal && live(u)).count();
        let per_device = m.iter().filter(|(k, u)| k.1 == device && live(u)).count();
        let (ws_terminal, ws_device) = {
            let s = self.slots.lock().unwrap();
            (
                s.0.get(terminal).copied().unwrap_or(0),
                s.1.get(device).copied().unwrap_or(0),
            )
        };
        if per_terminal as u32 + ws_terminal >= MAX_ATTACH_PER_TERMINAL
            || per_device as u32 + ws_device >= MAX_ATTACH_PER_DEVICE
        {
            return None;
        }
        m.insert(key, until);
        Some(true)
    }

    fn release(&self, terminal: &str, device: &str) -> bool {
        self.leases
            .lock()
            .unwrap()
            .remove(&(terminal.to_owned(), device.to_owned()))
            .is_some()
    }

    /// Removes the leases that ran out; they are the detaches nobody reported.
    pub(super) fn lapse(&self, now: i64) -> Vec<(String, String)> {
        let mut m = self.leases.lock().unwrap();
        let gone: Vec<_> = m
            .iter()
            .filter(|(_, u)| **u <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &gone {
            m.remove(k);
        }
        gone
    }

    pub(super) fn leased(&self, terminal: &str) -> u32 {
        self.leases
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.0 == terminal)
            .count() as u32
    }
}

/// An audit row and an event: `action` (`terminal.attached` / `terminal.detached`) was done on
/// `id` by `by` over the local path. Names only, like every terminal row.
async fn record(app: &App, action: &str, id: &str, by: &str, how: &str) -> Result<(), ApiError> {
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM core_terminals WHERE id=?")
        .bind(id)
        .fetch_optional(&app.pool)
        .await?
        .unwrap_or(0);
    store::audit::append_one(
        &app.pool,
        &NewAuditEvent {
            actor: BY,
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: "terminal".to_owned(),
                id: seq,
            }),
            details: json!({"terminal":id,"by_device":by,"local":true,"how":how}).to_string(),
        },
    )
    .await?;
    event_with(app, action, id, by, Some("local")).await
}

/// Records the local attaches whose lease ran out without a release (the app died, the Mac slept).
pub(super) async fn lapse(app: &App) {
    for (terminal, device) in app.terminals.lapse(app.clock.unix()) {
        touch(app, &terminal).await;
        let _ = record(app, "terminal.detached", &terminal, &device, "lapsed").await;
    }
}

#[utoipa::path(post, path="/api/v1/terminals/{id}/local", operation_id="grantLocalTerminal", tag="terminals", params(("id"=String,Path)), responses((status=200, description="A signed grant for the host's local socket", body=LocalTerminalGrant)))]
pub async fn grant(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<LocalTerminalGrant> {
    // The same live re-check as an attach (KAN-417): a revoked or re-scoped device gets nothing.
    match crate::auth::device_now(&app.pool, &me.device.id, Some(&me.device.scopes)).await {
        crate::auth::DeviceNow::Usable => {}
        crate::auth::DeviceNow::Gone => return Err(super::super::gate::auth_failed()),
        crate::auth::DeviceNow::Unknown => return Err(super::super::events::unavailable()),
    }
    let t = row(&app, &id).await?;
    if !matches!(t.status, TerminalStatus::Running | TerminalStatus::Created) {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "terminal_not_running",
            "the terminal is not running",
        ));
    }
    // Only a runner the Core is connected to can have a host that trusts the Core's grants.
    if !app.hub.online(&t.runner) {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "runner_offline",
            "the runner is not connected",
        ));
    }
    let now = app.clock.unix();
    let Some(fresh) = app
        .terminals
        .lease(&id, &me.device.id, now + LEASE_SECS as i64, now)
    else {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too_many_attaches",
            "too many clients are attached to this terminal or from this device",
        ));
    };
    let mut nonce = [0u8; 16];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    })?;
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&LocalGrant {
            v: GRANT_VERSION,
            terminal: id.clone(),
            runner: t.runner.clone(),
            device: me.device.id.clone(),
            device_spki: URL_SAFE_NO_PAD.encode(&me.device.routine_spki),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            iat: now,
            exp: now + GRANT_TTL_SECS,
            lease: LEASE_SECS,
        })
        .expect("a grant serializes"),
    );
    let sig = app.auth.identity.sign(&grant_message(&payload));
    if fresh {
        // A renewal is not another attach: one row when it begins, one when it ends.
        if let Err(e) = record(&app, "terminal.attached", &id, &me.device.id, "grant").await {
            app.terminals.release(&id, &me.device.id);
            return Err(e);
        }
        touch(&app, &id).await;
    }
    Ok(Json(LocalTerminalGrant {
        socket: format!("{id}.local.sock"),
        terminal: id,
        runner: t.runner,
        grant: format!("{payload}.{}", URL_SAFE_NO_PAD.encode(sig)),
        expires_at: ts(&iso_of_unix(now + GRANT_TTL_SECS)),
        lease_secs: LEASE_SECS,
    }))
}

#[utoipa::path(delete, path="/api/v1/terminals/{id}/local", operation_id="releaseLocalTerminal", tag="terminals", params(("id"=String,Path)), responses((status=204, description="The local attach was released")))]
pub async fn release(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> Response {
    if app.terminals.release(&id, &me.device.id) {
        touch(&app, &id).await;
        let _ = record(&app, "terminal.detached", &id, &me.device.id, "release").await;
    }
    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_is_new_once_renewed_after_and_counts_as_attached() {
        let r = Rooms::default();
        assert_eq!(r.lease("t_a", "d_1", 100, 50), Some(true));
        assert_eq!(r.lease("t_a", "d_1", 200, 60), Some(false));
        assert_eq!(r.attached("t_a"), 1);
        assert!(r.release("t_a", "d_1"));
        assert!(!r.release("t_a", "d_1"));
        assert_eq!(r.attached("t_a"), 0);
    }

    #[test]
    fn leases_share_the_attach_caps_and_an_expired_one_counts_for_nothing() {
        let r = Rooms::default();
        for d in 0..MAX_ATTACH_PER_TERMINAL {
            assert_eq!(r.lease("t_a", &format!("d_{d}"), 100, 50), Some(true));
        }
        // The terminal is full; another device is refused, and an expired lease is room again.
        assert_eq!(r.lease("t_a", "d_x", 100, 50), None);
        assert_eq!(r.lease("t_a", "d_x", 300, 100), Some(true));
        // Per device across terminals.
        for t in 0..MAX_ATTACH_PER_DEVICE {
            assert_eq!(r.lease(&format!("t_{t}"), "d_many", 1000, 50), Some(true));
        }
        assert_eq!(r.lease("t_over", "d_many", 1000, 50), None);
    }

    #[test]
    fn a_lease_that_ran_out_is_reported_once_by_lapse() {
        let r = Rooms::default();
        r.lease("t_a", "d_1", 100, 50);
        r.lease("t_a", "d_2", 500, 50);
        assert_eq!(r.lapse(99), vec![]);
        assert_eq!(r.lapse(100), vec![("t_a".to_owned(), "d_1".to_owned())]);
        assert_eq!(r.lapse(100), vec![]);
        assert_eq!(r.attached("t_a"), 1);
    }
}
