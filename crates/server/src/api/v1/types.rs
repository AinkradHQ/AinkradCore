//! The contract's shared shapes (E10.1): timestamps, pages, errors and the enums. Each enum
//! mirrors a core enum variant for variant (a new core variant fails to
//! compile here) and is on the wire as the core's snake_case text.
//!
//! Versioning (E0.4): adding an enum value, a union variant or an optional field is allowed
//! within `/api/v1`; clients must tolerate values they do not know. The spec marks every
//! enum open (`spec::normalise`), so generated clients keep an unknown value as a string
//! instead of failing the whole response. Removing or renaming anything is a new `/api/v2`.
//!
//! [`API_MINOR`] counts those additions: every change to `api/openapi.json` within `/api/v1`
//! bumps it by one (the contract's `info.version` is `1.<minor>.0`). A client reads it from
//! `GET /api/v1/me` and knows a server below the minor it was built for lacks something.

/// The `/api/v1` minor version: bumped by one on every additive change to the contract.
/// 0: the platform contract (E1-02): devices and pairing, push tokens, the event stream, the
/// audit log and settings. Citadel's contract, which reached minor 20, is parked with it in
/// `modules/citadel/api/openapi.json`.
/// 1: `GET /handshake` (E1-05.5).
/// 2: the event bus and audit hardening (E1-04, E1-10): `LatestEvent.floor`, the 410
/// `PastRetention` of `listEvents`, the socket's 4410 close, and the registered event kinds and
/// audit actions as `x-event-kinds` and `x-audit-actions`.
/// 3: signed requests and device identity (E1-07): `POST /handshake/challenge` and
///    `/handshake/session`, `identity_fingerprint` filled, devices by `d_…` id with kind,
///    scopes and fingerprint, `ErrorBody.server_time`. Bearer device keys, `createDevice` and
///    the six-character pairing are gone (a deliberate break before any client shipped; see
///    `api/compat-allow.txt`).
/// 4: pairing (E1-07.4, .7): `createPairing`, `getPairing`, `approvePairing`, `rejectPairing`,
///    and the pre-auth `claimPairing` and `pairStatus`.
/// 5: step-up, device management and lockouts (E1-09.3–.6): `createStepUpChallenge`, `stepUp`,
///    `getDevice`, `renameDevice`, `setDeviceScopes`, `listLockouts`, `clearLockout`,
///    `Device.stepup`, `x-ainkrad-destructive` and 403 `step_up_required`, and the socket's
///    4003 close on a scope change.
/// 6: scoped event streams (E1-04.3): `Event.seq` counts the device's own view, and
///    `x-event-scopes` lists each kind's scope.
/// 7: the runner hub (E1-11.2/.3): the `runner.refused` audit action.
/// 8: runner health (E1-11.4/.6): `listRunners`, `getRunner`, `runNoop`, the
///    `runner.connected`/`.disconnected`/`.degraded` event kinds (scope `read`), the
///    `runner.command` audit action.
/// 9: passkeys and the web client (E1-08): `passkeyRegistrationOptions`,
///    `claimPasskeyPairing`, `webSignInOptions`, `webSignIn`, `createWsTicket`; the pairing kind
///    `passkey`; `StepUpRequest.assertion` (and `stepup_sig` optional), `Challenge.options`; the
///    `passkey.locked` audit action.
/// 10: handshake hardening (KAN-251/252): `proveHandshake` (`POST /handshake {nonce}` with
///    `core_spki` and `core_sig`), `AuditEntry.entity_ref` (a device's `d_…` id; its
///    `entity_id` is now absent), `target=device:d_…`, and `entity_ref` in `audit` events.
/// 11: handshake review (L3, L4, M1): `proveHandshake` answers its own `HandshakeProof`, with
///    `core_spki` and `core_sig` required, and is under the challenge rate (429); a challenge is
///    stateless (still 32 bytes, 43 characters).
/// 12: scheduler and notifications (E2-11/12): the `job.ran`, `job.failed`, `job.missed` and
///    `notify.token_pruned` audit actions, the `notify.delivery` event kind (scope `admin`).
/// 13: the secrets broker (E2-07): `listSecrets`, `createSecret`, `rotateSecret`, `deleteSecret`,
///    `leaseSecret`, `redeemSecretLease` (scope `runner`), the `secret.*` audit actions.
/// 14: terminals (E2-01): `createTerminal`, `listTerminals`, `getTerminal`, `closeTerminal`,
///    `signalTerminal`, `attachTerminal` (501 until the terminal service, E2-05), the scope
///    `terminal` with step-up on create and attach, and the `terminal.*` event kinds.
/// 15: agent sessions (E2-08): `createAgentSession`, `listAgentSessions`, `getAgentSession`,
///    `getAgentTranscript`, `sendAgentMessage`, `decideAgentApproval` (scope `approve`),
///    `cancelAgentSession`, `killAgentSession`, `resumeAgentSession`; the `agent.*` event kinds
///    (scope `agent`, approvals `approve`) and audit actions; `RunnerDriver.slots`.
/// 16: runner host load in the API (E2-15.2): `Runner.host_load` carries `avg1` and `cores`.
/// 17: terminal service (E2-05/06): live attach/detach, resize, signal and close behavior.
/// 18: `killAgentSession` also stops a module's session, for an `admin` device (break-glass).
/// 19: terminal lifecycle (E2-05/06): `Terminal.orphaned`, a terminal whose runner host died ends
///    `exited` (`terminal.exited` with reason `host_lost`), idle terminals are closed
///    (`terminal.closed`, reason `idle`), and the settings `terminal.idle_secs`,
///    `terminal.max_per_device` and `terminal.max_per_runner`.
/// 20: the `secret.used` audit action (additive enum value).
/// 21: the `secret.master_rotated` audit action (master-key rotation, E2-07.1).
/// 22: health (E1-13.4, E1-19.3, E1-11.8): `getMetrics` (`GET /api/v1/metrics`, Prometheus text,
///    scope `admin`), the `alarm.raised` and `alarm.cleared` event kinds and audit actions (scope
///    `admin`), the `identity.rotation.started`, `.announced` and `.switched` audit actions, and
///    the `alarm.*` settings.
/// 23: terminal storage (E2-04.3, E2-06): the `terminal.reap_warning` event, the settings
///    `terminal.reap_grace_secs`, `terminal.orphan_grace_secs`, `terminal.scrollback_bytes` and
///    `terminal.scrollback_budget_bytes`, and `watch` and the scrollback limits on the runner's
///    `pty.open` and `pty.attach`.
/// 24: the setting `audit.anchor_interval_secs` (E1-10.4, off-box anchors of the audit chain head).
/// 25: the policy isolation fields (E8a-08): `min_isolation`, `image`, `vcpus`, `memory_mb`, `disk_mb`,
///    `wall_secs`, `egress` and `workspace` on the runner policy (`runner.schema.json`), all optional.
/// 26: runner isolation capability (E8a-09): `Runner.arch` and `Runner.isolation` (tiers offered now
///    and the `/dev/kvm` state) in the API; `isolation` on the runner's hello and heartbeat; a
///    session whose policy needs a tier is refused placement where it is not offered.
/// 27: the agent wake queue (E2-11.3): `wakeAgentSession` (`POST /agent-sessions/{id}/wake`) and
///    `AgentWake`/`AgentWakeRequest`; `AgentStart.epoch` in the runner schema (optional, 0 when absent).
pub const API_MINOR: u32 = 27;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// RFC 3339 UTC with exactly milliseconds, `2026-10-21T12:00:00.250Z`: one shape, so a
/// client's date parser never meets a second one (E0.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, schemars::JsonSchema)]
#[schema(value_type = String, format = DateTime)]
pub struct Timestamp(String);

impl Timestamp {
    /// A stored ISO-8601 UTC time in the wire shape: the fraction padded or cut to
    /// milliseconds. Stored times already are, except a few written without a fraction.
    pub fn new(stored: &str) -> Self {
        let body = stored.strip_suffix('Z').unwrap_or(stored);
        let (secs, frac) = body.split_once('.').unwrap_or((body, ""));
        let ms: String = frac.chars().chain("000".chars()).take(3).collect();
        Self(format!("{secs}.{ms}Z"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn ts(stored: &str) -> Timestamp {
    Timestamp::new(stored)
}

pub fn opt_ts(stored: Option<&str>) -> Option<Timestamp> {
    stored.map(Timestamp::new)
}

/// A page of a list. `next_after` is the cursor of the next page, absent on the last.
#[derive(Debug, Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_after: Option<i64>,
}

impl<T> Page<T> {
    /// `items` as fetched with one extra row: the extra one only says there is more.
    pub fn of(mut items: Vec<T>, limit: u32, cursor: impl Fn(&T) -> i64) -> Self {
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_after = more.then(|| items.last().map(&cursor)).flatten();
        Self { items, next_after }
    }
}

/// A JSON error: a stable `code` and a message for people.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    /// `err_` and a ULID, unique to this answer: logged with it (and, for a refused write,
    /// audited as `api.refused`), for the app's "Copy error".
    pub error_id: String,
    /// The server's clock in unix seconds, on a `clock_skew` refusal only (handshake spec §5.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time: Option<i64>,
}

macro_rules! api_enum {
    ($(#[$doc:meta])* $name:ident = $core:ty { $($v:ident),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($v),* }

        impl From<$core> for $name {
            fn from(v: $core) -> Self {
                match v { $(<$core>::$v => Self::$v),* }
            }
        }

        impl From<$name> for $core {
            fn from(v: $name) -> Self {
                match v { $($name::$v => Self::$v),* }
            }
        }
    };
}

use ainkrad_core::settings;

api_enum!(SettingScope = settings::ScopeKind { Server });
api_enum!(
    SettingUnit = settings::Unit {
        Seconds,
        Milliseconds,
        Percent,
        Count,
        Bytes,
        PerMinute
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_exactly_milliseconds() {
        for (stored, wire) in [
            ("2026-10-21T12:00:00Z", "2026-10-21T12:00:00.000Z"),
            ("2026-10-21T12:00:00.25Z", "2026-10-21T12:00:00.250Z"),
            ("2026-10-21T12:00:00.250Z", "2026-10-21T12:00:00.250Z"),
            ("2026-10-21T12:00:00.123456789Z", "2026-10-21T12:00:00.123Z"),
        ] {
            assert_eq!(Timestamp::new(stored).as_str(), wire);
        }
    }

    fn s<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    #[test]
    fn enums_speak_the_core_text() {
        assert_eq!(
            s(&SettingUnit::from(settings::Unit::PerMinute)),
            "\"per_minute\""
        );
        assert_eq!(s(&SettingScope::Server), "\"server\"");
    }

    #[test]
    fn a_page_says_whether_there_is_more() {
        let p = Page::of(vec![1, 2, 3], 2, |n| *n);
        assert_eq!((p.items, p.next_after), (vec![1, 2], Some(2)));
        let p = Page::of(vec![1, 2], 2, |n| *n);
        assert_eq!((p.items, p.next_after), (vec![1, 2], None));
    }
}
