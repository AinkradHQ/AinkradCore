//! Core's side of Entra's OAuth: Ainkrad's registered app, the token endpoint, and what a token
//! answer means. Sign-in itself is the device code flow ([`super::device`]); renewal is
//! [`super::renew`].
//!
//! **A public client.** The app has a client id and a tenant, and NO client secret: Core never
//! sends one (a public client that sent one would be refused). Anyone holding a refresh token
//! still needs the connection's tenant and this client id to use it.

use std::fmt;

use serde_json::Value;
use zeroize::Zeroizing;

use super::cred::tenant_id;
use super::http::{CallError, Endpoint, Http, classify};
use crate::connections::material::Material;
use crate::scheduler::{iso_of_unix, unix_secs};

/// Delegated scopes, all asked at sign-in: `openid` (the id token's tenant), `offline_access` (a
/// refresh token), `User.Read` (`/me`), the two basic listings, and the channel read and send
/// permissions. `ChannelMessage.Read.All` needs a tenant admin's consent. Never `Chat.*`,
/// `Mail.*`, `Files.*`, `Calendars.*`, `*.ReadWrite.All`, `Group.*` or `ChannelMessage.Delete`.
pub const SCOPES: &str = "openid offline_access User.Read Team.ReadBasic.All \
                          Channel.ReadBasic.All ChannelMessage.Read.All ChannelMessage.Send";
/// A token is renewed when it has less than this left.
pub(super) const SKEW_SECS: i64 = 120;

/// Ainkrad's registered Microsoft app: a public client of one tenant kind.
#[derive(Clone)]
pub struct TeamsApp {
    pub(super) client_id: String,
    /// `organizations` (any work or school tenant) or one tenant's GUID.
    pub(super) tenant: String,
}

impl TeamsApp {
    /// `None` when the client id is not a GUID-like id of at most 64 characters or the tenant is
    /// neither `organizations` nor a tenant GUID (`common` and `consumers` would admit personal
    /// accounts, which have no Teams channels; a name would be a path to build).
    pub fn new(client_id: &str, tenant: &str) -> Option<Self> {
        let id = client_id.trim();
        let id_ok = (1..=64).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let tenant_ok = tenant == "organizations" || tenant_id(tenant);
        (id_ok && tenant_ok).then(|| Self {
            client_id: id.to_owned(),
            tenant: tenant.to_owned(),
        })
    }

    pub(super) fn same(&self, other: &Self) -> bool {
        self.client_id == other.client_id && self.tenant == other.tenant
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }
}

impl fmt::Debug for TeamsApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TeamsApp(<redacted>)")
    }
}

/// What the token endpoint issued: (access, refresh if issued, id token if issued, expiry,
/// lifetime in seconds). Never printed.
pub(super) struct Issued {
    pub access: Zeroizing<String>,
    pub refresh: Option<Zeroizing<String>>,
    pub id_token: Option<Zeroizing<String>>,
    pub expires_at: String,
    pub lifetime: i64,
}

/// `AADSTS` codes (the body's `error_codes`) with which Entra says a grant is permanently dead and
/// the person must sign in again: 70000 (the refresh token is not valid), 70008 and 700082
/// (expired, inactive), 700084 (a fixed lifetime ran out), 50173 (revoked, a password changed or
/// reset), 50132 and 50133 (session invalid after a password change), 70043 (sign-in frequency).
const DEAD: [u64; 8] = [70000, 70008, 700_082, 700_084, 50173, 50132, 50133, 70043];
/// Codes with which Entra wants the person (multi-factor, a Conditional Access block or step-up,
/// an external challenge, consent): the grant is not dead, a later renewal may pass.
const INTERACTION: [u64; 5] = [50076, 50079, 53003, 50158, 65001];

/// `suberror` values that are the person's turn (a step-up, a prompt, consent), not a dead token.
const PERSON_SUBERRORS: [&str; 4] = [
    "basic_action",
    "additional_action",
    "consent_required",
    "message_only",
];

/// What an `invalid_grant` comes to. Entra sends it for dead tokens AND for step-ups, so the
/// documented dead-token `AADSTS` codes are looked at FIRST and condemn; then a step-up code or one
/// of the person-facing `suberror`s is the person's turn; anything else, an unknown `suberror`
/// (`bad_token` among them: Microsoft's reference does not say what it means) included, is no
/// verdict at all.
///
/// ponytail: a refresh that keeps failing with no verdict stays "active" until a call or a test
/// meets a real dead-token code; counting repeats into "needs sign in" is not built.
fn invalid_grant(body: &Value, status: u16) -> CallError {
    let codes: Vec<u64> = body
        .get("error_codes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    let has = |set: &[u64]| codes.iter().any(|c| set.contains(c));
    let person_suberror = body
        .get("suberror")
        .and_then(Value::as_str)
        .is_some_and(|s| PERSON_SUBERRORS.contains(&s));
    if has(&DEAD) {
        CallError::AuthFailed
    } else if has(&INTERACTION) || person_suberror {
        CallError::InteractionRequired
    } else {
        CallError::BadRequest(status)
    }
}

/// POSTs the token endpoint of `tenant`. An `invalid_grant` is judged by [`invalid_grant`]: only
/// the documented dead-token codes say THIS credential (a refresh token) is dead
/// ([`CallError::AuthFailed`]); `invalid_client`, `unauthorized_client` (including AADSTS7000215,
/// a wrong client secret) and `invalid_scope` are Core's own app ([`CallError::AppConfig`]);
/// `interaction_required`, `consent_required` and `login_required` want the person
/// ([`CallError::InteractionRequired`]). Any other 401 or 403 (an edge, a proxy) is
/// [`CallError::Forbidden`] and any other status is classified as for an API call. Returns the
/// whole 2xx body.
pub(super) async fn token_call(
    http: &Http,
    tenant: &str,
    form: &[(&str, &str)],
) -> Result<Value, CallError> {
    let res = http.entra(tenant, Endpoint::Token, form).await?;
    let (status, retry_after) = (res.status, res.retry_after);
    if (200..300).contains(&status) {
        return Ok(res.body);
    }
    let said = res.body.get("error").and_then(Value::as_str);
    Err(match (status, said) {
        (_, Some("invalid_grant")) if status < 500 => invalid_grant(&res.body, status),
        (_, Some("invalid_client" | "unauthorized_client" | "invalid_scope")) if status < 500 => {
            CallError::AppConfig
        }
        (_, Some("interaction_required" | "consent_required" | "login_required"))
            if status < 500 =>
        {
            CallError::InteractionRequired
        }
        (401 | 403, _) => CallError::Forbidden,
        (s, _) => classify(s, retry_after),
    })
}

/// The tokens of a 2xx answer. `now` is the clock for the expiry. A refresh token is required of
/// the caller, not here (a renewal may keep the old one).
pub(super) fn issued(body: &Value, now: &str) -> Result<Issued, CallError> {
    let text = |k: &str| {
        body.get(k)
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()))
    };
    let access = text("access_token").ok_or(CallError::Upstream(200))?;
    let secs = body
        .get("expires_in")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map_or(3600, |n| n.clamp(60, 86_400));
    let now = unix_secs(now).ok_or(CallError::Internal("the clock is unreadable"))?;
    Ok(Issued {
        access,
        refresh: text("refresh_token"),
        id_token: text("id_token"),
        expires_at: iso_of_unix(now + secs),
        lifetime: secs,
    })
}

/// Whether the access token is due for renewal at `now`: an expiry closer than the skew (relative
/// for a short-lived token: when `lifetime` is known, due when less than a quarter of its life is
/// left, at most the skew).
pub(super) fn due(m: &Material, now: &str, lifetime: Option<i64>) -> bool {
    let threshold = lifetime.map_or(SKEW_SECS, |l| SKEW_SECS.min(l / 4));
    let exp = m.expires_at.as_deref().and_then(unix_secs);
    match (super::cred::unpack(m), exp, unix_secs(now)) {
        (Some(_), Some(exp), Some(now)) => exp - now < threshold,
        _ => false,
    }
}
