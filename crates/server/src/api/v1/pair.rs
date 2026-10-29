//! Pairing, the new device's side (handshake spec §7.2 steps 3 and 8), before it has any
//! standing: `POST /pair/claim` with the typed code or the QR secret, its public keys and their
//! proof of possession, then `POST /pair/status`, signed with session `-`, until approved.
//!
//! A wrong, used, expired or burned credential is the one `pairing_failed`, counted against the
//! address (§11) and the global wrong-claim budget (20 in 5 minutes burn every live pairing,
//! §7.4), and audited. A bootstrap pairing is claimable only over this server's Unix socket by
//! its own user (§7.3).

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::gate::{self, Mode};
use super::{ApiError, too_many};
use crate::api::App;
use crate::auth::budget::LOCAL;
use crate::auth::crypto::{b64, fingerprint, random_id, spki_point, unb64, verify};
use crate::auth::pairing::{code_hash, normal_code, pop_message, sas, secret_hash};
use crate::gateway::Local;
use crate::gateway::preauth::PREAUTH_BODY;
use crate::store::gov::{self, ADDRESS, Claim};

const KEY_STORAGE: [&str; 5] = ["secure_enclave", "strongbox", "tee", "tpm", "software"];

/// A claim. The credential hash is SHA-256 of the canonical typed code (upper-cased, dashes
/// and spaces dropped, `I`/`L` read as `1` and `O` as `0`: 10 ASCII Crockford characters), or
/// of the QR secret's 16 decoded bytes (not its base64 text). Vectors:
/// `crates/server/tests/vectors/pairing-v1.json`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimBody {
    /// The typed code (`ABCDE-FGHJK`, any case); or `secret`.
    #[serde(default)]
    pub code: Option<String>,
    /// The QR secret; or `code`.
    #[serde(default)]
    pub secret: Option<String>,
    /// The routine key: a P-256 SubjectPublicKeyInfo, base64url.
    pub routine_spki: String,
    /// The step-up key, where the device has one.
    #[serde(default)]
    pub stepup_spki: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    /// `secure_enclave`, `strongbox`, `tee`, `tpm` or `software`: a claim.
    #[serde(default)]
    pub key_storage: Option<String>,
    /// The routine key's ES256 signature (raw r||s, base64url) over the UTF-8 string
    /// `AINKRAD-PAIR-V1` LF `<core_fp>` LF `<base64url of the credential hash>` LF
    /// `<fp(routine)>` LF `<fp(stepup) or ->`, no trailing newline; fp is base64url SHA-256 of
    /// the SPKI.
    pub pop: String,
    /// The step-up key over the same string, with `stepup_spki`.
    #[serde(default)]
    pub pop_stepup: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Claimed {
    /// The new device, `d_…`, pending until approved.
    pub device_id: Option<String>,
    /// The Core identity SPKI, base64url: its fingerprint must equal the QR's `c`.
    pub core_spki: Option<String>,
    /// The pairing, `p_…`: with `core_spki` and its own key the device computes the SAS
    /// itself and shows that, rather than trusting `sas` from whoever answered.
    pub pairing_id: Option<String>,
    /// Show this; the approver compares it with theirs. The first 16 upper-case Crockford
    /// characters of SHA-256(`AINKRAD-SAS-V1` ‖ core_spki ‖ routine_spki ‖ pairing id as
    /// UTF-8), as `XXXX-XXXX-XXXX-XXXX`.
    pub sas: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PairStatus {
    /// `pending`, `active`, `rejected` or `expired`.
    pub status: Option<String>,
}

fn pairing_failed() -> Response {
    ApiError::new(StatusCode::UNAUTHORIZED, "pairing_failed", "pairing failed").into_response()
}

/// A wrong claim: persisted against the address (its lockout survives a restart), and when it
/// spent the global budget, every live pairing is burned. Answered as the one
/// `pairing_failed`. No audit row per claim (review M4): the lockout and the burn are audited.
async fn wrong(app: &App, addr: &str, why: &'static str, spent: bool, now: i64) -> Response {
    tracing::warn!(addr, why, "pairing claim refused");
    let counted = async {
        gov::record_failure(&app.pool, addr, ADDRESS, now).await?;
        if spent {
            let burned = gov::burn_pairings(&app.pool).await?;
            tracing::warn!(
                burned = burned.len(),
                "wrong-claim budget spent: pairings burned"
            );
        }
        Ok::<(), sqlx::Error>(())
    };
    match counted.await {
        Ok(()) => pairing_failed(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

pub(super) fn bad(why: &str) -> Response {
    ApiError::bad_request(why).into_response()
}

#[utoipa::path(post, path = "/pair/claim", operation_id = "claimPairing", tag = "pairing",
    request_body = ClaimBody, security(()),
    responses((status = 202, description = "Claimed: the device is pending until the approver \
        matches the SAS. 401 `pairing_failed` for a wrong, used, expired or burned credential; \
        400 for keys or proofs that do not hold (the pairing is not spent)", body = Claimed)))]
pub async fn claim(State(app): State<App>, req: Request) -> Response {
    budgeted(&app, req, What::Claim).await
}

/// What a budgeted pairing call does with a pairing credential.
#[derive(Debug, Clone, Copy)]
pub(super) enum What {
    /// `/pair/claim`: a device or runner.
    Claim,
    /// `/pair/passkey/options`: a passkey's registration options (spends nothing).
    PasskeyOptions,
    /// `/pair/passkey/claim`: a passkey's credential.
    PasskeyClaim,
}

/// Every call that takes a pairing credential runs here, under the same budgets: a wrong one is
/// a wrong claim, whichever route it came to, so `/pair/passkey/*` is no oracle for codes.
pub(super) async fn budgeted(app: &App, req: Request, what: What) -> Response {
    let app = app.clone();
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let now = app.clock.unix();
    match gov::locked_until(&app.pool, &[&addr], now).await {
        Ok(Some(until)) => return too_many(std::time::Duration::from_secs((until - now) as u64)),
        Ok(None) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    // One evaluation slot from the address's budget and one from the global one, taken under
    // their locks before any lookup: concurrent claims cannot all be guesses, and the ones
    // past either budget are a cheap 429 that reads and writes nothing more (review M2).
    let busy = || too_many(std::time::Duration::from_secs(ADDRESS.lock as u64));
    if !app.auth.failures.reserve(&addr, now) {
        return busy();
    }
    // The host's own socket never takes part in the global budget: no amount of traffic from
    // outside can shut out the operator's `bootstrap`/`recover` (review N1).
    let global = addr != LOCAL;
    let slots = Slots {
        app: &app,
        addr: &addr,
        global,
        now,
        done: false,
    };
    if global && !app.auth.pair_budget.reserve(now) {
        drop(slots_without_global(slots));
        return busy();
    }
    let out = match what {
        What::Claim => evaluate(&app, &parts, raw, now).await,
        What::PasskeyOptions => super::passkey::options(&app, &parts, raw, now).await,
        What::PasskeyClaim => super::passkey::claim(&app, &parts, raw, now).await,
    };
    let spent = slots.finish(out.is_err());
    match out {
        Ok(r) => r,
        Err(why) => wrong(&app, &addr, why, spent, now).await,
    }
}

/// A claim's slots in the address's and the global budget. Given back by `finish`, or, when
/// the claim never finishes (the client went, the deadline cut it, the server stopped), by
/// `Drop`, as not failed: a dropped claim never keeps a slot (review N1).
struct Slots<'a> {
    app: &'a App,
    addr: &'a str,
    global: bool,
    now: i64,
    done: bool,
}

impl Slots<'_> {
    /// Gives both slots back, counting a `failed` claim; `true` when that spent the global
    /// budget.
    fn finish(mut self, failed: bool) -> bool {
        self.done = true;
        self.app.auth.failures.release(self.addr, failed, self.now);
        self.global && self.app.auth.pair_budget.release(failed, self.now)
    }
}

impl Drop for Slots<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.app.auth.failures.release(self.addr, false, self.now);
            if self.global {
                self.app.auth.pair_budget.release(false, self.now);
            }
        }
    }
}

/// `slots` holding the address's slot only (the global one was not taken).
fn slots_without_global(mut slots: Slots<'_>) -> Slots<'_> {
    slots.global = false;
    slots
}

/// The live pairing a typed `code` or QR `secret` names, and the credential's hash; of kind
/// `passkey` when `passkey`, else of any other kind. `Err` is a wrong claim (counted); `Ok(Err)`
/// an answer that is not one (a malformed body, a store error).
pub(super) async fn live_pairing(
    app: &App,
    parts: &axum::http::request::Parts,
    code: &Option<String>,
    secret: &Option<String>,
    passkey: bool,
) -> Result<Result<(gov::Pairing, [u8; 32]), Response>, &'static str> {
    let (hash, by_code) = match (code, secret) {
        (Some(code), None) => match normal_code(code) {
            Some(c) => (code_hash(&c), true),
            None => return Err("malformed code"),
        },
        (None, Some(secret)) => match unb64(secret, 22) {
            Some(s) => (secret_hash(&s), false),
            None => return Err("malformed secret"),
        },
        _ => return Ok(Err(bad("send one of code and secret"))),
    };
    let pairing = match gov::find_pairing(&app.pool, &hash, by_code).await {
        // Not yet swept by the scheduler is not live: `/pair/passkey/options` spends nothing,
        // so it must see the expiry itself.
        Ok(Some(p)) if p.status == "live" && p.expires_at > app.clock.now() => p,
        Ok(_) => return Err("no live pairing"),
        Err(e) => return Ok(Err(ApiError::from(e).into_response())),
    };
    if (pairing.kind == "passkey") != passkey {
        return Err("a passkey pairing on the device path, or the other way round");
    }
    let local = parts.extensions.get::<Local>().is_some_and(|l| l.same_user);
    if (pairing.bootstrap || pairing.recovery) && !local {
        return Err("bootstrap claimed from outside the host's socket");
    }
    Ok(Ok((pairing, hash)))
}

/// A claim's evaluation: its answer, or why it is a wrong claim.
async fn evaluate(
    app: &App,
    parts: &axum::http::request::Parts,
    raw: axum::body::Body,
    now: i64,
) -> Result<Response, &'static str> {
    let bytes = match gate::body(raw, PREAUTH_BODY).await {
        Ok(b) => b,
        Err(r) => return Ok(*r),
    };
    let Ok(b) = serde_json::from_slice::<ClaimBody>(&bytes) else {
        return Ok(bad("malformed body"));
    };
    let (pairing, hash) = match live_pairing(app, parts, &b.code, &b.secret, false).await? {
        Ok(found) => found,
        Err(r) => return Ok(r),
    };
    // The keys and their proofs; a failure here does not spend the pairing.
    let key = |text: &str| unb64(text, 122).filter(|k| spki_point(k).is_some());
    let Some(routine) = key(&b.routine_spki) else {
        return Ok(bad(
            "routine_spki is a P-256 SubjectPublicKeyInfo, base64url",
        ));
    };
    let stepup = match &b.stepup_spki {
        Some(s) => match key(s) {
            Some(k) => Some(k),
            None => {
                return Ok(bad(
                    "stepup_spki is a P-256 SubjectPublicKeyInfo, base64url",
                ));
            }
        },
        None => None,
    };
    if stepup.as_ref() == Some(&routine) {
        return Ok(bad("stepup_spki is a second key, not the routine key"));
    }
    if b.key_storage
        .as_deref()
        .is_some_and(|k| !KEY_STORAGE.contains(&k))
        || b.platform.as_deref().is_some_and(|p| p.len() > 64)
    {
        return Ok(bad("unknown key_storage, or a platform over 64 bytes"));
    }
    let stepup_fp = stepup.as_deref().map(fingerprint);
    let message = pop_message(
        &app.auth.identity.fp,
        &hash,
        &fingerprint(&routine),
        stepup_fp.as_deref(),
    );
    let proves = |key: &[u8], sig: Option<&String>| {
        sig.and_then(|s| unb64(s, 86))
            .is_some_and(|s| verify(key, &message, &s))
    };
    if !proves(&routine, Some(&b.pop))
        || stepup
            .as_ref()
            .is_some_and(|k| !proves(k, b.pop_stepup.as_ref()))
    {
        return Ok(bad("a proof of possession does not verify"));
    }
    let device_id = random_id("d_");
    let sas = sas(&app.auth.identity.spki, &routine, &pairing.id);
    let claim = Claim {
        pairing: &pairing,
        device_id: &device_id,
        routine_spki: &routine,
        stepup_spki: stepup.as_deref(),
        platform: b.platform.as_deref(),
        key_storage: b.key_storage.as_deref(),
        sas: &sas,
        passkey: None,
    };
    match gov::claim_pairing(&app.pool, &claim, now).await {
        Ok(true) => {}
        Ok(false) => return Err("pairing no longer live"),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Ok(ApiError::conflict("this key is enrolled already").into_response());
        }
        Err(e) => return Ok(ApiError::from(e).into_response()),
    }
    tracing::info!(device = device_id, pairing = pairing.id, "pairing claimed");
    let body = Claimed {
        device_id: Some(device_id),
        core_spki: Some(b64(&app.auth.identity.spki)),
        pairing_id: Some(pairing.id.clone()),
        sas: Some(sas),
    };
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

#[utoipa::path(post, path = "/pair/status", operation_id = "pairStatus", tag = "pairing",
    security(()),
    params(
        ("Ainkrad-Device" = String, Header, description = "The claimed device, `d_…`"),
        ("Ainkrad-Alg" = String, Header, description = "`ES256`"),
        ("Ainkrad-Timestamp" = i64, Header, description = "Unix seconds"),
        ("Ainkrad-Nonce" = String, Header, description = "16 random bytes, base64url"),
        ("Ainkrad-Signature" = String, Header,
            description = "Raw r||s over the canonical string with session `-`, base64url")),
    responses((status = 200, description = "Where the claimed device stands. Signed with \
        session `-`; the one call a pending device may make. Once `active`, it takes a session \
        (`/handshake/challenge`)", body = PairStatus)))]
pub async fn status(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    match gate::verify(&app, &parts, raw, PREAUTH_BODY, &addr, Mode::Pairing).await {
        Ok(v) => Json(PairStatus {
            status: Some(v.device.status),
        })
        .into_response(),
        Err(r) => *r,
    }
}
