//! The agent-session service (E2-08, P2.7): the platform primitive Citadel's issue runs and the
//! interactive chats sit on. A session is a harness on a runner (`ainkrad_proto::v2::agent`),
//! held by the runner's agent driver; the Core keeps its row and its transcript
//! (`store::agents`) and supervises it.
//!
//! - **One supervisor per live session**, started at create and, for every session not over,
//!   when the Core starts (`resume_all`). It long-polls the runner (`agent.read` from the
//!   stored `last_seq`), stores what comes back once, and carries on. So a lost answer, a runner
//!   reconnect or a Core restart costs a re-read, never a gap or a duplicate (E2-08.3).
//! - **Re-claim** (E2-08.5): while its runner is away the session waits for it; when it comes
//!   back the next read re-claims it. A runner that restarted reports the session
//!   `interrupted` (its harness went with it): the supervisor stores the rest of the transcript,
//!   then starts it again with the harness's own session id (`resume`) and fresh leases. A
//!   runner away past `lost_after`, or one that no longer knows the session, loses it.
//! - **Leases** (E2-07.2) are granted by the Core at each start, for the session's runner only,
//!   and travel only in the `agent.start` command: never in a response, an event or a row.
//! - **Capacity** (E2-08.1): a create is refused `runner_busy` when the runner's `agent`
//!   driver, or the harness's slot on it, is full (the runner refuses it too).

mod allocate;
mod ending;
mod failover;
pub mod gateway;
mod launch;
pub mod login;
pub mod plan_check;
pub mod subscription;
mod topup;
pub mod wake;
pub use failover::drive as drive_failover;
use launch::launch;
pub use launch::{Placement, placement};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::v2::{
    AGENT_DRIVER, AgentEvents, AgentRead, AgentStart, AgentState, Body, Command, ErrorCode, Reply,
    SecretGrant, StreamError,
};
use serde_json::{Value, json};

use crate::api::App;
use crate::api::v1::Caller;
use crate::hub::{Elevated, RunnerState};
use crate::module::Module;
use crate::store::agents::{self as store, Session};

/// How the supervisors pace themselves.
#[derive(Debug, Clone)]
pub struct AgentsConfig {
    /// How long one `agent.read` waits on the runner.
    pub read_wait: Duration,
    /// Between attempts while the runner is away or busy.
    pub retry: Duration,
    /// A runner away this long loses its sessions.
    pub lost_after: Duration,
    /// How long a command other than a read waits for its answer.
    pub answer: Duration,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            read_wait: Duration::from_secs(20),
            retry: Duration::from_secs(2),
            lost_after: Duration::from_secs(3600),
            answer: Duration::from_secs(15),
        }
    }
}

/// The sessions supervised in this process.
#[derive(Default)]
pub struct Agents {
    pub config: AgentsConfig,
    supervised: Mutex<HashSet<String>>,
    elevated: Mutex<HashMap<String, Elevated>>,
    leases: Mutex<HashMap<String, Leased>>,
    /// The accounts whose key a one-shot `gateway.test` is checking now (one at a time each).
    confirming: Mutex<HashSet<i64>>,
    /// Module credentials awaiting redemption (`Module::credentials`), by the SHA-256 of their
    /// lease id. In memory only: never stored, never logged, gone at the first redemption, at
    /// expiry or with the process.
    ephemeral: Mutex<HashMap<[u8; 32], Ephemeral>>,
}

/// What one start of a session was leased, kept until the runner confirms it: a resent start (its
/// answer was lost) carries the same leases, so it never piles new ones up.
#[derive(Clone)]
struct Leased {
    /// When the first of them ends (unix seconds).
    until: i64,
    secrets: Vec<SecretGrant>,
    /// The key of an API-key account, for the runner's gateway (KAN-435); never an env secret.
    gateway: Option<Box<ainkrad_proto::v2::GatewayGrant>>,
}

/// How long a module credential's lease lasts: the runner redeems it at the start of the session.
pub const EPHEMERAL_SECS: i64 = 120;

/// The most module credentials held at once.
const EPHEMERAL_MAX: usize = 4096;

/// A credential held for one runner to redeem once. No `Debug`.
pub struct Ephemeral {
    pub runner: String,
    pub var: String,
    pub value: zeroize::Zeroizing<String>,
    pub expires: i64,
}

/// Why the service refused, as the API maps it.
#[derive(Debug)]
pub enum Refusal {
    Runner(StreamError),
    Secrets(crate::store::secrets::Error),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for Refusal {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<crate::store::secrets::Error> for Refusal {
    fn from(e: crate::store::secrets::Error) -> Self {
        Self::Secrets(e)
    }
}

impl From<StreamError> for Refusal {
    fn from(e: StreamError) -> Self {
        Self::Runner(e)
    }
}

fn busy(why: &str) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::Busy, why))
}

/// Whether the runner can take one more `harness` session now: online, offering `agent`, under
/// its capacity and the harness's slot (counting the sessions the Core holds on it).
pub async fn admit(app: &App, runner: &str, harness: &str) -> Result<(), Refusal> {
    let default = serde_json::to_value(ainkrad_proto::runner::Policy::default())
        .expect("a policy serializes");
    admit_with(app, runner, harness, &default).await
}

/// [`admit`] for a session with `policy`: one that sets `min_isolation` is placed only on a runner
/// that offers a tier meeting it (E8a-09), see [`tier_refusal`].
pub async fn admit_with(
    app: &App,
    runner: &str,
    harness: &str,
    policy: &serde_json::Value,
) -> Result<(), Refusal> {
    admit_holding(app, runner, harness, policy, &[]).await
}

/// [`admit_with`] for a session that will hold `secrets`: one holding a provider-account secret
/// is also placed only where [`account_refusal`] allows.
pub async fn admit_holding(
    app: &App,
    runner: &str,
    harness: &str,
    policy: &serde_json::Value,
    secrets: &[store::SessionSecret],
) -> Result<(), Refusal> {
    let live = app.hub.runners();
    let Some(r) = live.get(runner).filter(|r| r.online) else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::Offline,
            "the runner is not connected",
        )));
    };
    let Some(d) = r.drivers.iter().find(|d| d.name == AGENT_DRIVER) else {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::UnsupportedCommand,
            "the runner offers no agent sessions",
        )));
    };
    if !d.slots.is_empty() && !d.slots.contains_key(harness) {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::InvalidArgs,
            "the runner offers no slot for that harness",
        )));
    }
    if let Some(why) = placement_refusal(r, secrets, policy) {
        return Err(Refusal::Runner(StreamError::new(
            ErrorCode::InvalidArgs,
            why,
        )));
    }
    let held = store::on_runner(&app.pool, runner).await?;
    let of_harness = held.iter().filter(|h| *h == harness).count();
    if held.len() >= d.capacity as usize
        || d.slots
            .get(harness)
            .is_some_and(|n| of_harness >= *n as usize)
    {
        return Err(busy("the runner's agent sessions are at their capacity"));
    }
    Ok(())
}

/// Why `runner` may not take a session with `policy`, when its isolation does not meet what the
/// policy needs: its `min_isolation`, any isolation field (at least `process`), or the legacy
/// `sandboxed` flag and mode (E8a-09). Fails closed, and there is no weaker tier to fall back to:
/// a policy that does not parse, a runner that never reported its isolation, one that is silent
/// (`degraded`), one whose offer does not reach the tier, and one offering a tier it names but
/// this Core does not know are all refused. `None` when the policy needs no isolation.
pub fn tier_refusal(runner: &RunnerState, policy: &serde_json::Value) -> Option<String> {
    let Ok(policy) = serde_json::from_value::<ainkrad_proto::runner::Policy>(policy.clone()) else {
        return Some("the session's policy does not have its shape".to_owned());
    };
    // Egress rules are placed only where the host-enforced filter was proven at start-up.
    if policy.egress.is_some() && !filters_egress(runner) {
        return Some(
            "the session sets egress rules and the runner does not offer a proven egress filter"
                .to_owned(),
        );
    }
    let required = policy.required_tier()?;
    let name = required.as_str();
    // Never sent to a runner that has not said what it enforces: an old runner would parse the
    // frame and drop the fields it does not know.
    let Some(caps) = &runner.isolation else {
        return Some(format!(
            "the session needs {name} isolation and the runner has not reported what it offers"
        ));
    };
    if runner.degraded {
        return Some(format!(
            "the session needs {name} isolation and the runner is silent, so its offer is unknown"
        ));
    }
    if !caps.meets(required) {
        return Some(format!(
            "the session needs {name} isolation and the runner offers {}",
            if caps.tiers.is_empty() {
                "none".to_owned()
            } else {
                caps.tiers.join(", ")
            }
        ));
    }
    None
}

/// Whether the runner proved its host-enforced egress filter at start-up: it says so with the
/// `egress-filter` op beside the agent driver's own.
fn filters_egress(runner: &RunnerState) -> bool {
    runner
        .drivers
        .iter()
        .filter(|d| d.name == AGENT_DRIVER)
        .any(|d| d.commands.iter().any(|c| c == "egress-filter"))
}

/// Whether `secrets` include a provider-account secret. By the `acct.` prefix alone, so a
/// malformed `acct.` name counts too: fail closed.
pub fn holds_account(secrets: &[store::SessionSecret]) -> bool {
    secrets
        .iter()
        .any(|s| s.name.starts_with(crate::store::secrets::ACCOUNT_PREFIX))
}

/// What a session holding a provider-account secret must ask for in its policy: a sandbox of at
/// least the `process` tier. Without one the runner may run the harness unconfined, with the
/// key in its environment and the host network.
///
/// (The design asked for `policy.egress` here. A process sandbox refuses a session that sets it
/// until the per-session intersection is wired, so the egress proof is demanded of the runner
/// instead, see [`account_refusal`].)
pub fn account_policy_problem(policy: &ainkrad_proto::runner::Policy) -> Option<&'static str> {
    // `required_tier` is `Some` only for `process` or stronger (`none` is filtered out), and tiers
    // are compared nowhere but `meets`, so presence is the whole test.
    policy.required_tier().is_none().then_some(
        "a session holding a provider-account secret must run sandboxed: set min_isolation to \
         process or stronger",
    )
}

/// `policy` with the account floor applied: a session that holds an account (an `acct.*` secret)
/// or draws one from a chain gets `min_isolation: process` when its policy asks for no sandbox
/// tier and leaves `min_isolation` out, so a client need not know the rule
/// [`account_policy_problem`] enforces. A policy that names a tier, sets `min_isolation` itself
/// (even `none`: an explicit choice is refused, not overridden), or does not parse is returned
/// unchanged; the checks after judge it.
pub fn with_account_floor(policy: serde_json::Value, holds: bool) -> serde_json::Value {
    if !holds {
        return policy;
    }
    let tiered = serde_json::from_value::<ainkrad_proto::runner::Policy>(policy.clone())
        .map_or(true, |p| p.required_tier().is_some());
    match policy {
        serde_json::Value::Object(mut m)
            if !tiered
                && m.get("min_isolation")
                    .is_none_or(serde_json::Value::is_null) =>
        {
            m.insert("min_isolation".into(), "process".into());
            serde_json::Value::Object(m)
        }
        other => other,
    }
}

/// Why a `runner` of this OS may not take a session that holds an account at all: Linux is judged
/// by the callers' own proofs; a macOS runner only when it advertises both proofs, the auth
/// gateway and the egress filter (its Seatbelt rules, proven by start-up self-tests); any other OS,
/// or one never reported, never.
fn os_refusal(runner: &RunnerState, what: &str) -> Option<String> {
    match runner.os.as_deref() {
        Some("linux") => None,
        Some("macos") => (!(serves_gateway(runner) && filters_egress(runner))).then(|| {
            format!(
                "a session {what} needs a macOS runner that passed both start-up proofs, the \
                 auth gateway and the egress filter"
            )
        }),
        other => Some(format!(
            "a session {what} needs a Linux or macOS runner, and this one is {}",
            other.unwrap_or("of an unreported OS")
        )),
    }
}

/// Why `runner` may not take a session holding a provider-account secret: real accounts are
/// placed only on a runner that proved its egress filter, and on macOS only when it also proved
/// the auth gateway ([`os_refusal`]); a runner that never said its OS is refused.
pub fn account_refusal(runner: &RunnerState) -> Option<String> {
    os_refusal(runner, "holding a provider-account secret").or_else(|| {
        (!filters_egress(runner)).then(|| {
            "a session holding a provider-account secret needs a runner with a proven egress filter"
                .to_owned()
        })
    })
}

/// [`tier_refusal`] plus, for a session holding a provider-account secret, the policy and runner
/// rules above. The one question both the create and the launch place a session by.
pub fn placement_refusal(
    runner: &RunnerState,
    secrets: &[store::SessionSecret],
    policy: &serde_json::Value,
) -> Option<String> {
    placement_refusal_with(runner, secrets, policy, false)
}

/// Whether a secret is an API-key account the runner's gateway serves (the account model's own
/// `acct.<provider>.<id>`), not an env secret.
fn gateway_bound(s: &store::SessionSecret) -> bool {
    crate::store::account_keys::gateway_served(&s.name)
}

/// Whether the runner lists the `gateway` command beside its agent driver's ops (KAN-435).
fn serves_gateway(runner: &RunnerState) -> bool {
    runner
        .drivers
        .iter()
        .filter(|d| d.name == AGENT_DRIVER)
        .any(|d| {
            d.commands
                .iter()
                .any(|c| c == ainkrad_proto::v2::CAP_GATEWAY)
        })
}

/// Why `runner` may not take a session that needs the auth gateway: a runner that lists the
/// `gateway` command (fail closed: an old runner never sees a grant), and on macOS also the proven
/// egress filter ([`os_refusal`]).
pub fn gateway_refusal(runner: &RunnerState) -> Option<String> {
    os_refusal(runner, "served by the auth gateway").or_else(|| {
        (!serves_gateway(runner)).then(|| {
            "a session served by the auth gateway needs a runner that offers the gateway".to_owned()
        })
    })
}

/// [`placement_refusal`] for a session that `needs_gateway` (it will carry a gateway grant): also
/// sandboxed at the `process` tier or stronger, and placed only where [`gateway_refusal`] allows.
/// Its key is not an env secret, so the egress-filter proof is not demanded.
pub fn placement_refusal_with(
    runner: &RunnerState,
    secrets: &[store::SessionSecret],
    policy: &serde_json::Value,
    needs_gateway: bool,
) -> Option<String> {
    // An API-key account is served by the gateway, so such a session needs it (KAN-435 G5); what
    // is left of the secrets is what the env rules below still judge.
    let needs_gateway = needs_gateway || secrets.iter().any(gateway_bound);
    let secrets: Vec<store::SessionSecret> = secrets
        .iter()
        .filter(|s| !gateway_bound(s))
        .cloned()
        .collect();
    let secrets = secrets.as_slice();
    if needs_gateway {
        let Ok(parsed) = serde_json::from_value::<ainkrad_proto::runner::Policy>(policy.clone())
        else {
            return Some("the session's policy does not have its shape".to_owned());
        };
        if let Some(why) = account_policy_problem(&parsed) {
            return Some(why.to_owned());
        }
        if let Some(why) = gateway_refusal(runner) {
            return Some(why);
        }
        // Any egress rule needs the proven host filter: fail closed, whatever tier_refusal says.
        if parsed.egress.is_some() && !filters_egress(runner) {
            return Some(
                "the session sets egress rules and the runner does not offer a proven egress filter"
                    .to_owned(),
            );
        }
    }
    if holds_account(secrets) {
        let Ok(parsed) = serde_json::from_value::<ainkrad_proto::runner::Policy>(policy.clone())
        else {
            return Some("the session's policy does not have its shape".to_owned());
        };
        if let Some(why) = account_policy_problem(&parsed) {
            return Some(why.to_owned());
        }
        if let Some(why) = subscription::account_refusal(runner, secrets) {
            return Some(why);
        }
    }
    tier_refusal(runner, policy)
}

/// Sends `command` to the session's runner and waits (at most `wait`) for its answer.
pub async fn ask(
    app: &App,
    runner: &str,
    command: Command,
    wait: Duration,
    proof: Option<Elevated>,
) -> Result<AgentEvents, StreamError> {
    let sent = if command.op() == ainkrad_proto::v2::OP_AGENT_READ {
        app.hub.dispatch_agent_read(runner, command)?
    } else {
        app.hub.dispatch_elevated(
            runner,
            command,
            proof.ok_or_else(|| {
                StreamError::new(ErrorCode::InvalidArgs, "agent elevation missing")
            })?,
        )?
    };
    let answer = tokio::time::timeout(wait, sent.outcome())
        .await
        .map_err(|_| StreamError::new(ErrorCode::Lost, "the runner did not answer in time"))??;
    match answer {
        Body::Result(
            Reply::AgentStart(ev)
            | Reply::AgentRead(ev)
            | Reply::AgentSend(ev)
            | Reply::AgentDecide(ev)
            | Reply::AgentStop(ev)
            | Reply::AgentLimit(ev),
        ) => Ok(ev),
        other => Err(StreamError::new(
            ErrorCode::BadFrame,
            format!("an answer of another op: {:?}", other_kind(&other)),
        )),
    }
}

fn other_kind(b: &Body) -> &'static str {
    match b {
        Body::Result(_) => "result",
        Body::Error(_) => "error",
        _ => "frame",
    }
}

/// Ends `s` as failed with `why` (no value or lease is ever in it).
async fn fail(app: &App, s: &Session, why: &str) {
    let outcome = json!({"kind": "failed", "reason": why, "fingerprint": "core"});
    if let Err(e) = store::end(&app.pool, &s.id, "ended", &outcome, &app.clock.now()).await {
        tracing::error!(session = s.id, error = %e, "ending a session failed");
    }
    // The Core's own end never moves a run: settled here, so no restart finds it unsettled.
    if let Err(e) = crate::store::failover::settle(&app.pool, &s.id).await {
        tracing::error!(session = s.id, error = %e, "settling a failover failed");
    }
}

pub fn describe(r: &Refusal) -> String {
    match r {
        Refusal::Runner(e) => e.message.clone(),
        Refusal::Secrets(e) => e.to_string(),
        Refusal::Db(e) => e.to_string(),
    }
}

/// Starts a just-created session and supervises it. A runner away (or an answer lost) leaves
/// it `starting`, for the supervisor; any other refusal has ended it, and is returned.
pub async fn start(app: &App, s: &Session) -> Result<(), Refusal> {
    let first = launch(app, s, false).await;
    match &first {
        Err(Refusal::Runner(e)) if matches!(e.code, ErrorCode::Offline | ErrorCode::Lost) => {
            supervise(app, &s.id);
            Ok(())
        }
        Err(_) => first,
        Ok(()) => {
            supervise(app, &s.id);
            Ok(())
        }
    }
}

/// Called only by the already-gated create route. The proof is retained for the supervisor's
/// reconnect/start path: resuming the same session continues the original elevated create.
pub fn authorize_create(app: &App, caller: &Caller, session: &str) {
    debug_assert!(caller.device.scopes.iter().any(|s| s == "agent"));
    app.agents
        .elevated
        .lock()
        .unwrap()
        .insert(session.to_owned(), app.hub.agent_elevation(caller));
}

#[cfg(feature = "test-support")]
pub fn authorize_for_tests(app: &App, session: &str) {
    app.agents
        .elevated
        .lock()
        .unwrap()
        .insert(session.to_owned(), Elevated::for_tests());
}

pub(crate) const MAX_PROMPT: usize = 64 * 1024;
pub(crate) const MAX_SECRETS: usize = 16;

/// Why [`validate_new`] refused a session.
#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The request is malformed (a 400).
    Bad(&'static str),
    /// It names something only an `admin` device may (a 403).
    Forbidden(&'static str),
}

fn harness_ok(h: &str) -> bool {
    (1..=32).contains(&h.len())
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// The checks every new session passes, whoever creates it (the client route and a module): ids,
/// sizes, secret names, the shape of the workspace and policy, and the `admin` gate for named
/// secrets and approval bypasses. `admin`: whether the creating device holds the admin scope.
pub fn validate_new(new: &store::NewSession<'_>, admin: bool) -> Result<(), Invalid> {
    use ainkrad_proto::runner::{Policy, Workspace, has_destructive_allow};
    if !crate::auth::crypto::is_id(new.runner, "d_") {
        return Err(Invalid::Bad("runner is a runner's device id, d_…"));
    }
    if !harness_ok(new.harness) {
        return Err(Invalid::Bad("harness is [a-z0-9_-]{1,32}"));
    }
    if new.prompt.is_some_and(|p| p.len() > MAX_PROMPT) || new.model.is_some_and(|m| m.len() > 128)
    {
        return Err(Invalid::Bad("the prompt (64 KiB) or model is too long"));
    }
    if new.secrets.len() > MAX_SECRETS
        || new.secrets.iter().any(|s| {
            !crate::store::secrets::valid_name(&s.name)
                || !ainkrad_proto::v2::valid_secret_var(&s.var)
                || s.var.eq_ignore_ascii_case(ainkrad_proto::v2::RUN_TOKEN_VAR)
        })
    {
        return Err(Invalid::Bad(
            "at most 16 secrets, each a secret's name and a variable [A-Z_][A-Z0-9_]* the runner \
             does not set itself (CITADEL_RUN_TOKEN is reserved for a module's run token)",
        ));
    }
    if let Some(why) = gateway::secrets_problem(new.harness, new.secrets) {
        return Err(Invalid::Bad(why));
    }
    // The gateway serves one account per session: the ledger records against that one.
    if new.secrets.iter().filter(|s| gateway_bound(s)).count() > 1 {
        return Err(Invalid::Bad(
            "a session names at most one API-key account (acct.<provider>.<id>)",
        ));
    }
    if !new.secrets.is_empty() && !admin {
        return Err(Invalid::Forbidden(
            "naming broker secrets requires the admin scope",
        ));
    }
    let workspace_ok = new.workspace.is_none_or(|w| {
        serde_json::from_value::<Workspace>(w.clone())
            .is_ok_and(|workspace| workspace.problem().is_none())
    });
    let policy = serde_json::from_value::<Policy>(new.policy.clone());
    let Some(policy) = policy.ok().filter(|_| workspace_ok) else {
        return Err(Invalid::Bad("workspace or policy does not have its shape"));
    };
    if policy.problem().is_some() {
        return Err(Invalid::Bad(
            "the policy's isolation fields are out of bounds: vcpus 1-32, memory_mb 64-262144, \
             disk_mb 16-1048576, wall_secs 1-86400, image sha256:<64 hex>, egress rules IP \
             addresses or CIDR blocks (no host names, at most 64 each)",
        ));
    }
    if holds_account(new.secrets)
        && let Some(why) = account_policy_problem(&policy)
    {
        return Err(Invalid::Bad(why));
    }
    if has_destructive_allow(&policy) && !admin {
        return Err(Invalid::Forbidden(
            "approval bypasses require the admin scope",
        ));
    }
    Ok(())
}

fn invalid_args(why: &str) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::InvalidArgs, why))
}

/// What a mounted module holds to create and drive its own agent sessions: no client is in hand
/// when a run starts, retries or is cut at its cap, so the module stands for the operator who
/// enabled it. The module's id comes from the [`Module`] itself (never a string or a `Session`
/// the caller asserts), and every call re-reads the session row, so a module can only ever
/// create sessions marked as its own and drive the ones that are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleAgents {
    module: &'static str,
}

impl ModuleAgents {
    /// The handle of `module`.
    ///
    /// # Panics
    ///
    /// On an illegal module id (`module::mount` refuses it too).
    pub fn of(module: &dyn Module) -> Self {
        assert!(crate::module::valid_id(module.id()), "illegal module id");
        assert!(module.id() != "acct", "module id \"acct\" is reserved");
        Self {
            module: module.id(),
        }
    }

    /// A handle for a module id, for tests of the ownership rules.
    #[cfg(any(test, feature = "test-support"))]
    pub fn named(module: &'static str) -> Self {
        Self { module }
    }

    /// Creates a session owned by the module and starts it. It passes the same checks as the
    /// client route ([`validate_new`]): naming broker secrets needs `new.created_by` to be a
    /// usable device with the admin scope, a `sandboxed` mode needs the sandbox flag, and a
    /// workspace or policy that does not parse is refused. Audited `agent.created`, by the system.
    pub async fn create(&self, app: &App, new: &store::NewSession<'_>) -> Result<Session, Refusal> {
        self.create_ref(app, new, None).await
    }

    /// [`create`](Self::create) with `owner_ref`, the module's own pointer to the session
    /// (`run:12`), which `Module::credentials` reads back at every launch. Never a credential.
    pub async fn create_ref(
        &self,
        app: &App,
        new: &store::NewSession<'_>,
        owner_ref: Option<&str>,
    ) -> Result<Session, Refusal> {
        let admin = crate::store::gov::get_device(&app.pool, new.created_by)
            .await?
            .is_some_and(|d| d.usable() && d.scopes.iter().any(|s| s == "admin"));
        validate_new(new, admin).map_err(|e| match e {
            Invalid::Bad(why) | Invalid::Forbidden(why) => invalid_args(why),
        })?;
        let sandbox_without_flag = serde_json::from_value::<ainkrad_proto::runner::Policy>(
            new.policy.clone(),
        )
        .is_ok_and(|p| p.mode == ainkrad_proto::runner::PermissionMode::Sandboxed && !p.sandboxed);
        if sandbox_without_flag {
            return Err(invalid_args("a sandboxed mode needs the sandbox flag"));
        }
        if let Some(why) = gateway::module_refusal(new.secrets) {
            return Err(invalid_args(why));
        }
        admit_holding(app, new.runner, new.harness, new.policy, new.secrets).await?;
        let s = store::create_owned_ref(
            &app.pool,
            new,
            Some(self.module),
            owner_ref,
            AuditActor::System,
            &app.clock.now(),
        )
        .await?;
        app.agents
            .elevated
            .lock()
            .unwrap()
            .insert(s.id.clone(), app.hub.module_elevation());
        start(app, &s).await?;
        Ok(s)
    }

    /// Stops, messages or answers a tool request of the live session `id` the module owns, and
    /// stores the answer. Refused for a session the module does not own (a client's, another
    /// module's), for one that is over, and for any command but `agent.stop`, `agent.send` and
    /// `agent.decide` naming that session.
    pub async fn instruct(&self, app: &App, id: &str, command: Command) -> Result<(), Refusal> {
        let invalid = invalid_args;
        let s = store::get(&app.pool, id)
            .await?
            .filter(|s| s.owner_module.as_deref() == Some(self.module))
            .ok_or_else(|| invalid("the session is not this module's"))?;
        if !s.live() {
            return Err(invalid("the session is over"));
        }
        let session = match &command {
            Command::AgentStop(c) => &c.session,
            Command::AgentSend(c) => &c.session,
            Command::AgentDecide(c) => &c.session,
            _ => {
                return Err(invalid(
                    "a module may only stop, message or answer a session",
                ));
            }
        };
        if *session != s.id {
            return Err(invalid("the command is about another session"));
        }
        // A chain session that never started has no runner session to stop: ended here.
        if matches!(command, Command::AgentStop(_))
            && crate::store::alloc::end_unstarted(&app.pool, &s.id, &app.clock.now()).await?
        {
            return Ok(());
        }
        let ev = ask(
            app,
            &s.runner,
            command,
            app.agents.config.answer,
            Some(app.hub.module_elevation()),
        )
        .await?;
        store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
        Ok(())
    }
}

/// Starts supervising `id`, unless this process already does; whether it started one.
pub fn supervise(app: &App, id: &str) -> bool {
    if !app.agents.supervised.lock().unwrap().insert(id.to_owned()) {
        return false;
    }
    // The session's connection tools (C4), when it has access to any.
    crate::connections::broker::supervise(app, id);
    let (app, id) = (app.clone(), id.to_owned());
    tokio::spawn(async move {
        let mut closing = app.closing.subscribe();
        tokio::select! {
            () = run(&app, &id) => {}
            () = crate::api::stopping(&mut closing) => {}
        }
        app.agents.supervised.lock().unwrap().remove(&id);
    });
    true
}

/// Supervises every session not over: what a starting Core does (a Core restart re-claims).
pub async fn resume_all(app: &App) -> Result<usize, sqlx::Error> {
    let live = store::live(&app.pool).await?;
    for s in &live {
        app.agents
            .elevated
            .lock()
            .unwrap()
            .insert(s.id.clone(), app.hub.continue_agent_elevation());
        supervise(app, &s.id);
    }
    // An attempt that ended while the Core was down, before its run moved, moves it now.
    failover::resume_unfinished(app).await?;
    Ok(live.len())
}

/// A session's supervisor, until it is over.
async fn run(app: &App, id: &str) {
    let cfg = app.agents.config.clone();
    let mut away: Option<tokio::time::Instant> = None;
    let mut killed: Option<tokio::time::Instant> = None;
    loop {
        let s = match store::get(&app.pool, id).await {
            Ok(Some(s)) if s.live() => s,
            Ok(Some(s)) => {
                // Over: nothing left to stop, but an upstream `auth_failed` it reported is checked.
                gateway::after(app, &s).await;
                // An attempt that is over may move its run to the next account (once).
                failover::after_end(app, &s).await;
                return;
            }
            Ok(None) => return,
            Err(e) => {
                tracing::error!(session = id, error = %e, "reading a session failed");
                tokio::time::sleep(cfg.retry).await;
                continue;
            }
        };
        // A client session does not outlive the device that made it (B-M1b).
        match ending::creator_revoked(app, &s, &mut away, &mut killed).await {
            ending::Revoked::Over => return,
            ending::Revoked::Retry => {
                tokio::time::sleep(cfg.retry).await;
                continue;
            }
            ending::Revoked::No => {}
        }
        // A budget stop or an auth failure the last answer recorded.
        gateway::after(app, &s).await;
        let step = match s.state.as_str() {
            // A chain session has no account until the pick has given it one (it waits, never launches).
            "starting" => match allocate::ready(app, &s).await {
                Ok(Some(row)) => launch(app, &row, false).await.map(drop),
                // Waiting for an account: the wait is bounded in the pick itself (`wait_max` from
                // the first wait), and this does not look like progress to the give-up timer.
                Ok(None) => {
                    // The pick found the runner online: not away.
                    away = None;
                    tokio::time::sleep(cfg.retry).await;
                    continue;
                }
                Err(e) => Err(e),
            },
            "interrupted" => launch(app, &s, true).await.map(drop),
            _ => read(app, &s, &cfg).await,
        };
        match step {
            Ok(()) => away = None,
            Err(Refusal::Runner(e)) if matches!(e.code, ErrorCode::Offline | ErrorCode::Lost) => {
                // A revoked runner never comes back: the session is lost now, not after the wait.
                // Only a runner the database says is gone ends it; an unreadable row falls
                // through to the retry and its bound.
                if crate::auth::device_now(&app.pool, &s.runner, None).await
                    == crate::auth::DeviceNow::Gone
                {
                    let outcome = json!({"kind": "lost", "reason": "the runner was revoked"});
                    let _ = store::end(&app.pool, id, "lost", &outcome, &app.clock.now()).await;
                    return;
                }
                let since = *away.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= cfg.lost_after {
                    let outcome = json!({"kind": "lost", "reason": "the runner never came back"});
                    let _ = store::end(&app.pool, id, "lost", &outcome, &app.clock.now()).await;
                    return;
                }
                tokio::time::sleep(cfg.retry).await;
            }
            Err(e) => {
                let since = *away.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= cfg.lost_after {
                    // The harness may be alive behind the failing answers: stopped before the end.
                    let _ = ending::stop_for_end(app, &s).await;
                    fail(app, &s, "bounded agent retries exhausted").await;
                    app.agents.leases.lock().unwrap().remove(id);
                    return;
                }
                tracing::warn!(session = id, why = describe(&e), "supervising a session");
                tokio::time::sleep(cfg.retry).await;
            }
        }
    }
}

/// One long poll: stores what came; an `interrupted` or `ended` runner state, once every entry
/// is stored, moves the session.
async fn read(app: &App, s: &Session, cfg: &AgentsConfig) -> Result<(), Refusal> {
    let after = u64::try_from(s.last_seq).unwrap_or(0);
    let wait = u64::try_from(cfg.read_wait.as_millis()).unwrap_or(u64::MAX);
    // The reports the ledger holds, as of the transaction that last committed: what the Core
    // acknowledges is never ahead of it (an answer whose ledger write failed is resent).
    let req = Command::AgentRead(AgentRead {
        gw_after: crate::store::gateway::ack_after(&app.pool, &s.id).await?,
        session: s.id.clone(),
        after,
        wait_ms: Some(wait),
    });
    let ev = match ask(app, &s.runner, req, cfg.read_wait + cfg.answer, None).await {
        Ok(ev) => ev,
        Err(e)
            if e.code == ErrorCode::InvalidArgs && e.message == ainkrad_proto::v2::NO_SESSION =>
        {
            // The runner no longer knows it (its state was wiped): nothing will come back.
            let outcome = json!({"kind": "lost", "reason": e.message});
            store::end(&app.pool, &s.id, "lost", &outcome, &app.clock.now()).await?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let held = store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    // Reports this answer moved the ledger's cursor over: more may be waiting (the runner sends a
    // batch at a time), so a session is not over for the Core until a read brings none that
    // advance it. A hole that never fills does not hold a session open: it is logged and passed.
    let reported = crate::store::gateway::cursor(&app.pool, &s.id).await? != (s.gw_epoch, s.gw_seq);
    if !reported && !ev.gateway.is_empty() {
        tracing::warn!(
            session = s.id,
            "gateway reports that did not advance the ledger's cursor"
        );
    }
    if held >= store::MAX_TRANSCRIPT && held < ev.last_seq {
        // Nothing more is stored: the session is stopped, not read forever.
        let stop = Command::AgentStop(ainkrad_proto::v2::AgentStop {
            session: s.id.clone(),
            kill: true,
        });
        let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
        let why = format!("the transcript reached {} entries", store::MAX_TRANSCRIPT);
        match ask(app, &s.runner, stop, cfg.answer, proof).await {
            Ok(_) => fail(app, s, &why).await,
            Err(e) => {
                let outcome = json!({
                    "kind": "lost",
                    "reason": format!("kill pending after transcript ceiling: {}", e.message)
                });
                let _ = store::end(&app.pool, &s.id, "lost", &outcome, &app.clock.now()).await;
            }
        }
        return Ok(());
    }
    if held < ev.last_seq || reported {
        return Ok(()); // more to read first
    }
    match ev.state {
        AgentState::Ended => {
            let outcome = ev
                .outcome
                .as_ref()
                .and_then(|o| serde_json::to_value(o).ok())
                .unwrap_or(Value::Null);
            store::end(&app.pool, &s.id, "ended", &outcome, &app.clock.now()).await?;
            // The runner may drop its copy: the Core holds all of it.
            ending::acknowledge(app, s, held).await?;
        }
        AgentState::Interrupted => {
            let why = "the runner restarted";
            store::set_state(
                &app.pool,
                &s.id,
                "interrupted",
                why,
                false,
                &app.clock.now(),
            )
            .await?;
        }
        AgentState::Running | AgentState::Unknown => {}
    }
    Ok(())
}

/// Holds `id` as supervised, as a supervisor that has not finished would (for tests).
#[cfg(feature = "test-support")]
pub fn hold_supervision_for_tests(app: &App, id: &str) {
    app.agents.supervised.lock().unwrap().insert(id.to_owned());
}

/// Lets go of what [`hold_supervision_for_tests`] held.
#[cfg(feature = "test-support")]
pub fn release_supervision_for_tests(app: &App, id: &str) {
    app.agents.supervised.lock().unwrap().remove(id);
}

/// The supervised session ids, for tests.
pub fn supervised(app: &App) -> Vec<String> {
    let all = app.agents.supervised.lock().unwrap();
    let mut v: Vec<String> = all.iter().cloned().collect();
    v.sort();
    v
}

impl Agents {
    pub fn new(config: AgentsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            supervised: Mutex::default(),
            elevated: Mutex::default(),
            leases: Mutex::default(),
            confirming: Mutex::default(),
            ephemeral: Mutex::default(),
        })
    }

    /// Holds `e` under lease `id` (a `l_…`), dropping what has expired; `false` when the table
    /// is full.
    pub(crate) fn stash(&self, id: &str, e: Ephemeral, now: i64) -> bool {
        let mut held = self.ephemeral.lock().unwrap();
        held.retain(|_, v| v.expires > now);
        if held.len() >= EPHEMERAL_MAX {
            return false;
        }
        held.insert(crate::auth::crypto::sha256(id.as_bytes()), e);
        true
    }

    /// The credential under lease `id` if it is `runner`'s and live; it is removed either way a
    /// match is found (single use). Another runner's lease is not found.
    pub fn take_ephemeral(&self, id: &str, runner: &str, now: i64) -> Option<Ephemeral> {
        let key = crate::auth::crypto::sha256(id.as_bytes());
        let mut held = self.ephemeral.lock().unwrap();
        if held.get(&key)?.runner != runner {
            return None;
        }
        held.remove(&key).filter(|e| e.expires > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(runner: &str, expires: i64) -> Ephemeral {
        Ephemeral {
            runner: runner.to_owned(),
            var: "x".to_owned(),
            value: zeroize::Zeroizing::new("v".to_owned()),
            expires,
        }
    }

    #[test]
    fn a_credential_is_redeemed_once_by_its_runner_before_it_expires() {
        let a = Agents::new(AgentsConfig::default());
        assert!(a.stash("l_one", held("d_a", 100), 0));
        // Another runner does not find it, and does not spend it.
        assert!(a.take_ephemeral("l_one", "d_b", 1).is_none());
        assert!(a.take_ephemeral("l_two", "d_a", 1).is_none());
        assert!(a.take_ephemeral("l_one", "d_a", 1).is_some());
        assert!(a.take_ephemeral("l_one", "d_a", 1).is_none(), "single use");
        assert!(a.stash("l_old", held("d_a", 10), 0));
        assert!(a.take_ephemeral("l_old", "d_a", 10).is_none(), "expired");
    }

    #[test]
    fn the_table_is_bounded_and_forgets_the_expired() {
        let a = Agents::new(AgentsConfig::default());
        for i in 0..EPHEMERAL_MAX {
            assert!(a.stash(&format!("l_{i}"), held("d_a", 100), 0));
        }
        assert!(!a.stash("l_more", held("d_a", 100), 0), "full");
        assert!(a.stash("l_more", held("d_a", 300), 200), "the expired went");
    }

    #[test]
    fn an_account_session_gets_the_process_floor_and_nothing_else_changes() {
        let parse = |v: serde_json::Value| {
            serde_json::from_value::<ainkrad_proto::runner::Policy>(v).unwrap()
        };
        let plain = serde_json::to_value(ainkrad_proto::runner::Policy::default()).unwrap();
        // No account: untouched, and still refused if it later holds one.
        assert_eq!(with_account_floor(plain.clone(), false), plain);
        // An account: the floor is added, so the rule it enforces now passes.
        let floored = with_account_floor(plain.clone(), true);
        assert!(account_policy_problem(&parse(floored.clone())).is_none());
        assert_eq!(floored["min_isolation"], "process");
        // A policy that names a stronger tier keeps it.
        let mut vm = plain.clone();
        vm["min_isolation"] = "microvm".into();
        assert_eq!(with_account_floor(vm.clone(), true), vm);
        // A legacy sandboxed policy already has a tier: unchanged.
        let mut legacy = plain;
        legacy["sandboxed"] = true.into();
        assert_eq!(with_account_floor(legacy.clone(), true), legacy);
        // An explicit `none` is the client's choice: unchanged, so the check after refuses it.
        let none = serde_json::json!({"mode": "ask", "min_isolation": "none"});
        assert_eq!(with_account_floor(none.clone(), true), none);
        // Not an object: left for the shape check after.
        assert_eq!(
            with_account_floor(serde_json::json!(7), true),
            serde_json::json!(7)
        );
    }
}
