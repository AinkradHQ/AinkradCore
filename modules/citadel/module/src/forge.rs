//! The forge and Linear integrations (S6): GitHub and GitLab pull requests and the Linear sync,
//! run as scheduler jobs (`Module::jobs`, E2-11) that poll; there is no inbound webhook (every
//! module route sits behind the device-signed client gate, which a forge cannot sign for).
//!
//! What makes it safe to call out:
//!
//! - **One client.** Every call goes through a client from `ainkrad_providers::guard::Policy`:
//!   https only, host names on an allow-list (the public hosts and the operator's
//!   `citadel_forge_hosts`), DNS answers vetted so private, loopback, link-local and metadata
//!   addresses are never dialed, no proxy, no redirects, timeouts, a size cap on answers. An
//!   API URL is checked against the list on every pass, not only when it is stored.
//! - **Credentials from the broker only.** A repo or a Linear link names a secret
//!   (`citadel.forge.<name>`, `citadel.linear.<name>`); a pass opens it with `secrets::open_for_module` (audited `secret.used`,
//!   once per secret per pass), holds it for the pass, and never stores or logs it. The
//!   providers cut it out of any error text.
//! - **A credential serves one host and one company.** Forge secrets are `citadel.forge.*` and
//!   Linear's `citadel.linear.*`, never a provider account's; the first poll binds a secret to the
//!   host and company it was linked for, and any other host or company is refused.
//! - **One pass at a time.** Each job takes a lock, so an overlapping occurrence skips: two passes
//!   can never act on one PR together.
//! - **A merge is bound to a head.** A PR merges only at the head sha its approval was given
//!   for; the forge refuses a moved head.
//! - **A rate-limited host rests.** A 429 (or a 403 that says so) pauses that host for a
//!   minute; every pass is bounded to `MAX_PRS_PER_PASS` PRs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_providers::guard::Policy;
use ainkrad_providers::{Client, Error, Secret};
use sqlx::SqlitePool;

mod linear;
mod poll;

pub use linear::sync as linear_sync;
pub use poll::sync as forge_sync;

/// The most PRs one pass works on.
// ponytail: a flat cap; fair rotation across repos if one repo ever starves the rest.
pub const MAX_PRS_PER_PASS: usize = 50;

/// How long a rate-limited host rests.
const REST: Duration = Duration::from_secs(60);

/// What the integrations need: the store, the broker's key and the call policy.
pub struct Runtime {
    pub(crate) pool: SqlitePool,
    sealer: Arc<SecretBox>,
    base: Policy,
    resting: Mutex<HashMap<String, Instant>>,
    /// Opened credentials, for `TOKEN_TTL`: one audited `secret.used` per secret per lease, not per pass.
    tokens: Mutex<HashMap<String, (Secret, Instant)>>,
    forge_lock: tokio::sync::Mutex<()>,
    linear_lock: tokio::sync::Mutex<()>,
}

/// How long an opened credential is kept (a rotation takes effect within it).
const TOKEN_TTL: Duration = Duration::from_secs(300);

impl Runtime {
    pub fn new(pool: SqlitePool, sealer: Arc<SecretBox>) -> Arc<Self> {
        Self::with_policy(pool, sealer, Policy::public())
    }

    /// With another base policy: tests point it at a fake server.
    pub fn with_policy(pool: SqlitePool, sealer: Arc<SecretBox>, base: Policy) -> Arc<Self> {
        Arc::new(Self {
            pool,
            sealer,
            base,
            resting: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            forge_lock: tokio::sync::Mutex::new(()),
            linear_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The jobs the module declares for these integrations.
    pub fn jobs(self: &Arc<Self>) -> Vec<Job> {
        let forge: Arc<dyn JobHandler> = Arc::new(Poll(self.clone(), Kind::Forge));
        let linear: Arc<dyn JobHandler> = Arc::new(Poll(self.clone(), Kind::Linear));
        vec![
            Job::new("forge_poll", Schedule::Every(60), forge),
            Job::new("linear_sync", Schedule::Every(300), linear),
        ]
    }

    /// The call policy now: the base and the operator's extra hosts.
    async fn pass(self: &Arc<Self>) -> Result<Pass, sqlx::Error> {
        let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM citadel_forge_hosts")
            .fetch_all(&self.pool)
            .await?;
        let policy = self.base.clone().with_hosts(hosts);
        Ok(Pass {
            rt: self.clone(),
            client: policy.client(),
            policy,
        })
    }

    fn resting(&self, host: &str) -> bool {
        let mut at = self.resting.lock().unwrap_or_else(|e| e.into_inner());
        match at.get(host) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                at.remove(host);
                false
            }
            None => false,
        }
    }

    fn rest(&self, host: &str) {
        let mut at = self.resting.lock().unwrap_or_else(|e| e.into_inner());
        at.insert(host.to_owned(), Instant::now() + REST);
    }
}

/// Whether a provider error says the host is rate limiting us.
fn rate_limited(e: &Error) -> bool {
    match e {
        Error::Http { status: 429, .. } => true,
        Error::Http {
            status: 403,
            message,
        } => message.to_lowercase().contains("rate limit"),
        _ => false,
    }
}

/// One pass's view: the client, the policy and the secrets opened so far.
pub(crate) struct Pass {
    rt: Arc<Runtime>,
    pub(crate) client: Client,
    policy: Policy,
}

impl Pass {
    /// The API URL's host when the policy allows it and the host is not resting; why not otherwise.
    pub(crate) fn host(&self, api_url: &str) -> Result<String, String> {
        self.policy
            .check_url(api_url)
            .map_err(|why| format!("the API URL is refused ({why})"))?;
        let host = reqwest_host(api_url).ok_or_else(|| "the API URL has no host".to_owned())?;
        if self.rt.resting(&host) {
            return Err(format!("{host} is rate limiting; resting"));
        }
        Ok(host)
    }

    /// The credential in broker secret `name` for `host` and `company`, opened at most once per
    /// `TOKEN_TTL`; why not otherwise (never a value). A secret of a provider account, or one
    /// bound to another host or company, is refused.
    pub(crate) async fn token(
        &mut self,
        name: &str,
        (host, company): (&str, i64),
        purpose: &str,
    ) -> Result<Secret, String> {
        let pool = &self.rt.pool;
        let bad = |e: sqlx::Error| format!("the credential {name} is unavailable: {e}");
        if crate::store::forge::is_account_secret(pool, name)
            .await
            .map_err(bad)?
        {
            return Err(format!(
                "the credential {name} is a provider account's, not a forge's"
            ));
        }
        crate::store::forge::bind_secret(pool, name, host, company)
            .await
            .map_err(bad)??;
        let cached = {
            let at = self.rt.tokens.lock().unwrap_or_else(|e| e.into_inner());
            at.get(name)
                .filter(|(_, since)| since.elapsed() < TOKEN_TTL)
                .map(|(t, _)| t.clone())
        };
        if let Some(t) = cached {
            return Ok(t);
        }
        let opened = ainkrad_core_server::store::secrets::open_for_module(
            pool,
            &self.rt.sealer,
            "citadel",
            name,
            purpose,
        )
        .await
        .map_err(|e| format!("the credential {name} is unavailable: {e}"))?;
        let token = Secret::new(opened.as_str());
        let mut at = self.rt.tokens.lock().unwrap_or_else(|e| e.into_inner());
        at.insert(name.to_owned(), (token.clone(), Instant::now()));
        Ok(token)
    }

    /// Notes what a call's failure says about the host.
    pub(crate) fn failed(&self, host: &str, e: &Error) {
        if rate_limited(e) {
            self.rt.rest(host);
        }
        // A refused credential may have been rotated: open it again next pass.
        if matches!(e, Error::Http { status: 401, .. }) {
            self.rt
                .tokens
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
    }
}

fn reqwest_host(url: &str) -> Option<String> {
    let u = ainkrad_providers::guard::parse(url)?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some(u.port().map_or(host.clone(), |p| format!("{host}:{p}")))
}

enum Kind {
    Forge,
    Linear,
}

struct Poll(Arc<Runtime>, Kind);

impl JobHandler for Poll {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            // The error is stored and audited by the scheduler: a store error says no secret.
            let pool = &self.0.pool;
            // Nothing to poll is an idle run: a frequent poll must not fill the audit chain.
            let idle = match self.1 {
                Kind::Forge => crate::store::forge::due_prs(pool)
                    .await
                    .map(|d| d.is_empty()),
                Kind::Linear => crate::store::linear::linear_projects(pool)
                    .await
                    .map(|d| d.is_empty()),
            }
            .map_err(|e| e.to_string())?;
            if idle {
                run.idle();
                return Ok(());
            }
            match self.1 {
                Kind::Forge => forge_sync(&self.0).await,
                Kind::Linear => linear_sync(&self.0).await,
            }
            .map_err(|e| e.to_string())
        })
    }
}
