//! The providers behind the Decisions service and the service itself (§2.1 to §2.3).
//!
//! - **Registry.** `gemini-decision-1` is the one live provider. `openai-decisions` and
//!   `microsoft-decision-1` are reserved ids only: nothing answers for them yet.
//! - **Transport.** A provider never dials. [`HubTransport`] picks the user's first ready `google`
//!   account, leases its key to the built-in runner (audited `secret.leased`, `"to":"gateway"`),
//!   and sends one `gateway.call`; the runner redeems the lease, runs the `gateway.test` dial
//!   checks, makes one POST and returns the body and the tokens. Offline Core, no built-in runner
//!   with `gateway-call`, or no ready account: [`ProviderError::Unavailable`], which is a fallback.
//! - **Service.** [`Service`] is the real [`Decide`]: cache, then one batched provider call for the
//!   misses, then the consumer's [`Fallback`], then equal scores ([`Source::None`]). It never fails
//!   for lack of a model. Every setting is read at the call (`decisions.*`).
//!
//! # How the future consumers call it
//!
//! Neither consumer exists yet (§2.6). Each builds a [`DecideRequest`], hands the service its own
//! [`Fallback`] and acts on the [`Scored`] it gets back. Both are advisory: the answer never
//! widens what the consumer's own rules allow.
//!
//! - **`Consumer::BrainSort`** (Brain, through `ModuleHost::decide`, as the module's user):
//!   `options` are the room ids; each source is one [`Question`] (`key` the source id, `text` its
//!   redacted title plus the first 400 characters); `context` carries `task` ("Which room does this
//!   note belong in?") and `option:<room id>` with each room's name and purpose. The fallback is
//!   the current rule sorter, and a result whose `source` is `Fallback`/`None` is that rule's.
//!   ```ignore
//!   let scored = decisions.decide(DecideRequest { consumer: Consumer::BrainSort, user, options: rooms,
//!       questions: sources.map(|s| Question { key: s.id, text: s.head(400), facts: s.facts() }),
//!       context: ctx }, &RuleSorter).await?;
//!   ```
//! - **`Consumer::AccountOrder`** (the allocator): `options` are account ids; one question per
//!   pick; `facts` are `failures`, `p50_ms` and `cooling` per account (`<account>.failures`, ...);
//!   the fallback is the current `store::alloc` order. Advisory only: `alloc::pick_in` still
//!   enforces every cap, window and budget on whatever it is told to try first.
//! - **`Consumer::HeavyJob`** (E15-3, tier 3): options `light` and `heavy`, one question per
//!   unknown command; the fallback is the rules and the history.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::ids::UserId;
use ainkrad_core::settings::{Key as SettingKey, Scope};
use futures_util::future::{BoxFuture, FutureExt};
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::cache;
use super::gemini::{self, Gemini};
use super::redact::Redactor;
use super::{
    Consumer, Decide, DecideError, DecideRequest, DecisionProvider, Fallback, ProviderCall,
    ProviderError, Question, Scored, Source, budget, check, equal,
};
use crate::api::App;
use crate::scheduler::Clock;
use crate::store::{self, settings};

/// Whether a registered provider answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Live,
    /// The id is held for a later provider; nothing answers for it.
    Reserved,
}

/// The provider registry: ids and whether they answer.
pub const REGISTRY: [(&str, State); 3] = [
    (gemini::ID, State::Live),
    ("openai-decisions", State::Reserved),
    ("microsoft-decision-1", State::Reserved),
];

/// What a provider call used, for the ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    /// The Core account whose key paid; `None` for a provider with no account (a fake).
    pub account: Option<i64>,
    pub model: String,
}

/// Scores and what they cost.
#[derive(Debug, Clone, PartialEq)]
pub struct Metered {
    pub scores: Vec<Vec<f32>>,
    pub usage: Usage,
}

/// A [`DecisionProvider`] that also says what a call used. The frozen trait returns scores only;
/// the service needs the tokens for the ledger and the cap, so it asks through this. A provider
/// that reports no usage implements it empty and is never charged.
pub trait MeteredProvider: DecisionProvider {
    fn score_metered<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Metered, ProviderError>> {
        async move {
            self.score(call).await.map(|scores| Metered {
                scores,
                usage: Usage::default(),
            })
        }
        .boxed()
    }
}

mod transport;
#[cfg(test)]
use transport::upstream_of;
pub use transport::{Called, HubTransport, Transport, class_name};

const DAILY_CAP: SettingKey = SettingKey::DecisionsDailyUsdMicros;
const TIMEOUT: SettingKey = SettingKey::DecisionsTimeoutMs;
const INPUT_PRICE: SettingKey = SettingKey::DecisionsInputPriceMicros;

/// The consumer's settings.
struct Keys {
    enabled: SettingKey,
    ttl: SettingKey,
    min_confidence: SettingKey,
}

fn keys(c: Consumer) -> Keys {
    match c {
        Consumer::HeavyJob => Keys {
            enabled: SettingKey::DecisionsHeavyJobEnabled,
            ttl: SettingKey::DecisionsHeavyJobTtlSecs,
            min_confidence: SettingKey::DecisionsHeavyJobMinConfidence,
        },
        Consumer::BrainSort => Keys {
            enabled: SettingKey::DecisionsBrainSortEnabled,
            ttl: SettingKey::DecisionsBrainSortTtlSecs,
            min_confidence: SettingKey::DecisionsBrainSortMinConfidence,
        },
        Consumer::AccountOrder => Keys {
            enabled: SettingKey::DecisionsAccountOrderEnabled,
            ttl: SettingKey::DecisionsAccountOrderTtlSecs,
            min_confidence: SettingKey::DecisionsAccountOrderMinConfidence,
        },
    }
}

/// Why a provider gave nothing: the `Fallback` reason and the audit `outcome`.
fn outcome_of(e: &ProviderError) -> &'static str {
    match e {
        ProviderError::Unavailable => "no_provider",
        ProviderError::Timeout => "timeout",
        ProviderError::Overloaded => "overloaded",
        ProviderError::CapReached => "cap_reached",
        ProviderError::Failed(_) => "failed",
    }
}

/// `stored` as scores in `options` order, if it holds exactly those options.
fn ordered(stored: &[(String, f32)], options: &[String]) -> Option<Vec<(String, f32)>> {
    if stored.len() != options.len() {
        return None;
    }
    options
        .iter()
        .map(|o| stored.iter().find(|(n, _)| n == o).cloned())
        .collect()
}

fn confident(scores: &[(String, f32)], min: f32) -> bool {
    scores.iter().map(|(_, s)| *s).fold(0.0, f32::max) >= min
}

/// The real [`Decide`].
pub struct Service {
    pool: SqlitePool,
    clock: Arc<dyn Clock + Send + Sync>,
    providers: Vec<Arc<dyn MeteredProvider>>,
    redact: Redactor,
}

impl Service {
    pub fn new(
        pool: SqlitePool,
        clock: Arc<dyn Clock + Send + Sync>,
        providers: Vec<Arc<dyn MeteredProvider>>,
        redact: Redactor,
    ) -> Self {
        Self {
            pool,
            clock,
            providers,
            redact,
        }
    }

    /// The Core's service: `gemini-decision-1` over the hub. `ws_root` is the canonical workspace
    /// and `home` the service user's home, for redaction.
    pub fn for_app(app: &App, ws_root: &Path, home: Option<&Path>) -> Self {
        let transport = Arc::new(HubTransport {
            pool: app.pool.clone(),
            hub: Arc::clone(&app.hub),
            clock: Arc::clone(&app.clock),
        });
        Self::new(
            app.pool.clone(),
            Arc::clone(&app.clock),
            vec![Arc::new(Gemini::new(transport)) as Arc<dyn MeteredProvider>],
            Redactor::new(ws_root, home),
        )
    }

    /// A setting's value now; a store error reads as the default.
    async fn setting(&self, key: SettingKey) -> i64 {
        settings::value(&self.pool, key, Scope::Server)
            .await
            .unwrap_or(key.spec().default)
    }

    /// One audit row per provider call; it never holds text. A failure is logged, never raised.
    async fn audit(
        &self,
        user: UserId,
        consumer: Consumer,
        provider: &str,
        counts: (usize, usize),
        usd: i64,
        outcome: &str,
    ) {
        let (asked, cached) = counts;
        let details = json!({"consumer": consumer.as_str(), "provider": provider, "questions": asked,
                             "cached": cached, "usd_micros": usd, "outcome": outcome});
        let event = NewAuditEvent {
            actor: AuditActor::User(user),
            action: "decision.asked".to_owned(),
            entity: None,
            details: details.to_string(),
        };
        if let Err(e) = store::audit::append_one(&self.pool, &event).await {
            tracing::warn!(error = %e, "recording a decision in the audit failed");
        }
    }

    async fn run(
        &self,
        req: DecideRequest,
        fallback: &dyn Fallback,
    ) -> Result<Vec<Scored>, DecideError> {
        check(&req)?;
        let k = keys(req.consumer);
        let n = req.questions.len();
        let min = self.setting(k.min_confidence).await as f32 / 100.0;
        let mut out: Vec<Option<Scored>> = vec![None; n];
        let mut why: &'static str = "no_provider";
        let provider = if self.setting(k.enabled).await == 0 {
            why = "disabled";
            None
        } else {
            self.providers.first().cloned()
        };
        if let Some(p) = provider {
            why = self.ask(&req, &*p, &k, &mut out).await;
        }
        let mut done = Vec::with_capacity(n);
        for (q, got) in req.questions.iter().zip(out) {
            let own = |why: &'static str| {
                fallback.score(q).map(|scores| Scored {
                    key: q.key.clone(),
                    scores,
                    source: Source::Fallback(why),
                })
            };
            done.push(match got {
                Some(s) if confident(&s.scores, min) => s,
                Some(s) => own("low_confidence").unwrap_or(s),
                None => own(why).unwrap_or_else(|| Scored {
                    key: q.key.clone(),
                    scores: equal(&req.options),
                    source: Source::None,
                }),
            });
        }
        Ok(done)
    }

    /// Fills `out` from the cache, then from one provider call for what is left; returns why the
    /// rest has no model answer (`ok` when nothing is left).
    async fn ask(
        &self,
        req: &DecideRequest,
        p: &dyn MeteredProvider,
        k: &Keys,
        out: &mut [Option<Scored>],
    ) -> &'static str {
        let (now, unix) = (self.clock.now(), self.clock.unix());
        let ctx = self.redact.facts(&req.context);
        let texts: Vec<String> = req
            .questions
            .iter()
            .map(|q: &Question| self.redact.text(&q.text))
            .collect();
        let facts: Vec<BTreeMap<String, String>> = req
            .questions
            .iter()
            .map(|q| self.redact.facts(&q.facts))
            .collect();
        let ctx_hash = cache::context_hash(&ctx);
        let ckeys: Vec<cache::Key> = (0..texts.len())
            .map(|i| {
                cache::key(
                    req.consumer.as_str(),
                    p.id(),
                    &req.options,
                    &texts[i],
                    &facts[i],
                    &ctx_hash,
                )
            })
            .collect();
        let hits = cache::get_many(&self.pool, &ckeys, &now)
            .await
            .unwrap_or_default();
        for (i, q) in req.questions.iter().enumerate() {
            if let Some(scores) = hits.get(&ckeys[i]).and_then(|s| ordered(s, &req.options)) {
                out[i] = Some(Scored {
                    key: q.key.clone(),
                    scores,
                    source: Source::Cache,
                });
            }
        }
        let misses: Vec<usize> = (0..out.len()).filter(|i| out[*i].is_none()).collect();
        if misses.is_empty() {
            return "ok";
        }
        let cap = self.setting(DAILY_CAP).await;
        if budget::cap_reached(&self.pool, &now, cap)
            .await
            .unwrap_or(false)
        {
            return "cap_reached";
        }
        let timeout_ms = u64::try_from(self.setting(TIMEOUT).await).unwrap_or(8_000);
        let call = ProviderCall {
            consumer: req.consumer,
            user: req.user,
            options: req.options.clone(),
            questions: misses.iter().map(|i| texts[*i].clone()).collect(),
            facts: misses.iter().map(|i| facts[*i].clone()).collect(),
            context: ctx,
            timeout_ms,
        };
        // Each attempt is bounded by the transport; this is only the guard around both.
        let guard = Duration::from_millis(timeout_ms * 2 + 2_000);
        let asked = match tokio::time::timeout(guard, p.score_metered(&call)).await {
            Ok(r) => r,
            Err(_) => Err(ProviderError::Timeout),
        };
        let cached = req.questions.len() - misses.len();
        let m = match asked.and_then(|m| valid(m, &call)) {
            Ok(m) => m,
            Err(e) => {
                self.audit(
                    req.user,
                    req.consumer,
                    p.id(),
                    (misses.len(), cached),
                    0,
                    outcome_of(&e),
                )
                .await;
                return outcome_of(&e);
            }
        };
        let price = self.setting(INPUT_PRICE).await;
        let usd = budget::cost_micros(m.usage.input_tokens, price);
        if let Some(account) = m.usage.account {
            let charge = budget::Charge {
                consumer: req.consumer.as_str(),
                account,
                model: &m.usage.model,
                input_tokens: m.usage.input_tokens,
                usd_micros: usd,
            };
            if let Err(e) = budget::record(&self.pool, &charge, &now).await {
                tracing::warn!(error = %e, "recording a decision's cost failed");
            }
        }
        self.audit(
            req.user,
            req.consumer,
            p.id(),
            (misses.len(), cached),
            usd,
            "ok",
        )
        .await;
        let mut rows = Vec::with_capacity(misses.len());
        for (i, scores) in misses.iter().zip(m.scores) {
            let pairs: Vec<(String, f32)> = req.options.iter().cloned().zip(scores).collect();
            rows.push((ckeys[*i], pairs.clone()));
            out[*i] = Some(Scored {
                key: req.questions[*i].key.clone(),
                scores: pairs,
                source: Source::Model {
                    provider: p.id(),
                    model: m.usage.model.clone(),
                },
            });
        }
        let ttl = self.setting(k.ttl).await;
        if let Err(e) =
            cache::put_many(&self.pool, req.consumer.as_str(), p.id(), &rows, unix, ttl).await
        {
            tracing::warn!(error = %e, "caching decisions failed");
        }
        "ok"
    }
}

/// A provider's answer, checked against the call: one finite vector per question, one score per option.
fn valid(m: Metered, call: &ProviderCall) -> Result<Metered, ProviderError> {
    let ok = m.scores.len() == call.questions.len()
        && m.scores
            .iter()
            .all(|s| s.len() == call.options.len() && s.iter().all(|x| x.is_finite()));
    ok.then_some(m).ok_or_else(|| {
        ProviderError::Failed("the provider's scores do not match the call".to_owned())
    })
}

impl Decide for Service {
    fn decide<'a>(
        &'a self,
        req: DecideRequest,
        fallback: &'a dyn Fallback,
    ) -> BoxFuture<'a, Result<Vec<Scored>, DecideError>> {
        async move { self.run(req, fallback).await }.boxed()
    }
}

#[cfg(test)]
mod tests;
