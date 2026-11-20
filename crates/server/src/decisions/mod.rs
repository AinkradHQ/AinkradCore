//! The Decisions service (E15-0, spec §2): a general Core AI advisor that scores fixed options per
//! question. Core-internal, no HTTP route. Each question goes cache → provider (batched) →
//! [`Fallback`] → [`Source::None`] (equal scores): the service never fails because no model is
//! there, and [`DecideError`] is only ever `TooMany` or `BadOptions`.
//!
//! Frozen in F0: these types and traits. The E15-0 lane adds `provider`, `gemini`, `cache`,
//! `redact` and `budget` beside this file and the real [`Decide`] behind [`Stub`]'s signature.
//! The traits return boxed futures (`futures_util::future::BoxFuture`, the codebase's form for an
//! async method behind `dyn`), which is what `#[async_trait]` would expand to.

pub mod budget;
pub mod cache;
pub mod gemini;
pub mod provider;
pub mod redact;

pub use provider::Service;

use std::collections::BTreeMap;

use ainkrad_core::ids::UserId;
use futures_util::future::{BoxFuture, FutureExt};

/// The fewest and most options a request scores.
pub const OPTIONS: std::ops::RangeInclusive<usize> = 2..=16;
/// The most questions one request carries (and one provider call batches).
pub const MAX_QUESTIONS: usize = 1000;

/// Who asks: the cache TTL, settings and audit are per consumer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Consumer {
    HeavyJob,
    /// Future: Brain sorting (§2.6).
    BrainSort,
    /// Future: account order and failover (§2.6).
    AccountOrder,
}

impl Consumer {
    /// The name in settings (`decisions.<consumer>.*`), audit and the cost subject.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeavyJob => "heavy_job",
            Self::BrainSort => "brain_sort",
            Self::AccountOrder => "account_order",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecideRequest {
    pub consumer: Consumer,
    pub user: UserId,
    /// Fixed option ids scored per question ([`OPTIONS`]).
    pub options: Vec<String>,
    /// 1 to [`MAX_QUESTIONS`]; more is `TooMany`.
    pub questions: Vec<Question>,
    /// Shared facts; redacted before sending, hashed for the cache.
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    /// The caller's own key, echoed in [`Scored::key`].
    pub key: String,
    pub text: String,
    pub facts: BTreeMap<String, String>,
}

/// One question's scores: one `(option, score)` per option, in the request's order.
#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    pub key: String,
    pub scores: Vec<(String, f32)>,
    pub source: Source,
}

/// Where a question's scores came from.
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    Model {
        provider: &'static str,
        model: String,
    },
    Cache,
    /// The consumer's [`Fallback`], with why no model answered (`no_provider`, `cap_reached`, ...).
    Fallback(&'static str),
    /// Neither a model nor the fallback: equal scores.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideError {
    /// More than [`MAX_QUESTIONS`].
    TooMany,
    /// Options outside [`OPTIONS`], or one repeated.
    BadOptions,
}

/// One provider call, after redaction: what a [`DecisionProvider`] sends.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderCall {
    pub consumer: Consumer,
    pub user: UserId,
    pub options: Vec<String>,
    /// Redacted question texts, at most [`MAX_QUESTIONS`].
    pub questions: Vec<String>,
    /// Redacted facts per question, in `questions` order.
    pub facts: Vec<BTreeMap<String, String>>,
    /// Redacted shared context.
    pub context: BTreeMap<String, String>,
    pub timeout_ms: u64,
}

/// Why a provider gave no scores; every one means [`Fallback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// No account, an offline Core, or no built-in runner with `gateway-call`.
    Unavailable,
    Timeout,
    /// The upstream reported overload (retried once).
    Overloaded,
    /// `decisions.daily_usd_micros` is reached until UTC midnight.
    CapReached,
    /// A malformed answer, or any other failure (redacted, no provider text).
    Failed(String),
}

/// The service.
pub trait Decide: Send + Sync {
    fn decide<'a>(
        &'a self,
        req: DecideRequest,
        fallback: &'a dyn Fallback,
    ) -> BoxFuture<'a, Result<Vec<Scored>, DecideError>>;
}

/// The consumer's own rule, used when no model answers.
pub trait Fallback: Send + Sync {
    fn score(&self, q: &Question) -> Option<Vec<(String, f32)>>;
}

/// A model behind the service (`gemini-decision-1` first).
pub trait DecisionProvider: Send + Sync {
    fn id(&self) -> &'static str;
    /// One score vector per question, each in `call.options` order.
    fn score<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Vec<Vec<f32>>, ProviderError>>;
}

/// The request's shape checks, shared by every [`Decide`].
pub fn check(req: &DecideRequest) -> Result<(), DecideError> {
    let mut seen = req.options.clone();
    seen.sort();
    seen.dedup();
    if !OPTIONS.contains(&req.options.len()) || seen.len() != req.options.len() {
        return Err(DecideError::BadOptions);
    }
    if req.questions.len() > MAX_QUESTIONS {
        return Err(DecideError::TooMany);
    }
    Ok(())
}

/// Equal scores over `options`.
pub fn equal(options: &[String]) -> Vec<(String, f32)> {
    let s = 1.0 / options.len().max(1) as f32;
    options.iter().map(|o| (o.clone(), s)).collect()
}

/// F0's stand-in: no provider, so every question is the fallback's, then equal scores.
pub struct Stub;

impl Decide for Stub {
    fn decide<'a>(
        &'a self,
        req: DecideRequest,
        fallback: &'a dyn Fallback,
    ) -> BoxFuture<'a, Result<Vec<Scored>, DecideError>> {
        async move {
            check(&req)?;
            Ok(req
                .questions
                .iter()
                .map(|q| match fallback.score(q) {
                    Some(scores) => Scored {
                        key: q.key.clone(),
                        scores,
                        source: Source::Fallback("no_provider"),
                    },
                    None => Scored {
                        key: q.key.clone(),
                        scores: equal(&req.options),
                        source: Source::None,
                    },
                })
                .collect())
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Local;
    impl Fallback for Local {
        fn score(&self, q: &Question) -> Option<Vec<(String, f32)>> {
            (q.key == "known").then(|| vec![("light".to_owned(), 1.0), ("heavy".to_owned(), 0.0)])
        }
    }

    fn req(options: &[&str], n: usize) -> DecideRequest {
        DecideRequest {
            consumer: Consumer::HeavyJob,
            user: UserId(1),
            options: options.iter().map(|s| s.to_string()).collect(),
            questions: (0..n)
                .map(|i| Question {
                    key: if i == 0 {
                        "known".into()
                    } else {
                        format!("q{i}")
                    },
                    text: "cargo build".into(),
                    facts: BTreeMap::new(),
                })
                .collect(),
            context: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn the_stub_answers_the_fallback_then_equal_scores_and_checks_the_shape() {
        let got = Stub
            .decide(req(&["light", "heavy"], 2), &Local)
            .await
            .unwrap();
        assert_eq!(got[0].source, Source::Fallback("no_provider"));
        assert_eq!(got[0].scores[0], ("light".to_owned(), 1.0));
        assert_eq!(got[1].source, Source::None);
        assert_eq!(got[1].scores, equal(&["light".into(), "heavy".into()]));
        let e = |r| async move { Stub.decide(r, &Local).await.unwrap_err() };
        assert_eq!(e(req(&["a", "b"], 1001)).await, DecideError::TooMany);
        assert_eq!(e(req(&["a"], 1)).await, DecideError::BadOptions);
        assert_eq!(e(req(&["a", "a"], 1)).await, DecideError::BadOptions);
        assert_eq!(Consumer::HeavyJob.as_str(), "heavy_job");
    }
}
