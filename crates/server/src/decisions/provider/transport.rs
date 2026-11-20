//! The Core's side of a `gateway.call`: the [`Transport`] a provider sends through, and
//! [`HubTransport`], which leases the user's Google key to the built-in runner and sends the op.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::UserId;
use ainkrad_proto::v2::{
    Body, CAP_GATEWAY_CALL, GatewayAuth, GatewayCall, GatewayCalled, Reply, Upstream,
    UpstreamStatus, Wire,
};
use futures_util::future::{BoxFuture, FutureExt};
use sqlx::sqlite::SqlitePool;

use super::ProviderError;
use crate::hub::Hub;
use crate::scheduler::Clock;
use crate::store::{self, accounts, gov, secrets};

/// What a transport answered, and the account that was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Called {
    pub answer: GatewayCalled,
    pub account: i64,
}

/// One POST through a leased key (the `gateway.call` of the built-in runner); a fake in tests.
pub trait Transport: Send + Sync {
    fn call<'a>(
        &'a self,
        user: UserId,
        path: &'a str,
        body: String,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Called, ProviderError>>;
}

/// An upstream class as text, never provider text.
pub fn class_name(s: UpstreamStatus, http: u16) -> String {
    let class = crate::agents::gateway::test::class_name(s);
    format!("{class} (http {http})")
}

/// The upstream of an account's frozen base URL (`https://host[/path]`, 443 only), for Google's wire.
pub(super) fn upstream_of(base_url: &str) -> Option<Upstream> {
    if crate::store::providers::url_problem(base_url).is_some() {
        return None;
    }
    let rest = base_url.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = path.trim_end_matches('/');
    Some(Upstream {
        host: host.strip_suffix(":443").unwrap_or(host).to_owned(),
        base_path: if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        },
        wire: Wire::GeminiGenerate,
        auth: GatewayAuth::XGoogApiKey,
    })
}

/// The Core's own transport: the hub, the secrets broker and the clock.
pub struct HubTransport {
    pub pool: SqlitePool,
    pub hub: Arc<Hub>,
    pub clock: Arc<dyn Clock + Send + Sync>,
}

impl HubTransport {
    /// The online built-in runner (the installer's local enrolment) that lists `gateway-call`.
    async fn built_in(&self) -> Result<String, ProviderError> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? \
             AND device_id IS NOT NULL",
        )
        .bind(gov::LOCAL_ENROL_SAS)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ProviderError::Unavailable)?;
        let runners = self.hub.runners();
        ids.into_iter()
            .find(|id| {
                runners.get(id).is_some_and(|r| {
                    r.online
                        && !r.degraded
                        && r.drivers
                            .iter()
                            .any(|d| d.commands.iter().any(|c| c == CAP_GATEWAY_CALL))
                })
            })
            .ok_or(ProviderError::Unavailable)
    }

    /// The first ready `google` API-key account (oldest first, the allocator's own tie-break; the
    /// AI order of E7-1 replaces it when it lands) whose key can be leased to `runner`.
    async fn lease(
        &self,
        runner: &str,
        user: UserId,
    ) -> Result<(accounts::Account, Upstream, String), ProviderError> {
        let all = accounts::list(&self.pool)
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        for a in all
            .into_iter()
            .filter(|a| a.provider == "google" && a.state == "active")
        {
            let Some(up) = upstream_of(&a.base_url) else {
                continue;
            };
            let leased = secrets::lease_to(
                &self.pool,
                &a.secret_name,
                runner,
                None,
                "core:decisions",
                AuditActor::User(user),
                &self.clock.now(),
                self.clock.unix(),
                Some("gateway"),
            )
            .await;
            if let Ok((lease, _)) = leased {
                return Ok((a, up, lease));
            }
        }
        Err(ProviderError::Unavailable)
    }

    async fn send(
        &self,
        user: UserId,
        path: &str,
        body: String,
        timeout_ms: u64,
    ) -> Result<Called, ProviderError> {
        let runner = self.built_in().await?;
        let (account, upstream, lease) = self.lease(&runner, user).await?;
        let call = GatewayCall {
            lease: lease.clone(),
            provider: account.provider.clone(),
            user_key: None,
            upstream: Some(upstream),
            path: path.to_owned(),
            body,
            timeout_ms: Some(timeout_ms),
        };
        let answer = match self.hub.dispatch_gateway_call(&runner, call) {
            Err(_) => Err(ProviderError::Unavailable),
            Ok(sent) => {
                // The runner's own limit is `timeout_ms`; the grace is for the round trip.
                let wait = Duration::from_millis(timeout_ms + 2_000);
                match tokio::time::timeout(wait, sent.outcome()).await {
                    Ok(Ok(Body::Result(Reply::GatewayCall(answer)))) => Ok(Called {
                        answer,
                        account: account.id,
                    }),
                    Ok(Ok(_)) => Err(ProviderError::Failed(
                        "the runner answered something else".to_owned(),
                    )),
                    Ok(Err(_)) => Err(ProviderError::Unavailable),
                    Err(_) => Err(ProviderError::Timeout),
                }
            }
        };
        if answer.is_err() {
            // Nobody redeemed it, or it was spent on a call that failed: it must not stay live.
            let _ = store::account_keys::revoke_unused_lease(&self.pool, &lease).await;
        }
        answer
    }
}

impl Transport for HubTransport {
    fn call<'a>(
        &'a self,
        user: UserId,
        path: &'a str,
        body: String,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Called, ProviderError>> {
        self.send(user, path, body, timeout_ms).boxed()
    }
}
