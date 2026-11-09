//! `gateway.test` (KAN-435 G4, spec 7.1): one free request through the same dialer a session
//! uses, to see whether an account's key and upstream answer. The Core never dials a provider;
//! it leases the key to a runner and gets back a status class and a latency, never a body.
//!
//! The request is a model list call (or the provider's declared authenticated path, for one whose
//! model list needs no key): a route the agent's route table never allows, so a test can
//! not be made to spend anything. The key is checked against its host first, as for a session.

use std::sync::Arc;
use std::time::Instant;

use ainkrad_proto::v2::{GatewayAuth, GatewayTest, GatewayTested, Wire};
use zeroize::Zeroizing;

use super::dial::{DialError, Dialer};
use super::{Key, status, upstream_problem};
use crate::v2::agent::secrets::Redeem;

/// The most of the reply read: the class comes from the status and an error's `type`.
const MAX_REPLY: usize = status::PROBE_BYTES;

/// The model-list path of a wire, under the upstream's base path.
fn list_path(wire: Wire, base: &str) -> String {
    match wire {
        Wire::AnthropicMessages => format!("{base}/v1/models?limit=1"),
        Wire::OpenaiResponses => format!("{base}/models"),
        Wire::GeminiGenerate => format!("{base}/v1beta/models?pageSize=1"),
    }
}

/// The path of the one request: the Core's authenticated `test_path` under the base path when the
/// provider declares one, else the wire's model list.
fn request_path(req: &GatewayTest) -> String {
    match &req.test_path {
        Some(path) => format!("{}{path}", req.upstream.base_path),
        None => list_path(req.upstream.wire, &req.upstream.base_path),
    }
}

/// Redeems the lease, checks the key against the host, makes the request. An `Err` is a reason
/// fit for the Core (the grant or lease was wrong); a dial or HTTP failure is an `Ok` class.
pub async fn run(
    req: &GatewayTest,
    redeem: Option<&Redeem>,
    dialer: Arc<Dialer>,
) -> Result<GatewayTested, String> {
    let redeem = redeem.ok_or("this runner cannot redeem a gateway lease")?;
    let leased = redeem(req.lease.clone()).await?;
    let key = Key::new(leased.value).map_err(str::to_owned)?;
    if let Some(why) = upstream_problem(&req.provider, req.user_key.as_ref(), &req.upstream, &key) {
        return Err(format!("the gateway test: {why}"));
    }
    let up = &req.upstream;
    let auth = match up.auth {
        GatewayAuth::XApiKey => ("x-api-key", Zeroizing::new(key.expose().to_owned())),
        GatewayAuth::Bearer => (
            "authorization",
            Zeroizing::new(format!("Bearer {}", key.expose())),
        ),
        GatewayAuth::XGoogApiKey => ("x-goog-api-key", Zeroizing::new(key.expose().to_owned())),
    };
    let mut headers = vec![(auth.0, auth.1.as_str()), ("accept", "application/json")];
    if up.wire == Wire::AnthropicMessages {
        headers.push(("anthropic-version", "2023-06-01"));
    }
    let started = Instant::now();
    let result = match dialer
        .request(
            &up.host,
            "GET",
            &request_path(req),
            &headers,
            b"",
            MAX_REPLY,
        )
        .await
    {
        Ok(reply) => status::of_http(reply.status, &reply.body),
        Err(e) => match e {
            DialError::BadHost | DialError::BadRequest => {
                return Err(
                    "the gateway test: the upstream is not one the gateway dials".to_owned(),
                );
            }
            e => status::of_dial(e),
        },
    };
    Ok(GatewayTested {
        result,
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use ainkrad_proto::v2::{GatewayTest, Upstream, Wire};

    use super::request_path;

    fn test(wire: Wire, base: &str, path: Option<&str>) -> GatewayTest {
        GatewayTest {
            lease: "l_x".to_owned(),
            provider: "p".to_owned(),
            user_key: None,
            upstream: Upstream {
                host: "h.example.com".to_owned(),
                base_path: base.to_owned(),
                wire,
                auth: wire.auth(),
            },
            test_path: path.map(str::to_owned),
        }
    }

    #[test]
    fn the_declared_path_is_the_request_and_the_wire_model_list_is_the_default() {
        let req = test(Wire::OpenaiResponses, "/api/v1", Some("/key"));
        assert_eq!(request_path(&req), "/api/v1/key");
        let req = test(Wire::OpenaiResponses, "/v1", None);
        assert_eq!(request_path(&req), "/v1/models");
        let req = test(Wire::AnthropicMessages, "", None);
        assert_eq!(request_path(&req), "/v1/models?limit=1");
    }
}
