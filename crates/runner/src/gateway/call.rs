//! `gateway.call` (E15-0): one `POST` through a lease for a Core service (the Decisions service).
//! The Core never dials a provider; it leases the key to the built-in runner, which redeems it,
//! runs the same checks as `gateway.test` (the key may go to this host, the host is a plain DNS
//! name, the dialer refuses private addresses), makes the one request and returns the body
//! (at most [`MAX_GATEWAY_CALL_BYTES`]) and the tokens the upstream reported.
//!
//! The Core names the path and the body; the host, the method and the key's header are fixed by the
//! grant's upstream, so a call can only ever reach the host the key was bound to.

use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    CallUsage, GatewayAuth, GatewayCall, GatewayCalled, MAX_GATEWAY_CALL_BYTES, UpstreamStatus,
    Wire,
};
use serde_json::Value;
use zeroize::Zeroizing;

use super::dial::{DialError, Dialer};
use super::{Key, status, upstream_problem};
use crate::v2::agent::secrets::Redeem;

/// The most request body one call sends: 1000 redacted questions fit well inside it.
pub const MAX_CALL_BODY: usize = 4 * 1024 * 1024;
/// How long a call may take when the Core names no time, and the most it may name.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// A request path under the upstream's base path: `/` then at least one plain segment, no query,
/// fragment, escape, dot segment or empty segment (`:` is allowed for `models/x:generateContent`).
pub fn path_ok(p: &str) -> bool {
    p.len() <= 256
        && p.starts_with('/')
        && !p.ends_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~:-".contains(&b))
        && p.split('/')
            .skip(1)
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

fn num(v: &Value, ptr: &str) -> u64 {
    v.pointer(ptr).and_then(Value::as_u64).unwrap_or(0)
}

/// The tokens a response reports: the Decisions API's `usage.total_input_tokens` /
/// `total_output_tokens`, Gemini's `usageMetadata`, or the usual `usage.input_tokens` /
/// `output_tokens`. Zero for a body that says none.
pub fn usage_of(body: &[u8]) -> CallUsage {
    let v = serde_json::from_slice::<Value>(body).unwrap_or_default();
    let pick = |ptrs: &[&str]| {
        ptrs.iter()
            .map(|p| num(&v, p))
            .find(|n| *n > 0)
            .unwrap_or(0)
    };
    CallUsage {
        input: pick(&[
            "/usage/total_input_tokens",
            "/usageMetadata/promptTokenCount",
            "/usage/input_tokens",
        ]),
        output: pick(&[
            "/usage/total_output_tokens",
            "/usageMetadata/candidatesTokenCount",
            "/usage/output_tokens",
        ]),
        ..CallUsage::default()
    }
}

/// Redeems the lease, checks the key against its host, makes the request. An `Err` is a reason fit
/// for the Core (the call, the grant or the lease was wrong); a dial or HTTP failure is an `Ok`
/// class, and only an `ok` one carries a body.
pub async fn run(
    req: &GatewayCall,
    redeem: Option<&Redeem>,
    own: Vec<std::net::IpAddr>,
) -> Result<GatewayCalled, String> {
    let up = req
        .upstream
        .as_ref()
        .ok_or("the gateway call names no upstream")?;
    if !path_ok(&req.path) {
        return Err("the gateway call's path is not a plain path".to_owned());
    }
    if req.body.len() > MAX_CALL_BODY {
        return Err("the gateway call's body is too large".to_owned());
    }
    let wait = req
        .timeout_ms
        .map_or(DEFAULT_TIMEOUT, Duration::from_millis)
        .min(MAX_TIMEOUT);
    let redeem = redeem.ok_or("this runner cannot redeem a gateway lease")?;
    let leased = redeem(req.lease.clone()).await?;
    let key = Key::new(leased.value).map_err(str::to_owned)?;
    if let Some(why) = upstream_problem(&req.provider, req.user_key.as_ref(), up, &key) {
        return Err(format!("the gateway call: {why}"));
    }
    let auth = match up.auth {
        GatewayAuth::XApiKey => ("x-api-key", Zeroizing::new(key.expose().to_owned())),
        GatewayAuth::Bearer => (
            "authorization",
            Zeroizing::new(format!("Bearer {}", key.expose())),
        ),
        GatewayAuth::XGoogApiKey => ("x-goog-api-key", Zeroizing::new(key.expose().to_owned())),
    };
    let mut headers = vec![
        (auth.0, auth.1.as_str()),
        ("accept", "application/json"),
        ("content-type", "application/json"),
    ];
    if up.wire == Wire::AnthropicMessages {
        headers.push(("anthropic-version", "2023-06-01"));
    }
    let dialer = Dialer::new(own).with_total(wait);
    let path = format!("{}{}", up.base_path, req.path);
    let started = Instant::now();
    let reply = dialer
        .request(
            &up.host,
            "POST",
            &path,
            &headers,
            req.body.as_bytes(),
            MAX_GATEWAY_CALL_BYTES,
        )
        .await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let called = match reply {
        Ok(r) => {
            let result = status::of_http(r.status, &r.body);
            let ok = result == UpstreamStatus::Ok;
            GatewayCalled {
                result,
                http_status: r.status,
                usage: if ok {
                    usage_of(&r.body)
                } else {
                    CallUsage::default()
                },
                retry_after: status::retry_after(&r.headers),
                truncated: ok && r.truncated,
                body: if ok {
                    String::from_utf8_lossy(&r.body).into_owned()
                } else {
                    String::new()
                },
                latency_ms,
            }
        }
        Err(DialError::BadHost | DialError::BadRequest) => {
            return Err("the gateway call: the upstream is not one the gateway dials".to_owned());
        }
        Err(e) => GatewayCalled {
            result: status::of_dial(e),
            latency_ms,
            ..GatewayCalled::default()
        },
    };
    Ok(called)
}

#[cfg(test)]
mod tests {
    use super::{path_ok, usage_of};

    #[test]
    fn a_path_is_plain_or_refused() {
        assert!(path_ok("/v1beta/decisions"));
        assert!(path_ok("/v1beta/models/x:generateContent"));
        for bad in [
            "", "v1", "/", "/a/", "/a//b", "/a/../b", "/a/./b", "/a?x=1", "/a#f", "/a b", "/a%2f",
        ] {
            assert!(!path_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn usage_is_read_from_the_decisions_and_the_generate_shapes() {
        let u = usage_of(br#"{"usage":{"total_input_tokens":812,"total_output_tokens":0}}"#);
        assert_eq!((u.input, u.output), (812, 0));
        let u = usage_of(br#"{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":7}}"#);
        assert_eq!((u.input, u.output), (5, 7));
        assert_eq!(usage_of(b"not json").input, 0);
    }
}
