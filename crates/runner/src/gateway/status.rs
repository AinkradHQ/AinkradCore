//! The outcome class of an upstream exchange (KAN-435 G4, spec 4.6 and 6): a closed enum and a
//! retry hint, never the provider's text. An error body is read for its `type`, `code` and
//! `status` strings only, and nothing else of it is kept.

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::Value;

use super::dial::DialError;

/// The most of an error body read to classify it.
pub(super) const PROBE_BYTES: usize = 16 * 1024;

/// The class of an HTTP status, with the error `body` (the start of it) of a non-2xx.
///
/// Quota is told from rate limiting by the provider's own error `type` / `code` only: OpenAI's
/// `insufficient_quota`, Anthropic's `billing_error` (and a 402). A Gemini `RESOURCE_EXHAUSTED`
/// and an Anthropic credit message are not told apart without reading their text, which is never
/// done: both read as rate limited.
pub(super) fn of_http(status: u16, body: &[u8]) -> UpstreamStatus {
    let v = serde_json::from_slice::<Value>(body).unwrap_or_default();
    let field = |k: &str| {
        v.pointer("/error")
            .and_then(|e| e.get(k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let (kind, code) = (field("type"), field("code"));
    let billing = status == 402
        || kind.as_deref() == Some("billing_error")
        || code.as_deref() == Some("insufficient_quota")
        || kind.as_deref() == Some("insufficient_quota");
    match status {
        200..=299 => UpstreamStatus::Ok,
        _ if billing => UpstreamStatus::Quota,
        429 => UpstreamStatus::RateLimited,
        _ if key_rejected(status, &v) => UpstreamStatus::AuthFailed,
        // 5xx, a 403 about a resource, and any other refusal the upstream itself made.
        _ => UpstreamStatus::ServerError,
    }
}

/// The upstream says the key itself is bad: a 401, or an error whose `type`, `code` or detail
/// `reason` names the key (`authentication_error`, `invalid_api_key`, `API_KEY_INVALID`). A 403
/// about a resource (a Gemini file or cached content, an Anthropic `permission_error`) is not: the
/// key works, and the session must not be ended or the account disabled for it.
fn key_rejected(status: u16, v: &Value) -> bool {
    const KEY: [&str; 3] = ["authentication_error", "invalid_api_key", "API_KEY_INVALID"];
    let named = |x: Option<&Value>| x.and_then(Value::as_str).is_some_and(|s| KEY.contains(&s));
    let e = v.get("error");
    let in_details = e
        .and_then(|e| e.get("details"))
        .and_then(Value::as_array)
        .is_some_and(|d| d.iter().any(|x| named(x.get("reason"))));
    status == 401
        || named(e.and_then(|e| e.get("type")))
        || named(e.and_then(|e| e.get("code")))
        || in_details
}

/// The class of a request that did not get an answer.
pub(super) fn of_dial(e: DialError) -> UpstreamStatus {
    match e {
        DialError::Refused(_) => UpstreamStatus::RefusedAddress,
        DialError::Tls => UpstreamStatus::TlsFailed,
        _ => UpstreamStatus::Unreachable,
    }
}

/// `retry-after` as seconds, when it is a plain number of them.
pub(super) fn retry_after(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(n, _)| n == "retry-after")
        .and_then(|(_, v)| v.trim().parse().ok())
}

/// When Anthropic says its limit resets (`anthropic-ratelimit-*-reset`, an RFC 3339 time): the
/// value only if it is shaped like one.
pub(super) fn reset_at(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .filter(|(n, _)| n.starts_with("anthropic-ratelimit-") && n.ends_with("-reset"))
        .map(|(_, v)| v.trim())
        .find(|v| {
            (10..=40).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b":.+-".contains(&b))
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_is_classed_by_its_code_and_the_errors_type_never_its_text() {
        let class = |s, b: &str| of_http(s, b.as_bytes());
        assert_eq!(class(200, ""), UpstreamStatus::Ok);
        assert_eq!(class(429, "{}"), UpstreamStatus::RateLimited);
        assert_eq!(class(429, "not json"), UpstreamStatus::RateLimited);
        assert_eq!(
            class(
                429,
                r#"{"error":{"code":"insufficient_quota","message":"x"}}"#
            ),
            UpstreamStatus::Quota
        );
        assert_eq!(
            class(400, r#"{"type":"error","error":{"type":"billing_error"}}"#),
            UpstreamStatus::Quota
        );
        assert_eq!(class(402, ""), UpstreamStatus::Quota);
        assert_eq!(class(401, ""), UpstreamStatus::AuthFailed);
        // A 403 is the key's only when the error says so; a resource's is the upstream's.
        assert_eq!(class(403, ""), UpstreamStatus::ServerError);
        assert_eq!(
            class(
                403,
                r#"{"error":{"type":"permission_error","message":"x"}}"#
            ),
            UpstreamStatus::ServerError
        );
        assert_eq!(
            class(
                403,
                r#"{"error":{"status":"PERMISSION_DENIED","message":"file"}}"#
            ),
            UpstreamStatus::ServerError
        );
        assert_eq!(
            class(403, r#"{"error":{"type":"authentication_error"}}"#),
            UpstreamStatus::AuthFailed
        );
        assert_eq!(
            class(
                400,
                r#"{"error":{"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"#
            ),
            UpstreamStatus::AuthFailed
        );
        assert_eq!(
            class(403, r#"{"error":{"code":"invalid_api_key"}}"#),
            UpstreamStatus::AuthFailed
        );
        assert_eq!(class(529, ""), UpstreamStatus::ServerError);
        assert_eq!(
            class(400, r#"{"error":{"type":"invalid_request_error"}}"#),
            UpstreamStatus::ServerError
        );
        // The words of an error message decide nothing.
        assert_eq!(
            class(
                429,
                r#"{"error":{"message":"insufficient_quota billing_error"}}"#
            ),
            UpstreamStatus::RateLimited
        );
    }

    #[test]
    fn the_retry_hints_are_numbers_and_times_only() {
        let h = |n: &str, v: &str| vec![(n.to_owned(), v.to_owned())];
        assert_eq!(retry_after(&h("retry-after", "30")), Some(30));
        assert_eq!(retry_after(&h("retry-after", "Wed, 21 Oct")), None);
        assert_eq!(
            reset_at(&h(
                "anthropic-ratelimit-requests-reset",
                "2026-11-04T10:00:00Z"
            ))
            .as_deref(),
            Some("2026-11-04T10:00:00Z")
        );
        assert_eq!(
            reset_at(&h("anthropic-ratelimit-requests-reset", "<script>")),
            None
        );
        assert_eq!(
            reset_at(&h("x-ratelimit-reset", "2026-11-04T10:00:00Z")),
            None
        );
    }
}
