//! The head of a request from the harness (KAN-435 G3, threats T6 and T8). The client is the
//! agent, so nothing here trusts it: framing is checked before anything else, and a request that
//! could be read two ways (two lengths, a length and a transfer coding, an obs-fold, a header
//! name with a space) is refused whole. The upstream request is built fresh from what survives.

use super::reply::parse_lines;

/// Why a request is not served: an HTTP status and a short machine-readable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refusal {
    pub status: u16,
    pub code: &'static str,
}

pub(super) const fn refuse(status: u16, code: &'static str) -> Refusal {
    Refusal { status, code }
}

/// The largest request head.
pub(super) const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Debug)]
pub(super) struct Request {
    pub method: String,
    pub target: String,
    /// Lower-case names.
    pub headers: Vec<(String, String)>,
    /// The `Content-Length`, when the request has one.
    pub length: Option<usize>,
}

impl Request {
    pub(super) fn parse(raw: &[u8]) -> Result<Request, Refusal> {
        let bad = refuse(400, "bad_request");
        let (first, headers) = parse_lines(raw).map_err(|()| bad)?;
        let mut parts = first.split(' ');
        let (Some(method), Some(target), Some("HTTP/1.1"), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad);
        };
        if method.is_empty()
            || !method.bytes().all(|b| b.is_ascii_uppercase())
            || headers.len() > MAX_HEADERS
        {
            return Err(bad);
        }
        let count = |name: &str| headers.iter().filter(|h| h.0 == name).count();
        // Framing first: one length, and no transfer coding next to it. A chunked body is not
        // read at all (411), so there is no second framing for a front and a back to disagree on.
        if count("host") > 1 || count("content-length") > 1 {
            return Err(bad);
        }
        let length = match headers.iter().find(|h| h.0 == "content-length") {
            Some((_, v)) => {
                let digits =
                    !v.is_empty() && v.len() <= 18 && v.bytes().all(|b| b.is_ascii_digit());
                Some(v.parse::<usize>().ok().filter(|_| digits).ok_or(bad)?)
            }
            None => None,
        };
        if count("transfer-encoding") > 0 {
            return Err(if length.is_some() {
                bad
            } else {
                refuse(411, "length_required")
            });
        }
        if method == "CONNECT" {
            return Err(refuse(405, "method_not_allowed"));
        }
        // Origin-form only: an absolute URI (`http://host/...`), `*` or an authority is not a path
        // on this gateway.
        if !target.starts_with('/')
            || !target.bytes().all(|b| b.is_ascii_graphic())
            || target.contains('#')
        {
            return Err(bad);
        }
        let upgrade = headers.iter().any(|(n, v)| {
            n == "upgrade"
                || (n == "connection"
                    && v.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
        });
        if upgrade {
            return Err(refuse(426, "upgrade_not_supported"));
        }
        Ok(Request {
            method: method.to_owned(),
            target: target.to_owned(),
            headers,
            length,
        })
    }
}

/// The request headers that may reach the upstream; the gateway adds its own `host`,
/// `content-length`, `accept-encoding`, `connection` and the auth header. Everything else,
/// whatever the agent sent as auth, a cookie or a forwarding header included, is dropped.
pub(super) fn header_ok(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "accept"
            | "anthropic-version"
            | "anthropic-beta"
            | "user-agent"
            | "openai-beta"
            | "x-goog-api-client"
    ) || name.starts_with("x-stainless-")
}
