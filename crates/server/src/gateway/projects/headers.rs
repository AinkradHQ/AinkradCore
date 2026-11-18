//! Which headers cross the Host router, either way, and how cookies are kept host-only.

use axum::http::{HeaderMap, header};

use super::client::client_claim;

/// Headers that belong to one hop and are never forwarded either way (RFC 9110 §7.6.1).
const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The lower-case tokens of every `Connection` header.
pub(super) fn tokens(h: &HeaderMap) -> Vec<String> {
    h.get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect()
}

/// End-to-end headers only: no hop-by-hop, none `Connection` names, no proxy or Core headers,
/// and client claims ([`client_claim`]) only `from_edge`.
pub(super) fn forwardable(from: &HeaderMap, from_edge: bool) -> HeaderMap {
    let named = tokens(from);
    let mut out = HeaderMap::new();
    for (name, value) in from {
        let n = name.as_str();
        let drop = HOP.contains(&n)
            || named.iter().any(|t| t == n)
            || n == "host"
            || n == "forwarded"
            || n == "x-real-ip"
            || n.starts_with("x-forwarded-")
            || n.starts_with("x-ainkrad-")
            || (!from_edge && client_claim(n));
        if !drop {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// A `Set-Cookie` value without its `Domain` attribute: the cookie stays on the project's host.
pub(super) fn host_only(cookie: &str) -> String {
    cookie
        .split(';')
        .enumerate()
        .filter(|(i, a)| {
            *i == 0
                || !a
                    .trim_start()
                    .get(..6)
                    .is_some_and(|n| n.eq_ignore_ascii_case("domain"))
        })
        .map(|(_, a)| a)
        .collect::<Vec<_>>()
        .join(";")
}
