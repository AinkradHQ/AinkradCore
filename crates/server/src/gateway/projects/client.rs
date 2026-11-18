//! Who the client is (review fix, PR #338): only Cloudflare's edge, or a `--trusted-proxy`, is
//! believed about the client's address.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request};

use crate::api::limit::Cidr;

/// The peers project traffic is believed from: Cloudflare's edge (`Cidr::CLOUDFLARE`) and the
/// `serve --trusted-proxy` list (a local tunnel such as `cloudflared`).
pub fn edge(trusted_proxies: &[Cidr]) -> Arc<[Cidr]> {
    Cidr::CLOUDFLARE
        .iter()
        .chain(trusted_proxies)
        .copied()
        .collect()
}

/// The client's address and whether the peer is on the [`edge`]: `CF-Connecting-IP` from an
/// edge peer (the peer itself when it sends none), else the peer. None without a peer (tests).
pub(super) fn client_ip(req: &Request, edge: &[Cidr]) -> (Option<IpAddr>, bool) {
    let Some(peer) = req.extensions().get::<ConnectInfo<SocketAddr>>() else {
        return (None, false);
    };
    let peer = peer.0.ip().to_canonical();
    if !edge.iter().any(|c| c.contains(peer)) {
        return (Some(by_network(peer)), false);
    }
    let cf = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok()?.trim().parse::<IpAddr>().ok());
    (
        Some(by_network(cf.map_or(peer, |ip| ip.to_canonical()))),
        true,
    )
}

/// An IPv6 client is keyed by its /64 (one subscriber holds the whole range, so per-address keys
/// would let it dodge the rate cap); IPv4 is kept as is.
fn by_network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & (!0u128 << 64)).into()),
        v4 => v4,
    }
}

/// Headers that name the client and are believed only from an [`edge`] peer.
pub(super) fn client_claim(name: &str) -> bool {
    name.starts_with("cf-") || ["true-client-ip", "x-client-ip", "client-ip"].contains(&name)
}
