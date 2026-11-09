//! A session's gateway, from its grant (KAN-435 G3): redeem the lease into memory, check the key
//! against its host, open the socket. The key never leaves this module except into the gateway's
//! own memory and the session's redactor.

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::Arc;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::GatewayGrant;

use super::dial::Dialer;
use super::{Config, Event, Gateway, Key, REQUEST_TOTAL, sandbox_env, socket_in, start};
use crate::v2::agent::secrets::Redeem;

/// An open gateway, the sandbox slot's variables, and what it reports.
pub type Opened = (
    Gateway,
    Vec<(String, String)>,
    tokio::sync::mpsc::UnboundedReceiver<Event>,
);

/// Redeems `grant.lease`, teaches `redactor` the value, and starts the gateway on a socket in
/// `dir` (the session's private dir). Returns it with the sandbox slot's variables
/// (`AINKRAD_SANDBOX_GW_*`; they name the socket and forwarder, never the key) and the channel
/// of what the gateway reports (usage, upstream signals, a close). Errors say what failed and
/// never hold the lease or the key.
pub async fn open(
    grant: &GatewayGrant,
    redeem: Option<&Redeem>,
    dir: &Path,
    redactor: &mut Redactor,
) -> Result<Opened, String> {
    let redeem = redeem.ok_or("this runner cannot redeem a gateway lease")?;
    let leased = redeem(grant.lease.clone()).await?;
    redactor.known(&leased.name, &leased.value);
    let key = Key::new(leased.value).map_err(str::to_owned)?;
    let own = crate::egress::host_addresses()?;
    let dialer = Arc::new(Dialer::new(own).with_total(REQUEST_TOTAL));
    let cfg = Config::new(grant, key, dialer).map_err(|why| format!("the gateway grant: {why}"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("the gateway's directory: {e}"))?;
    let sock = socket_in(dir);
    let (events, rx) = tokio::sync::mpsc::unbounded_channel();
    let gateway = start(&sock, cfg, events).map_err(|e| format!("the gateway socket: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("the forwarder: {e}"))?;
    let env = sandbox_env(&sock, &exe)
        .into_iter()
        .map(|(n, v)| Ok((n, v.into_string().map_err(|_| "a non-UTF-8 gateway path")?)))
        .collect::<Result<_, &str>>()?;
    Ok((gateway, env, rx))
}
