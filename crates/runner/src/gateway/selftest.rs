//! The start-up check behind the `gateway` capability (KAN-435 G3): a runner offers it only after
//! it has opened a gateway socket on this host and seen it answer a request with the refusal it
//! owes. Nothing is dialled and no key is involved: the grant is made up and its key is a filler.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{Ceiling, GatewayAuth, GatewayGrant, ModelPrice, Rate, Upstream, Wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::dial::Dialer;
use super::{Config, Key, socket_in, start};

/// Opens a gateway on a private socket, sends it a request for a path it refuses, and expects
/// the 403. A runner that cannot bind its sockets or serve one does not advertise the gateway.
pub async fn selftest() -> Result<(), String> {
    let grant = GatewayGrant {
        lease: String::new(),
        account: 0,
        provider: "anthropic".to_owned(),
        user_key: None,
        upstream: Upstream {
            host: "api.anthropic.com".to_owned(),
            base_path: String::new(),
            wire: Wire::AnthropicMessages,
            auth: GatewayAuth::XApiKey,
        },
        models: vec!["m".to_owned()],
        prices: vec![ModelPrice {
            model: "m".to_owned(),
            input: 1,
            output: 1,
            cache_read: 1,
            cache_write: 1,
        }],
        ceiling: Ceiling {
            tokens: 1,
            usd_micros: 1,
        },
        rate: Rate {
            per_minute: 1,
            concurrent: 1,
        },
    };
    // Built, not written: a filler in the shape the key rule accepts for the host.
    let key =
        Key::new(Zeroizing::new(format!("sk-ant-{}", "0".repeat(24)))).map_err(str::to_owned)?;
    let cfg = Config::new(&grant, key, Arc::new(Dialer::new(vec![]))).map_err(str::to_owned)?;
    let dir = std::env::temp_dir().join(format!("ainkrad-gw-selftest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let result = async {
        let sock = socket_in(&dir);
        let _gateway = start(&sock, cfg).map_err(|e| format!("the socket: {e}"))?;
        let ask = async {
            let mut c = UnixStream::connect(&sock).await?;
            c.write_all(b"GET /selftest HTTP/1.1\r\nHost: x\r\n\r\n")
                .await?;
            let mut out = vec![0u8; 64];
            let n = c.read(&mut out).await?;
            out.truncate(n);
            Ok::<_, std::io::Error>(out)
        };
        let out = timeout(Duration::from_secs(5), ask)
            .await
            .map_err(|_| "the gateway did not answer".to_owned())?
            .map_err(|e| format!("the gateway: {e}"))?;
        out.starts_with(b"HTTP/1.1 403 ")
            .then_some(())
            .ok_or_else(|| "the gateway did not refuse an unknown path".to_owned())
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    result
}
