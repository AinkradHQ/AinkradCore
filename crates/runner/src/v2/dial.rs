//! One connection to the hub (E1-11.3): the `/handshake` fingerprint against the pin before
//! anything signed is sent, a session, the signed upgrade, then `serve` with this TLS
//! session's exporter.

use std::sync::Arc;

use ainkrad_proto::v2::{EXPORTER_LABEL, NO_CHANNEL_BINDING};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use super::client::{Client, LinkError, Signer};
use super::key::{Enrolment, Key};
use super::{ExecDriver, Link, serve};

pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Dials the hub as `enrolment`'s device: the socket and its exporter. A Core that does not
/// report the pinned fingerprint gets nothing signed (`LinkError::Mismatch`).
pub async fn dial(
    client: &Client,
    key: &Key,
    enrolment: &Enrolment,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<(Socket, [u8; 32]), LinkError> {
    let presented = client.core_fp().await?;
    // The pin, or the next key a rotation announced (`Enrolment::accepts`); the request is
    // signed for the one presented, which `serve` then holds the Core's proof to.
    if !enrolment.accepts(&presented) {
        tracing::error!(
            pinned = enrolment.core_fp,
            presented,
            "core_identity_mismatch: refusing this Core"
        );
        return Err(LinkError::Mismatch {
            pinned: enrolment.core_fp.clone(),
            presented,
        });
    }
    let signer = Signer {
        key,
        device: &enrolment.device_id,
        core_fp: &presented,
    };
    let session = client.session(signer).await?;
    let mut req = client
        .hub_url()
        .into_client_request()
        .map_err(|e| LinkError::Config(e.to_string()))?;
    let path = req.uri().path().to_owned();
    for (name, value) in signer.headers(Some(&session), "GET", &path, b"") {
        let value = HeaderValue::from_str(&value).expect("signing headers are ASCII");
        req.headers_mut().insert(name, value);
    }
    let connector = tls.map(Connector::Rustls);
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(req, None, false, connector)
        .await
        .map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) => {
                let body = r.body().as_deref().unwrap_or_default();
                let code = serde_json::from_slice::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["code"].as_str().map(str::to_owned))
                    .unwrap_or_default();
                LinkError::Refused(r.status().as_u16(), code)
            }
            other => LinkError::Transport(other.to_string()),
        })?;
    let exporter = match ws.get_ref() {
        MaybeTlsStream::Rustls(tls) => {
            let mut x = [0; 32];
            tls.get_ref()
                .1
                .export_keying_material(&mut x, EXPORTER_LABEL, None)
                .map_err(|e| LinkError::Transport(format!("no TLS exporter: {e}")))?;
            x
        }
        // `Client::new` allows plain text only to a loopback host.
        MaybeTlsStream::Plain(_) => NO_CHANNEL_BINDING,
        _ => return Err(LinkError::Config("an unknown transport".to_owned())),
    };
    Ok((ws, exporter))
}

/// One connection, served until it ends.
pub async fn connect_once(
    client: &Client,
    link_key: Arc<Key>,
    enrolment: Arc<std::sync::Mutex<Enrolment>>,
    save: Option<std::path::PathBuf>,
    exec: Arc<ExecDriver>,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<(), LinkError> {
    let current = enrolment.lock().unwrap().clone();
    let (ws, exporter) = dial(client, &link_key, &current, tls).await?;
    let link = Link {
        key: link_key,
        enrolment,
        save,
        exporter,
    };
    serve(ws, exec, &link)
        .await
        .map(drop)
        .map_err(LinkError::Protocol)
}
