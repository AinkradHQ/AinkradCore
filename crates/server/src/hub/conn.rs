//! One authenticated runner connection: registered as the runner's live one, welcomed, then
//! frames both ways until it ends, which closes it with a code saying why
//! (`ainkrad_proto::v2::close_code`).

use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Control, CoreWelcome, Frame, PROTOCOL_VERSION, RunnerHello, close_code,
};
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use super::OUT_QUEUE;
use super::connect::send;
use crate::api::App;
use crate::store::gov::Device;

/// Why a connection ended.
enum End {
    /// The runner closed it or the socket failed: nothing left to say.
    Gone,
    Replaced,
    Revoked,
    Restart,
    Silent,
    Slow,
}

pub(super) async fn run(
    app: App,
    mut socket: WebSocket,
    device: Device,
    hello: RunnerHello,
    revoked: impl Future<Output = ()>,
) {
    tokio::pin!(revoked);
    let hub = Arc::clone(&app.hub);
    let cfg = hub.config.clone();
    let (out_tx, mut out_rx) = mpsc::channel(OUT_QUEUE);
    let replaced = Arc::new(Notify::new());
    let generation = hub.register(&device.id, hello, out_tx, Arc::clone(&replaced));
    let mut control_seq = 1;
    let welcome = Control::Welcome(CoreWelcome {
        protocol: PROTOCOL_VERSION.to_owned(),
    });
    let mut end = match send(
        &mut socket,
        Frame::new(CONTROL_STREAM, control_seq, Body::Control(welcome)),
    )
    .await
    {
        Ok(()) => None,
        Err(()) => Some(End::Gone),
    };
    let mut closing = app.closing.subscribe();
    let mut beat = tokio::time::interval(cfg.heartbeat);
    beat.reset();
    let mut heard = Instant::now();
    let end = loop {
        if let Some(end) = end.take() {
            break end;
        }
        tokio::select! {
            () = crate::api::stopping(&mut closing) => break End::Restart,
            () = &mut revoked => break End::Revoked,
            () = replaced.notified() => break End::Replaced,
            Some(frame) = out_rx.recv() => match timed(&mut socket, frame, cfg.send_timeout).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break End::Gone,
                Err(_) => break End::Slow,
            },
            _ = beat.tick() => {
                if heard.elapsed() > cfg.heartbeat * 3 {
                    break End::Silent;
                }
                control_seq += 1;
                match timed(&mut socket, Frame::new(CONTROL_STREAM, control_seq, Body::Heartbeat), cfg.send_timeout).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break End::Gone,
                    Err(_) => break End::Slow,
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(text))) => {
                    heard = Instant::now();
                    match serde_json::from_str::<Frame>(&text) {
                        Ok(f) if f.stream_id != CONTROL_STREAM => hub.received(&device.id, f),
                        Ok(_) => {}
                        Err(_) => tracing::debug!(device = device.id, "not a frame; skipped"),
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break End::Gone,
                Some(Ok(_)) => heard = Instant::now(),
            },
        }
    };
    hub.unregister(&device.id, generation);
    let (code, why) = match end {
        End::Gone => {
            tracing::info!(device = device.id, "runner disconnected");
            return;
        }
        End::Replaced => (close_code::REPLACED, "replaced by a newer connection"),
        End::Revoked => (close_code::REVOKED, "revoked"),
        End::Restart => (close_code::RESTART, "server restarting; reconnect"),
        End::Silent => (close_code::SILENT, "no heartbeat"),
        End::Slow => (close_code::SLOW, "too slow"),
    };
    tracing::info!(device = device.id, code, why, "runner connection closed");
    let close = Message::Close(Some(CloseFrame {
        code,
        reason: why.into(),
    }));
    let closing = async {
        if socket.send(close).await.is_ok() {
            while let Some(Ok(msg)) = socket.recv().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), closing).await;
}

/// A send, cut at `limit`: `Err` when it took longer, `Ok(Err)` when the socket failed.
async fn timed(
    socket: &mut WebSocket,
    frame: Frame,
    limit: Duration,
) -> Result<Result<(), axum::Error>, tokio::time::error::Elapsed> {
    let text = serde_json::to_string(&frame).expect("a frame serializes");
    tokio::time::timeout(limit, socket.send(Message::Text(text.into()))).await
}
