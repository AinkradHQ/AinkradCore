//! One authenticated runner connection: registered as the runner's live one, welcomed, then
//! frames both ways until it ends, which closes it with a code saying why
//! (`ainkrad_proto::v2::close_code`).

use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Control, CoreWelcome, Frame, Heartbeat, PROTOCOL_VERSION, RunnerHello,
    close_code,
};
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use serde_json::{Value, json};

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
    let connected = json!({
        "device_id": device.id,
        "name": device.name,
        "version": hello.runner_version,
        "drivers": hello.drivers.iter().map(|d| &d.name).collect::<Vec<_>>(),
    });
    let now = app.clock.unix();
    // What the runner still holds, to settle the Core's terminal rows once it is registered.
    let held = hello
        .drivers
        .iter()
        .any(|d| d.name == ainkrad_proto::v2::DRIVER_PTY)
        .then(|| hello.terminals.clone());
    let (generation, streams) = hub.register(
        &device.id,
        &device.name,
        hello,
        out_tx,
        Arc::clone(&replaced),
        now,
    );
    emit(&app, CONNECTED, connected).await;
    if let Some(held) = held {
        let (app, runner) = (app.clone(), device.id.clone());
        tokio::spawn(async move {
            crate::api::v1::reconcile_terminals(&app, &runner, &held, now).await
        });
    }
    mark_used(&app, &device).await;
    let mut control_seq = 1;
    let welcome = Control::Welcome(CoreWelcome {
        protocol: PROTOCOL_VERSION.to_owned(),
        boot: Some(hub.boot.clone()),
        heartbeat_ms: Some(u64::try_from(cfg.heartbeat.as_millis()).unwrap_or(u64::MAX)),
        streams,
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
    // A pending identity rotation goes to every runner, on every connection of its window, so
    // one that was offline when it started still learns the next key (security review RH7).
    if let (None, Some(r)) = (&end, &app.auth.identity.rotation) {
        control_seq += 1;
        let frame = Frame::new(
            CONTROL_STREAM,
            control_seq,
            Body::Control(Control::Rotation(r.clone())),
        );
        if send(&mut socket, frame).await.is_err() {
            end = Some(End::Gone);
        }
    }
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
                let silent = heard.elapsed() > cfg.heartbeat * 2;
                let at = app.clock.unix() - i64::try_from(heard.elapsed().as_secs()).unwrap_or(0);
                if hub.seen(&device.id, at, silent) {
                    tracing::warn!(device = device.id, "runner degraded: silent past two heartbeats");
                    emit(&app, DEGRADED, json!({"device_id": device.id, "reason": "silent"})).await;
                }
                control_seq += 1;
                match timed(
                    &mut socket,
                    Frame::new(CONTROL_STREAM, control_seq, Body::Heartbeat(Heartbeat::default())),
                    cfg.send_timeout,
                )
                .await {
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
                        Ok(f) => {
                            // Heartbeat frames carry the host load (E2-15.2).
                            if let Ok(Some(Body::Heartbeat(hb))) = f.body() {
                                hub.load(&device.id, hb);
                            }
                        }
                        Err(_) => tracing::debug!(device = device.id, "not a frame; skipped"),
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break End::Gone,
                Some(Ok(_)) => heard = Instant::now(),
            },
        }
    };
    let revoked_now = matches!(end, End::Revoked);
    hub.unregister(&device.id, generation, app.clock.unix(), revoked_now);
    mark_used(&app, &device).await;
    let reason = match end {
        End::Gone => "gone",
        End::Replaced => "replaced",
        End::Revoked => "revoked",
        End::Restart => "restart",
        End::Silent => "silent",
        End::Slow => "slow",
    };
    emit(
        &app,
        DISCONNECTED,
        json!({"device_id": device.id, "reason": reason}),
    )
    .await;
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

/// The platform's runner event kinds (`store::kinds`).
pub const CONNECTED: &str = "runner.connected";
pub const DISCONNECTED: &str = "runner.disconnected";
pub const DEGRADED: &str = "runner.degraded";

/// Appends one event in its own write; a failure is logged, never fatal to the connection.
async fn emit(app: &App, kind: &str, payload: Value) {
    let written = async {
        let mut tx = crate::store::begin_write(&app.pool).await?;
        crate::store::events::append(&mut tx, kind, &payload).await?;
        tx.commit().await
    };
    if let Err(e) = written.await {
        tracing::error!(error = %e, kind, "writing a runner event failed");
    }
}

/// Records the device's use (`last_used_at`, at most once a minute).
async fn mark_used(app: &App, device: &Device) {
    let now = app.clock.now();
    let last = crate::store::gov::get_device(&app.pool, &device.id)
        .await
        .ok()
        .flatten()
        .and_then(|d| d.last_used_at);
    if let Err(e) = crate::store::gov::mark_used(&app.pool, &device.id, last.as_deref(), &now).await
    {
        tracing::error!(error = %e, "marking a runner used failed");
    }
}
