//! The port stream as a byte pipe (P6-02): [`HubDial`] opens `port.open` on the run's runner
//! (`Hub::dispatch_port`, P6-01) and pumps it through an in-memory duplex the Host router speaks
//! HTTP over. Tests swap in their own [`Dial`].

use std::sync::Arc;

use ainkrad_proto::v2::{Body as Frame, ErrorCode, Output, PortOpen, STREAM_WINDOW};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::hub::{Dispatched, Hub};

/// The pipe between the HTTP side and a port stream: what is buffered past the runner's window.
const PIPE: usize = 16 * 1024;
const CHUNK: usize = 16 * 1024;

/// Why a port stream did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// The runner is at its `run.port` stream cap (or its capacity): 503.
    Busy,
    /// Offline, or it refused: 502.
    Unreachable,
}

/// Opens a byte stream to an exposed port of a live run. The hub in production ([`HubDial`]), a
/// local socket in tests.
pub trait Dial: Send + Sync + 'static {
    fn dial(&self, runner: &str, open: PortOpen) -> Result<DuplexStream, DialError>;
}

/// [`Dial`] over the runner hub: `Hub::dispatch_port`, pumped through an in-memory pipe.
pub struct HubDial(pub Arc<Hub>);

impl Dial for HubDial {
    fn dial(&self, runner: &str, open: PortOpen) -> Result<DuplexStream, DialError> {
        let d = self
            .0
            .dispatch_port(runner, open)
            .map_err(|e| match e.code {
                ErrorCode::Busy => DialError::Busy,
                _ => DialError::Unreachable,
            })?;
        let (ours, theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(pump(d, theirs));
        Ok(ours)
    }
}

/// Moves bytes between the pipe and the port stream. The runner's output is granted back only once
/// written into the pipe, which holds [`PIPE`]: so the runner gets credit as fast as the public
/// client reads, no faster. The Core's own sends stay inside the runner's credit.
// ponytail: a pipe EOF ends the stream both ways (the port stream has no half-close frame).
async fn pump(mut d: Dispatched, io: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(io);
    let mut window = STREAM_WINDOW;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let cap = buf.len().min(usize::try_from(window).unwrap_or(usize::MAX));
        tokio::select! {
            frame = d.next_ungranted() => match frame {
                Some(Frame::Output(Output { data })) => {
                    let Ok(bytes) = STANDARD.decode(data) else { break };
                    if wr.write_all(&bytes).await.is_err() {
                        break;
                    }
                    d.grant_read(bytes.len() as u64);
                }
                Some(Frame::Credit(c)) => window = window.saturating_add(c.bytes),
                // `result` or `error`: the runner ended it. Dropping the pipe ends the HTTP side.
                _ => return,
            },
            n = rd.read(&mut buf[..cap]), if cap > 0 => match n {
                Ok(n) if n > 0 => {
                    window -= n as u64;
                    let data = STANDARD.encode(&buf[..n]);
                    if d.send(Frame::Output(Output { data })).is_err() {
                        break;
                    }
                }
                _ => break,
            },
        }
    }
    let _ = d.send(Frame::Close(Default::default()));
}
