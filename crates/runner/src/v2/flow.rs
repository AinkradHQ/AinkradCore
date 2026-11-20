//! One credited byte stream between a long command and the Core (E15-4: `job.run` output and the
//! `sync.*` chunk frames). The Core grants credit as it reads; the runner sends `output` frames only
//! within it, and grants credit back for the `output` frames it receives. A `signal` control frame
//! and the Core's `close` (the cancel) are surfaced to the command that owns the stream.

use std::collections::VecDeque;

use ainkrad_proto::v2::{Body, Control, Credit, Output};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::{mpsc, oneshot};

/// Where a command's frames go: the session's `done` channel, which numbers and sends them.
pub type Out = mpsc::UnboundedSender<(u64, Body)>;

/// Why a stream ended under a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The Core sent `close`.
    Cancelled,
    /// The stream was forgotten (a Core restart, a lost stream).
    Dropped,
}

pub enum Event {
    Signal(String),
    Stop(Stop),
}

pub struct Flow {
    stream: u64,
    out: Out,
    inbox: mpsc::UnboundedReceiver<Body>,
    cancel: oneshot::Receiver<()>,
    /// What the Core will still take.
    credit: u64,
    signals: VecDeque<String>,
    stopped: Option<Stop>,
}

impl Flow {
    /// `window`: the credit the Core starts the stream with (`STREAM_WINDOW`, or
    /// `SYNC_STREAM_WINDOW` on a `sync.*` stream).
    pub fn new(
        stream: u64,
        out: Out,
        inbox: mpsc::UnboundedReceiver<Body>,
        cancel: oneshot::Receiver<()>,
        window: u64,
    ) -> Self {
        Self {
            stream,
            out,
            inbox,
            cancel,
            credit: window,
            signals: VecDeque::new(),
            stopped: None,
        }
    }

    /// Sends a frame that is not output (a control frame).
    pub fn send(&self, body: Body) {
        let _ = self.out.send((self.stream, body));
    }

    /// Waits for one inbound frame, applying it; `Some` when it is output (decoded).
    async fn step(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        if let Some(s) = self.stopped {
            return Err(s);
        }
        let got = tokio::select! {
            r = &mut self.cancel => { let _ = r; self.stopped = Some(Stop::Cancelled); return Err(Stop::Cancelled); }
            b = self.inbox.recv() => b,
        };
        match got {
            None => {
                self.stopped = Some(Stop::Dropped);
                Err(Stop::Dropped)
            }
            Some(Body::Credit(c)) => {
                self.credit = self.credit.saturating_add(c.bytes);
                Ok(None)
            }
            Some(Body::Control(Control::Signal(s))) => {
                self.signals.push_back(s.signal);
                Ok(None)
            }
            Some(Body::Output(Output { data })) => match STANDARD.decode(data) {
                Ok(bytes) => {
                    // Read: the sender may send that much more.
                    self.send(Body::Credit(Credit {
                        bytes: bytes.len() as u64,
                    }));
                    Ok(Some(bytes))
                }
                Err(_) => Ok(None),
            },
            Some(_) => Ok(None),
        }
    }

    /// Sends `data` as `output` frames of at most `frame` bytes each, waiting for credit.
    pub async fn write(&mut self, data: &[u8], frame: usize) -> Result<(), Stop> {
        for part in data.chunks(frame.max(1)) {
            while self.credit < part.len() as u64 {
                self.step().await?;
            }
            self.credit -= part.len() as u64;
            self.send(Body::Output(Output {
                data: STANDARD.encode(part),
            }));
        }
        Ok(())
    }

    /// The next `output` frame's bytes from the Core.
    pub async fn read(&mut self) -> Result<Vec<u8>, Stop> {
        loop {
            if let Some(bytes) = self.step().await? {
                return Ok(bytes);
            }
        }
    }

    /// The next signal or stop, absorbing credit meanwhile.
    pub async fn event(&mut self) -> Event {
        loop {
            if let Some(s) = self.signals.pop_front() {
                return Event::Signal(s);
            }
            if let Err(stop) = self.step().await {
                return Event::Stop(stop);
            }
        }
    }

    /// A signal already received, if any (without waiting).
    pub fn take_signal(&mut self) -> Option<String> {
        self.signals.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainkrad_proto::v2::SignalReq;

    type Rig = (
        Flow,
        mpsc::UnboundedReceiver<(u64, Body)>,
        mpsc::UnboundedSender<Body>,
        oneshot::Sender<()>,
    );

    fn flow(window: u64) -> Rig {
        let (out, out_rx) = mpsc::unbounded_channel();
        let (in_tx, inbox) = mpsc::unbounded_channel();
        let (cancel_tx, cancel) = oneshot::channel();
        (
            Flow::new(7, out, inbox, cancel, window),
            out_rx,
            in_tx,
            cancel_tx,
        )
    }

    #[tokio::test]
    async fn output_waits_for_credit_and_goes_in_frames() {
        let (mut f, mut out, inbox, _c) = flow(4);
        let task = tokio::spawn(async move {
            f.write(b"abcdefgh", 3).await.unwrap();
            f
        });
        tokio::task::yield_now().await;
        // 4 bytes of credit: "abc" goes, "def" cannot until more arrives.
        let (s, first) = out.recv().await.unwrap();
        assert_eq!(s, 7);
        assert!(matches!(first, Body::Output(Output { data }) if data == STANDARD.encode(b"abc")));
        inbox.send(Body::Credit(Credit { bytes: 100 })).unwrap();
        let _f = task.await.unwrap();
        let mut got = 0;
        while let Ok((_, Body::Output(o))) = out.try_recv() {
            got += STANDARD.decode(o.data).unwrap().len();
        }
        assert_eq!(got, 5);
    }

    #[tokio::test]
    async fn read_grants_credit_back_and_a_signal_or_close_surfaces() {
        let (mut f, mut out, inbox, cancel) = flow(0);
        inbox
            .send(Body::Output(Output {
                data: STANDARD.encode(b"hello"),
            }))
            .unwrap();
        assert_eq!(f.read().await.unwrap(), b"hello");
        assert!(matches!(
            out.recv().await.unwrap().1,
            Body::Credit(Credit { bytes: 5 })
        ));
        inbox
            .send(Body::Control(Control::Signal(SignalReq {
                signal: "TERM".into(),
            })))
            .unwrap();
        assert!(matches!(f.event().await, Event::Signal(s) if s == "TERM"));
        cancel.send(()).unwrap();
        assert!(matches!(f.event().await, Event::Stop(Stop::Cancelled)));
        assert_eq!(f.read().await, Err(Stop::Cancelled));
    }
}
