//! The idle deadline: a connection that moves no bytes either way for `Limits::idle` is
//! closed. hyper's header-read deadline only starts at a request's first byte, so without
//! this a client that connects and stays silent, or idles between keep-alive requests, would
//! hold its connection forever. An upgraded connection (a WebSocket) leaves hyper, and this,
//! behind: the event stream keeps its own pings.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// A stream that records when it last moved a byte.
pub struct Idle<I> {
    io: I,
    since: Instant,
    /// Milliseconds after `since` of the last byte read or written.
    last: Arc<AtomicU64>,
}

/// When the stream last moved, as a clock shared with the watchdog.
#[derive(Clone)]
pub struct Activity {
    since: Instant,
    last: Arc<AtomicU64>,
}

impl Activity {
    /// When the connection goes idle unless it moves before then.
    pub fn deadline(&self, idle: Duration) -> Instant {
        self.since + Duration::from_millis(self.last.load(Ordering::Relaxed)) + idle
    }
}

pub fn wrap<I>(io: I) -> (Idle<I>, Activity) {
    let (since, last) = (Instant::now(), Arc::new(AtomicU64::new(0)));
    let activity = Activity {
        since,
        last: Arc::clone(&last),
    };
    (Idle { io, since, last }, activity)
}

impl<I> Idle<I> {
    fn touch(&self) {
        let ms = u64::try_from(self.since.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(ms, Ordering::Relaxed);
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Idle<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.touch();
        }
        polled
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Idle<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.io).poll_write(cx, data);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
