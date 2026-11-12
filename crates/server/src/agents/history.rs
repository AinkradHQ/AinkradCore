//! A runner's harness history for a module (E5-3): the one fixed `history.read` op, sent only to
//! a runner that listed `history-read`, which it does only when its user switched it on. The
//! module names the harness and a cursor; it names no path, program or argument, and the runner
//! reads only its own harness's session files.

use ainkrad_proto::v2::{Body, CAP_HISTORY_READ, ErrorCode, HistoryChunk, HistoryRead, Reply};

use super::*;

/// A read, runner side, is bounded to its size cap; the Core waits a little longer.
const WAIT: Duration = Duration::from_secs(60);

/// Why a history was not read: a plain code (`not_offered`, `busy`, `outdated`, `failed`).
#[derive(Debug, PartialEq, Eq)]
pub struct HistoryError(pub &'static str);

/// Asks `runner` for the new entries of its harness history after `req.cursor`.
pub async fn read_history(
    app: &App,
    runner: &str,
    req: HistoryRead,
) -> Result<HistoryChunk, HistoryError> {
    let offered = app.hub.runners().get(runner).is_some_and(|r| {
        r.online
            && r.drivers
                .iter()
                .any(|d| d.commands.iter().any(|c| c == CAP_HISTORY_READ))
    });
    if !offered {
        return Err(HistoryError("not_offered"));
    }
    let sent = app
        .hub
        .dispatch_history_read(runner, req)
        .map_err(|_| HistoryError("failed"))?;
    match tokio::time::timeout(WAIT, sent.outcome()).await {
        Ok(Ok(Body::Result(Reply::HistoryRead(c)))) => Ok(c),
        Ok(Err(e)) if e.code == ErrorCode::Busy => Err(HistoryError("busy")),
        Ok(Err(e)) if e.code == ErrorCode::UnsupportedCommand => Err(HistoryError("outdated")),
        _ => Err(HistoryError("failed")),
    }
}
