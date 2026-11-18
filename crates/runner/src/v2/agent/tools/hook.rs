//! `ainkrad-hook checkpoint <socket>`: the command of a harness's checkpoint hook (Brain B8-04,
//! agy `Stop`, Codex `PreCompact` and `SessionEnd`). It asks the Core, over the session's own
//! tools socket, to distil this session's new turns now (`brainAiCheckpoint`).
//!
//! Fail-open by construction: an explicit deadline, stdout and stderr stay empty, the exit code is
//! always 0, whatever happens (no socket, no such tool, a refusal, a Core that is down). The
//! hook's stdin is ignored: the Core knows the session from the socket, nothing from the harness's
//! payload is trusted or sent. The authority is the socket (the session is the socket); no
//! credential is in the command or the request.

use std::process::ExitCode;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

/// The whole hook, socket to reply. Below the 2 s the harnesses' hook entries allow (a Codex
/// `SessionEnd` hook has 3 s at most).
pub const DEADLINE: Duration = Duration::from_millis(1500);

/// The most of the reply that is read (it is discarded).
const REPLY_MAX: u64 = 64 * 1024;

/// The one request line.
fn request() -> Vec<u8> {
    let call = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "brainAiCheckpoint", "arguments": {}}});
    let mut line = call.to_string().into_bytes();
    line.push(b'\n');
    line
}

/// Sends the request and waits for the answer (a connection that closes first drops the call
/// still in flight, so the answer is waited for), all within `deadline`. Prints nothing.
pub async fn checkpoint(sock: &str, deadline: Duration) {
    let _ = timeout(deadline, async {
        let mut stream = UnixStream::connect(sock).await?;
        stream.write_all(&request()).await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.take(REPLY_MAX).read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(())
    })
    .await;
}

pub async fn checkpoint_main(sock: &str) -> ExitCode {
    checkpoint(sock, DEADLINE).await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    use super::*;

    fn sock(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("hook-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("t.sock").to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn it_calls_the_checkpoint_op_once_and_waits_for_the_answer() {
        let path = sock("call");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n")
                .await
                .unwrap();
            line
        });
        checkpoint(&path, DEADLINE).await;
        let got: serde_json::Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(got["method"], "tools/call");
        assert_eq!(got["params"]["name"], "brainAiCheckpoint");
        assert_eq!(got["params"]["arguments"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn no_socket_or_a_silent_core_ends_within_the_deadline_without_error() {
        checkpoint("/nonexistent/tools.sock", DEADLINE).await;
        // A Core that accepts and never answers: the hook gives up at its deadline.
        let path = sock("silent");
        let listener = UnixListener::bind(&path).unwrap();
        let _hold = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let at = Instant::now();
        checkpoint(&path, Duration::from_millis(200)).await;
        assert!(at.elapsed() < Duration::from_secs(2));
    }
}
