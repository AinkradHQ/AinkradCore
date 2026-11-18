//! Serving a mirror: `git upload-pack` for smart HTTP (see the parent's security model). Every
//! request first takes one of a few slots (before anything is inflated or spawned), and every
//! stream has a total time limit after which its process group is killed.

use std::process::Stdio;
use std::time::Duration;

use axum::body::{Body, Bytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::{Group, Mirrors, REQUEST_MAX, ServeError, protocol_of, scrub};

/// The longest one pack stream may take, however slowly it is read.
const STREAM_LIMIT: Duration = Duration::from_secs(30 * 60);

impl Mirrors {
    async fn slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ServeError> {
        (self.serving.clone().acquire_owned().await).map_err(|_| ServeError::Bad("closed"))
    }

    /// The reference advertisement of `git upload-pack` for smart HTTP. `protocol` is the
    /// client's `Git-Protocol` header (`version=2`), passed on only if it is that plain.
    pub async fn advertise(
        &self,
        repo: i64,
        key: &str,
        protocol: Option<&str>,
    ) -> Result<Vec<u8>, ServeError> {
        let dir = self.ready(repo, key)?;
        let _slot = self.slot().await?;
        let mut cmd = self.command(
            &[
                "upload-pack",
                "--stateless-rpc",
                "--advertise-refs",
                "--timeout=30",
                &dir,
            ],
            None,
        );
        let v2 = protocol_of(protocol).is_some_and(|p| p == "version=2");
        if let Some(p) = protocol_of(protocol) {
            cmd.env("GIT_PROTOCOL", p);
        }
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let mut group = Group::new(
            child
                .id()
                .ok_or_else(|| ServeError::Failed("no pid".into()))?,
        );
        let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let io = async {
            tokio::join!(
                async {
                    if let Some(o) = out.as_mut() {
                        o.take(16 << 20).read_to_end(&mut a).await.ok();
                    }
                },
                async {
                    if let Some(e) = err.as_mut() {
                        e.take(1 << 16).read_to_end(&mut b).await.ok();
                    }
                },
            );
        };
        let done = tokio::time::timeout(Duration::from_secs(30), io)
            .await
            .is_ok();
        // Before the wait, while the group id is still ours.
        group.kill();
        let waited = child.wait().await;
        group.reaped();
        let ok = done && waited.is_ok_and(|s| s.success());
        match ok {
            true => {
                // Version 2 has no service line; version 0 and 1 have one and a flush.
                let mut body = if v2 {
                    vec![]
                } else {
                    b"001e# service=git-upload-pack\n0000".to_vec()
                };
                body.extend(a);
                Ok(body)
            }
            false => Err(ServeError::Failed(scrub(
                &String::from_utf8_lossy(&b),
                None,
            ))),
        }
    }

    /// `git upload-pack` answering one request: its output as it is made. `gzip` says the
    /// request is gzip-compressed, as git sends a large one.
    pub async fn upload_pack(
        &self,
        repo: i64,
        key: &str,
        protocol: Option<&str>,
        request: &[u8],
        gzip: bool,
    ) -> Result<Body, ServeError> {
        let dir = self.ready(repo, key)?;
        let permit = self.slot().await?;
        let request = match gzip {
            true => self.gunzip(request).await?,
            false => request.to_vec(),
        };
        let mut cmd = self.command(
            &["upload-pack", "--stateless-rpc", "--timeout=60", &dir],
            None,
        );
        if let Some(p) = protocol_of(protocol) {
            cmd.env("GIT_PROTOCOL", p);
        }
        // Nobody reads its stderr: a full pipe would stall it.
        cmd.stdin(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let group = Group::with_deadline(
            child
                .id()
                .ok_or_else(|| ServeError::Failed("no pid".into()))?,
            STREAM_LIMIT,
        );
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
            return Err(ServeError::Failed("no pipes".into()));
        };
        tokio::spawn(async move {
            let _ = stdin.write_all(&request).await;
        });
        // The child, its group (with the time limit) and the slot live as long as the stream.
        let stream = futures_util::stream::unfold(
            (stdout, group, child, permit),
            |(mut out, mut group, mut child, permit)| async move {
                let mut buf = vec![0; 64 << 10];
                match out.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        Some((
                            Ok::<_, std::io::Error>(Bytes::from(buf)),
                            (out, group, child, permit),
                        ))
                    }
                    _ => {
                        group.kill();
                        let _ = child.wait().await;
                        group.reaped();
                        None
                    }
                }
            },
        );
        Ok(Body::from_stream(stream))
    }

    /// `request` decompressed, within `REQUEST_MAX`, by the system `gzip`.
    async fn gunzip(&self, request: &[u8]) -> Result<Vec<u8>, ServeError> {
        let mut cmd = Command::new("gzip");
        cmd.arg("-dc")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
            return Err(ServeError::Failed("no pipes".into()));
        };
        let input = request.to_vec();
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
        });
        let mut out = Vec::new();
        stdout
            .take(REQUEST_MAX as u64 + 1)
            .read_to_end(&mut out)
            .await
            .map_err(|e| ServeError::Failed(e.to_string()))?;
        match out.len() <= REQUEST_MAX && child.wait().await.is_ok_and(|s| s.success()) {
            true => Ok(out),
            false => Err(ServeError::Bad(
                "the request is not valid gzip or is too large",
            )),
        }
    }
}
