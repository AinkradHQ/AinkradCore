//! SFTP on the `ssh` driver (Leyline Y2-03, plan T5): `ssh.sftp.*` over `russh-sftp`, on the pooled,
//! host-key-checked connection `ssh.exec` uses (same pins, leases, chain and capacity).
//!
//! - **Paths are data.** They go into SFTP packets as given; there is no shell to read them, so
//!   `../x`, a newline or a leading `-` are only names. Only an empty path, a NUL or one over
//!   `SFTP_MAX_PATH` is refused. (What `..` means is the host's SFTP server's business.)
//! - **No symlink is followed unasked.** `stat` is `lstat` unless `follow`; `remove` removes a link,
//!   never its target.
//! - **Bounded.** One transfer moves at most `SFTP_MAX_BYTES`; a listing answers at most
//!   `SFTP_MAX_ENTRIES`; a transfer waiting on the Core for `IDLE_WAIT` ends; bytes ride the
//!   terminal's `output`/`credit` framing, so a slow Core slows the transfer, not the runner's memory.
//! - **A write leaves no partial file.** The bytes go to `.<name>.part-<random>` beside the target,
//!   created `EXCLUDE`, and are renamed over it only after `eof` and a matching size. Cancel, error,
//!   timeout or a dropped stream remove it (best effort: a lost connection cannot).
//! - **What the host says is data**: errors carry fixed texts and the status code, never the
//!   host's message; entry names are returned as given.

use std::future::Future;
use std::io::SeekFrom;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Command, Control, Credit, ErrorCode, MAX_SSH_HOPS, OP_SFTP_LIST, OP_SFTP_MKDIR,
    OP_SFTP_READ, OP_SFTP_REMOVE, OP_SFTP_RENAME, OP_SFTP_STAT, OP_SFTP_WRITE, Output, Reply,
    SFTP_MAX_ENTRIES, SFTP_MAX_PATH, STREAM_WINDOW, SftpDone, SftpEntries, SftpEntry, SftpKind,
    SftpRead, SftpTransferred, SftpWrite, SshRoute, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;

use super::pool::InUse;
use super::{CONNECT_TIMEOUT, SshDriver, cancelled, check_hop, fail, invalid};

/// What `info()` lists beside `ssh.exec`.
pub(super) const OPS: [&str; 7] = [
    OP_SFTP_LIST,
    OP_SFTP_STAT,
    OP_SFTP_READ,
    OP_SFTP_WRITE,
    OP_SFTP_MKDIR,
    OP_SFTP_RENAME,
    OP_SFTP_REMOVE,
];

/// Bytes per `output` frame and per SFTP read.
const CHUNK: usize = 32 * 1024;
/// A transfer that hears nothing from the Core for this long ends (a slot and a channel are held).
const IDLE_WAIT: Duration = Duration::from_secs(300);
/// A list, stat, mkdir, rename or remove, from start to answer.
const UNARY_TIMEOUT: Duration = Duration::from_secs(120);
/// Best-effort removal of a write's temporary file.
const CLEANUP: Duration = Duration::from_secs(10);

fn sftp_err(e: SftpError) -> StreamError {
    let (code, why) = match e {
        SftpError::Status(s) => (
            match s.status_code {
                StatusCode::NoSuchFile => ErrorCode::SftpNotFound,
                StatusCode::PermissionDenied => ErrorCode::SftpDenied,
                _ => ErrorCode::SftpFailed,
            },
            format!("sftp: {}", s.status_code),
        ),
        SftpError::Timeout => (ErrorCode::SftpFailed, "sftp: timed out".to_owned()),
        _ => (ErrorCode::SftpFailed, "sftp: the session failed".to_owned()),
    };
    fail(code, why)
}

fn io_err(_: std::io::Error) -> StreamError {
    fail(ErrorCode::SftpFailed, "sftp: the transfer failed")
}

fn path_ok(p: &str) -> Result<(), StreamError> {
    match p.is_empty() || p.len() > SFTP_MAX_PATH || p.contains('\0') {
        true => Err(invalid("a path is empty, too long, or has a NUL")),
        false => Ok(()),
    }
}

fn entry(name: String, a: &FileAttributes) -> SftpEntry {
    let kind = match a.permissions.map(|m| m & 0o170_000) {
        Some(0o040_000) => SftpKind::Dir,
        Some(0o100_000) => SftpKind::File,
        Some(0o120_000) => SftpKind::Symlink,
        _ => SftpKind::Other,
    };
    SftpEntry {
        name,
        kind,
        size: a.size,
        mode: a.permissions.map(|m| m & 0o7777),
        mtime: a.mtime.map(u64::from),
        uid: a.uid,
        gid: a.gid,
    }
}

/// Runs `f`, or stops with `cancelled` if `cancel` fires or is dropped.
async fn or_cancel<T>(
    cancel: &mut oneshot::Receiver<()>,
    f: impl Future<Output = Result<T, StreamError>>,
) -> Result<T, StreamError> {
    tokio::select! {
        r = f => r,
        _ = cancel => Err(cancelled()),
    }
}

/// The next frame from the Core on a transfer stream: cancelled when the stream or the op is
/// gone, `sftp_failed` after `IDLE_WAIT` of silence.
async fn next_frame(
    inbox: &mut UnboundedReceiver<Body>,
    cancel: &mut oneshot::Receiver<()>,
) -> Result<Body, StreamError> {
    let wait = tokio::time::timeout(IDLE_WAIT, inbox.recv());
    match or_cancel(cancel, async {
        wait.await.map_err(|_| {
            fail(
                ErrorCode::SftpFailed,
                "the Core went quiet during the transfer",
            )
        })
    })
    .await?
    {
        Some(b) => Ok(b),
        None => Err(cancelled()),
    }
}

impl SshDriver {
    /// A pooled connection for `route` with an SFTP session on a new channel. Hold the `InUse` for
    /// as long as the session is used.
    async fn sftp_open(
        &self,
        route: &SshRoute,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Result<(InUse, SftpSession), StreamError> {
        if route.hops.len() > MAX_SSH_HOPS {
            return Err(invalid("at most 3 jump hosts"));
        }
        for hop in route.hops.iter().chain([&route.target]) {
            check_hop(hop)?;
        }
        let setup = async {
            let conn = self.connect(&route.target, &route.hops).await?;
            let failed = |m: &str| fail(ErrorCode::SshFailed, m.to_owned());
            let ch = (conn.0.handle.channel_open_session().await)
                .map_err(|_| failed("cannot open a channel"))?;
            (ch.request_subsystem(true, "sftp").await)
                .map_err(|_| fail(ErrorCode::SftpFailed, "the host has no sftp subsystem"))?;
            let sftp = SftpSession::new(ch.into_stream()).await.map_err(sftp_err)?;
            Ok((conn, sftp))
        };
        or_cancel(cancel, async {
            tokio::time::timeout(CONNECT_TIMEOUT, setup)
                .await
                .map_err(|_| fail(ErrorCode::SshFailed, "timed out connecting"))?
        })
        .await
    }

    /// `ssh.sftp.list`, `stat`, `mkdir`, `rename` and `remove`: one request, one answer.
    pub async fn sftp_unary(
        &self,
        command: &Command,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<Reply, StreamError> {
        let (route, paths): (&SshRoute, Vec<&str>) = match command {
            Command::SshSftpList(r) => (&r.route, vec![&r.path]),
            Command::SshSftpStat(r) => (&r.route, vec![&r.path]),
            Command::SshSftpMkdir(r) => (&r.route, vec![&r.path]),
            Command::SshSftpRename(r) => (&r.route, vec![&r.from, &r.to]),
            Command::SshSftpRemove(r) => (&r.route, vec![&r.path]),
            _ => return Err(invalid("not an sftp request")),
        };
        paths.into_iter().try_for_each(path_ok)?;
        let (_conn, sftp) = self.sftp_open(route, &mut cancel).await?;
        let run = tokio::time::timeout(UNARY_TIMEOUT, Self::unary(&sftp, command));
        let out = or_cancel(&mut cancel, async {
            run.await
                .map_err(|_| fail(ErrorCode::SftpFailed, "sftp: timed out"))?
        })
        .await;
        let _ = sftp.close().await;
        out
    }

    async fn unary(sftp: &SftpSession, command: &Command) -> Result<Reply, StreamError> {
        Ok(match command {
            Command::SshSftpList(r) => {
                let dir = sftp.read_dir(&r.path).await.map_err(sftp_err)?;
                let mut entries: Vec<_> =
                    dir.map(|e| entry(e.file_name(), &e.metadata())).collect();
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                let truncated = entries.len() > SFTP_MAX_ENTRIES;
                entries.truncate(SFTP_MAX_ENTRIES);
                Reply::SshSftpList(SftpEntries { entries, truncated })
            }
            Command::SshSftpStat(r) => {
                let attrs = match r.follow {
                    true => sftp.metadata(&r.path).await,
                    false => sftp.symlink_metadata(&r.path).await,
                };
                Reply::SshSftpStat(entry(r.path.clone(), &attrs.map_err(sftp_err)?))
            }
            Command::SshSftpMkdir(r) => {
                if let Err(e) = sftp.create_dir(&r.path).await {
                    return Err(match taken(sftp, &r.path).await {
                        true => exists(),
                        false => sftp_err(e),
                    });
                }
                Reply::SshSftpMkdir(SftpDone {})
            }
            Command::SshSftpRename(r) => {
                // SFTP v3 has no "fail if it exists" rename everywhere: ask first (a race is the host's).
                if taken(sftp, &r.to).await {
                    return Err(exists());
                }
                sftp.rename(&r.from, &r.to).await.map_err(sftp_err)?;
                Reply::SshSftpRename(SftpDone {})
            }
            Command::SshSftpRemove(r) => {
                match r.dir {
                    true => sftp.remove_dir(&r.path).await,
                    false => sftp.remove_file(&r.path).await,
                }
                .map_err(sftp_err)?;
                Reply::SshSftpRemove(SftpDone {})
            }
            _ => return Err(invalid("not an sftp request")),
        })
    }

    /// `ssh.sftp.read`: the file as `output` frames through `send`, within the Core's credit.
    pub async fn sftp_read(
        &self,
        req: &SftpRead,
        send: impl Fn(Body),
        mut inbox: UnboundedReceiver<Body>,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<SftpTransferred, StreamError> {
        path_ok(&req.path)?;
        let (_conn, sftp) = self.sftp_open(&req.route, &mut cancel).await?;
        let out = Self::read_file(&sftp, self.cap, req, &send, &mut inbox, &mut cancel).await;
        let _ = sftp.close().await;
        out
    }

    async fn read_file(
        sftp: &SftpSession,
        cap: u64,
        req: &SftpRead,
        send: &impl Fn(Body),
        inbox: &mut UnboundedReceiver<Body>,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Result<SftpTransferred, StreamError> {
        let mut file = or_cancel(cancel, async {
            sftp.open(&req.path).await.map_err(sftp_err)
        })
        .await?;
        let meta = file.metadata().await.map_err(sftp_err)?;
        if meta.permissions.is_some_and(|m| m & 0o170_000 != 0o100_000) {
            return Err(fail(ErrorCode::SftpFailed, "sftp: not a regular file"));
        }
        if meta
            .size
            .is_some_and(|s| s.saturating_sub(req.offset) > cap)
        {
            return Err(too_large());
        }
        if req.offset > 0 {
            file.seek(SeekFrom::Start(req.offset))
                .await
                .map_err(io_err)?;
        }
        let (mut credit, mut total, mut buf) = (STREAM_WINDOW, 0u64, vec![0u8; CHUNK]);
        loop {
            while let Ok(b) = inbox.try_recv() {
                if let Body::Credit(c) = b {
                    credit = credit.saturating_add(c.bytes);
                }
            }
            if credit == 0 {
                if let Body::Credit(c) = next_frame(inbox, cancel).await? {
                    credit = c.bytes;
                }
                continue;
            }
            let want = usize::try_from(credit).unwrap_or(CHUNK).min(CHUNK);
            let got = or_cancel(cancel, async {
                file.read(&mut buf[..want]).await.map_err(io_err)
            })
            .await?;
            if got == 0 {
                break;
            }
            total += got as u64;
            if total > cap {
                return Err(too_large());
            }
            credit -= got as u64;
            send(Body::Output(Output {
                data: STANDARD.encode(&buf[..got]),
            }));
        }
        let _ = file.close().await;
        Ok(SftpTransferred { bytes: total })
    }

    /// `ssh.sftp.write`: the Core's `output` frames into a temporary file, renamed over the target
    /// after `eof`. `send` carries the credit the runner grants back.
    pub async fn sftp_write(
        &self,
        req: &SftpWrite,
        send: impl Fn(Body),
        mut inbox: UnboundedReceiver<Body>,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<SftpTransferred, StreamError> {
        path_ok(&req.path)?;
        let (dir, name) = match req.path.rfind('/') {
            Some(i) => req.path.split_at(i + 1),
            None => ("", req.path.as_str()),
        };
        if name.is_empty() {
            return Err(invalid("a file path does not end in /"));
        }
        if req.size.is_some_and(|s| s > self.cap) {
            return Err(too_large());
        }
        let (_conn, sftp) = self.sftp_open(&req.route, &mut cancel).await?;
        let id: String = (super::super::key::random::<8>().iter())
            .map(|b| format!("{b:02x}"))
            .collect();
        let tmp = format!("{dir}.{name}.part-{id}");
        let out =
            Self::write_file(&sftp, self.cap, req, &tmp, &send, &mut inbox, &mut cancel).await;
        if out.is_err() {
            let _ = tokio::time::timeout(CLEANUP, sftp.remove_file(&tmp)).await;
        }
        let _ = sftp.close().await;
        out
    }

    async fn write_file(
        sftp: &SftpSession,
        cap: u64,
        req: &SftpWrite,
        tmp: &str,
        send: &impl Fn(Body),
        inbox: &mut UnboundedReceiver<Body>,
        cancel: &mut oneshot::Receiver<()>,
    ) -> Result<SftpTransferred, StreamError> {
        if !req.overwrite && sftp.symlink_metadata(&req.path).await.is_ok() {
            return Err(exists());
        }
        let flags = OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE;
        let mut file = or_cancel(cancel, async {
            sftp.open_with_flags(tmp, flags).await.map_err(sftp_err)
        })
        .await?;
        // Before the first byte: a file meant for its owner alone is never readable by others.
        if let Some(mode) = req.mode {
            let attrs = FileAttributes {
                permissions: Some(mode & 0o7777),
                ..FileAttributes::default()
            };
            or_cancel(cancel, async {
                file.set_metadata(attrs).await.map_err(sftp_err)
            })
            .await?;
        }
        // The sender may send one window before any grant; each write hands its bytes back.
        let (mut allowed, mut owed, mut total) = (STREAM_WINDOW, 0u64, 0u64);
        loop {
            match next_frame(inbox, cancel).await? {
                Body::Output(Output { data }) => {
                    let bytes = (STANDARD.decode(data))
                        .map_err(|_| invalid("a write frame is not base64"))?;
                    let n = bytes.len() as u64;
                    if n > allowed {
                        return Err(invalid("more bytes than the credit granted"));
                    }
                    total += n;
                    if total > cap {
                        return Err(too_large());
                    }
                    or_cancel(cancel, async {
                        file.write_all(&bytes).await.map_err(io_err)
                    })
                    .await?;
                    allowed -= n;
                    owed += n;
                    // Grants in steps, not per frame: each is a frame the runner holds for a resume.
                    if owed >= CHUNK as u64 {
                        send(Body::Credit(Credit { bytes: owed }));
                        (allowed, owed) = (allowed + owed, 0);
                    }
                }
                Body::Control(Control::Eof) => break,
                _ => {}
            }
        }
        or_cancel(cancel, async { file.shutdown().await.map_err(io_err) }).await?;
        if req.size.is_some_and(|s| s != total) {
            return Err(fail(
                ErrorCode::SftpFailed,
                "sftp: fewer or more bytes than declared",
            ));
        }
        // ponytail: replacing is remove then rename (SFTP v3 renames do not replace), so a crash
        // between them leaves the data in the part file; the posix-rename extension if it matters.
        if sftp.symlink_metadata(&req.path).await.is_ok() {
            or_cancel(cancel, async {
                sftp.remove_file(&req.path).await.map_err(sftp_err)
            })
            .await?;
        }
        or_cancel(cancel, async {
            sftp.rename(tmp, &req.path).await.map_err(sftp_err)
        })
        .await?;
        Ok(SftpTransferred { bytes: total })
    }
}

/// Something (even a dangling link) is at `path`.
async fn taken(sftp: &SftpSession, path: &str) -> bool {
    sftp.symlink_metadata(path).await.is_ok()
}

fn exists() -> StreamError {
    fail(ErrorCode::SftpExists, "sftp: the path is taken")
}

fn too_large() -> StreamError {
    fail(ErrorCode::TooLarge, "a transfer is capped at 2 GiB")
}
