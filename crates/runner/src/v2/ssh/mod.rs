//! The `ssh` driver (Leyline Y2-01, plan T1-T4, T10): `ssh.exec` runs one command on a remote host over
//! `russh`, for the Core, under `exec.run`'s limits (timeout and output caps, redaction, capacity).
//!
//! What an attacker-controlled host or a hostile log reader can and cannot get:
//! - **Host key first.** The presented key is checked against the Core's pinned fingerprints inside the
//!   key exchange. A key that is not pinned ends the connection there: `host_key_unknown` (nothing
//!   pinned yet, so a person may trust it) or `host_key_changed`. No authentication request has been
//!   sent by then, so a man in the middle never sees even a signature.
//! - **Modern algorithms only.** Ed25519 and ECDSA host and user keys; russh's SHA-2 key exchanges,
//!   AEAD/CTR ciphers and SHA-2 MACs. No RSA at all (the `rsa` feature is off: RUSTSEC-2023-0071), so
//!   no `ssh-rsa`/SHA-1; no DSA (the `dsa` feature is off), no CBC, no compression. `kex-strict`
//!   (Terrapin) is on in russh 0.65.1.
//! - **The key.** Redeemed from the lease by this runner, held in `Zeroizing`/`ZeroizeOnDrop` types,
//!   used for one `publickey` authentication and dropped. It is never in argv, env, a file or a log;
//!   errors are fixed texts or russh's own (which carry no key bytes). Gap, stated: russh and
//!   `ssh-key` copy while parsing and signing, and those copies are not ours to wipe.
//! - **Jump hosts.** Each hop is verified and authenticated with its own key and pins; the next hop
//!   is a `direct-tcpip` channel through the previous one, so a hop is only asked to carry traffic
//!   after it passed both checks. At most `MAX_SSH_HOPS` jumps.
//! - **What the host returns** is data: capped, redacted, lossy UTF-8, like `exec.run`'s output.
//! - **Pool.** Every op redeems every lease of its chain, so a connection is reused only by an op that
//!   holds every hop's key (the pool key is the chain's addresses plus each key's fingerprint) and
//!   whose pins still list the key each hop presented. A connection idle 5 minutes is closed by a
//!   sweeper; none is closed under a running command (no russh inactivity timeout).
//! - **Cancel and time.** One deadline (the clamped timeout) covers redeem, dial and run; a cancel
//!   (fired or dropped) at any point stops the op, and the command is never sent after one. On a
//!   timeout or cancel of a running command the runner sends a best-effort `KILL` signal and closes
//!   the channel; sshd may ignore the signal (OpenSSH before 7.9 does), the channel close still ends
//!   the remote session.

use std::borrow::Cow;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    DriverInfo, ErrorCode, ExecResult, FEATURE_PTY_SSH, MAX_SSH_HOPS, OP_EXEC_RUN, OP_SSH_EXEC,
    SshExec, SshHop, StreamError,
};
use russh::client::{self, Handle, Handler};
use russh::keys::{
    Algorithm, EcdsaCurve, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
};
use russh::{ChannelMsg, Preferred, Sig};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::oneshot::{self, error::TryRecvError};
use zeroize::Zeroizing;

use super::agent::secrets::{Form, Redeem};
use super::exec::{ExecDriver, Raw};
use pool::{Conn, InUse, Pool, pool_key};

pub const DRIVER: &str = "ssh";

/// A pooled connection unused this long is closed (plan T8).
const IDLE: Duration = Duration::from_secs(300);
/// Connecting, key exchange and authentication of the whole chain.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Pooled connections kept at once; the least recently used goes first.
pub(super) const POOL_MAX: usize = 32;
const MAX_RUN_BYTES: usize = 64 * 1024;

/// Host-key algorithms offered: no RSA, so no `ssh-rsa` (SHA-1); no DSA.
const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
];

/// `keepalive`: an interactive terminal pings a silent host (and gives up on a dead link); a command
/// is left alone, since its own deadline covers it.
fn config(keepalive: bool) -> Arc<client::Config> {
    Arc::new(client::Config {
        // kex, ciphers, MACs and compression stay russh's defaults (SHA-2, AEAD/CTR, none); a test
        // pins that no SHA-1/CBC/DSA name is in them.
        preferred: Preferred {
            key: Cow::Borrowed(HOST_KEYS),
            ..Preferred::DEFAULT
        },
        // No russh inactivity timeout: it would drop a command that is silent for longer than it,
        // under the exec ceiling. Idle connections are closed by the pool's sweeper.
        inactivity_timeout: None,
        keepalive_interval: keepalive.then_some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..client::Config::default()
    })
}

/// Checks one hop's host key against its pins, and remembers what it saw.
pub(super) struct Verify {
    pinned: Vec<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl Handler for Verify {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Certificates are not offered (`host_key_certificates` is empty); refuse one anyway.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let ok = self.pinned.contains(&fp);
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ok)
    }
}

pub struct SshDriver {
    exec: Arc<ExecDriver>,
    redeem: Redeem,
    /// Keyed by the chain's addresses and every hop key's fingerprint.
    // ponytail: two ops that miss together dial twice and the later one wins; a per-key dial lock
    // if that ever costs.
    pool: Pool,
    idle: Duration,
    /// The runner binary `ssh-pty` terminals start; unset, this process's own executable.
    bin: Option<std::path::PathBuf>,
    /// The most bytes one SFTP transfer moves (`SFTP_MAX_BYTES`; a test lowers it).
    cap: u64,
}

pub(super) fn fail(code: ErrorCode, m: impl Into<String>) -> StreamError {
    StreamError::new(code, m)
}

pub(super) fn invalid(m: &str) -> StreamError {
    fail(ErrorCode::InvalidArgs, m)
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A hostname, IPv4 or IPv6 literal (with a `%zone`): nothing that could read as another field. The
/// same rule as Leyline's `valid::address` (255 bytes, `. : % _ -`); a test pins the two together.
fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 255
        && !h.starts_with('-')
        && (h.bytes()).all(|b| b.is_ascii_alphanumeric() || b".-:_%".contains(&b))
}

/// A portable POSIX user name.
fn user_ok(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && !u.starts_with('-')
        && (u.bytes()).all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(super) fn check_hop(h: &SshHop) -> Result<(), StreamError> {
    if !host_ok(&h.host) || !user_ok(&h.user) || h.port == 0 || !plain(&h.lease, 256) {
        return Err(invalid("a hop needs a host, a port, a user and a lease"));
    }
    if !h
        .pinned_keys
        .iter()
        .all(|p| p.starts_with("SHA256:") && plain(p, 64))
    {
        return Err(invalid("pinned_keys are SHA256:<base64> fingerprints"));
    }
    Ok(())
}

fn host_key_refusal(hop: usize, first_contact: bool, fingerprint: String) -> StreamError {
    let (code, why) = match first_contact {
        true => (
            ErrorCode::HostKeyUnknown,
            "unknown host key; nothing was authenticated",
        ),
        false => (
            ErrorCode::HostKeyChanged,
            "the host key changed; nothing was authenticated",
        ),
    };
    let hop = u8::try_from(hop).unwrap_or(u8::MAX);
    StreamError::new(code, why).with_host_key(hop, fingerprint)
}

impl SshDriver {
    pub fn new(exec: Arc<ExecDriver>, redeem: Redeem) -> Self {
        Self {
            exec,
            redeem,
            pool: Pool::default(),
            idle: IDLE,
            bin: None,
            cap: ainkrad_proto::v2::SFTP_MAX_BYTES,
        }
    }

    /// Tests run inside the test binary: the real `ainkrad-runner` is what `ssh-pty` must start.
    #[cfg(test)]
    pub(in crate::v2) fn with_bin(mut self, bin: std::path::PathBuf) -> Self {
        self.bin = Some(bin);
        self
    }

    #[cfg(test)]
    fn with_cap(mut self, cap: u64) -> Self {
        self.cap = cap;
        self
    }

    #[cfg(test)]
    fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = idle;
        self
    }

    /// Offered only where `exec.run` is (the same decision: the Core may run commands here).
    pub fn info(&self) -> Option<DriverInfo> {
        let e = self.exec.info();
        e.commands
            .iter()
            .any(|c| c == OP_EXEC_RUN)
            .then(|| DriverInfo {
                name: DRIVER.to_owned(),
                commands: std::iter::once(OP_SSH_EXEC)
                    .chain(sftp::OPS)
                    .chain([FEATURE_PTY_SSH])
                    .map(str::to_owned)
                    .collect(),
                capacity: e.capacity,
                ..DriverInfo::default()
            })
    }

    /// A slot for one `ssh.exec`: the same capacity as `exec.run` (`busy` when full).
    pub fn slot(&self) -> Result<OwnedSemaphorePermit, StreamError> {
        self.exec.slot()
    }

    /// Runs `req` to its end, its timeout, or `cancel` (fired or dropped). One deadline covers the
    /// lease redemption, the dial and the command; the command is never sent after a cancel.
    pub async fn run(
        &self,
        req: &SshExec,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<ExecResult, StreamError> {
        if req.hops.len() > MAX_SSH_HOPS {
            return Err(invalid("at most 3 jump hosts"));
        }
        if req.run.is_empty() || req.run.len() > MAX_RUN_BYTES || req.run.contains('\0') {
            return Err(invalid("run is empty, too long, or has a NUL"));
        }
        for hop in req.hops.iter().chain([&req.target]) {
            check_hop(hop)?;
        }
        let (timeout, cap) = self.exec.clamp(&req.limits);
        tracing::debug!(hops = req.hops.len(), "ssh.exec");
        let started = Instant::now();
        let end = tokio::time::Instant::now() + timeout;
        let setup = tokio::time::timeout(CONNECT_TIMEOUT, self.connect(&req.target, &req.hops));
        let conn = tokio::select! {
            c = setup => c.map_err(|_| fail(ErrorCode::SshFailed, "timed out connecting"))??,
            () = tokio::time::sleep_until(end) => {
                return Err(fail(ErrorCode::SshFailed, "timed out before the command started"));
            }
            _ = &mut cancel => return Err(cancelled()),
        };
        let mut result = self.run_on(&conn.0, &req.run, end, cap, cancel).await?;
        result.duration_ms = started.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Every hop's key redeemed (so an op that cannot produce them never rides a pooled
    /// connection), then a pooled connection for exactly those keys, or a fresh one.
    async fn connect(&self, target: &SshHop, hops: &[SshHop]) -> Result<InUse, StreamError> {
        let chain: Vec<&SshHop> = hops.iter().chain([target]).collect();
        let mut keys = Vec::with_capacity(chain.len());
        for hop in &chain {
            keys.push(self.load_key(&hop.lease).await?);
        }
        let name = pool_key(&chain, &keys);
        if let Some(conn) = self.pooled(&name, &chain) {
            return Ok(conn);
        }
        let conn = self.dial(&chain, keys).await?;
        Ok(self.pool_put(name, Arc::new(conn)))
    }

    /// A key from its lease, parsed. Never logged; errors are fixed text.
    async fn load_key(&self, lease: &str) -> Result<PrivateKey, StreamError> {
        let text = self.key_text(lease).await?;
        parse_key(&text).map_err(|m| fail(ErrorCode::SshAuthFailed, m))
    }

    /// The leased key's OpenSSH text. A lease is redeemed once: whoever calls this holds the key.
    /// Delivery (`file` or `env`) is ignored on purpose: the key is only ever in this memory, and is
    /// then handed on over a pipe or used here, never written to a file or an environment.
    async fn key_text(&self, lease: &str) -> Result<Zeroizing<String>, StreamError> {
        let auth = |m: String| fail(ErrorCode::SshAuthFailed, self.exec.redact(&m));
        let leased = (self.redeem)(lease.to_owned())
            .await
            .map_err(|e| auth(format!("cannot redeem the key lease: {e}")))?;
        let bytes = match leased.form {
            // A `file` secret's value is its bytes in base64.
            Form::File { .. } => {
                use base64::Engine;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(leased.value.as_bytes())
                    .map_err(|_| auth("the leased key is not base64".into()))?;
                Zeroizing::new(raw)
            }
            _ => Zeroizing::new(leased.value.as_bytes().to_vec()),
        };
        let text =
            std::str::from_utf8(&bytes).map_err(|_| auth("the leased key is not text".into()))?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Connects hop by hop with each hop's key; each hop's host key is verified before its
    /// authentication.
    async fn dial(&self, chain: &[&SshHop], keys: Vec<PrivateKey>) -> Result<Conn, StreamError> {
        let mut auth = KeyAuth(keys.into());
        dial_chain(chain, config(false), &mut auth, &|m| self.exec.redact(&m)).await
    }

    /// The command on `conn`, to its end, `end`, or `cancel`.
    async fn run_on(
        &self,
        conn: &Conn,
        run: &str,
        end: tokio::time::Instant,
        cap: usize,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<ExecResult, StreamError> {
        let failed = |m: &str| fail(ErrorCode::SshFailed, m.to_owned());
        let mut ch = tokio::select! {
            ch = conn.handle.channel_open_session() => {
                ch.map_err(|_| failed("cannot open a channel"))?
            }
            () = tokio::time::sleep_until(end) => {
                return Err(failed("timed out before the command started"));
            }
            _ = &mut cancel => return Err(cancelled()),
        };
        // Nothing is sent once a cancel has fired or its sender was dropped.
        if !matches!(cancel.try_recv(), Err(TryRecvError::Empty)) {
            let _ = ch.close().await;
            return Err(cancelled());
        }
        ch.exec(true, run.as_bytes().to_vec())
            .await
            .map_err(|_| failed("cannot send the command"))?;
        let (mut out, mut err) = (Raw::new(cap), Raw::new(cap));
        let (mut exit_code, mut timed_out, mut exited) = (None, false, false);
        loop {
            tokio::select! {
                msg = ch.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => out.push(&data),
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => err.push(&data),
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = i32::try_from(exit_status).ok();
                        exited = true;
                    }
                    // Killed by a signal: no exit code, but an end.
                    Some(ChannelMsg::ExitSignal { .. }) => exited = true,
                    Some(ChannelMsg::Failure) => return Err(failed("the host refused the command")),
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                },
                () = tokio::time::sleep_until(end) => {
                    timed_out = true;
                    break;
                }
                _ = &mut cancel => {
                    stop(&ch).await;
                    return Err(cancelled());
                }
            }
        }
        if timed_out {
            stop(&ch).await;
        } else {
            let _ = ch.close().await;
            if !exited {
                // A dropped connection, or a host that ended the channel without saying how.
                return Err(failed("the channel ended before the command's exit status"));
            }
        }
        Ok(ExecResult {
            exit_code: exit_code.filter(|_| !timed_out),
            timed_out,
            duration_ms: 0,
            stdout: self.exec.finish(out),
            stderr: self.exec.finish(err),
        })
    }
}

/// How one hop is authenticated, after its host key was accepted.
trait HopAuth {
    fn authenticate(
        &mut self,
        handle: &mut Handle<Verify>,
        hop: &SshHop,
        index: usize,
    ) -> impl std::future::Future<Output = Result<(), StreamError>> + Send;
}

/// `ssh.exec`: one `publickey` attempt per hop, with that hop's key.
struct KeyAuth(std::collections::VecDeque<PrivateKey>);

impl HopAuth for KeyAuth {
    async fn authenticate(
        &mut self,
        handle: &mut Handle<Verify>,
        hop: &SshHop,
        index: usize,
    ) -> Result<(), StreamError> {
        let key = self
            .0
            .pop_front()
            .ok_or_else(|| fail(ErrorCode::Internal, "a hop without a key"))?;
        publickey(handle, &hop.user, key, index).await
    }
}

/// One `publickey` attempt; `key` is dropped here.
async fn publickey(
    handle: &mut Handle<Verify>,
    user: &str,
    key: PrivateKey,
    hop: usize,
) -> Result<(), StreamError> {
    let denied = |m: &str| fail(ErrorCode::SshAuthFailed, format!("hop {hop}: {m}"));
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    match handle.authenticate_publickey(user, key).await {
        Ok(r) if r.success() => Ok(()),
        Ok(_) => Err(denied("the host refused the key")),
        Err(_) => Err(denied("the connection ended during authentication")),
    }
}

/// An OpenSSH private key, unencrypted. The error is fixed text.
fn parse_key(text: &str) -> Result<PrivateKey, &'static str> {
    russh::keys::decode_secret_key(text, None)
        .map_err(|_| "the leased key is not a usable unencrypted private key")
}

/// Connects hop by hop (each next hop is a `direct-tcpip` channel through the previous one); each
/// hop's host key is verified against its pins before `auth` is asked to authenticate it. `redact`
/// cleans a failure's text.
async fn dial_chain(
    chain: &[&SshHop],
    cfg: Arc<client::Config>,
    auth: &mut impl HopAuth,
    redact: &(dyn Fn(String) -> String + Sync),
) -> Result<Conn, StreamError> {
    let mut handles: Vec<Handle<Verify>> = Vec::new();
    let mut host_keys = Vec::new();
    for (i, hop) in chain.iter().enumerate() {
        let at = |m: String| fail(ErrorCode::SshFailed, redact(format!("hop {i}: {m}")));
        let seen = Arc::new(Mutex::new(None));
        let verify = Verify {
            pinned: hop.pinned_keys.clone(),
            seen: Arc::clone(&seen),
        };
        let connected = match handles.last() {
            None => {
                let tcp = TcpStream::connect((hop.host.as_str(), hop.port))
                    .await
                    .map_err(|e| at(format!("cannot connect: {e}")))?;
                client::connect_stream(Arc::clone(&cfg), tcp, verify).await
            }
            Some(prev) => {
                let ch = prev
                    .channel_open_direct_tcpip(
                        hop.host.clone(),
                        u32::from(hop.port),
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| at(format!("the previous hop cannot reach it: {e}")))?;
                client::connect_stream(Arc::clone(&cfg), ch.into_stream(), verify).await
            }
        };
        let mut handle = match connected {
            Ok(handle) => handle,
            Err(e) => {
                let presented = seen.lock().unwrap().clone();
                return Err(match presented {
                    Some(fp) if !hop.pinned_keys.contains(&fp) => {
                        host_key_refusal(i, hop.pinned_keys.is_empty(), fp)
                    }
                    _ => at(format!("the connection failed: {e}")),
                });
            }
        };
        // Only reachable after `check_server_key` accepted this hop.
        host_keys.extend(seen.lock().unwrap().clone());
        auth.authenticate(&mut handle, hop, i).await?;
        handles.push(handle);
    }
    let handle = handles
        .pop()
        .ok_or_else(|| fail(ErrorCode::Internal, "an empty chain"))?;
    Ok(Conn {
        handle,
        _jumps: handles,
        host_keys,
        used: Mutex::new(Instant::now()),
        busy: AtomicUsize::new(0),
    })
}

pub(super) fn cancelled() -> StreamError {
    fail(ErrorCode::Cancelled, "cancelled")
}

/// Best effort: ask the remote command to die, then close the channel. sshd may ignore the signal
/// (OpenSSH before 7.9); the close still ends the session on the host's side.
async fn stop(ch: &russh::Channel<client::Msg>) {
    let _ = ch.signal(Sig::KILL).await;
    let _ = ch.close().await;
}

#[cfg(test)]
pub(in crate::v2) mod fixture;
mod pool;
pub mod pty;
#[cfg(test)]
pub(in crate::v2) mod pty_tests;
#[cfg(test)]
mod safety_tests;
mod sftp;
#[cfg(test)]
mod sftp_fixture;
#[cfg(test)]
mod sftp_tests;
#[cfg(test)]
mod tests;
