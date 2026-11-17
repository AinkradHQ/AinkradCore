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
//! - **Pool.** A connection is reused only by an op that redeemed the same target key (the pool key
//!   holds its fingerprint) and whose pins still list every hop's key. Unused 5 minutes: closed.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    DriverInfo, ErrorCode, ExecResult, MAX_SSH_HOPS, OP_EXEC_RUN, OP_SSH_EXEC, SshExec, SshHop,
    StreamError,
};
use russh::client::{self, Handle, Handler};
use russh::keys::{
    Algorithm, EcdsaCurve, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
};
use russh::{ChannelMsg, Preferred};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use zeroize::Zeroizing;

use super::agent::secrets::{Form, Redeem};
use super::exec::{ExecDriver, Raw};

pub const DRIVER: &str = "ssh";

/// A pooled connection unused this long is closed (plan T8).
const IDLE: Duration = Duration::from_secs(300);
/// Connecting, key exchange and authentication of the whole chain.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Pooled connections kept at once; the least recently used goes first.
const POOL_MAX: usize = 32;
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

fn config(idle: Duration) -> Arc<client::Config> {
    Arc::new(client::Config {
        // kex, ciphers, MACs and compression stay russh's defaults (SHA-2, AEAD/CTR, none); a test
        // pins that no SHA-1/CBC/DSA name is in them.
        preferred: Preferred {
            key: Cow::Borrowed(HOST_KEYS),
            ..Preferred::DEFAULT
        },
        inactivity_timeout: Some(idle),
        ..client::Config::default()
    })
}

/// Checks one hop's host key against its pins, and remembers what it saw.
struct Verify {
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

/// A verified, authenticated chain. `_jumps` stay open for as long as `handle` runs over them.
struct Conn {
    handle: Handle<Verify>,
    _jumps: Vec<Handle<Verify>>,
    /// The host key each hop presented, in chain order: re-checked against the pins on every use.
    host_keys: Vec<String>,
    used: Mutex<Instant>,
}

pub struct SshDriver {
    exec: Arc<ExecDriver>,
    redeem: Redeem,
    /// Keyed by the chain's addresses and the target key's fingerprint.
    // ponytail: two ops that miss together dial twice and the later one wins; a per-key dial lock
    // if that ever costs.
    pool: Mutex<HashMap<String, Arc<Conn>>>,
    idle: Duration,
}

fn fail(code: ErrorCode, m: impl Into<String>) -> StreamError {
    StreamError::new(code, m)
}

fn invalid(m: &str) -> StreamError {
    fail(ErrorCode::InvalidArgs, m)
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn check_hop(h: &SshHop) -> Result<(), StreamError> {
    if !plain(&h.host, 253) || !plain(&h.user, 64) || h.port == 0 || !plain(&h.lease, 256) {
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

fn pool_key(req: &SshExec, key_fp: &str) -> String {
    let at = |h: &SshHop| format!("{}@{}:{}", h.user, h.host, h.port);
    let chain: Vec<String> = req.hops.iter().chain([&req.target]).map(at).collect();
    format!("{}#{key_fp}", chain.join(">"))
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
            pool: Mutex::new(HashMap::new()),
            idle: IDLE,
        }
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
                commands: vec![OP_SSH_EXEC.to_owned()],
                capacity: e.capacity,
                ..DriverInfo::default()
            })
    }

    /// A slot for one `ssh.exec`: the same capacity as `exec.run` (`busy` when full).
    pub fn slot(&self) -> Result<OwnedSemaphorePermit, StreamError> {
        self.exec.slot()
    }

    /// Runs `req` to its end, its timeout, or `cancel` (fired or dropped).
    pub async fn run(
        &self,
        req: &SshExec,
        cancel: oneshot::Receiver<()>,
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
        // The target's key first: its fingerprint is the pool key, so a pooled connection is only
        // ever reused by an op that holds the key.
        let key = self.load_key(&req.target.lease).await?;
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let name = pool_key(req, &fp);
        let conn = match self.pooled(&name, req) {
            Some(conn) => conn,
            None => {
                let dial = self.dial(req, key);
                let conn = tokio::time::timeout(CONNECT_TIMEOUT, dial)
                    .await
                    .map_err(|_| fail(ErrorCode::SshFailed, "timed out connecting"))??;
                self.pool_put(name, Arc::new(conn))
            }
        };
        let result = self.run_on(&conn, &req.run, timeout, cap, cancel).await;
        *conn.used.lock().unwrap() = Instant::now();
        let mut result = result?;
        result.duration_ms = started.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// A key from its lease, parsed. Never logged; errors are fixed text.
    async fn load_key(&self, lease: &str) -> Result<PrivateKey, StreamError> {
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
        russh::keys::decode_secret_key(text, None)
            .map_err(|_| auth("the leased key is not a usable unencrypted private key".into()))
    }

    fn pooled(&self, name: &str, req: &SshExec) -> Option<Arc<Conn>> {
        let mut pool = self.pool.lock().unwrap();
        pool.retain(|_, c| !c.handle.is_closed() && c.used.lock().unwrap().elapsed() < self.idle);
        let conn = pool.get(name)?;
        // Every hop's pins must still list the key it presented when the chain was dialled.
        let pinned = req.hops.iter().chain([&req.target]);
        let holds = conn
            .host_keys
            .iter()
            .zip(pinned)
            .all(|(k, h)| h.pinned_keys.contains(k));
        if !holds {
            pool.remove(name);
            return None;
        }
        *conn.used.lock().unwrap() = Instant::now();
        Some(Arc::clone(conn))
    }

    fn pool_put(&self, name: String, conn: Arc<Conn>) -> Arc<Conn> {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() >= POOL_MAX
            && let Some(oldest) = pool
                .iter()
                .min_by_key(|(_, c)| *c.used.lock().unwrap())
                .map(|(k, _)| k.clone())
        {
            pool.remove(&oldest);
        }
        pool.insert(name, Arc::clone(&conn));
        conn
    }

    /// Connects hop by hop; each hop's host key is verified before its authentication.
    async fn dial(&self, req: &SshExec, target_key: PrivateKey) -> Result<Conn, StreamError> {
        let chain: Vec<&SshHop> = req.hops.iter().chain([&req.target]).collect();
        let cfg = config(self.idle);
        let mut target_key = Some(target_key);
        let mut handles: Vec<Handle<Verify>> = Vec::new();
        let mut host_keys = Vec::new();
        for (i, hop) in chain.iter().enumerate() {
            let at = |m: String| {
                let m = self.exec.redact(&format!("hop {i}: {m}"));
                fail(ErrorCode::SshFailed, m)
            };
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
            let key = match i + 1 == chain.len() {
                true => target_key.take(),
                false => Some(self.load_key(&hop.lease).await?),
            };
            let key = key.ok_or_else(|| fail(ErrorCode::Internal, "no key for the target"))?;
            self.authenticate(&mut handle, &hop.user, key, i).await?;
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
        })
    }

    /// One `publickey` attempt; `key` is dropped here.
    async fn authenticate(
        &self,
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

    async fn run_on(
        &self,
        conn: &Conn,
        run: &str,
        timeout: Duration,
        cap: usize,
        mut cancel: oneshot::Receiver<()>,
    ) -> Result<ExecResult, StreamError> {
        let failed = |m: &str| fail(ErrorCode::SshFailed, m.to_owned());
        let mut ch = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|_| failed("cannot open a channel"))?;
        ch.exec(true, run.as_bytes().to_vec())
            .await
            .map_err(|_| failed("cannot send the command"))?;
        let (mut out, mut err) = (Raw::new(cap), Raw::new(cap));
        let (mut exit_code, mut timed_out) = (None, false);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                msg = ch.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => out.push(&data),
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => err.push(&data),
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = i32::try_from(exit_status).ok();
                    }
                    Some(ChannelMsg::Failure) => return Err(failed("the host refused the command")),
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                },
                () = &mut deadline => {
                    timed_out = true;
                    break;
                }
                _ = &mut cancel => {
                    let _ = ch.close().await;
                    return Err(fail(ErrorCode::Cancelled, "cancelled"));
                }
            }
        }
        let _ = ch.close().await;
        Ok(ExecResult {
            exit_code: exit_code.filter(|_| !timed_out),
            timed_out,
            duration_ms: 0,
            stdout: self.exec.finish(out),
            stderr: self.exec.finish(err),
        })
    }
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
