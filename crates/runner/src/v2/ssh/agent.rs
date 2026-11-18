//! Mac-direct (Leyline Y6-01, plan T7): a short-lived ssh-agent inside the runner, bound to the hosts
//! the Core pinned, so `ssh`, `scp` and editors on this machine reach ONE host (and its jump hops)
//! without a key file anywhere.
//!
//! Security model.
//! - **The key never leaves the runner.** The Core sends leases; the runner redeems them into
//!   `PrivateKey`s that live only in this process's memory. The agent protocol here has no way to
//!   add, remove, list-with-secret or export a key: the only requests answered are "list identities"
//!   (public keys), "sign" and `session-bind@openssh.com`; every other message is `FAILURE`. (russh's
//!   own agent server is not used: it takes add/remove/lock from any peer and has no per-connection
//!   state for a bind.)
//! - **Every sign request is checked, here, by this code, one by one.** It is signed only if: the
//!   agent is live (not dropped, not past its deadline); the connection did a `session-bind` whose
//!   signature the host key verifies (so the host key is really the one of that ssh session); that
//!   host key's fingerprint is pinned for THIS key's own host (a jump host's key cannot sign for the
//!   target, nor the reverse); and the data to sign is, parsed to its last byte, an ssh `publickey`
//!   userauth request for `ssh-connection` over exactly that session id, for that key's own user,
//!   with the key's own algorithm and blob (and, host-bound, the bound host key), so nothing else
//!   (e.g. a git signature) is ever signed. One bind per connection: a refused bind (a forwarded
//!   one, `-A`, among them) or a second bind poisons the connection, and nothing on it is signed
//!   again. An unbound connection, or a bound one to any other host, is refused and counted.
//! - **Who may connect.** The socket sits in a fresh 0700 directory of the runner's temporary
//!   directory (mode 0600), and each connection's peer uid must be the directory owner's: another
//!   local user is closed before a byte is read. At most 16 connections, frames at most 64 KiB.
//! - **Lifetime.** Ends at its deadline, a wall-clock (`SystemTime`) time checked on every request
//!   and by a once-a-second timer, so a Mac that slept past it does not stretch the TTL; on `drop`;
//!   and when the runner has been cut off from the Core for 5 minutes (`link_lost`). Ending clears
//!   the keys at once (`PrivateKey` zeroizes on drop), closes the listener and every connection and
//!   removes the directory.
//! - **On disk:** the socket and an `ssh_config` of public settings only. Never a key.
//!
//! Gap, stated: the host keys are pinned by fingerprint (all the Core holds), so `ssh` runs with
//! `StrictHostKeyChecking accept-new` into a private known-hosts file; the pin is enforced by this
//! agent (an unpinned host gets no signature, and password login is off in the config), not by ssh.

use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ainkrad_proto::v2::{
    ErrorCode, SSH_AGENT_MAX_KEYS, SSH_AGENT_MAX_TTL_SECS, SshAgentDrop, SshAgentDropped,
    SshAgentLoad, SshAgentLoaded,
};
use russh::keys::signature::{Signer, Verifier};
use russh::keys::ssh_key::Signature;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};

use super::{CONNECT_TIMEOUT, SshDriver, fail, invalid, plain};
use ainkrad_proto::v2::StreamError;

/// Cut off from the Core this long, every agent ends.
const LINK_GRACE: Duration = Duration::from_secs(300);
const MAX_LIVE: usize = 8;
const MAX_CONNS: usize = 16;
const MAX_FRAME: usize = 64 * 1024;
/// A peer that does not read its answer this long is closed.
const WRITE_WAIT: Duration = Duration::from_secs(5);
/// How often the timer looks at the wall clock.
const TICK: Duration = Duration::from_secs(1);
/// Ended agents kept (for their counts) until the Core drops them; past this the ended go.
const KEEP_ENDED: usize = 32;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const IDENTITIES: u8 = 12;
const SIGN_RESPONSE: u8 = 14;
const USERAUTH_REQUEST: u8 = 50;

/// Where "now" comes from (the wall clock: a sleep does not stop it); a test moves it.
pub(super) type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The signature algorithms a key may be used with: Ed25519 and ECDSA, which have no hash flags.
const ALGOS: &[&[u8]] = &[
    b"ssh-ed25519",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
];

struct Held {
    key: PrivateKey,
    blob: Vec<u8>,
    /// Fingerprints of the host keys this key may sign for.
    pins: Vec<String>,
    /// The login user on that machine.
    user: String,
}

struct Bind {
    fp: String,
    /// The host key's wire blob, as the bind gave it.
    host: Vec<u8>,
    sid: Vec<u8>,
}

/// One connection's state: one bind at most, and once anything about a bind was wrong, nothing
/// more on this connection is signed.
#[derive(Default)]
struct Conn {
    bind: Option<Bind>,
    poisoned: bool,
}

pub(super) struct Live {
    /// Emptied by `end`: the map of agents keeps only the counters after that.
    keys: Mutex<Vec<Held>>,
    deadline: SystemTime,
    clock: Clock,
    stop: watch::Sender<bool>,
    sigs: AtomicU64,
    refused: AtomicU64,
    /// The uid a peer must have.
    owner: u32,
}

impl Live {
    fn alive(&self) -> bool {
        !*self.stop.borrow() && (self.clock)() < self.deadline
    }

    fn end(&self) {
        self.stop.send_replace(true);
        self.keys.lock().unwrap().clear();
    }

    /// One request, answered. `conn` is this connection's.
    fn answer(&self, conn: &mut Conn, msg: &[u8]) -> Vec<u8> {
        if !self.alive() {
            self.end();
            return vec![FAILURE];
        }
        let mut r = Rd(msg);
        match r.u8() {
            // Public keys only.
            Some(11) => {
                let keys = self.keys.lock().unwrap();
                let mut o = vec![IDENTITIES];
                o.extend((keys.len() as u32).to_be_bytes());
                for k in keys.iter() {
                    put(&mut o, &k.blob);
                    put(&mut o, b"");
                }
                o
            }
            Some(13) => self.sign(conn, &mut r).unwrap_or_else(|| {
                self.refused.fetch_add(1, SeqCst);
                vec![FAILURE]
            }),
            Some(27) if r.string() == Some(&b"session-bind@openssh.com"[..]) => {
                // Anything but a first, good bind poisons the connection.
                let first = !conn.poisoned && conn.bind.is_none();
                match first.then(|| self.bind(&mut r)).flatten() {
                    Some(b) => {
                        conn.bind = Some(b);
                        vec![SUCCESS]
                    }
                    None => {
                        conn.poisoned = true;
                        vec![FAILURE]
                    }
                }
            }
            _ => vec![FAILURE],
        }
    }

    /// `session-bind@openssh.com`: the host key and session id of the ssh session this connection
    /// serves, proven by the host key's signature over the session id.
    fn bind(&self, r: &mut Rd) -> Option<Bind> {
        let (hk, sid, sig, forwarded) = (r.string()?, r.string()?, r.string()?, r.u8()?);
        if forwarded != 0 || sid.is_empty() || sid.len() > 128 || !r.0.is_empty() {
            return None;
        }
        let host = PublicKey::from_bytes(hk).ok()?;
        let fp = host.fingerprint(HashAlg::Sha256).to_string();
        if !self
            .keys
            .lock()
            .unwrap()
            .iter()
            .any(|k| k.pins.contains(&fp))
        {
            return None;
        }
        let sig = Signature::try_from(sig).ok()?;
        Verifier::<Signature>::verify(&host, sid, &sig).ok()?;
        Some(Bind {
            fp,
            host: hk.to_vec(),
            sid: sid.to_vec(),
        })
    }

    fn sign(&self, conn: &Conn, r: &mut Rd) -> Option<Vec<u8>> {
        let bind = conn.bind.as_ref().filter(|_| !conn.poisoned)?;
        let (blob, data, flags) = (r.string()?, r.string()?, r.u32()?);
        // Ed25519 and ECDSA only: there are no hash flags to honour.
        if flags != 0 || !r.0.is_empty() {
            return None;
        }
        let keys = self.keys.lock().unwrap();
        // The key of that blob whose own machine is the bound host (the same key may serve two).
        let key = keys
            .iter()
            .find(|k| k.blob == blob && k.pins.contains(&bind.fp))?;
        userauth_ok(data, key, bind)?;
        let sig: Signature = Signer::try_sign(&key.key, data).ok()?;
        let wire = Vec::<u8>::try_from(sig).ok()?;
        self.sigs.fetch_add(1, SeqCst);
        let mut o = vec![SIGN_RESPONSE];
        put(&mut o, &wire);
        Some(o)
    }
}

/// The data of a sign request, read to its last byte: `string session id, byte 50, string user,
/// string "ssh-connection", string method, bool TRUE, string algorithm, string key blob` and, for
/// the host-bound method, `string host key`. Every field must be the one this key and bind allow.
fn userauth_ok(data: &[u8], key: &Held, bind: &Bind) -> Option<()> {
    let mut d = Rd(data);
    let sid = d.string()?;
    let (kind, user, service, method) = (d.u8()?, d.string()?, d.string()?, d.string()?);
    let hostbound = match method {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    let (has_sig, algo, blob) = (d.u8()?, d.string()?, d.string()?);
    let host_ok = !hostbound || d.string()? == bind.host.as_slice();
    let algo_ok =
        ALGOS.contains(&algo) && algo == key.key.algorithm().as_str().as_bytes();
    (sid == bind.sid.as_slice()
        && kind == USERAUTH_REQUEST
        && user == key.user.as_bytes()
        && service == b"ssh-connection"
        && has_sig == 1
        && algo_ok
        && blob == key.blob.as_slice()
        && host_ok
        && d.0.is_empty())
    .then_some(())
}

/// An agent message reader: nothing here can read past the end.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn u8(&mut self) -> Option<u8> {
        let s = self.0;
        let (a, b) = s.split_first()?;
        self.0 = b;
        Some(*a)
    }

    fn u32(&mut self) -> Option<u32> {
        let s = self.0;
        let (a, b) = s.split_at_checked(4)?;
        self.0 = b;
        Some(u32::from_be_bytes(a.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let s = self.0;
        let (a, b) = s.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

/// Reads `buf` or learns that the agent ended; `false` ends the connection.
async fn read(s: &mut UnixStream, buf: &mut [u8], stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        r = s.read_exact(buf) => r.is_ok(),
        () = stopped(stop) => false,
    }
}

async fn serve_conn(live: Arc<Live>, mut s: UnixStream) {
    let mut stop = live.stop.subscribe();
    let mut conn = Conn::default();
    loop {
        let mut len = [0u8; 4];
        if !read(&mut s, &mut len, &mut stop).await {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_FRAME {
            return;
        }
        let mut msg = vec![0u8; n];
        if !read(&mut s, &mut msg, &mut stop).await {
            return;
        }
        let out = live.answer(&mut conn, &msg);
        let mut frame = (out.len() as u32).to_be_bytes().to_vec();
        frame.extend(out);
        if !matches!(
            tokio::time::timeout(WRITE_WAIT, s.write_all(&frame)).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

/// Accepts until the agent ends (dropped, or its wall-clock deadline), then removes its directory.
async fn accept(live: Arc<Live>, listener: UnixListener, dir: PathBuf) {
    let mut stop = live.stop.subscribe();
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    // Not a sleep for the TTL: tokio's clock stops while the Mac sleeps, the wall clock does not.
    let mut tick = tokio::time::interval(TICK);
    // After a long pause (a slept Mac, a test's jump in time) one check is enough, not one per missed second.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            a = listener.accept() => match a {
                Ok((s, _)) => {
                    // Another user's process is closed before it can say anything.
                    let mine = s.peer_cred().is_ok_and(|c| c.uid() == live.owner);
                    if let (true, Ok(permit)) = (mine, Arc::clone(&slots).try_acquire_owned()) {
                        let live = Arc::clone(&live);
                        tokio::spawn(async move {
                            serve_conn(live, s).await;
                            drop(permit);
                        });
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            },
            () = stopped(&mut stop) => break,
            _ = tick.tick() => if !live.alive() { break },
        }
    }
    live.end();
    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

#[derive(Default)]
pub(super) struct Agents {
    live: Mutex<HashMap<String, Arc<Live>>>,
    /// The Core link is down; counted by `epoch` so only the loss that started a timer ends agents.
    down: AtomicBool,
    epoch: AtomicU64,
}

impl Agents {
    fn end_all(&self) {
        for l in self.live.lock().unwrap().values() {
            l.end();
        }
    }
}

/// A path ssh_config can hold inside double quotes.
fn quotable(p: &Path) -> Option<&str> {
    let s = p.to_str()?;
    // No quote of either kind and no backslash: the path goes inside ssh_config quotes, and the
    // Core puts it inside single quotes in the ready command.
    (s.bytes()
        .all(|b| b.is_ascii_graphic() && !b"\"'\\".contains(&b)))
    .then_some(s)
}

struct Socket {
    dir: PathBuf,
    sock: PathBuf,
    config: PathBuf,
    listener: UnixListener,
}

/// The directory, the socket (bound, 0600) and the `ssh_config` beside it.
fn make_socket() -> Result<Socket, std::io::Error> {
    let rand: [u8; 6] = super::super::key::random();
    let name: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("ainkrad-ssh.{name}"));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let built = (|| {
        let (sock, config) = (dir.join("agent.sock"), dir.join("ssh_config"));
        let (s, d) = (quotable(&sock), quotable(&dir));
        let (Some(s), Some(d)) = (s, d) else {
            return Err(std::io::Error::other("the temporary directory path is odd"));
        };
        let listener = UnixListener::bind(&sock)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        let text = format!(
            "Host *\n  IdentityAgent \"{s}\"\n  UserKnownHostsFile \"{d}/known_hosts\"\n  \
             GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking accept-new\n  \
             PreferredAuthentications publickey\n  PasswordAuthentication no\n  \
             KbdInteractiveAuthentication no\n  ForwardAgent no\n"
        );
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)?;
        std::io::Write::write_all(&mut f, text.as_bytes())?;
        Ok((sock, config, listener))
    })();
    match built {
        Ok((sock, config, listener)) => Ok(Socket {
            dir,
            sock,
            config,
            listener,
        }),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            Err(e)
        }
    }
}

impl SshDriver {
    /// Starts the agent `req.id`: redeems every lease, opens the socket, answers where it is.
    pub async fn agent_load(&self, req: &SshAgentLoad) -> Result<SshAgentLoaded, StreamError> {
        self.load_agent(req, Arc::new(SystemTime::now), None).await
    }

    /// [`agent_load`](Self::agent_load) with the clock, and the uid a peer must have, a test chooses.
    pub(super) async fn load_agent(
        &self,
        req: &SshAgentLoad,
        clock: Clock,
        owner: Option<u32>,
    ) -> Result<SshAgentLoaded, StreamError> {
        let id_ok = !req.id.is_empty()
            && req.id.len() <= 64
            && req
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let keys_ok = (1..=SSH_AGENT_MAX_KEYS).contains(&req.keys.len())
            && req.keys.iter().all(|k| {
                plain(&k.lease, 256)
                    && plain(&k.user, 64)
                    && (1..=8).contains(&k.pinned_keys.len())
                    && k.pinned_keys
                        .iter()
                        .all(|p| p.starts_with("SHA256:") && plain(p, 64))
            });
        if !id_ok || !keys_ok || !(1..=SSH_AGENT_MAX_TTL_SECS).contains(&req.ttl_secs) {
            return Err(invalid(
                "an agent needs an id, a ttl and 1 to 4 pinned keys with their users",
            ));
        }
        {
            let mut live = self.agents.live.lock().unwrap();
            if live.contains_key(&req.id) {
                return Err(invalid("that agent id is taken"));
            }
            if live.len() > KEEP_ENDED {
                live.retain(|_, l| l.alive());
            }
            if live.values().filter(|l| l.alive()).count() >= MAX_LIVE {
                return Err(fail(ErrorCode::Busy, "too many agents are live"));
            }
        }
        let mut keys = Vec::with_capacity(req.keys.len());
        for k in &req.keys {
            let key = tokio::time::timeout(CONNECT_TIMEOUT, self.load_key(&k.lease))
                .await
                .map_err(|_| fail(ErrorCode::SshAuthFailed, "timed out redeeming a key lease"))??;
            let blob = key
                .public_key()
                .to_bytes()
                .map_err(|_| fail(ErrorCode::Internal, "an unusable key"))?;
            keys.push(Held {
                key,
                blob,
                pins: k.pinned_keys.clone(),
                user: k.user.clone(),
            });
        }
        let io = |_| fail(ErrorCode::Internal, "cannot open the agent socket");
        let Socket {
            dir,
            sock,
            config,
            listener,
        } = make_socket().map_err(io)?;
        let owner = match owner {
            Some(o) => o,
            None => std::fs::metadata(&dir).map_err(io)?.uid(),
        };
        let ttl = Duration::from_secs(u64::from(req.ttl_secs));
        let live = Arc::new(Live {
            keys: Mutex::new(keys),
            deadline: clock() + ttl,
            clock,
            stop: watch::channel(false).0,
            sigs: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            owner,
        });
        self.agents
            .live
            .lock()
            .unwrap()
            .insert(req.id.clone(), Arc::clone(&live));
        tokio::spawn(accept(live, listener, dir));
        let path = |p: PathBuf| p.to_string_lossy().into_owned();
        Ok(SshAgentLoaded {
            socket: path(sock),
            config: path(config),
        })
    }

    /// Ends the agent and tells what it did; an id that is not here is not an error.
    pub fn agent_drop(&self, req: &SshAgentDrop) -> SshAgentDropped {
        let Some(l) = self.agents.live.lock().unwrap().remove(&req.id) else {
            return SshAgentDropped::default();
        };
        let was_live = l.alive();
        l.end();
        SshAgentDropped {
            was_live,
            signatures: l.sigs.load(SeqCst),
            refused: l.refused.load(SeqCst),
        }
    }

    /// The Core link is back.
    pub fn link_up(&self) {
        self.agents.down.store(false, SeqCst);
        self.agents.epoch.fetch_add(1, SeqCst);
    }

    /// The Core link went: if it stays down for `LINK_GRACE`, every agent ends. Calling it again
    /// while down (a failed reconnect) does not restart the countdown.
    pub fn link_lost(&self) {
        if self.agents.down.swap(true, SeqCst) {
            return;
        }
        let e = self.agents.epoch.fetch_add(1, SeqCst) + 1;
        let agents = Arc::clone(&self.agents);
        tokio::spawn(async move {
            tokio::time::sleep(LINK_GRACE).await;
            if agents.epoch.load(SeqCst) == e {
                agents.end_all();
            }
        });
    }
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
