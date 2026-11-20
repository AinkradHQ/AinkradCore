//! In-process `russh` servers and a fake Core's key leases, for the `ssh.exec` tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::ExecLimits;
use russh::keys::ssh_key::LineEnding;
use russh::server::{Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;

use super::super::agent::secrets::Leased;
use super::super::exec::tests::{RUNNER_KEY, driver};
use super::sftp_fixture::{Fs, MemFs, Sftp};
use super::*;

pub(in crate::v2) fn never() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    std::mem::forget(tx);
    rx
}

pub(in crate::v2) fn fp(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// A throwaway 2048-bit RSA key made with `ssh-keygen` (generating one in a debug build is slow).
pub(in crate::v2) const RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1B+BB583HHMCHagayAdGD9yiYJDABMAliiBcbwfMgEr7IR90gkCW
wqzC+PF1pcDtrGgxxFVzns+LyK2zKF9hlYGlIKcu2cK6SAW+PTySHRPoT7lUuGtDpkxNnL
JTeTKzC0Z4av5C3fGNaiAoG6EzVgXmeMqIYoUZhPO3o3uRc7GkqcNi2RSDegtN5XvdRhGq
nkW1MQlA4HlGq8ivsNKLSVKrHPoRUWjvzhJ/QJoL2/1l0gFqCQPTC/NfIBqL/gvRlXt8vY
/En2i68AUdw82WT7+XlOfhKdoSlXEoOu5DO4vuUwpoclxhPaKBgz4SvbdROf8XVt9wzZ/K
KrOgayN5BwAAA7gVVLWIFVS1iAAAAAdzc2gtcnNhAAABAQDUH4EHnzcccwIdqBrIB0YP3K
JgkMAEwCWKIFxvB8yASvshH3SCQJbCrML48XWlwO2saDHEVXOez4vIrbMoX2GVgaUgpy7Z
wrpIBb49PJIdE+hPuVS4a0OmTE2cslN5MrMLRnhq/kLd8Y1qICgboTNWBeZ4yohihRmE87
eje5FzsaSpw2LZFIN6C03le91GEaqeRbUxCUDgeUaryK+w0otJUqsc+hFRaO/OEn9Amgvb
/WXSAWoJA9ML818gGov+C9GVe3y9j8SfaLrwBR3DzZZPv5eU5+Ep2hKVcSg67kM7i+5TCm
hyXGE9ooGDPhK9t1E5/xdW33DNn8oqs6BrI3kHAAAAAwEAAQAAAQEAiUceLP2YH/w6GVFK
i7tRV0CVgWMMMcbcRIju6Rgl+70KywPdVdJQ/wnpYEx7s9qothP0aThYDCYLM8NeF7mqoK
P3ZqtrgZgpECVPWbgSY2kXxkiNkJAyhrQI4mjx5pSuFJT1p2CHi7UgrNbEviTT4U8OOYvx
Obkjq8xCQzXcCv91jEuUt90GXXKx2W1XU2Xi9bVI617Euzy42WGFtVfSLL+1JZ0/6Xhzjr
iKreoQ+wMg/Qc5u4TjUWnfRSKKqms40DmfQ3cdAUtuQKDRZ1MMZwOeIQSpGUYfxTZ1aFFm
adCOnnlMDCn9kzBXf0GXLJCT+ZCCSsvBE9v85aO/fnFFEQAAAIBHfs9kyJU+FBlk/n7rQC
iO6sYk54ZDs9yDn0tNHqprH9Bot+Q6E3xvR0vd94sVRqQAJDkKhlYBu8mrp5H9nhBO9CdR
8Yvgcar+OthcdUgaJZIV4q/j0q/PVmO0Ub43N8p/2H2pQ+NXJbh/PptWwYfB2h7QCToc1t
X/jIyrA2wWbQAAAIEA6v4nS4jXp0KZezVJS6eCHPgkjOLGct6udjCVxBGp/BYz6RQsgBaE
tQ+RIQ4WvHkxBHwHrUfFWO9P9zt2RiB7xVsz1qPAcUQp/Gq5ldHpMZKN36gWeUJHWa/WTY
H8lYjZ3t9Mi6Sot6WvWHScGXvzBc9Z9O4B+XWwh7cMjvFWHN8AAACBAOcV+SudjxkIA6d7
kD9MKeH5A0g1GvL7mMCR7YTtj7cvGdhp244o0uymnV2zGlvX8TFtli1FdmBWObzMxVnL1H
aPJEy7pEly9qeC8+PJO1Fkxj+n/ffWMckhou05SUdoFg3jfZPCr6NbfrMqqzrohYxeLZOT
GRC2LbPIpu9GewDZAAAAAAEC
-----END OPENSSH PRIVATE KEY-----
";

pub(in crate::v2) fn new_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

/// What a fixture server saw.
#[derive(Default)]
pub(in crate::v2) struct Seen {
    /// Connections accepted.
    pub(in crate::v2) conns: AtomicUsize,
    /// Any authentication traffic at all (none, offered, or signed).
    pub(in crate::v2) auth: AtomicUsize,
    /// `direct-tcpip` channels it carried.
    pub(in crate::v2) forwards: AtomicUsize,
    /// `exec` requests received: a cancelled op must leave this at 0.
    pub(in crate::v2) execs: AtomicUsize,
    /// Channel `signal` requests (the best-effort KILL).
    pub(in crate::v2) signals: AtomicUsize,
    /// The algorithm of each verified `publickey` signature (`ssh-ed25519`, `rsa-sha2-512`, ...).
    pub(in crate::v2) algos: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub(in crate::v2) struct Fixture {
    name: &'static str,
    accept: bool,
    seen: Arc<Seen>,
    /// What the `sftp` subsystem serves.
    fs: Fs,
    /// Session channels of this connection, until a subsystem request takes one.
    chans: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Server for Fixture {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.seen.conns.fetch_add(1, SeqCst);
        Self {
            chans: Arc::default(),
            ..self.clone()
        }
    }
}

impl russh::server::Handler for Fixture {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        self.seen.auth.fetch_add(1, SeqCst);
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.seen.auth.fetch_add(1, SeqCst);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.seen.auth.fetch_add(1, SeqCst);
        (self.seen.algos.lock().unwrap()).push(key.algorithm.as_str().to_owned());
        Ok(if self.accept {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.chans.lock().unwrap().insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let taken = self.chans.lock().unwrap().remove(&channel);
        match (name, taken) {
            ("sftp", Some(ch)) => {
                session.channel_success(channel)?;
                russh_sftp::server::run(ch.into_stream(), Sftp::new(Arc::clone(&self.fs))).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        // A dropped `reply` refuses the channel.
        if let Ok(mut tcp) = tokio::net::TcpStream::connect((host, port as u16)).await {
            self.seen.forwards.fetch_add(1, SeqCst);
            reply.accept().await;
            tokio::spawn(async move {
                let mut ch = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut ch, &mut tcp).await;
            });
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        _: ChannelId,
        _: russh::Sig,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.signals.fetch_add(1, SeqCst);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        self.seen.execs.fetch_add(1, SeqCst);
        session.channel_success(channel)?;
        let (h, name) = (session.handle(), self.name);
        tokio::spawn(async move {
            let mut code = 0;
            match cmd.as_str() {
                "name" => drop(h.data(channel, format!("{name}\n").into_bytes()).await),
                "both" => {
                    let _ = h.data(channel, b"out\n".to_vec()).await;
                    let _ = h.extended_data(channel, 1, b"oops\n".to_vec()).await;
                    code = 3;
                }
                "secret" => drop(
                    h.data(channel, format!("key {RUNNER_KEY}\n").into_bytes())
                        .await,
                ),
                "flood" => {
                    for _ in 0..160 {
                        let _ = h.data(channel, vec![b'A'; 32 * 1024]).await;
                    }
                }
                "sleep" => tokio::time::sleep(Duration::from_secs(30)).await,
                // Ends the channel without saying how the command ended.
                "noexit" => {
                    let _ = h.eof(channel).await;
                    let _ = h.close(channel).await;
                    return;
                }
                _ => code = 127,
            }
            let _ = h.exit_status_request(channel, code).await;
            let _ = h.eof(channel).await;
            let _ = h.close(channel).await;
        });
        Ok(())
    }
}

pub(in crate::v2) struct Server {
    pub(in crate::v2) port: u16,
    pub(in crate::v2) host_key: PrivateKey,
    pub(in crate::v2) seen: Arc<Seen>,
    pub(in crate::v2) fs: Fs,
}

impl Server {
    pub(in crate::v2) fn pin(&self) -> Vec<String> {
        vec![fp(&self.host_key)]
    }

    pub(in crate::v2) fn hop(&self, user: &str, lease: &str) -> SshHop {
        SshHop {
            host: "127.0.0.1".to_owned(),
            port: self.port,
            user: user.to_owned(),
            pinned_keys: self.pin(),
            lease: lease.to_owned(),
        }
    }
}

pub(in crate::v2) async fn serve(name: &'static str, accept: bool) -> Server {
    let config = russh::server::Config {
        keys: vec![new_key()],
        auth_rejection_time: Duration::from_millis(5),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    };
    start(name, accept, config).await
}

pub(in crate::v2) async fn start(
    name: &'static str,
    accept: bool,
    config: russh::server::Config,
) -> Server {
    let host_key = config.keys[0].clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let fs = MemFs::with_root();
    let mut fixture = Fixture {
        name,
        accept,
        seen: Arc::clone(&seen),
        fs: Arc::clone(&fs),
        chans: Arc::default(),
    };
    tokio::spawn(async move {
        let _ = fixture.run_on_socket(Arc::new(config), &listener).await;
    });
    Server {
        port,
        host_key,
        seen,
        fs,
    }
}

/// Leases handed out by the fake Core: lease id to the key's OpenSSH text, as a `file` secret
/// (base64 of the bytes), like the Core's `leyline-keys` secrets.
#[derive(Clone, Default)]
pub(in crate::v2) struct Leases {
    pub(in crate::v2) keys: Arc<Mutex<HashMap<String, String>>>,
    pub(in crate::v2) redeemed: Arc<AtomicUsize>,
    /// How long a redemption takes (the Core answering slowly).
    pub(in crate::v2) delay: Arc<Mutex<Duration>>,
}

impl Leases {
    pub(in crate::v2) fn add(&self, lease: &str, pem: &str) {
        self.keys.lock().unwrap().insert(lease.into(), pem.into());
    }

    pub(in crate::v2) fn key(&self, lease: &str) -> PrivateKey {
        let k = new_key();
        self.add(lease, &k.to_openssh(LineEnding::LF).unwrap());
        k
    }

    pub(in crate::v2) fn redeem(&self) -> Redeem {
        let this = self.clone();
        Arc::new(move |lease: String| {
            let this = this.clone();
            Box::pin(async move {
                this.redeemed.fetch_add(1, SeqCst);
                let delay = *this.delay.lock().unwrap();
                tokio::time::sleep(delay).await;
                let pem = this.keys.lock().unwrap().get(&lease).cloned();
                let pem = pem.ok_or_else(|| "no such lease".to_owned())?;
                use base64::Engine;
                Ok(Leased {
                    name: "id".into(),
                    delivery: "file".into(),
                    value: Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pem)),
                    form: Form::File {
                        name: "id".into(),
                        mode: 0o600,
                    },
                })
            })
        })
    }
}

pub(in crate::v2) fn ssh(leases: &Leases) -> SshDriver {
    SshDriver::new(Arc::new(driver(4)), leases.redeem())
}

pub(in crate::v2) fn req(target: SshHop, hops: Vec<SshHop>, run: &str) -> SshExec {
    SshExec {
        target,
        hops,
        run: run.to_owned(),
        limits: ExecLimits {
            timeout_ms: Some(10_000),
            max_output_bytes: None,
        },
    }
}

pub(in crate::v2) fn text(r: &ExecResult) -> &str {
    &r.stdout.text
}
