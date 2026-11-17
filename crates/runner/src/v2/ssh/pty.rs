//! Interactive SSH terminals (Leyline Y2-02, plan T1/T2/T3/T4): `ainkrad-runner ssh-pty` is the
//! program of a terminal the runner opens through `PtyOpen`, so attach, resume, snapshot,
//! scrollback and the disk budget are the terminal host's, unchanged.
//!
//! Security model (on top of the one in `mod.rs`: host key checked inside the key exchange before any
//! authentication, modern algorithms only, every hop verified and authenticated in turn):
//! - **The key's way here.** The runner redeems each hop's lease (the Core's delivery, `file` or
//!   `env`, is ignored) and hands the keys to this process as JSON on an inherited pipe, descriptor
//!   3, that the terminal host filled and closed before starting it. Not argv, not env, not a file,
//!   not the terminal: `/proc/<pid>/cmdline|environ` never hold it. Each key is parsed once,
//!   used for one `publickey` attempt and wiped (`Zeroizing`, wipe on drop). The same gaps as
//!   `ssh.exec`: russh and `ssh-key` copy while parsing and signing, and those copies are not ours to
//!   wipe. This process lives as long as the terminal, but holds no key after authentication.
//! - **Nothing is logged.** No tracing subscriber exists here; failures are fixed texts printed on
//!   the terminal. A password or keyboard-interactive answer is read from the terminal with echo off
//!   (or on, when the host asks for it), goes to the host and is wiped; it is never in a message.
//! - **What the host prints is data.** Prompts, banners and instructions it sends before login are
//!   stripped of control characters before they reach the terminal (no escape sequences before the
//!   person has even logged in). The shell's own output is the terminal's bytes, as in any ssh.
//! - **Ending.** The remote shell's exit code is this process's, or one of `SSH_PTY_EXIT_*` (a
//!   host-key refusal prints the fingerprint). HUP and TERM from the terminal host's close end it at
//!   once, closing the channel. A host that stops answering is dropped after about two minutes
//!   (keepalive every 30 s, three missed).
//!
//! Not covered: the terminal sandbox's network (`--terminal-network`) and `--terminal-user` change
//! what a terminal may reach; an ssh terminal refuses to start under either (see `PtyDriver`).

use std::collections::VecDeque;
use std::io::Read;
use std::os::fd::AsFd;
use std::process::ExitCode;
use std::sync::Arc;

use ainkrad_proto::v2::{
    ErrorCode, MAX_SSH_HOPS, SSH_PTY_EXIT_AUTH_FAILED, SSH_PTY_EXIT_FAILED,
    SSH_PTY_EXIT_HOST_KEY_CHANGED, SSH_PTY_EXIT_HOST_KEY_UNKNOWN, SshHop, SshTerminal, StreamError,
};
use ainkrad_ptyhost::pty::{FD3_MAX, Hidden};
use russh::ChannelMsg;
use russh::MethodKind;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{PrivateKeyWithHashAlg, ssh_key::PrivateKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use super::{
    CONNECT_TIMEOUT, HopAuth, SshDriver, Verify, check_hop, config, dial_chain, fail, invalid,
    parse_key,
};

/// Password or keyboard-interactive attempts per hop before giving up.
const ATTEMPTS: usize = 3;
/// Longest a typed answer may be.
const MAX_ANSWER: usize = 1024;

/// One machine of the chain, as the runner hands it over: the hop and its key (OpenSSH text).
#[derive(Serialize, Deserialize)]
pub(crate) struct PtyHop {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pinned_keys: Vec<String>,
    pub key: String,
}

impl Drop for PtyHop {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for PtyHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyHop")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("key", &"[hidden]")
            .finish_non_exhaustive()
    }
}

/// What fd 3 carries: the chain, first jump to target.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Params {
    pub hops: Vec<PtyHop>,
}

/// What the runner gives the terminal host to start `ssh-pty`.
pub struct Launch {
    pub program: String,
    pub args: Vec<String>,
    pub fd3: Hidden,
}

impl SshDriver {
    /// Redeems every hop's lease and packs the keys for `ssh-pty`'s descriptor 3. Refuses what
    /// `ssh.exec` refuses (hop limits, bad fields) and an unreadable key, before any terminal starts.
    pub async fn terminal_launch(&self, req: &SshTerminal) -> Result<Launch, StreamError> {
        if req.hops.len() > MAX_SSH_HOPS {
            return Err(invalid("at most 3 jump hosts"));
        }
        let chain: Vec<&SshHop> = req.hops.iter().chain([&req.target]).collect();
        for hop in &chain {
            check_hop(hop)?;
        }
        let redeem = async {
            let mut hops = Vec::with_capacity(chain.len());
            for h in &chain {
                let text = self.key_text(&h.lease).await?;
                parse_key(&text).map_err(|m| fail(ErrorCode::SshAuthFailed, m))?;
                hops.push(PtyHop {
                    host: h.host.clone(),
                    port: h.port,
                    user: h.user.clone(),
                    pinned_keys: h.pinned_keys.clone(),
                    key: text.to_string(),
                });
            }
            Ok::<_, StreamError>(hops)
        };
        let hops = tokio::time::timeout(CONNECT_TIMEOUT, redeem)
            .await
            .map_err(|_| fail(ErrorCode::SshFailed, "timed out redeeming the key leases"))??;
        let blob = Zeroizing::new(
            serde_json::to_vec(&Params { hops })
                .map_err(|_| fail(ErrorCode::Internal, "cannot pack the terminal's keys"))?,
        );
        if blob.len() > FD3_MAX {
            return Err(invalid("the chain's keys are too large for one terminal"));
        }
        let program = match &self.bin {
            Some(bin) => bin.clone(),
            None => std::env::current_exe()
                .map_err(|e| fail(ErrorCode::SpawnFailed, format!("no runner binary: {e}")))?,
        };
        use base64::Engine;
        Ok(Launch {
            program: program.to_string_lossy().into_owned(),
            args: vec!["ssh-pty".to_owned()],
            fd3: Hidden(base64::engine::general_purpose::STANDARD.encode(&*blob)),
        })
    }
}

/// The person's side of the terminal: bytes typed, bytes shown, size changes, and a stop.
pub(crate) struct Term<O> {
    pub input: mpsc::UnboundedReceiver<Vec<u8>>,
    pub out: O,
    /// Rows and columns now.
    pub size: (u16, u16),
    pub resize: mpsc::UnboundedReceiver<(u16, u16)>,
    /// The `TERM` the remote pty asks for.
    pub name: String,
}

/// Printable text from the host only: no control characters, newlines as CR LF.
fn clean(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\n' => Some("\r\n".to_owned()),
            c if c.is_control() => None,
            c => Some(c.to_string()),
        })
        .collect()
}

impl<O: AsyncWrite + Unpin> Term<O> {
    async fn show(&mut self, text: &str) {
        let _ = self.out.write_all(text.as_bytes()).await;
        let _ = self.out.flush().await;
    }

    /// A line typed by the person, with echo on or off. `None`: cancelled (Ctrl-C, Ctrl-D, or the
    /// terminal went away). The answer is wiped when dropped.
    async fn ask(&mut self, prompt: &str, echo: bool) -> Option<Zeroizing<String>> {
        let p = clean(prompt);
        self.show(&p).await;
        let mut line = Zeroizing::new(Vec::<u8>::new());
        let mut escape = false;
        loop {
            let chunk = self.input.recv().await?;
            for b in chunk {
                if escape {
                    // The rest of an arrow or function key: `ESC [ … final`.
                    escape = !(0x40..=0x7e).contains(&b) || b == b'[';
                    continue;
                }
                match b {
                    0x1b => escape = true,
                    b'\r' | b'\n' => {
                        self.show("\r\n").await;
                        // Bytes typed ahead are dropped with the line, not sent to a shell.
                        return Some(Zeroizing::new(String::from_utf8_lossy(&line).into_owned()));
                    }
                    0x03 | 0x04 => {
                        self.show("\r\n").await;
                        return None;
                    }
                    0x7f | 0x08 => {
                        // Back over one UTF-8 character.
                        while let Some(last) = line.pop() {
                            if last & 0xc0 != 0x80 {
                                break;
                            }
                        }
                        if echo {
                            self.show("\x08 \x08").await;
                        }
                    }
                    b if b >= 0x20 && line.len() < MAX_ANSWER => {
                        line.push(b);
                        if echo && b < 0x80 {
                            self.show(&char::from(b).to_string()).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// `publickey` with the hop's key, then, while the host still offers them, keyboard-interactive and
/// password, answered by the person typing.
struct PromptAuth<'a, O> {
    keys: VecDeque<Zeroizing<String>>,
    term: &'a mut Term<O>,
}

fn denied(index: usize, why: &str) -> StreamError {
    fail(ErrorCode::SshAuthFailed, format!("hop {index}: {why}"))
}

fn ended(index: usize) -> StreamError {
    denied(index, "the connection ended during authentication")
}

impl<O: AsyncWrite + Unpin + Send> HopAuth for PromptAuth<'_, O> {
    async fn authenticate(
        &mut self,
        handle: &mut Handle<Verify>,
        hop: &SshHop,
        index: usize,
    ) -> Result<(), StreamError> {
        let text = (self.keys.pop_front()).ok_or_else(|| fail(ErrorCode::Internal, "no key"))?;
        let key: PrivateKey =
            parse_key(&text).map_err(|m| fail(ErrorCode::SshAuthFailed, m.to_owned()))?;
        drop(text);
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let mut res = handle
            .authenticate_publickey(&hop.user, key)
            .await
            .map_err(|_| ended(index))?;
        let (mut keyboard, mut password, mut announced) = (ATTEMPTS, ATTEMPTS, false);
        loop {
            let AuthResult::Failure {
                remaining_methods, ..
            } = res
            else {
                return Ok(());
            };
            let methods = remaining_methods;
            let want_keyboard = keyboard > 0 && methods.contains(&MethodKind::KeyboardInteractive);
            let want_password = password > 0 && methods.contains(&MethodKind::Password);
            if !(want_keyboard || want_password) {
                return Err(denied(index, "the host refused the key"));
            }
            if !announced {
                announced = true;
                let who = clean(&format!("{}@{}", hop.user, hop.host));
                self.term.show(&format!("{who}\r\n")).await;
            }
            res = if want_keyboard {
                keyboard -= 1;
                self.keyboard(handle, hop, index).await?
            } else {
                password -= 1;
                let answer = (self.term.ask("Password: ", false).await)
                    .ok_or_else(|| denied(index, "cancelled"))?;
                handle
                    .authenticate_password(&hop.user, answer.as_str())
                    .await
                    .map_err(|_| ended(index))?
            };
        }
    }
}

impl<O: AsyncWrite + Unpin + Send> PromptAuth<'_, O> {
    /// One keyboard-interactive exchange: every prompt the host sends is shown and answered.
    async fn keyboard(
        &mut self,
        handle: &mut Handle<Verify>,
        hop: &SshHop,
        index: usize,
    ) -> Result<AuthResult, StreamError> {
        let mut reply = handle
            .authenticate_keyboard_interactive_start(&hop.user, None)
            .await
            .map_err(|_| ended(index))?;
        for _ in 0..8 {
            match reply {
                KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
                KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    return Ok(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    for text in [&name, &instructions] {
                        if !text.is_empty() {
                            self.term.show(&format!("{}\r\n", clean(text))).await;
                        }
                    }
                    let mut answers = Vec::with_capacity(prompts.len());
                    let mut wipe = Vec::with_capacity(prompts.len());
                    for p in &prompts {
                        let a = (self.term.ask(&p.prompt, p.echo).await)
                            .ok_or_else(|| denied(index, "cancelled"))?;
                        answers.push(a.to_string());
                        wipe.push(a);
                    }
                    reply = handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .map_err(|_| ended(index))?;
                }
            }
        }
        Err(denied(index, "too many keyboard-interactive rounds"))
    }
}

/// The exit code and the line a failure prints.
fn exit_for(e: &StreamError) -> (i32, String) {
    let (code, what) = match e.code {
        ErrorCode::HostKeyUnknown => (SSH_PTY_EXIT_HOST_KEY_UNKNOWN, "host key unknown"),
        ErrorCode::HostKeyChanged => (SSH_PTY_EXIT_HOST_KEY_CHANGED, "host key changed"),
        ErrorCode::SshAuthFailed => (SSH_PTY_EXIT_AUTH_FAILED, "authentication failed"),
        _ => (SSH_PTY_EXIT_FAILED, "connection failed"),
    };
    let line = match &e.host_key {
        Some(k) => format!("{what}: {} (hop {}); {}", k.fingerprint, k.hop, e.message),
        None => format!("{what}: {}", e.message),
    };
    (code, line)
}

/// Connects, authenticates and runs the remote login shell on this terminal until it ends; the
/// exit code of this process. `stop` carries an exit code when the terminal is being closed.
pub(crate) async fn run<O: AsyncWrite + Unpin + Send>(
    mut params: Params,
    mut term: Term<O>,
    mut stop: mpsc::UnboundedReceiver<i32>,
) -> i32 {
    let hops: Vec<SshHop> = params
        .hops
        .iter()
        .map(|h| SshHop {
            host: h.host.clone(),
            port: h.port,
            user: h.user.clone(),
            pinned_keys: h.pinned_keys.clone(),
            lease: String::new(),
        })
        .collect();
    let keys: VecDeque<Zeroizing<String>> = (params.hops.iter_mut())
        .map(|h| Zeroizing::new(std::mem::take(&mut h.key)))
        .collect();
    drop(params);
    if hops.is_empty() || hops.len() > MAX_SSH_HOPS + 1 {
        term.show("ssh terminal: bad parameters\r\n").await;
        return SSH_PTY_EXIT_FAILED;
    }
    let chain: Vec<&SshHop> = hops.iter().collect();
    let mut auth = PromptAuth {
        keys,
        term: &mut term,
    };
    let conn = tokio::select! {
        c = dial_chain(&chain, config(true), &mut auth, &|m| m) => c,
        Some(code) = stop.recv() => return code,
    };
    drop(auth);
    let conn = match conn {
        Ok(c) => c,
        Err(e) => {
            let (code, line) = exit_for(&e);
            term.show(&format!("\r\n{}\r\n", clean(&line))).await;
            return code;
        }
    };
    let (rows, cols) = term.size;
    let mut ch = match conn.handle.channel_open_session().await {
        Ok(ch) => ch,
        Err(_) => {
            term.show("\r\ncannot open a channel\r\n").await;
            return SSH_PTY_EXIT_FAILED;
        }
    };
    let started = async {
        ch.request_pty(
            true,
            &term.name,
            u32::from(cols),
            u32::from(rows),
            0,
            0,
            &[],
        )
        .await?;
        ch.request_shell(true).await
    };
    if started.await.is_err() {
        term.show("\r\ncannot start a shell\r\n").await;
        return SSH_PTY_EXIT_FAILED;
    }
    let mut code = None;
    loop {
        tokio::select! {
            msg = ch.wait() => match msg {
                Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. }) => {
                    if term.out.write_all(&data).await.is_err() || term.out.flush().await.is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    code = Some(i32::try_from(exit_status).unwrap_or(SSH_PTY_EXIT_FAILED));
                }
                Some(ChannelMsg::ExitSignal { .. }) => code = Some(SSH_PTY_EXIT_FAILED),
                Some(ChannelMsg::Failure) => {
                    term.show("\r\nthe host refused a terminal or a shell\r\n").await;
                    code = Some(SSH_PTY_EXIT_FAILED);
                    break;
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            typed = term.input.recv() => match typed {
                Some(bytes) => {
                    if ch.data(&bytes[..]).await.is_err() {
                        break;
                    }
                }
                None => {
                    let _ = ch.close().await;
                    break;
                }
            },
            Some((rows, cols)) = term.resize.recv() => {
                let _ = ch.window_change(u32::from(cols), u32::from(rows), 0, 0).await;
            }
            Some(c) = stop.recv() => {
                let _ = ch.close().await;
                return c;
            }
        }
    }
    match code {
        Some(c) => c,
        None => {
            term.show("\r\nconnection closed\r\n").await;
            SSH_PTY_EXIT_FAILED
        }
    }
}

/// Descriptor 3 as the terminal host left it: the parameters, read to the end, at most
/// `FD3_MAX` bytes. The pipe is opened by path, so no `unsafe` is needed to adopt it.
fn read_params() -> Result<Params, &'static str> {
    let mut f = std::fs::File::open("/dev/fd/3").map_err(|_| "no key handoff on descriptor 3")?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.by_ref()
        .take(FD3_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read the key handoff")?;
    if bytes.len() > FD3_MAX {
        return Err("the key handoff is too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "the key handoff is not valid")
}

/// `ainkrad-runner ssh-pty`: stdin and stdout are the terminal (a PTY), descriptor 3 the handoff.
pub async fn pty_main() -> ExitCode {
    use tokio::signal::unix::{SignalKind, signal};
    let params = match read_params() {
        Ok(p) => p,
        Err(why) => {
            eprintln!("ssh-pty: {why}; it is started by the runner, not by hand");
            return ExitCode::from(255);
        }
    };
    let Ok(raw) = ainkrad_sys::raw_mode(std::io::stdin().as_fd()) else {
        eprintln!("ssh-pty: stdin is not a terminal; it is started by the runner, not by hand");
        return ExitCode::from(255);
    };
    let size = |fallback: (u16, u16)| {
        ainkrad_sys::tty_size(std::io::stdout().as_fd())
            .ok()
            .filter(|(r, c)| *r > 0 && *c > 0)
            .unwrap_or(fallback)
    };
    let (input_tx, input) = mpsc::unbounded_channel();
    // A thread, not a task: a blocking read must not hold the runtime's end.
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || input_tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let (resize_tx, resize) = mpsc::unbounded_channel();
    let (stop_tx, stop) = mpsc::unbounded_channel();
    if let Ok(mut winch) = signal(SignalKind::window_change()) {
        tokio::spawn(async move {
            while winch.recv().await.is_some() {
                let _ = resize_tx.send(size((24, 80)));
            }
        });
    }
    for (kind, code) in [(SignalKind::hangup(), 129), (SignalKind::terminate(), 143)] {
        if let Ok(mut s) = signal(kind) {
            let tx = stop_tx.clone();
            tokio::spawn(async move {
                s.recv().await;
                let _ = tx.send(code);
            });
        }
    }
    let term = Term {
        input,
        out: tokio::io::stdout(),
        size: size((24, 80)),
        resize,
        name: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned()),
    };
    let code = run(params, term, stop).await;
    drop(raw);
    ExitCode::from(u8::try_from(code & 0xff).unwrap_or(255))
}
