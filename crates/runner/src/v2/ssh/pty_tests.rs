//! `ssh-pty` against an in-process `russh` shell server: the terminal session, resize, host-key
//! refusals before authentication, password and keyboard-interactive prompts, and what the key
//! handoff carries. The end-to-end test through `PtyOpen` (resume, seeded-secret scan) is in
//! `terminal_tests` below.

use std::borrow::Cow;
use std::sync::Mutex;
use std::sync::atomic::Ordering::SeqCst;

use ainkrad_proto::v2::{
    SSH_PTY_EXIT_AUTH_FAILED, SSH_PTY_EXIT_HOST_KEY_CHANGED, SSH_PTY_EXIT_HOST_KEY_UNKNOWN,
    SshTerminal,
};
use russh::MethodKind;
use russh::keys::ssh_key::LineEnding;
use russh::server::{Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, Pty};
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::fixture::{Leases, fp, new_key, ssh};
use super::pty::{Params, PtyHop, Term, run};
use super::*;

mod real;

pub(in crate::v2) const PASSWORD: &str = "hunter2-Tr1cky";
const CODE: &str = "424242";

/// What the shell server saw.
#[derive(Default)]
pub(in crate::v2) struct Log {
    pub(in crate::v2) auths: AtomicUsize,
    pub(in crate::v2) ptys: Mutex<Vec<(String, u32, u32)>>,
    pub(in crate::v2) windows: Mutex<Vec<(u32, u32)>>,
    pub(in crate::v2) passwords: Mutex<Vec<String>>,
    pub(in crate::v2) codes: Mutex<Vec<String>>,
}

#[derive(Clone)]
pub(in crate::v2) struct Shell {
    pub(in crate::v2) accept_key: bool,
    pub(in crate::v2) log: Arc<Log>,
}

impl russh::server::Server for Shell {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for Shell {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        self.log.auths.fetch_add(1, SeqCst);
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.log.auths.fetch_add(1, SeqCst);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.log.auths.fetch_add(1, SeqCst);
        Ok(if self.accept_key {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<Auth, Self::Error> {
        self.log.passwords.lock().unwrap().push(password.to_owned());
        Ok(if password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let Some(mut response) = response else {
            return Ok(Auth::Partial {
                name: "Login".into(),
                // An escape sequence in what the host sends: it must not reach the terminal.
                instructions: "Type the code\x1b]0;pwned\x07".into(),
                prompts: Cow::Owned(vec![("Code: ".into(), false)]),
            });
        };
        let code = response
            .next()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let ok = code == CODE;
        self.log.codes.lock().unwrap().push(code);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log
            .ptys
            .lock()
            .unwrap()
            .push((term.to_owned(), cols, rows));
        session.channel_success(channel)
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.windows.lock().unwrap().push((cols, rows));
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ready\r\n".to_vec())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let text = String::from_utf8_lossy(data).into_owned();
        if text.contains("exit") {
            session.exit_status_request(channel, 5)?;
            session.eof(channel)?;
            return session.close(channel);
        }
        session.data(channel, format!("got:{text}\r\n").into_bytes())
    }
}

pub(in crate::v2) struct Host {
    pub(in crate::v2) port: u16,
    pub(in crate::v2) host_key: PrivateKey,
    pub(in crate::v2) log: Arc<Log>,
}

impl Host {
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

pub(in crate::v2) async fn shell(accept_key: bool, password: bool, keyboard: bool) -> Host {
    let mut methods = vec![MethodKind::PublicKey];
    if password {
        methods.push(MethodKind::Password);
    }
    if keyboard {
        methods.push(MethodKind::KeyboardInteractive);
    }
    let config = russh::server::Config {
        keys: vec![new_key()],
        methods: methods.as_slice().into(),
        auth_rejection_time: Duration::from_millis(5),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    };
    let host_key = config.keys[0].clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Log::default());
    let mut server = Shell {
        accept_key,
        log: Arc::clone(&log),
    };
    tokio::spawn(async move {
        let _ = server.run_on_socket(Arc::new(config), &listener).await;
    });
    Host {
        port,
        host_key,
        log,
    }
}

/// Everything written to the terminal.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl AsyncWrite for Sink {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    async fn until(&self, needle: &str) {
        for _ in 0..200 {
            if self.text().contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("never saw {needle:?}; terminal shows {:?}", self.text());
    }
}

/// A running `ssh-pty` session and the person's side of its terminal.
struct Rig {
    typed: mpsc::UnboundedSender<Vec<u8>>,
    resize: mpsc::UnboundedSender<(u16, u16)>,
    stop: mpsc::UnboundedSender<i32>,
    shown: Sink,
    ended: tokio::task::JoinHandle<i32>,
}

impl Rig {
    fn start(params: Params) -> Self {
        let (typed, input) = mpsc::unbounded_channel();
        let (resize_tx, resize) = mpsc::unbounded_channel();
        let (stop, stop_rx) = mpsc::unbounded_channel();
        let shown = Sink::default();
        let term = Term {
            input,
            out: shown.clone(),
            size: (24, 80),
            resize,
            name: "xterm-256color".to_owned(),
        };
        Self {
            typed,
            resize: resize_tx,
            stop,
            shown,
            ended: tokio::spawn(run(params, term, stop_rx)),
        }
    }

    fn type_(&self, text: &str) {
        // A closed session (it ended) drops the keys, as a terminal would.
        let _ = self.typed.send(text.as_bytes().to_vec());
    }

    async fn code(self) -> i32 {
        tokio::time::timeout(Duration::from_secs(10), self.ended)
            .await
            .expect("ssh-pty did not end")
            .unwrap()
    }
}

fn hop(h: &SshHop, key: &PrivateKey) -> PtyHop {
    PtyHop {
        host: h.host.clone(),
        port: h.port,
        user: h.user.clone(),
        pinned_keys: h.pinned_keys.clone(),
        key: key.to_openssh(LineEnding::LF).unwrap().to_string(),
    }
}

fn params(h: &SshHop, key: &PrivateKey) -> Params {
    Params {
        hops: vec![hop(h, key)],
    }
}

#[tokio::test]
async fn a_shell_session_carries_input_output_resize_and_the_remote_exit_code() {
    let s = shell(true, false, false).await;
    let rig = Rig::start(params(&s.hop("me", "-"), &new_key()));
    rig.shown.until("ready").await;
    rig.type_("hello");
    rig.shown.until("got:hello").await;
    rig.resize.send((40, 132)).unwrap();
    for _ in 0..100 {
        if !s.log.windows.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*s.log.windows.lock().unwrap(), [(132, 40)], "cols, rows");
    assert_eq!(
        *s.log.ptys.lock().unwrap(),
        [("xterm-256color".to_owned(), 80, 24)],
        "the remote pty starts at the terminal's size"
    );
    rig.type_("exit\r");
    assert_eq!(rig.code().await, 5, "the remote shell's exit code");
}

#[tokio::test]
async fn closing_the_terminal_ends_the_session() {
    let s = shell(true, false, false).await;
    let rig = Rig::start(params(&s.hop("me", "-"), &new_key()));
    rig.shown.until("ready").await;
    rig.stop.send(129).unwrap();
    assert_eq!(rig.code().await, 129);
}

#[tokio::test]
async fn a_wrong_or_unknown_host_key_aborts_before_any_authentication_and_shows_the_fingerprint() {
    for (pinned, exit, what) in [
        (
            Some(fp(&new_key())),
            SSH_PTY_EXIT_HOST_KEY_CHANGED,
            "changed",
        ),
        (None, SSH_PTY_EXIT_HOST_KEY_UNKNOWN, "unknown"),
    ] {
        let s = shell(true, true, true).await;
        let mut h = s.hop("me", "-");
        h.pinned_keys = pinned.into_iter().collect();
        let rig = Rig::start(params(&h, &new_key()));
        let shown = rig.shown.clone();
        assert_eq!(rig.code().await, exit);
        let text = shown.text();
        assert!(
            text.contains(&format!("host key {what}: {}", fp(&s.host_key))),
            "{text:?}"
        );
        assert_eq!(s.log.auths.load(SeqCst), 0, "no authentication was sent");
        assert!(s.log.passwords.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_password_typed_in_the_terminal_logs_in_and_is_not_echoed() {
    let s = shell(false, true, false).await;
    let rig = Rig::start(params(&s.hop("me", "-"), &new_key()));
    rig.shown.until("Password: ").await;
    // Typed in pieces, with a correction: backspace removes the last character.
    rig.type_("hunterX");
    rig.type_("\x7f2-Tr1cky");
    rig.type_("\r");
    rig.shown.until("ready").await;
    assert_eq!(*s.log.passwords.lock().unwrap(), [PASSWORD]);
    let shown = rig.shown.text();
    assert!(
        !shown.contains("hunter"),
        "the password was echoed: {shown:?}"
    );
    rig.type_("exit\r");
    assert_eq!(rig.code().await, 5);
}

#[tokio::test]
async fn wrong_passwords_end_with_the_auth_exit_code_and_no_password_is_shown() {
    let s = shell(false, true, false).await;
    let rig = Rig::start(params(&s.hop("me", "-"), &new_key()));
    for guess in ["wrong-one", "wrong-two", "wrong-three"] {
        rig.shown.until("Password: ").await;
        rig.type_(&format!("{guess}\r"));
        // The next prompt (or the end) shows after the answer is judged.
        for _ in 0..100 {
            if s.log.passwords.lock().unwrap().iter().any(|p| p == guess) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let shown = rig.shown.clone();
    assert_eq!(rig.code().await, SSH_PTY_EXIT_AUTH_FAILED);
    assert!(!shown.text().contains("wrong-"), "{:?}", shown.text());
    // The host may stop offering `password` after a refusal; at most three tries either way.
    assert!((1..=3).contains(&s.log.passwords.lock().unwrap().len()));
}

#[tokio::test]
async fn a_keyboard_interactive_prompt_is_answered_in_the_terminal_and_the_host_text_is_clean() {
    let s = shell(false, false, true).await;
    let rig = Rig::start(params(&s.hop("me", "-"), &new_key()));
    rig.shown.until("Code: ").await;
    rig.type_(CODE);
    rig.type_("\r");
    rig.shown.until("ready").await;
    assert_eq!(*s.log.codes.lock().unwrap(), [CODE]);
    let shown = rig.shown.text();
    assert!(shown.contains("Type the code"), "{shown:?}");
    // Control characters of the host's text are dropped: no escape or bell reaches the terminal.
    assert!(
        !shown.contains('\x1b') && !shown.contains('\x07'),
        "{shown:?}"
    );
    assert!(!shown.contains(CODE), "the answer was echoed: {shown:?}");
}

#[test]
fn the_handoff_never_prints_a_key() {
    let key = new_key();
    let p = params(
        &SshHop {
            host: "h".into(),
            port: 22,
            user: "u".into(),
            pinned_keys: vec![],
            lease: String::new(),
        },
        &key,
    );
    let body = p.hops[0].key.lines().nth(1).unwrap().to_owned();
    assert!(!format!("{p:?}").contains(&body));
    assert!(
        serde_json::to_string(&p).unwrap().contains(&body),
        "control"
    );
}

#[tokio::test]
async fn the_launch_carries_every_hops_key_whatever_the_leases_delivery_and_refuses_bad_chains() {
    let leases = Leases::default();
    let (a, b) = (
        shell(true, false, false).await,
        shell(true, false, false).await,
    );
    let (ka, kb) = (leases.key("l_a"), leases.key("l_b"));
    let d = ssh(&leases);
    let req = SshTerminal {
        target: b.hop("me", "l_b"),
        hops: vec![a.hop("jump", "l_a")],
    };
    let launch = d.terminal_launch(&req).await.unwrap();
    assert_eq!(launch.args, ["ssh-pty"]);
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(launch.fd3.0.as_bytes())
        .unwrap();
    let got: Params = serde_json::from_slice(&blob).unwrap();
    let users: Vec<&str> = got.hops.iter().map(|h| h.user.as_str()).collect();
    assert_eq!(users, ["jump", "me"], "first jump to target");
    let pem = |k: &PrivateKey| k.to_openssh(LineEnding::LF).unwrap().to_string();
    assert_eq!(
        (got.hops[0].key.clone(), got.hops[1].key.clone()),
        (pem(&ka), pem(&kb))
    );
    assert_eq!(got.hops[1].pinned_keys, b.pin());
    // An unredeemable lease, an unreadable key and four jumps are refused before any terminal.
    leases.add("l_bad", "not a key");
    for (lease, code) in [
        ("l_missing", ErrorCode::SshAuthFailed),
        ("l_bad", ErrorCode::SshAuthFailed),
    ] {
        let req = SshTerminal {
            target: b.hop("me", lease),
            hops: vec![],
        };
        assert_eq!(d.terminal_launch(&req).await.err().unwrap().code, code);
    }
    let four = SshTerminal {
        target: b.hop("me", "l_b"),
        hops: (0..4).map(|_| a.hop("j", "l_a")).collect(),
    };
    assert_eq!(
        d.terminal_launch(&four).await.err().unwrap().code,
        ErrorCode::InvalidArgs
    );
}

/// R2-1: the runner takes what Leyline's `valid::address` takes (`. : % _ -`, 255 bytes, no leading
/// `-`), and nothing it refuses.
#[test]
fn a_host_is_what_leylines_address_rule_allows() {
    let long = "a".repeat(255);
    for ok in [
        "db.example.com",
        "10.0.0.1",
        "fe80::1%en0",
        "::1",
        "a_b-c",
        long.as_str(),
    ] {
        assert!(host_ok(ok), "{ok}");
    }
    let too_long = "a".repeat(256);
    for bad in [
        "",
        "-oProxyCommand=x",
        "a b",
        "a;b",
        "a=b",
        "a\nb",
        "é",
        too_long.as_str(),
    ] {
        assert!(!host_ok(bad), "{bad:?}");
    }
}
