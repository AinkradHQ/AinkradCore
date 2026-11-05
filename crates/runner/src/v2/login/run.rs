//! One sign-in's life: the PTY, the output, the code, the ending (KAN-441 L2).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, LoginResult, LoginUrl, StreamError};
use ainkrad_ptyhost::pty::{self, Pty, Spec};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::parse::{self, Screen};
use super::{
    LoginDriver, MAX_OUTPUT, Msg, PROMPT_QUIET, QUIET, SIZE, TICK, child_env, err, make_stubs,
    private_dir, result, runner_env,
};

/// Removes a sign-in's scratch dir and its `active` entry when dropped, so a panic or an abort of
/// the task cannot leave either behind.
pub(super) struct Guard {
    pub(super) driver: Arc<LoginDriver>,
    pub(super) id: String,
    pub(super) scratch: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        self.driver
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

impl LoginDriver {
    /// Runs one sign-in to its end, cleans up, then answers whoever waits.
    pub(super) async fn run(
        self: Arc<Self>,
        id: String,
        mut rx: mpsc::UnboundedReceiver<Msg>,
        url_tx: oneshot::Sender<Result<LoginUrl, StreamError>>,
    ) {
        let scratch = self.cfg.root.join(&id);
        let guard = Guard {
            driver: Arc::clone(&self),
            id: id.clone(),
            scratch: scratch.clone(),
        };
        let mut run = Run {
            url_tx: Some(url_tx),
            code_tx: None,
            acks: Vec::new(),
        };
        let end = self.drive(&id, &scratch, &mut rx, &mut run).await;
        drop(guard);
        // Late messages (a code that raced the ending) get no answer from the dropped channel.
        rx.close();
        run.finish(&id, end);
    }

    async fn drive(
        &self,
        id: &str,
        scratch: &Path,
        rx: &mut mpsc::UnboundedReceiver<Msg>,
        run: &mut Run,
    ) -> End {
        for d in ["home", "tmp"] {
            if private_dir(&scratch.join(d)).is_err() {
                return End::Fail("the runner could not make a scratch directory".to_owned());
            }
        }
        if make_stubs(scratch).is_err() {
            return End::Fail("the runner could not make a scratch directory".to_owned());
        }
        // `claude` updates itself: a version off the pinned list is not driven.
        if let Err(why) = self.version(scratch).await {
            return End::Unsupported(why);
        }
        let spec = Spec {
            program: Some(self.cfg.program.display().to_string()),
            args: self
                .cfg
                .args
                .iter()
                .cloned()
                .chain(["setup-token".to_owned()])
                .collect(),
            cwd: Some(scratch.join("home").display().to_string()),
            env: child_env(&runner_env(), scratch),
            size: SIZE,
            scrollback_bytes: None,
        };
        let Ok(spawned) = Pty::spawn(&spec) else {
            return End::Fail("claude could not be started".to_owned());
        };
        let (mut pty, mut reader, mut writer, mut exit) =
            (spawned.pty, spawned.reader, spawned.writer, spawned.exit);
        // Output may hold the echo of the code or the token: every copy here wipes itself.
        let (out_tx, mut out) = mpsc::channel::<Zeroizing<Vec<u8>>>(64);
        std::thread::spawn(move || {
            let mut buf = Zeroizing::new([0u8; 4096]);
            while let Ok(n) = reader.read(&mut buf[..]) {
                if n == 0
                    || out_tx
                        .blocking_send(Zeroizing::new(buf[..n].to_vec()))
                        .is_err()
                {
                    break;
                }
            }
        });
        let end = self
            .watch(id, rx, run, &mut out, &mut writer, &mut pty, &mut exit)
            .await;
        // Kill first (the whole process group), then reap; the caller wipes the scratch dir.
        pty::hang_up(pty.pid, self.cfg.grace, exit.clone()).await;
        // A leader that ended by itself leaves its children: the zombie still holds the group id.
        if let Some(kill) = ainkrad_sys::signal_number("KILL") {
            let _ = ainkrad_sys::killpg(pty.pid, kill);
        }
        pty.reap();
        end
    }

    #[allow(clippy::too_many_arguments)]
    async fn watch(
        &self,
        id: &str,
        rx: &mut mpsc::UnboundedReceiver<Msg>,
        run: &mut Run,
        out: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>,
        writer: &mut Box<dyn Write + Send>,
        pty: &mut Pty,
        exit: &mut tokio::sync::watch::Receiver<Option<pty::Exit>>,
    ) -> End {
        let mut screen = Screen::new(usize::from(SIZE.cols));
        let (now, mut bytes) = (Instant::now(), 0usize);
        let deadline = now + self.cfg.timeout;
        let url_deadline = now + self.cfg.url_timeout;
        let (mut last_out, mut url_at) = (now, None::<Instant>);
        let mut pending: Option<(Zeroizing<String>, oneshot::Sender<LoginResult>)> = None;
        let mut typed = false;
        let mut typed_at = None::<Instant>;
        // Kept to mask it in what the child says back (the terminal echoes what is typed).
        let mut sent = Zeroizing::new(String::new());
        let (mut exited, mut drain) = (false, None::<Instant>);
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                chunk = out.recv() => {
                    let Some(chunk) = chunk else {
                        return self.ended(&mut screen, typed, exit, run.url_tx.is_some(), &sent).await;
                    };
                    bytes += chunk.len();
                    if bytes > MAX_OUTPUT {
                        return End::Fail("claude printed far more than a sign-in does".to_owned());
                    }
                    last_out = Instant::now();
                    screen.feed(&chunk);
                }
                _ = tick.tick() => {
                    let quiet = last_out.elapsed();
                    if quiet >= QUIET && !screen.idle() {
                        screen.flush();
                    }
                    if Instant::now() >= deadline {
                        return End::Fail("the sign-in timed out".to_owned());
                    }
                    if let Some(at) = typed_at && at.elapsed() >= self.cfg.answer_timeout {
                        screen.flush();
                        let last = parse::last_line(screen.done(), &screen.tail(), &[&sent])
                            .map(|l| format!(" (it last said: {l})"))
                            .unwrap_or_default();
                        return End::Fail(format!(
                            "claude gave no token within {}s of the code; the code may be wrong or expired{last}",
                            self.cfg.answer_timeout.as_secs()
                        ));
                    }
                    if url_at.is_none() && Instant::now() >= url_deadline {
                        return End::Fail("claude showed no sign-in URL in time".to_owned());
                    }
                    if url_at.is_some() {
                        let ready = parse::asks_for_code(screen.done(), &screen.tail());
                        if pending.is_some() && !typed && (ready || quiet >= PROMPT_QUIET) {
                            let (code, tx) = pending.take().unwrap();
                            if type_code(writer, &code, self.cfg.enter_delay).await.is_err() {
                                return End::Fail("the code could not be typed".to_owned());
                            }
                            typed = true;
                            typed_at = Some(Instant::now());
                            sent = code;
                            run.code_tx = Some(tx);
                            // Anything the child printed before the code is not its answer.
                            screen.wipe();
                        }
                    }
                }
                Some(msg) = rx.recv() => match msg {
                    Msg::Cancel(ack) => {
                        run.acks.push(ack);
                        if let Some((_, tx)) = pending.take() {
                            run.code_tx = Some(tx);
                        }
                        return End::Cancelled;
                    }
                    Msg::Code(code, tx) => {
                        if typed || pending.is_some() {
                            let _ = tx.send(result(id, Some("a code was already given")));
                        } else {
                            pending = Some((code, tx));
                        }
                    }
                },
                _ = exit.changed(), if !exited => {
                    exited = true;
                    pty.release_slave();
                    drain = Some(Instant::now() + Duration::from_secs(1));
                }
                _ = async { tokio::time::sleep_until(drain.unwrap()).await }, if drain.is_some() => {
                    return self.ended(&mut screen, typed, exit, run.url_tx.is_some(), &sent).await;
                }
            }
            // What the new output says.
            if url_at.is_none() {
                if let Some(url) = parse::find_url(screen.done()) {
                    url_at = Some(Instant::now());
                    if let Some(tx) = run.url_tx.take() {
                        let _ = tx.send(Ok(LoginUrl {
                            login_id: id.to_owned(),
                            url,
                        }));
                    }
                } else if parse::asks_for_code(screen.done(), &screen.tail()) {
                    return End::Fail(
                        "claude asked for the code but printed no sign-in URL".to_owned(),
                    );
                }
            } else if typed && let Some(token) = parse::find_token(screen.done()) {
                screen.wipe();
                return End::Token(token);
            }
        }
    }

    /// The output (or the child) ended before a token: say why, with no secret in it.
    async fn ended(
        &self,
        screen: &mut Screen,
        typed: bool,
        exit: &mut tokio::sync::watch::Receiver<Option<pty::Exit>>,
        no_url: bool,
        sent: &str,
    ) -> End {
        screen.flush();
        let _ =
            tokio::time::timeout(Duration::from_millis(500), exit.wait_for(Option::is_some)).await;
        if typed && let Some(t) = parse::find_token(screen.done()) {
            screen.wipe();
            return End::Token(t);
        }
        let how = match exit.borrow().as_ref() {
            Some(pty::Exit { code: Some(0), .. }) => "exited".to_owned(),
            Some(pty::Exit { code: Some(c), .. }) => format!("exited with code {c}"),
            Some(pty::Exit {
                signal: Some(s), ..
            }) => format!("was ended by {s}"),
            _ => "closed its output".to_owned(),
        };
        let phase = match (no_url, typed) {
            (true, _) => "before it showed a sign-in URL",
            (false, true) => "before it printed a token",
            (false, false) => "before it was given the code",
        };
        let last = parse::last_line(screen.done(), &screen.tail(), &[sent])
            .map(|l| format!(" (it last said: {l})"))
            .unwrap_or_default();
        End::Fail(format!("claude {how} {phase}{last}"))
    }
}

/// The code, then its Enter as a write of its own `delay` later (see `ENTER_DELAY`); a zero
/// `delay` sends both in one write.
async fn type_code(
    writer: &mut Box<dyn Write + Send>,
    code: &str,
    delay: Duration,
) -> std::io::Result<()> {
    if delay.is_zero() {
        let mut line = Zeroizing::new(Vec::with_capacity(code.len() + 1));
        line.extend_from_slice(code.as_bytes());
        line.push(b'\r');
        writer.write_all(&line)?;
        return writer.flush();
    }
    writer.write_all(code.as_bytes())?;
    writer.flush()?;
    tokio::time::sleep(delay).await;
    writer.write_all(b"\r")?;
    writer.flush()
}

enum End {
    Token(Zeroizing<String>),
    Fail(String),
    /// The CLI is not one this runner can drive (version drift); the Core may use another runner.
    Unsupported(String),
    Cancelled,
}

/// Who waits for an answer.
struct Run {
    url_tx: Option<oneshot::Sender<Result<LoginUrl, StreamError>>>,
    code_tx: Option<oneshot::Sender<LoginResult>>,
    acks: Vec<oneshot::Sender<()>>,
}

impl Run {
    fn finish(mut self, id: &str, end: End) {
        if let Some(tx) = self.url_tx.take() {
            let (code, why) = match &end {
                End::Cancelled => (ErrorCode::Cancelled, "the sign-in was cancelled".to_owned()),
                End::Fail(w) => (ErrorCode::Internal, w.clone()),
                End::Unsupported(w) => (ErrorCode::UnsupportedCommand, w.clone()),
                End::Token(_) => (ErrorCode::Internal, "the sign-in ended".to_owned()),
            };
            let _ = tx.send(Err(err(code, why)));
        }
        if let Some(tx) = self.code_tx.take() {
            let r = match end {
                // ponytail: the wire type is a plain String, so this copy is not wiped; the
                // session's frame buffer holds it until the Core acknowledges anyway.
                End::Token(t) => LoginResult {
                    login_id: id.to_owned(),
                    token: Some(t.to_string()),
                    error: None,
                },
                End::Fail(w) | End::Unsupported(w) => result(id, Some(&w)),
                End::Cancelled => result(id, Some("cancelled")),
            };
            let _ = tx.send(r);
        }
        for a in self.acks.drain(..) {
            let _ = a.send(());
        }
    }
}
