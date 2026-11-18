//! Terminal recording (Y3-02, plan T9, risk R6). Opt-in per host (`leyline_hosts.record`, off by
//! default): a host with it off gets no row and no file.
//!
//! Security model.
//! - Output only. The tap (`OutputTap`) is called by the Core's relay with the bytes the runner
//!   sent to the client; what a client types never reaches it, and `Cast` has no way to write
//!   input. The file holds `"o"` events only.
//! - Typed passwords: with echo off nothing of them is in the output anyway, and a `Scrub` drops
//!   what follows an echo-off prompt (`Password:`, `[sudo] password for x:`, `Enter passphrase
//!   ...:`) up to the next line break, in case the remote does echo. Prompt detection is a
//!   heuristic on the output text (the Core cannot read the remote's termios); a custom prompt it
//!   does not recognise on a remote that echoes typed secrets is the known gap.
//! - Secrets the remote prints go through the proto `Redactor` before they are written; the last
//!   unfinished word is held back until it is whole, so a secret split across two relay chunks is
//!   still seen whole.
//! - The file is a sequence of `[u32 big-endian length][age blob]` blocks, each the zstd of a few
//!   KiB of cast lines, encrypted to a recipient whose identity is sealed under the Core's master
//!   key. Independent blocks survive a crash (a torn last block is skipped) and are appended
//!   without holding the session in memory. A recording is stopped at `MAX_PLAIN` bytes.
//! - Hot path: `Tap::output` clones the base64 string into a bounded channel and returns; decode,
//!   redaction, compression, encryption and disk writes run on the writer task. A full channel
//!   drops the chunk (a gap in the offsets), never blocks the relay (bench: `benches/relay_tap.rs`).

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{OutputTap, TerminalSize};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sqlx::Row;
use tokio::sync::mpsc;

pub use crate::cast::open_cast;
use crate::cast::{BLOCK, Cast, seal_block};

/// The label the identity is sealed under (a sealed value only opens under its own label).
const LABEL: &str = "leyline.recording.identity";
/// Chunks queued between the relay and the writer.
const QUEUE: usize = 1024;
/// The writer flushes at least this often.
const FLUSH: Duration = Duration::from_secs(2);

// ---- the key -----------------------------------------------------------------------------------

/// The recipient recordings are encrypted to; the identity is made, and sealed under the master
/// key, the first time. Two first uses at once keep the first row.
pub async fn recipient(app: &App) -> Result<Recipient, String> {
    let sealer = app.secrets.as_ref().ok_or("the master key is not loaded")?;
    let read = || async {
        sqlx::query_scalar::<_, String>("SELECT recipient FROM leyline_recording_key WHERE id = 1")
            .fetch_optional(&app.pool)
            .await
            .map_err(|e| e.to_string())
    };
    if read().await?.is_none() {
        let id = Identity::generate();
        let sealed = sealer
            .seal(LABEL, id.to_string().expose_secret().as_bytes())
            .map_err(|e| e.to_string())?;
        sqlx::query(
            "INSERT OR IGNORE INTO leyline_recording_key (id, recipient, key_id, sealed) VALUES (1, ?, ?, ?)",
        )
        .bind(id.to_public().to_string())
        .bind(sealer.key_id())
        .bind(sealed)
        .execute(&app.pool)
        .await
        .map_err(|e| e.to_string())?;
    }
    let text = read().await?.ok_or("the recording key was not stored")?;
    Recipient::from_str(&text).map_err(|e| e.to_owned())
}

/// The identity that opens recordings. Sealed under an older master key, it is sealed again under
/// the current one, so a master-key rotation does not strand recordings.
pub async fn identity(app: &App) -> Result<Identity, String> {
    let sealer = app.secrets.as_ref().ok_or("the master key is not loaded")?;
    let row = sqlx::query("SELECT key_id, sealed FROM leyline_recording_key WHERE id = 1")
        .fetch_optional(&app.pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no recording was ever made")?;
    let key_id: String = row.try_get("key_id").map_err(|e| e.to_string())?;
    let sealed: Vec<u8> = row.try_get("sealed").map_err(|e| e.to_string())?;
    let plain = sealer
        .open_as(&key_id, LABEL, &sealed)
        .map_err(|_| "the recording key did not open".to_owned())?;
    let text = std::str::from_utf8(&plain).map_err(|e| e.to_string())?;
    let id = Identity::from_str(text).map_err(|e| e.to_owned())?;
    if key_id != sealer.key_id()
        && let Ok(fresh) = sealer.seal(LABEL, &plain)
    {
        let _ = sqlx::query(
            "UPDATE leyline_recording_key SET key_id = ?, sealed = ? WHERE id = 1 AND key_id = ?",
        )
        .bind(sealer.key_id())
        .bind(fresh)
        .bind(&key_id)
        .execute(&app.pool)
        .await;
    }
    Ok(id)
}

// ---- the tap and the writer --------------------------------------------------------------------

struct Chunk {
    offset: u64,
    b64: String,
    at: Duration,
}

/// What the relay calls: queue and return.
pub struct Tap {
    tx: mpsc::Sender<Chunk>,
    t0: Instant,
}

impl Tap {
    /// A tap and the queue its writer reads (public for `benches/relay_tap.rs`).
    pub fn queue() -> (Self, Drain) {
        let (tx, rx) = mpsc::channel(QUEUE);
        (
            Self {
                tx,
                t0: Instant::now(),
            },
            Drain(rx),
        )
    }
}

/// The reading end of a [`Tap`].
pub struct Drain(mpsc::Receiver<Chunk>);

impl Drain {
    /// Blocks for the next chunk's size, `None` when every tap is gone (the bench's drain thread).
    pub fn next_blocking(&mut self) -> Option<usize> {
        self.0.blocking_recv().map(|c| c.b64.len())
    }
}

impl OutputTap for Tap {
    fn output(&self, offset: u64, b64: &str) {
        // A full queue loses the chunk (a gap in the offsets); the relay is never made to wait.
        let _ = self.tx.try_send(Chunk {
            offset,
            b64: b64.to_owned(),
            at: self.t0.elapsed(),
        });
    }
}

/// `<data>/leyline/recordings`, next to the Core's database.
pub fn dir(app: &App) -> Result<PathBuf, String> {
    let db = app.pool.connect_options().get_filename().to_path_buf();
    let home = db.parent().ok_or("the database has no directory")?;
    Ok(home.join("leyline").join("recordings"))
}

/// Starts recording `terminal` of `host` when the host has it on. Never fails the terminal: a
/// recording that cannot start is logged and nothing is written.
pub(crate) async fn begin(
    app: &App,
    session: &str,
    host: &str,
    terminal: &str,
    size: TerminalSize,
) {
    let on = sqlx::query_scalar::<_, String>("SELECT record FROM leyline_hosts WHERE id = ?")
        .bind(host)
        .fetch_optional(&app.pool)
        .await;
    if !matches!(&on, Ok(Some(w)) if w == "on") {
        return;
    }
    if let Err(e) = start(app, session, host, terminal, size).await {
        tracing::warn!(error = %e, "a leyline recording could not start");
    }
}

async fn start(
    app: &App,
    session: &str,
    host: &str,
    terminal: &str,
    size: TerminalSize,
) -> Result<(), String> {
    let to = recipient(app).await?;
    let dir = dir(app)?;
    let file = format!("{session}.cast.age");
    let path = dir.join(&file);
    let made = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path.parent().expect("a file in a directory"))?;
            std::fs::OpenOptions::new()
                .create_new(true)
                .append(true)
                .mode(0o600)
                .open(path)
        })
        .await
        .map_err(|e| e.to_string())?
    };
    let out = made.map_err(|e| e.to_string())?;
    let now = app.clock.unix();
    sqlx::query(
        "INSERT INTO leyline_recordings (session, host_id, file, started_at) VALUES (?, ?, ?, ?)",
    )
    .bind(session)
    .bind(host)
    .bind(&file)
    .bind(now)
    .execute(&app.pool)
    .await
    .map_err(|e| e.to_string())?;
    let (tap, drain) = Tap::queue();
    tokio::spawn(run(
        app.clone(),
        session.to_owned(),
        drain.0,
        Cast::new(size, now),
        Sink {
            file: out,
            to,
            bytes: 0,
        },
    ));
    // Last: from here every attach is recorded; the terminal's id has not left the Core yet.
    app.terminals.tap(terminal, Arc::new(tap));
    Ok(())
}

struct Sink {
    file: std::fs::File,
    to: Recipient,
    bytes: u64,
}

impl Sink {
    fn write(&mut self, plain: &[u8]) -> std::io::Result<()> {
        let block = seal_block(plain, &self.to)?;
        self.file.write_all(&block)?;
        self.bytes += block.len() as u64;
        Ok(())
    }
}

/// Writes what the cast holds; `None` when the disk refused (the recording stops there).
async fn flush(app: &App, session: &str, cast: &mut Cast, mut sink: Sink) -> Option<Sink> {
    let plain = cast.take();
    if plain.is_empty() {
        return Some(sink);
    }
    let (sink, wrote) = tokio::task::spawn_blocking(move || {
        let r = sink.write(&plain);
        (sink, r)
    })
    .await
    .ok()?;
    if wrote.is_err() {
        tracing::warn!("a leyline recording could not be written; it stops here");
        return None;
    }
    let _ = sqlx::query("UPDATE leyline_recordings SET bytes = ? WHERE session = ?")
        .bind(i64::try_from(sink.bytes).unwrap_or(i64::MAX))
        .bind(session)
        .execute(&app.pool)
        .await;
    Some(sink)
}

/// The writer: ends when every tap is dropped (the terminal ended, `Rooms::untap`).
async fn run(app: App, session: String, mut rx: mpsc::Receiver<Chunk>, mut cast: Cast, sink: Sink) {
    let mut sink = Some(sink);
    let mut tick = tokio::time::interval(FLUSH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut last, mut fresh) = (0.0, false);
    while let Some(s) = sink.take() {
        tokio::select! {
            c = rx.recv() => {
                let Some(c) = c else { sink = Some(s); break };
                if let Ok(data) = B64.decode(&c.b64) {
                    last = c.at.as_secs_f64();
                    fresh = true;
                    cast.push(c.offset, &data, last);
                }
                sink = if cast.pending() >= BLOCK { flush(&app, &session, &mut cast, s).await } else { Some(s) };
            }
            _ = tick.tick() => {
                if !fresh {
                    cast.idle(last);
                }
                fresh = false;
                sink = flush(&app, &session, &mut cast, s).await;
            }
        }
    }
    if let Some(s) = sink {
        cast.idle(last);
        let _ = flush(&app, &session, &mut cast, s).await;
    }
    let _ = sqlx::query("UPDATE leyline_recordings SET ended_at = ? WHERE session = ?")
        .bind(app.clock.unix())
        .bind(&session)
        .execute(&app.pool)
        .await;
}
