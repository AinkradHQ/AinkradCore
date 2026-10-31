//! Off-box anchors of the audit chain head (E1-10.4; threat model T-AUD-2).
//!
//! Whoever can write the database can rebuild a hash chain, so the head is published where the
//! host cannot rewrite it: a small statement `{core_fp, anchor_seq, prev_anchor_hash, head_seq,
//! head_hash, rows, at}`, signed by the Core identity key, PUT as a new object
//! `<prefix>anchors/<seq>-<time>-<random>.json` to the create-only backup bucket (no overwrite,
//! no delete), and optionally appended to a local file the operator copies off the box. It holds
//! hashes and counts only, never audit content.
//!
//! Anchors chain: each names the hash of the one before. A key rotation keeps verifying: the
//! first anchor of the new key carries the rotation statement the old key signed (the anchorer
//! files every pending statement it sees under `<home>/anchors/rotations.json`).
//! `verify` checks signatures, that chain and the key lineage, then that every anchored head is
//! still in the database with the same hash and row count: a rebuilt, truncated or rolled-back
//! chain fails.
//!
//! Failures never reach the audit log or the Core: the job logs and retries with backoff.

use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::Rotation;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;

use super::s3::{Bucket, S3Error};
use super::{private_dir, private_file, random_hex};
use crate::auth::Identity;
use crate::auth::crypto::{b64, sha256};
use crate::scheduler::Clock;
use crate::store::audit::chain;

/// Under the bucket's prefix.
pub const PREFIX: &str = "anchors/";
const DOMAIN: &str = "AINKRAD-AUDIT-ANCHOR-V1\n";
const SPKI_B64: usize = 122;
const SIG_B64: usize = 86;
/// First retry delay after a failure; it doubles up to the interval.
const BACKOFF: i64 = 30;
/// The most bytes an anchor object may have when read back.
const MAX_ANCHOR: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub v: u32,
    pub core_fp: String,
    pub anchor_seq: u64,
    /// Hex SHA-256 of the previous anchor's `statement` text; zeros for the first.
    pub prev_anchor_hash: String,
    pub head_seq: i64,
    pub head_hash: String,
    pub rows: u64,
    pub at: String,
}

/// One anchor as stored: the exact statement text that was signed, the signer's public key
/// (SPKI, base64url), the signature over `DOMAIN ‖ statement`, and the rotation statement when
/// the key changed since the anchor before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub statement: String,
    pub spki: String,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<Rotation>,
}

fn message(statement: &str) -> Vec<u8> {
    format!("{DOMAIN}{statement}").into_bytes()
}

fn hash_of(statement: &str) -> String {
    chain::hex(&sha256(statement.as_bytes()))
}

type Error = String;

fn io<E: fmt::Display>(what: &str) -> impl Fn(E) -> Error + '_ {
    move |e| format!("{what}: {e}")
}

// ---- state kept beside the database ---------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct Head {
    anchor_seq: u64,
    hash: String,
    fp: String,
}

fn dir(home: &Path) -> PathBuf {
    home.join("anchors")
}

/// Written whole through a private temp file, then renamed into place.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", random_hex()?));
    let mut f = private_file(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<Option<T>, Error> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(io(&path.display().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Where anchors go: the create-only bucket and/or a local append-only file.
pub struct Sinks {
    pub bucket: Option<Bucket>,
    pub file: Option<PathBuf>,
}

/// The anchor number in an object key `<prefix>anchors/<12 digits>.json`; anything else under
/// the prefix is not an anchor name.
fn seq_of_key(prefix: &str, key: &str) -> Option<u64> {
    let n = key.strip_prefix(prefix)?.strip_suffix(".json")?;
    if n.len() == 12 && n.bytes().all(|b| b.is_ascii_digit()) {
        n.parse().ok()
    } else {
        None
    }
}

/// How many invalid objects `newest_in_bucket` looks past before giving up.
const MAX_WALK: usize = 16;

/// The newest VALID anchor in the bucket: named `<12 digits>.json`, signed, its number equal to
/// its name's, by this Core's key or one it rotated from. The bucket is create-only, so an
/// object nobody can delete may be junk or forged; it is skipped, never trusted. Errors when
/// there are anchor-named objects and none is valid (nothing bogus is then written).
async fn newest_in_bucket(
    bucket: &Bucket,
    id: &Identity,
    known: &[Rotation],
) -> Result<Head, Error> {
    let prefix = format!("{}{PREFIX}", bucket.prefix);
    let mut keys: Vec<(u64, String)> = bucket
        .list(&prefix)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|k| seq_of_key(&prefix, &k).map(|n| (n, k)))
        .collect();
    if keys.is_empty() {
        return Ok(Head::default());
    }
    keys.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    for (n, key) in keys.iter().take(MAX_WALK) {
        let Some(text) = fetch_text(bucket, key).await? else {
            continue;
        };
        let Ok(c) = verify::check_one(text.trim()) else {
            continue;
        };
        let ours = c.st.core_fp == id.fp || known.iter().any(|r| r.old_fp == c.st.core_fp);
        if c.st.anchor_seq == *n && ours {
            return Ok(Head {
                anchor_seq: *n,
                hash: hash_of(&c.signed.statement),
                fp: c.st.core_fp,
            });
        }
    }
    Err(
        "the bucket holds anchor objects but no valid recent one (forged or damaged?); not \
         anchoring until an operator looks"
            .to_owned(),
    )
}

/// The object's text; `None` when it is too big to be an anchor (a few hundred bytes).
async fn fetch_text(bucket: &Bucket, key: &str) -> Result<Option<String>, Error> {
    let tmp = std::env::temp_dir().join(format!(
        ".anchor-{}",
        random_hex().map_err(|e| e.to_string())?
    ));
    let got = bucket.get(key, &tmp).await.map_err(|e| e.to_string());
    let text = fs::File::open(&tmp).and_then(|f| {
        let mut text = String::new();
        f.take(MAX_ANCHOR + 1)
            .read_to_string(&mut text)
            .map(|_| text)
    });
    let _ = fs::remove_file(&tmp);
    got?;
    let text = text.map_err(io(key))?;
    Ok((text.len() as u64 <= MAX_ANCHOR).then_some(text))
}

async fn fetch(bucket: &Bucket, key: &str) -> Result<Signed, Error> {
    let text = fetch_text(bucket, key)
        .await?
        .ok_or_else(|| format!("{key}: too large to be an anchor"))?;
    serde_json::from_str(text.trim()).map_err(io(key))
}

/// Takes the home's anchor lock (blocks while another anchor runs), released on drop.
async fn lock(home: &Path) -> Result<fs::File, Error> {
    private_dir(&dir(home)).map_err(io("anchors dir"))?;
    let path = dir(home).join(".lock");
    tokio::task::spawn_blocking(move || {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        f.lock()?;
        Ok::<_, std::io::Error>(f)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(io("anchor lock"))
}

/// Anchors the chain head now: `Ok(None)` when there is nothing to anchor yet. The chain is
/// verified first, and a broken one is never anchored (that would bless the tampering).
pub async fn anchor_once(
    pool: &SqlitePool,
    home: &Path,
    id: &Identity,
    sinks: &Sinks,
    clock: &impl Clock,
) -> Result<Option<Signed>, Error> {
    let _lock = lock(home).await?;
    let done = chain::verify_db(pool)
        .await
        .map_err(io("reading the audit chain"))?
        .map_err(|b| format!("not anchoring: {b}"))?;
    let Some((head_seq, head_hash)) = done.head.filter(|h| !h.1.is_empty()) else {
        return Ok(None);
    };
    let (head_path, rot_path) = (
        dir(home).join("head.json"),
        dir(home).join("rotations.json"),
    );
    let mut known: Vec<Rotation> = read_json(&rot_path)?.unwrap_or_default();
    // The newest of what this box remembers and what the bucket holds: a stale or lost
    // head.json (a crash after the PUT, a restore) never makes a sequence number repeat.
    let local = read_json::<Head>(&head_path)?.unwrap_or_default();
    let head = match &sinks.bucket {
        Some(b) => {
            let remote = newest_in_bucket(b, id, &known).await?;
            if remote.anchor_seq >= local.anchor_seq {
                remote
            } else {
                local
            }
        }
        None => local,
    };
    if let Some(r) = &id.rotation
        && !known.contains(r)
    {
        known.push(r.clone());
        write_atomic(
            &rot_path,
            &serde_json::to_vec(&known).map_err(|e| e.to_string())?,
        )
        .map_err(io("rotations.json"))?;
    }
    let rotation = (!head.fp.is_empty() && head.fp != id.fp)
        .then(|| {
            known
                .iter()
                .find(|r| r.old_fp == head.fp && r.new_fp == id.fp)
        })
        .flatten()
        .cloned();
    let at = clock.now();
    let st = Statement {
        v: 1,
        core_fp: id.fp.clone(),
        anchor_seq: head
            .anchor_seq
            .checked_add(1)
            .ok_or_else(|| "the anchor sequence cannot grow further".to_owned())?,
        prev_anchor_hash: if head.hash.is_empty() {
            chain::GENESIS.to_owned()
        } else {
            head.hash
        },
        head_seq,
        head_hash,
        rows: done.rows,
        at,
    };
    let statement = serde_json::to_string(&st).map_err(|e| e.to_string())?;
    let signed = Signed {
        sig: b64(&id.sign(&message(&statement))),
        spki: b64(&id.spki),
        statement,
        rotation,
    };
    let mut line = serde_json::to_string(&signed).map_err(|e| e.to_string())?;
    line.push('\n');

    // The bucket is authoritative: a refusal there leaves the state alone, so the next try
    // reuses the sequence number and nothing is forked.
    if let Some(bucket) = &sinks.bucket {
        // One name per sequence number, so a second PUT of it is refused by the create-only bucket.
        let key = format!("{}{PREFIX}{:012}.json", bucket.prefix, st.anchor_seq);
        let tmp = dir(home).join(format!(".put-{}", random_hex().map_err(|e| e.to_string())?));
        private_file(&tmp)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .map_err(io("anchor temp file"))?;
        let put = bucket.put_new(&key, &tmp).await;
        let _ = fs::remove_file(&tmp);
        if let Err(e) = put {
            // Refused because the name exists: fine only if it already holds this very anchor.
            let taken = e
                .downcast_ref::<S3Error>()
                .is_some_and(|s| matches!(s.status, 403 | 412));
            if !taken {
                return Err(format!("bucket: {e}"));
            }
            if !fetch(bucket, &key).await.is_ok_and(|s| s == signed) {
                return Err(format!(
                    "anchor number {} is already taken by a different object (a forged or \
                     damaged one in the create-only bucket?)",
                    st.anchor_seq
                ));
            }
        }
    }
    let appended = match &sinks.file {
        Some(path) => append(path, &line).map_err(io(&path.display().to_string())),
        None => Ok(()),
    };
    // Without a bucket the file is the record: a failed append must not advance the state.
    if appended.is_ok() || sinks.bucket.is_some() {
        let next = Head {
            anchor_seq: st.anchor_seq,
            hash: hash_of(&signed.statement),
            fp: st.core_fp,
        };
        write_atomic(
            &head_path,
            &serde_json::to_vec(&next).map_err(|e| e.to_string())?,
        )
        .map_err(io("head.json"))?;
    }
    appended.map(|()| Some(signed))
}

/// Appends `line` to `path` (created 0600): one write, flushed to disk.
fn append(path: &Path, line: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

// ---- the job ----------------------------------------------------------------------------------

/// When the next anchor is due: at once, then every `interval`; after a failure, sooner, with
/// a delay that doubles from `BACKOFF` up to the interval.
#[derive(Debug)]
pub struct Schedule {
    pub next: i64,
    fails: u32,
    interval: i64,
}

impl Schedule {
    pub fn new(now: i64, interval: Duration) -> Self {
        Self {
            next: now,
            fails: 0,
            interval: i64::try_from(interval.as_secs()).unwrap_or(i64::MAX),
        }
    }

    pub fn due(&self, now: i64) -> bool {
        now >= self.next
    }

    pub fn ok(&mut self, now: i64) {
        self.fails = 0;
        self.next = now + self.interval;
    }

    pub fn fail(&mut self, now: i64) {
        self.fails += 1;
        let delay = BACKOFF.saturating_mul(1 << (self.fails - 1).min(20));
        self.next = now + delay.min(self.interval);
    }
}

pub struct AnchorJob<C> {
    pub pool: SqlitePool,
    pub home: PathBuf,
    pub identity: Arc<Identity>,
    pub sinks: Sinks,
    pub clock: C,
    pub interval: Duration,
}

impl<C: Clock> AnchorJob<C> {
    /// Anchors if due; a failure is logged (no secrets: S3 errors carry a status and a code) and
    /// retried by the schedule. Never panics, never touches the audit log. Returns whether it ran.
    pub async fn step(&self, schedule: &mut Schedule) -> bool {
        let now = self.clock.unix();
        if !schedule.due(now) {
            return false;
        }
        match anchor_once(
            &self.pool,
            &self.home,
            &self.identity,
            &self.sinks,
            &self.clock,
        )
        .await
        {
            Ok(done) => {
                schedule.ok(now);
                if let Some(s) =
                    done.and_then(|s| serde_json::from_str::<Statement>(&s.statement).ok())
                {
                    tracing::info!(
                        anchor_seq = s.anchor_seq,
                        head_seq = s.head_seq,
                        "audit head anchored"
                    );
                }
            }
            Err(e) => {
                schedule.fail(now);
                tracing::error!(error = %e, retry_at = schedule.next, "audit anchor failed; will retry");
            }
        }
        true
    }

    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut schedule = Schedule::new(self.clock.unix(), self.interval);
        let mut poll = tokio::time::interval(Duration::from_secs(15));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = poll.tick() => { self.step(&mut schedule).await; }
            }
        }
    }
}

mod verify;
pub use verify::{Report, Tampered, read_bucket, read_lines, verify};

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
