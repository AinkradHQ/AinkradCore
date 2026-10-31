//! Audit commands (E1-10.1, E1-10.3; usage in `super::USAGE`): verify the hash chain, export it
//! as JSONL. Both open the
//! database read-only and never migrate it: they inspect evidence and must not change it.

use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::ops::anchor::{self, Sinks};
use ainkrad_core_server::ops::config::Home;
use ainkrad_core_server::ops::s3::Bucket;
use ainkrad_core_server::scheduler::SystemClock;
use ainkrad_core_server::store::audit::chain::{self, Verified};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use crate::cli::Result_;

/// Runs an audit command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["audit", "verify", "--export", file] => verify_export(Path::new(file)),
        ["audit", "anchor", home, rest @ ..] => anchor(Path::new(home), rest).await,
        ["audit", "verify-anchors", home, rest @ ..] => verify_anchors(Path::new(home), rest).await,
        ["audit", "verify", db] => verify(Path::new(db)).await,
        ["audit", "export", db] => export(Path::new(db), None).await,
        ["audit", "export", db, file] => export(Path::new(db), Some(Path::new(file))).await,
        _ => return None,
    })
}

async fn open(db: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new().filename(db).read_only(true);
    SqlitePool::connect_with(options).await
}

fn report(v: &Verified) {
    let (seq, hash) = v.head.clone().unwrap_or_default();
    println!(
        "audit chain ok: {} rows ({} from before the chain), head seq {seq} {hash}",
        v.rows, v.unchained
    );
}

async fn verify(db: &Path) -> Result_ {
    let pool = open(db).await?;
    let v = chain::verify_db(&pool).await??;
    report(&v);
    Ok(())
}

fn verify_export(file: &Path) -> Result_ {
    let v = chain::verify_export(BufReader::new(std::fs::File::open(file)?))?;
    report(&v);
    Ok(())
}

async fn export(db: &Path, file: Option<&Path>) -> Result_ {
    let pool = open(db).await?;
    let n = match file {
        Some(file) => {
            let f =
                std::fs::File::create_new(file).map_err(|e| format!("{}: {e}", file.display()))?;
            chain::export(&pool, &mut BufWriter::new(f)).await?
        }
        None => chain::export(&pool, &mut std::io::stdout().lock()).await?,
    };
    std::io::stderr().flush()?;
    eprintln!("{n} audit rows exported");
    Ok(())
}

/// `--name value` flags and the bare `--local-only`; `None` on anything else.
fn flags<'a>(rest: &[&'a str], known: &[&str]) -> Option<Vec<(&'a str, &'a str)>> {
    let mut out = Vec::new();
    let mut it = rest.iter();
    while let Some(&a) = it.next() {
        match a {
            "--local-only" if known.contains(&a) => out.push((a, "")),
            f if known.contains(&f) => out.push((f, *it.next()?)),
            _ => return None,
        }
    }
    Some(out)
}

const ANCHOR_USAGE: &str = "usage: audit anchor <home> [--file <path>] [--local-only]";

/// Anchors the chain head once, now (the same job `serve` runs every `audit.anchor_interval_secs`).
async fn anchor(home: &Path, rest: &[&str]) -> Result_ {
    let f = flags(rest, &["--file", "--local-only"]).ok_or(ANCHOR_USAGE)?;
    let get = |n: &str| f.iter().find(|(k, _)| *k == n).map(|(_, v)| *v);
    let file = get("--file")
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("AINKRAD_ANCHOR_FILE")
                .ok()
                .filter(|v| !v.is_empty())
        })
        .map(Into::into);
    let bucket = if get("--local-only").is_some() {
        None
    } else {
        Bucket::from_env().map_err(|e| e.to_string())?
    };
    if bucket.is_none() && file.is_none() {
        return Err("no sink: set AINKRAD_BACKUP_* for the bucket, and/or --file <path>".into());
    }
    let home = Home(home.to_path_buf());
    let pool = open(&home.db()).await?;
    let id = Identity::load_readonly(&home.0)?;
    let sinks = Sinks { bucket, file };
    match anchor::anchor_once(&pool, &home.0, &id, &sinks, &SystemClock).await? {
        Some(s) => {
            let st: anchor::Statement = serde_json::from_str(&s.statement)?;
            println!(
                "anchored audit head seq {} {} as anchor {}",
                st.head_seq, st.head_hash, st.anchor_seq
            );
        }
        None => println!("the audit log has no chained rows yet; nothing to anchor"),
    }
    Ok(())
}

/// Exit 0: every anchor checks out against the database. Exit 3: evidence of tampering.
/// Exit 1: could not check (unreadable source, database error).
async fn verify_anchors(home: &Path, rest: &[&str]) -> Result_ {
    let f = flags(rest, &["--from", "--core-fp"])
        .ok_or("usage: audit verify-anchors <home> --from <file|dir|bucket> [--core-fp <fp>]")?;
    let get = |n: &str| f.iter().find(|(k, _)| *k == n).map(|(_, v)| *v);
    let from = get("--from").ok_or("verify-anchors needs --from <file|dir|bucket>")?;
    let home = Home(home.to_path_buf());
    let lines = if from == "bucket" {
        let bucket = Bucket::from_env()
            .map_err(|e| e.to_string())?
            .ok_or("no bucket: set AINKRAD_BACKUP_*")?;
        anchor::read_bucket(&bucket).await?
    } else {
        anchor::read_lines(Path::new(from)).map_err(|e| format!("{from}: {e}"))?
    };
    // The newest signer must be the key the operator expects: recorded offline, else this
    // host's own (weaker: a host that lies about its key could pass).
    let pin = match get("--core-fp") {
        Some(fp) => Some(fp.to_owned()),
        None => Some(
            Identity::load_readonly(&home.0)
                .map_err(|e| {
                    format!(
                        "cannot read this host's identity key to pin the signer ({e}); pass \
                         --core-fp <fingerprint>"
                    )
                })?
                .fp,
        ),
    };
    let pool = open(&home.db()).await?;
    let report = anchor::verify(&pool, &lines, pin.as_deref()).await??;
    println!(
        "audit anchors ok: {} anchors, newest {} saw head seq {} {} ({} rows)",
        report.anchors,
        report.last.anchor_seq,
        report.last.head_seq,
        report.last.head_hash,
        report.last.rows
    );
    Ok(())
}
