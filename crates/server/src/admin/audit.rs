//! Audit commands (E1-10.1, E1-10.3; usage in `super::USAGE`): verify the hash chain, export it
//! as JSONL. Both open the
//! database read-only and never migrate it: they inspect evidence and must not change it.

use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use ainkrad_core_server::store::audit::chain::{self, Verified};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use crate::Result_;

/// Runs an audit command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["audit", "verify", "--export", file] => verify_export(Path::new(file)),
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
