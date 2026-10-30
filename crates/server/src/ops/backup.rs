//! `backup` and `backup-keygen` (E1-13.2, E1-13.6; threat model T-BAK-1..3).
//!
//! A backup is: a consistent snapshot of the database (`store::backup`, `VACUUM INTO`) plus the
//! master key and the Core identity key, in a signed archive (`archive`), encrypted with `age` to the configured recipient,
//! kept in `<home>/backups/` and PUT once to the bucket under a new name. The host holds only the
//! recipient (public); the identity that decrypts lives offline (Q-TM2).

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use age::secrecy::ExposeSecret;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use super::config::{Config, Home};
use super::s3::Bucket;
use super::{Result_, archive, compact, random_hex};
use crate::scheduler::{Clock, SystemClock};
use crate::store;

/// A consistent snapshot of the home's database at `dest` (which must not exist), without
/// creating or migrating the database.
pub(crate) async fn snapshot(home: &Home, dest: &Path) -> Result_ {
    if !home.db().exists() {
        return Err(format!("no database at {}", home.db().display()).into());
    }
    let options = SqliteConnectOptions::new()
        .filename(home.db())
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePool::connect_with(options).await?;
    let done = store::backup(&pool, dest).await;
    pool.close().await;
    Ok(done?)
}

/// Writes the signed archive of the home's snapshot and master key (and, in a backup, the Core
/// identity key) through `out` (an `age` writer for a backup, a plain file for an export). The plaintext snapshot lives only in the
/// 0700 `backups/` directory, and only while this runs.
pub(crate) async fn archive_home(
    home: &Home,
    kind: &str,
    out: &mut impl Write,
) -> Result<archive::Manifest, Box<dyn std::error::Error>> {
    let signer = archive::load_signer(&fs::read(home.signing_key())?)?;
    let plain = home.backups().join(format!(".{kind}-{}.db", random_hex()?));
    let made = async {
        snapshot(home, &plain).await?;
        // An export holds the master key in clear, so it never holds the sealed secrets (E2-07):
        // only the encrypted backup carries them.
        if kind == "export" {
            strip_secrets(&plain).await?;
        }
        let master = home.master_key();
        let identity = home.identity();
        let mut files = vec![
            ("core.db", plain.as_path()),
            ("keys/master.key", master.as_path()),
        ];
        // The Core identity only inside the encrypted backup, never in a plaintext export. A
        // home that never served has none yet.
        if kind == "backup" && identity.exists() {
            files.push((archive::IDENTITY, identity.as_path()));
        }
        Ok(archive::write(
            out,
            &signer,
            kind,
            &SystemClock.now(),
            &files,
        )?)
    }
    .await;
    let _ = fs::remove_file(&plain);
    made
}

/// Wipes the secrets broker's rows from a snapshot, free pages included (`secure_delete`, then
/// `VACUUM`), so neither a sealed value nor a lease survives in the file.
async fn strip_secrets(db: &Path) -> Result_ {
    use sqlx::Connection;
    let mut conn =
        sqlx::SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(db)).await?;
    let present: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'core_secrets'")
            .fetch_one(&mut conn)
            .await?;
    if present > 0 {
        sqlx::raw_sql(
            "PRAGMA secure_delete = ON; DELETE FROM core_secret_leases; DELETE FROM core_secrets; \
             VACUUM;",
        )
        .execute(&mut conn)
        .await?;
    }
    conn.close().await?;
    Ok(())
}

pub async fn backup(config: &Config, local_only: bool) -> Result_ {
    let home = config.home();
    let recipient =
        age::x25519::Recipient::from_str(config.backup_recipient.trim()).map_err(|_| {
            "backup_recipient is not an age recipient (age1...): run `backup-keygen` on another \
             machine and put the recipient in the config"
        })?;
    let bucket = match (local_only, Bucket::from_env()?) {
        (true, _) => None,
        (false, Some(b)) => Some(b),
        (false, None) => {
            return Err(
                "no bucket: set AINKRAD_BACKUP_* (e.g. from /etc/ainkrad/backup.env) \
                        or pass --local-only"
                    .into(),
            );
        }
    };
    let name = format!("{}-{}.age", compact(&SystemClock.now()), random_hex()?);
    let path = home.backups().join(&name);

    let file = super::private_file(&path)?;
    let written = async {
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
        let mut sealed = encryptor.wrap_output(BufWriter::new(file))?;
        let manifest = archive_home(&home, "backup", &mut sealed).await?;
        sealed.finish()?.into_inner()?.sync_all()?;
        Ok::<_, Box<dyn std::error::Error>>(manifest)
    }
    .await;
    let manifest = match written {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
    };
    let size = fs::metadata(&path)?.len();
    eprintln!(
        "snapshot {} bytes (sha256 {}), signed by {}, encrypted: {} ({size} bytes)",
        manifest.files[0].size,
        manifest.files[0].sha256,
        manifest.signer_fp,
        path.display()
    );
    prune(&home.backups(), config.backup_keep_local as usize)?;
    match bucket {
        Some(bucket) => {
            let key = format!("{}{name}", bucket.prefix);
            bucket.put_new(&key, &path).await?;
            eprintln!("uploaded as {key}");
            println!("{key}");
        }
        None => println!("{}", path.display()),
    }
    Ok(())
}

/// Keeps the newest `keep` `*.age` files in `dir` (names start with their UTC time).
fn prune(dir: &Path, keep: usize) -> std::io::Result<()> {
    let mut names: Vec<PathBuf> = fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "age"))
        .collect();
    names.sort();
    let drop = names.len().saturating_sub(keep);
    for old in &names[..drop] {
        fs::remove_file(old)?;
    }
    Ok(())
}

/// Prints a new age identity and its recipient, once, in `age-keygen`'s format.
pub fn keygen() -> Result_ {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    eprintln!(
        "A new age identity follows. Keep it OFF the Core host (a password manager and a printed \
         copy): it is the only key that decrypts the backups. Put the recipient (age1...) in the \
         config as backup_recipient. Save the identity lines below to a file for `restore \
         --identity`."
    );
    println!("# created: {}", SystemClock.now());
    println!("# public key: {recipient}");
    println!("{}", identity.to_string().expose_secret());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("core-prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for n in [
            "20261001T000000Z-a.age",
            "20261003T000000Z-c.age",
            "20261002T000000Z-b.age",
            ".backup-x.db",
        ] {
            fs::write(dir.join(n), b"").unwrap();
        }
        prune(&dir, 2).unwrap();
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                ".backup-x.db",
                "20261002T000000Z-b.age",
                "20261003T000000Z-c.age"
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
