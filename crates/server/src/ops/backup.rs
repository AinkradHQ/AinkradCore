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
            ("core.db".to_owned(), plain.clone()),
            ("keys/master.key".to_owned(), master.clone()),
        ];
        // A rotation's retired and pending master keys, so a backup taken at any point of one
        // (or just after) restores with every key its database still names. A plaintext
        // export never carries secrets, so no spare keys either.
        if kind == "backup" {
            for (id, path, retired) in super::secretbox::key_files(&home.keys())? {
                let suffix = if retired { ".retired" } else { "" };
                files.push((format!("keys/master.{id}.key{suffix}"), path));
            }
        }
        // The Core identity only inside the encrypted backup, never in a plaintext export. A
        // home that never served has none yet.
        if kind == "backup" && identity.exists() {
            files.push((archive::IDENTITY.to_owned(), identity));
        }
        let files: Vec<(&str, &Path)> = files
            .iter()
            .map(|(n, p)| (n.as_str(), p.as_path()))
            .collect();
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
    let bucket = match (local_only, Bucket::from_env().map_err(|e| e.to_string())?) {
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
            bucket
                .put_new(&key, &path)
                .await
                .map_err(|e| e.to_string())?;
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

    /// KAN-253: a blob sealed by the stock crates.io age 0.11.5, before the localisation-free fork was patched in,
    /// must still open, and a blob sealed now must open with the same key. A wrong key must not open it.
    #[test]
    fn age_blob_sealed_before_the_fork_still_opens() {
        use std::io::{Read, Write};
        const OLD_BLOB_HEX: &str = concat!(
            "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139204d7343482b63346b5337736e7845315a",
            "7a4e35724e56506275647658314831796f584f683077616d6e6b770a572f73786c7a38646e6c713861487836637a4b58",
            "54714d75694736366266353570584334506253546a42730a2d3e20632d677265617365207229366f2220775a63520a4a",
            "7a770a2d2d2d20393449717a773463312b527576436d58564172484c344578564c4a3268526b344a3055333961494c49",
            "78630a034f7fb10bb3689db35dd47e094317fc8af18c33230293ab4d5bbf549a9f3e684c6cfb5d9a02fd0092b92fcaa4",
            "23d62b4fdccaafbe64547849df7bd1c3e7c5abf4",
        );
        let old: Vec<u8> = (0..OLD_BLOB_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&OLD_BLOB_HEX[i..i + 2], 16).unwrap())
            .collect();
        // Test-only throwaway key for the fixed blob above; never a real recipient.
        let identity: age::x25519::Identity =
            "AGE-SECRET-KEY-1LUAHR44JF4ZQSH8XDE2DDWMYKC2M86N3CDNFAC2AT88CFYL0C69SDF3K5Y"
                .parse()
                .unwrap();
        let open = |blob: &[u8], id: &age::x25519::Identity| -> Result<Vec<u8>, String> {
            let d = age::Decryptor::new(blob).map_err(|e| e.to_string())?;
            let mut r = d
                .decrypt(std::iter::once(id as &dyn age::Identity))
                .map_err(|e| e.to_string())?;
            let mut out = vec![];
            r.read_to_end(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        };
        assert_eq!(
            open(&old, &identity).unwrap(),
            b"ainkrad age compatibility fixture"
        );
        assert!(open(&old, &age::x25519::Identity::generate()).is_err());

        let rec = identity.to_public();
        let enc =
            age::Encryptor::with_recipients(std::iter::once(&rec as &dyn age::Recipient)).unwrap();
        let mut sealed = vec![];
        let mut w = enc.wrap_output(&mut sealed).unwrap();
        w.write_all(b"round trip").unwrap();
        w.finish().unwrap();
        assert_eq!(open(&sealed, &identity).unwrap(), b"round trip");
    }
}
