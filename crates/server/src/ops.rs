//! Operations (E1-13): `init`, the config, encrypted signed backups to a create-only bucket,
//! `restore`, `export`/`import`, and redacted structured logs. `run` is the CLI dispatch for
//! these verbs; `USAGE` documents them.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub mod archive;
pub mod backup;
pub mod config;
pub mod export;
pub mod init;
pub mod logging;
pub mod master_rotate;
pub mod restore;
pub mod s3;
pub mod secretbox;

pub type Result_ = Result<(), Box<dyn std::error::Error>>;

pub const USAGE: &str = "Operations (E1-13):
  ainkrad-core-server init <home>
  ainkrad-core-server serve --config <file> [serve flags]
  ainkrad-core-server backup [--config <file>] [--local-only]
  ainkrad-core-server backup-keygen
  ainkrad-core-server restore <file.age|s3:<key>> --identity <age identity file>
                 --signer <fingerprint> <new home>
  ainkrad-core-server export [--config <file>] <file>
  ainkrad-core-server import <file> --signer <fingerprint> <new home>
init creates a home (refusing a path that exists and is not an empty directory): config.toml,
core.db (migrated), keys/master.key (32 random bytes) and keys/backup-signing.p8 (P-256), both
0600 in a 0700 directory, and backups/. It prints the signing key's fingerprint: record it
offline next to the age identity; restore and import need it as --signer.
The config is --config <file>, else $AINKRAD_CONFIG. Keys: home, listen, hostname,
acme_contact, log_format (text|json), backup_recipient (age1...), backup_keep_local; each is
overridden by AINKRAD_<KEY in upper case>. serve --config takes --listen, --hostname,
--acme-contact and --log-format from it unless given on the command line.
backup takes a consistent snapshot, adds the master key and the Core identity key, signs it
(manifest: version, time, each file's size and SHA-256; the signer's key and fingerprint) and
encrypts it to backup_recipient with age, into
<home>/backups/<UTC time>-<random>.age (keeping backup_keep_local), then PUTs it once, as a
new object <prefix><UTC time>-<random>.age, to the bucket named by AINKRAD_BACKUP_ENDPOINT,
_BUCKET, _REGION, _PREFIX (default core/), _ACCESS_KEY, _SECRET_KEY (from the environment only,
never printed; on the VM /etc/ainkrad/backup.env). --local-only skips the bucket. It refuses a
snapshot above the single-PUT limit (multipart needs overwrite rights the backup key lacks).
backup-keygen prints a new age identity and its recipient once: keep the identity OFF the host.
restore decrypts a backup (a file, or s3:<key> fetched from the bucket), checks the signature
against --signer before writing anything, and builds a new home in a fresh directory: the
database (integrity and schema checked, then migrated), the master key and the Core identity
key (core-identity.p8, 0600; so paired devices and runners still accept it) from the backup, a
new config and a new signing key; a backup without the identity restores with a warning that
everything must be paired again. export writes the same signed archive unencrypted, 0600,
never over an existing file: it holds the master key, so move it like a private key; it never
holds the Core identity nor the broker's secrets (only a backup carries those). import is restore for an export (a new identity: pair again).";

/// Runs an operations verb; `None` when `args` is not one (the caller prints the usage).
pub async fn run(args: &[&str]) -> Option<Result_> {
    let (verb, rest) = args.split_first()?;
    let (pos, flags) = split(rest)?;
    let flag = |name: &str| flags.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
    let only = |allowed: &[&str]| flags.iter().all(|(n, _)| allowed.contains(n));
    let config = || config::Config::find(flag("--config"));
    Some(match (*verb, pos.as_slice()) {
        ("init", [home]) if flags.is_empty() => init::init(Path::new(home)).await,
        ("backup", []) if only(&["--config", "--local-only"]) => match config() {
            Ok(c) => backup::backup(&c, flag("--local-only").is_some()).await,
            Err(e) => Err(e.into()),
        },
        ("backup-keygen", []) if flags.is_empty() => backup::keygen(),
        // Without flags it is the raw `restore <src> <db>` (main.rs).
        ("restore", [src, home]) if !flags.is_empty() && only(&["--identity", "--signer"]) => {
            let (Some(identity), Some(signer)) = (flag("--identity"), flag("--signer")) else {
                return Some(Err("restore needs --identity and --signer".into()));
            };
            restore::restore(src, Path::new(identity), signer, Path::new(home)).await
        }
        ("export", [file]) if only(&["--config"]) => match config() {
            Ok(c) => export::export(&c, Path::new(file)).await,
            Err(e) => Err(e.into()),
        },
        ("import", [file, home]) if only(&["--signer"]) => match flag("--signer") {
            Some(signer) => restore::import(Path::new(file), signer, Path::new(home)).await,
            None => Err("import needs --signer".into()),
        },
        _ => return None,
    })
}

type Split<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>);

/// Positionals and `--name value` flags (`--local-only` takes no value); `None` on a flag
/// with no value.
fn split<'a>(rest: &[&'a str]) -> Option<Split<'a>> {
    let (mut pos, mut flags) = (Vec::new(), Vec::new());
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--local-only" => flags.push((*a, "")),
            f if f.starts_with("--") => flags.push((f, *it.next()?)),
            p => pos.push(p),
        }
    }
    Some((pos, flags))
}

/// Creates `dir` (and parents) and makes it 0700.
pub(crate) fn private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Creates a new file, 0600, never over an existing one.
pub(crate) fn private_file(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// 16 random hex characters (64 bits): the unique half of a snapshot's name.
pub(crate) fn random_hex() -> io::Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `2026-10-29T10:00:00.000Z` as `20261029T100000Z`: sortable, and safe in an object key
/// (no `:`) and in a SigV4 `x-amz-date`.
pub(crate) fn compact(iso: &str) -> String {
    let d: String = iso.chars().filter(char::is_ascii_digit).take(14).collect();
    format!("{}T{}Z", &d[..8], &d[8..])
}
