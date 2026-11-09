//! The step-up key (spec §8, Q6 option 1): a second P-256 key, made at pairing beside the
//! routine one, kept in its own file and encrypted at rest with a passphrase, so holding the
//! routine keystore alone never elevates. Typing the passphrase is the CLI's user verification.
//!
//! The file: JSON, mode 0600 in a 0700 directory, `{version, kdf, iterations, salt, nonce,
//! device_id, core_fp, sealed}`. The key is PBKDF2-HMAC-SHA256 (at least [`MIN_ITERATIONS`])
//! over the passphrase and a random 16-byte salt; the PKCS#8 is sealed with AES-256-GCM under a
//! random 12-byte nonce, and every other field is the AEAD's associated data, so an edited
//! header (a lowered iteration count, another device) fails to open like a wrong passphrase.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::{Key, b64, random, unb64};

/// The domain separation string of a step-up proof (§8).
pub const DOMAIN: &str = "AINKRAD-STEPUP-V1";

/// The exact bytes the step-up key signs (§8): five fields joined by LF, no trailing newline.
pub fn message(core_fp: &str, device: &str, session: &str, challenge: &str) -> Vec<u8> {
    [DOMAIN, core_fp, device, session, challenge]
        .join("\n")
        .into_bytes()
}

const VERSION: u32 = 1;
const KDF: &str = "pbkdf2-hmac-sha256";
/// OWASP's 2023 figure for PBKDF2-HMAC-SHA256; a file asking for fewer is refused.
pub const MIN_ITERATIONS: u32 = 600_000;
/// Passphrases shorter than this are refused when the key is made.
const MIN_PASSPHRASE: usize = 8;

/// Where the step-up key of the keystore at `keystore` lives: beside it.
pub fn path_for(keystore: &Path) -> PathBuf {
    keystore.with_extension("stepup.json")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    kdf: String,
    iterations: u32,
    salt: String,
    nonce: String,
    device_id: String,
    core_fp: String,
    /// The PKCS#8, sealed, with its 16-byte tag.
    sealed: String,
}

impl Envelope {
    /// The associated data: every field but the sealed bytes.
    fn aad(&self) -> Vec<u8> {
        format!(
            "ainkradctl-stepup\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.version,
            self.kdf,
            self.iterations,
            self.salt,
            self.nonce,
            self.device_id,
            self.core_fp
        )
        .into_bytes()
    }
}

fn cipher(passphrase: &[u8], salt: &[u8], iterations: u32) -> LessSafeKey {
    let mut k = Zeroizing::new([0u8; 32]);
    let n = NonZeroU32::new(iterations).expect("iterations checked above zero");
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, n, salt, passphrase, &mut *k);
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &*k).expect("a 32-byte key"))
}

/// Seals `key` under `passphrase` and writes it to `path` (0600 from its first byte, in a
/// 0700 directory, renamed into place once written).
pub fn save(
    path: &Path,
    key: &Key,
    passphrase: &[u8],
    device_id: &str,
    core_fp: &str,
) -> Result<(), String> {
    let salt = random::<16>();
    let nonce = random::<12>();
    let mut env = Envelope {
        version: VERSION,
        kdf: KDF.into(),
        iterations: MIN_ITERATIONS,
        salt: b64(&salt),
        nonce: b64(&nonce),
        device_id: device_id.into(),
        core_fp: core_fp.into(),
        sealed: String::new(),
    };
    let mut sealed = key.pkcs8().to_vec();
    cipher(passphrase, &salt, env.iterations)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(env.aad()),
            &mut sealed,
        )
        .map_err(|_| "sealing the step-up key failed".to_owned())?;
    env.sealed = b64(&sealed);
    write_private(
        path,
        &serde_json::to_vec_pretty(&env).expect("serialisable"),
    )
}

/// Why a device whose step-up file is missing cannot elevate.
pub fn no_key(path: &Path) -> String {
    format!(
        "this device has no step-up key ({} is missing: it was paired with --no-stepup or the \
         file was lost), so it cannot elevate; do this from a device that can, or re-pair this one",
        path.display()
    )
}

/// Opens the step-up key at `path` for `device_id` of `core_fp`. A wrong passphrase and an
/// edited file are one error.
pub fn load(path: &Path, passphrase: &[u8], device_id: &str, core_fp: &str) -> Result<Key, String> {
    let shown = path.display();
    let meta = fs::metadata(path).map_err(|_| no_key(path))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is readable by others (mode {:o}): chmod 600 it",
            meta.permissions().mode() & 0o777
        ));
    }
    let text = fs::read(path).map_err(|e| format!("reading {shown}: {e}"))?;
    let env: Envelope =
        serde_json::from_slice(&text).map_err(|_| format!("{shown} is not a step-up key file"))?;
    if env.version != VERSION || env.kdf != KDF {
        return Err(format!(
            "{shown}: version {} / {} unknown",
            env.version, env.kdf
        ));
    }
    if env.iterations < MIN_ITERATIONS {
        return Err(format!("{shown}: {} iterations is too few", env.iterations));
    }
    if env.device_id != device_id || env.core_fp != core_fp {
        return Err(format!("{shown} belongs to another device or Core"));
    }
    let wrong = || format!("wrong step-up passphrase (or {shown} was altered)");
    let salt = unb64(&env.salt).ok_or_else(wrong)?;
    let nonce: [u8; 12] = unb64(&env.nonce)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(wrong)?;
    let mut sealed = Zeroizing::new(unb64(&env.sealed).ok_or_else(wrong)?);
    let pkcs8 = cipher(passphrase, &salt, env.iterations)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(env.aad()),
            &mut sealed,
        )
        .map_err(|_| wrong())?;
    Key::from_pkcs8(pkcs8).ok_or_else(wrong)
}

/// Writes `bytes` to `path`, 0600 from the first byte, in a 0700 directory, by rename.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}-{}.tmp", std::process::id()));
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("writing {}: {e}", path.display())
    })
}

/// Where the passphrase comes from: a file (`--stepup-passphrase-file`, else
/// `$AINKRAD_STEPUP_PASSPHRASE_FILE`), else the terminal.
#[derive(Debug, Clone, Default)]
pub struct Passphrase {
    pub file: Option<PathBuf>,
}

impl Passphrase {
    pub fn new(flag: Option<&str>) -> Self {
        let file = flag
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("AINKRAD_STEPUP_PASSPHRASE_FILE").map(PathBuf::from));
        Self { file }
    }

    /// The passphrase; `confirm` asks twice on a terminal (when the key is made).
    pub fn read(&self, confirm: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        let p = match &self.file {
            Some(f) => {
                let text = Zeroizing::new(
                    fs::read(f).map_err(|e| format!("the passphrase file {}: {e}", f.display()))?,
                );
                Zeroizing::new(strip_newline(&text).to_vec())
            }
            None => {
                let p = prompt("step-up passphrase: ")?;
                if confirm && *prompt("again: ")? != *p {
                    return Err("the passphrases differ".into());
                }
                p
            }
        };
        if confirm && p.len() < MIN_PASSPHRASE {
            return Err(format!(
                "a step-up passphrase has at least {MIN_PASSPHRASE} bytes"
            ));
        }
        Ok(p)
    }
}

/// One trailing `\n` (or `\r\n`) dropped, nothing else.
fn strip_newline(b: &[u8]) -> &[u8] {
    let b = b.strip_suffix(b"\n").unwrap_or(b);
    b.strip_suffix(b"\r").unwrap_or(b)
}

/// Reads a line from the controlling terminal with echo off (`stty`, no unsafe code).
fn prompt(label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let no_tty = || {
        "no terminal to ask the step-up passphrase on: give --stepup-passphrase-file or set \
         AINKRAD_STEPUP_PASSPHRASE_FILE"
            .to_owned()
    };
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| no_tty())?;
    let stty = |arg: &str| {
        let input = tty
            .try_clone()
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        Command::new("stty")
            .arg(arg)
            .stdin(input)
            .status()
            .is_ok_and(|s| s.success())
    };
    if !stty("-echo") {
        return Err(no_tty());
    }
    let mut out = tty.try_clone().map_err(|_| no_tty())?;
    let _ = write!(out, "{label}");
    let _ = out.flush();
    let mut line = Zeroizing::new(Vec::new());
    let read = std::io::BufReader::new(&tty).read_until(b'\n', &mut line);
    stty("echo");
    let _ = writeln!(out);
    read.map_err(|e| format!("reading the passphrase: {e}"))?;
    Ok(Zeroizing::new(strip_newline(&line).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_0600_opens_only_with_its_passphrase_and_header() {
        let dir = std::env::temp_dir().join(format!("ctl-su-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = path_for(&dir.join("sub").join("keystore.json"));
        assert!(path.ends_with("keystore.stepup.json"));
        let key = Key::generate();
        save(&path, &key, b"correct horse", "d_x", "fp").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&path), mode(path.parent().unwrap())), (0o600, 0o700));
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&b64(key.pkcs8())));
        let back = load(&path, b"correct horse", "d_x", "fp").unwrap();
        assert_eq!(back.spki(), key.spki());
        assert!(
            load(&path, b"wrong horse", "d_x", "fp")
                .unwrap_err()
                .contains("wrong step-up passphrase")
        );
        assert!(load(&path, b"correct horse", "d_y", "fp").is_err());
        // A lowered iteration count is refused; a raised one fails the AAD like a wrong passphrase.
        let edit = |from: &str, to: &str| fs::write(&path, text.replace(from, to)).unwrap();
        edit("600000", "1000");
        assert!(
            load(&path, b"correct horse", "d_x", "fp")
                .unwrap_err()
                .contains("too few")
        );
        edit("600000", "600001");
        assert!(
            load(&path, b"correct horse", "d_x", "fp")
                .unwrap_err()
                .contains("wrong")
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load(&path, b"correct horse", "d_x", "fp")
                .unwrap_err()
                .contains("readable")
        );
        fs::remove_dir_all(&dir).unwrap();
        assert!(
            load(&path, b"x", "d_x", "fp")
                .unwrap_err()
                .contains("no step-up key")
        );
    }

    #[test]
    fn the_message_is_five_lines() {
        assert_eq!(
            message("f", "d", "s", "c"),
            b"AINKRAD-STEPUP-V1\nf\nd\ns\nc"
        );
        assert_eq!(strip_newline(b"pw\r\n"), b"pw");
        assert_eq!(strip_newline(b"pw\n\n"), b"pw\n");
    }
}
