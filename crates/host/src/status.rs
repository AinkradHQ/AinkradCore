//! `status`. **Executes no installed binary.** Versions come from the root-written manifest
//! `installed.json`; each fixed file under the bin dir is checked and hashed, never run. The
//! only processes started are `systemctl show` for three fixed units.
//!
//! A binary is opened with `O_NOFOLLOW`; `fstat` on that descriptor must show a regular file,
//! owned by the owner uid (root), `nlink == 1`, not group- or other-writable. The hash is read
//! through the same descriptor and cached by `(dev, ino, size, mtime, ctime)`, so a file is
//! hashed again only after it changed.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::exec::SYSTEMCTL;
use crate::wire::Code;
use crate::{Ctx, state};

const MANIFEST: &str = "installed.json";
const CACHE: &str = "hashcache.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    v: u32,
    binaries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    version: String,
    sha256: String,
    size: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
struct Seen {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    sha256: String,
}

fn valid_entry(e: &Entry) -> bool {
    let name = !e.name.is_empty()
        && e.name.len() <= 64
        && e.name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let version = !e.version.is_empty()
        && e.version.len() <= 64
        && e.version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+~_-".contains(&b));
    let sha = e.sha256.len() == 64
        && e.sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    name && version && sha
}

/// `ok`, `differs`, `unsafe` or `missing` for `bin_dir/name`.
fn check(
    ctx: &Ctx,
    e: &Entry,
    dir_safe: bool,
    cache: &mut BTreeMap<String, Seen>,
) -> (&'static str, String) {
    let path = ctx.bin_dir.join(&e.name);
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    else {
        let missing = std::fs::symlink_metadata(&path).is_err();
        return (if missing { "missing" } else { "unsafe" }, String::new());
    };
    let Ok(m) = file.metadata() else {
        return ("unsafe", String::new());
    };
    if !dir_safe
        || !m.is_file()
        || m.uid() != ctx.owner_uid
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
    {
        return ("unsafe", String::new());
    }
    if m.len() != e.size {
        return ("differs", String::new());
    }
    let seen = Seen {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
        sha256: String::new(),
    };
    let sha = match cache.get(&e.name) {
        Some(c)
            if Seen {
                sha256: String::new(),
                ..c.clone()
            } == seen =>
        {
            c.sha256.clone()
        }
        _ => {
            ctx.hashes.fetch_add(1, Ordering::Relaxed);
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut f = file;
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(_) => return ("unsafe", String::new()),
                }
            }
            let sha: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            cache.insert(
                e.name.clone(),
                Seen {
                    sha256: sha.clone(),
                    ..seen
                },
            );
            sha
        }
    };
    (if sha == e.sha256 { "ok" } else { "differs" }, sha)
}

fn bin_dir_safe(ctx: &Ctx) -> bool {
    std::fs::symlink_metadata(&ctx.bin_dir)
        .is_ok_and(|m| m.is_dir() && m.uid() == ctx.owner_uid && m.mode() & 0o022 == 0)
}

/// One unit's `systemctl show`: `None` when systemctl cannot be run at all.
fn unit(ctx: &Ctx, name: &str) -> Option<BTreeMap<String, String>> {
    let args = [
        "--no-ask-password".to_owned(),
        "show".to_owned(),
        "-p".to_owned(),
        "ActiveState,SubState,ActiveEnterTimestamp,NRestarts,LoadState".to_owned(),
        name.to_owned(),
    ];
    let out = ctx.exec.run(SYSTEMCTL, &args, 16 * 1024).ok()?;
    out.ok.then_some(())?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| {
                (
                    k.to_owned(),
                    v.chars()
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .take(64)
                        .collect(),
                )
            })
            .collect(),
    )
}

fn unit_json(p: &BTreeMap<String, String>) -> Value {
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    json!({"load": get("LoadState"), "active": get("ActiveState"), "sub": get("SubState"),
           "since": get("ActiveEnterTimestamp"), "restarts": get("NRestarts").parse::<u64>().ok()})
}

pub fn status(ctx: &Ctx) -> Result<Value, Code> {
    let Some(core) = unit(ctx, "ainkrad-core.service") else {
        return Err(Code::Failed);
    };
    let mut units = json!({"core": unit_json(&core)});
    for (key, name) in [
        ("runner", "ainkrad-runner.service"),
        ("backup_timer", "ainkrad-backup.timer"),
    ] {
        match unit(ctx, name) {
            Some(p) if p.get("LoadState").is_some_and(|l| l != "not-found") => {
                units[key] = unit_json(&p);
            }
            Some(_) => {}
            None => return Err(Code::Failed),
        }
    }
    let dir_safe = bin_dir_safe(ctx);
    let (manifest, entries) = match state::read_capped(&ctx.state_dir.join(MANIFEST), 64 * 1024) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ("absent", Vec::new()),
        Err(_) => ("invalid", Vec::new()),
        Ok(bytes) => match serde_json::from_slice::<Manifest>(&bytes) {
            Ok(m) if m.v == 1 && m.binaries.len() <= 16 && m.binaries.iter().all(valid_entry) => {
                ("ok", m.binaries)
            }
            _ => ("invalid", Vec::new()),
        },
    };
    let old: BTreeMap<String, Seen> = state::read_capped(&ctx.state_dir.join(CACHE), 64 * 1024)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut cache = old.clone();
    let binaries: Vec<Value> = entries
        .iter()
        .map(|e| {
            let (state, sha) = check(ctx, e, dir_safe, &mut cache);
            json!({"name": e.name, "version": e.version, "sha256_12": sha.get(..12).unwrap_or(""), "state": state})
        })
        .collect();
    if cache != old {
        // Best effort: a cache that cannot be written only costs a rehash next time.
        let _ = serde_json::to_vec(&cache).map(|b| state::write_atomic(&ctx.state_dir, CACHE, &b));
    }
    let host_id = state::read_capped(&ctx.state_dir.join("host_id"), 128)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| {
            (1..=64).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
    Ok(
        json!({"helper_version": env!("CARGO_PKG_VERSION"), "host_id": host_id, "manifest": manifest,
              "bin_dir_safe": dir_safe, "binaries": binaries, "units": units}),
    )
}

/// Whether `ainkrad-runner.service` is installed (`LoadState` is anything but `not-found`).
pub fn runner_installed(ctx: &Ctx) -> Option<bool> {
    let p = unit(ctx, "ainkrad-runner.service")?;
    Some(p.get("LoadState").is_some_and(|l| l != "not-found"))
}
