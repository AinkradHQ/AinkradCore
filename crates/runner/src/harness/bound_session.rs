//! A runner-bound account's session config dir (E7 review M2). The account's home
//! (`<config>/bound/<key>`) holds the one credential that never leaves this runner; a session must
//! not be able to write into it (a planted hook, a swapped config, a symlink). So the session
//! works in a fresh dir of its own that holds only the credential file(s), copied in at the start;
//! the credential the harness rotated is copied back when the session ends, and the dir is wiped.
//!
//! Trust decisions: the home is never the sandbox's config dir (never writable by the agent); what
//! the session wrote is untrusted, so a file is taken back only when it is a regular file reached
//! without a symlink on its path, at most [`MAX_CREDENTIAL`] bytes, valid JSON, and is written
//! atomically (temp file, then rename). The copy-back never recreates a wiped home. A rotated
//! credential is also taken back only for the SAME account: a session cannot swap in the login of
//! another account (see [`same_account`]); a mismatch keeps the stored one and is logged by file
//! name only.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use super::HarnessExecutor;
use super::account::bound_key;
use crate::Job;

/// The most a credential file may be. Real ones are a few KB.
pub(crate) const MAX_CREDENTIAL: u64 = ainkrad_proto::v2::MAX_CREDENTIAL as u64;

fn credential_files(harness: &str) -> &'static [&'static str] {
    ainkrad_proto::v2::credential_files(harness)
}

/// `root/rel` as a regular file, read without following a symlink on the way: every component
/// must be a real dir (the last a real file), and the opened file must be the one that was checked.
/// `None` for anything else, a file over [`MAX_CREDENTIAL`], or text that is not JSON.
pub(crate) fn read_credential(root: &Path, rel: &str) -> Option<Vec<u8>> {
    let mut path = root.to_path_buf();
    let parts: Vec<_> = Path::new(rel).components().collect();
    if parts.iter().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    for (i, c) in parts.iter().enumerate() {
        path.push(c);
        let m = fs::symlink_metadata(&path).ok()?;
        let last = i + 1 == parts.len();
        if m.file_type().is_symlink() || (last && !m.is_file()) || (!last && !m.is_dir()) {
            return None;
        }
    }
    let before = fs::symlink_metadata(&path).ok()?;
    let f = File::open(&path).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file()
        || (m.dev(), m.ino()) != (before.dev(), before.ino())
        || m.len() > MAX_CREDENTIAL
    {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_CREDENTIAL + 1).read_to_end(&mut buf).ok()?;
    let ok = buf.len() as u64 <= MAX_CREDENTIAL
        && serde_json::from_slice::<serde_json::Value>(&buf).is_ok();
    ok.then_some(buf)
}

use ainkrad_proto::v2::same_account;

/// A private dir, every parent a real dir (created when missing), never through a symlink.
fn private_path(root: &Path, rel: &Path) -> std::io::Result<PathBuf> {
    let mut path = root.to_path_buf();
    for c in rel.components() {
        path.push(c);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(_) => return Err(std::io::Error::other("a path part is not a plain dir")),
            Err(_) => fs::DirBuilder::new().mode(0o700).create(&path)?,
        }
    }
    Ok(path)
}

/// Writes `bytes` to `root/rel` atomically (a private temp file, then rename), mode 0600.
pub(crate) fn write_credential(root: &Path, rel: &str, bytes: &[u8]) -> std::io::Result<()> {
    let rel = Path::new(rel);
    let dir = private_path(root, rel.parent().unwrap_or(Path::new("")))?;
    let name = rel
        .file_name()
        .ok_or_else(|| std::io::Error::other("no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    match written.and_then(|()| fs::rename(&tmp, dir.join(name))) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Removes every per-session copy (`<config>/bound-sessions/run-*`) a runner that died mid-session
/// left: each may hold an `auth.json`. Run at runner start, before any session.
pub(crate) fn sweep(config_root: &Path) {
    let Ok(rd) = fs::read_dir(config_root.join("bound-sessions")) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with("run-") {
            wipe(&e.path());
        }
    }
}

/// Removes `dir` and everything in it (links inside are removed, never followed). A `dir` that is
/// itself a symlink is left alone.
pub(crate) fn wipe(dir: &Path) {
    if fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// One session's dir over an account's home. Dropping it (the end, a failure, a cancelled run)
/// takes the rotated credential back and wipes the dir.
pub(super) struct BoundSession {
    home: PathBuf,
    dir: PathBuf,
    files: &'static [&'static str],
}

impl BoundSession {
    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Copies each credential file the session left back into the home, when it changed and is
    /// valid. A home that is gone (the account was wiped meanwhile) is not recreated.
    fn take_back(&self) {
        if !fs::symlink_metadata(&self.home)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
        {
            return;
        }
        for rel in self.files {
            let Some(new) = read_credential(&self.dir, rel) else {
                continue;
            };
            let old = read_credential(&self.home, rel);
            if old.as_deref() == Some(new.as_slice()) {
                continue;
            }
            // Only the same account's rotation comes back. No stored credential to compare with
            // (the home had none) is a refusal too: a session never plants a first login.
            if !old.is_some_and(|o| same_account(&o, &new)) {
                tracing::warn!(
                    file = rel,
                    "refused a rotated credential of another account"
                );
                continue;
            }
            if let Err(e) = write_credential(&self.home, rel, &new) {
                tracing::warn!(error = %e, "could not store a rotated credential");
            }
        }
    }
}

impl Drop for BoundSession {
    fn drop(&mut self) {
        self.take_back();
        wipe(&self.dir);
    }
}

impl HarnessExecutor {
    /// The per-session config dir for `job` when its account is runner-bound (`home` is
    /// [`HarnessExecutor::config_dir`]'s answer), `None` for any other job.
    pub(super) fn bound_session(
        &self,
        job: &Job,
        home: &Path,
    ) -> Result<Option<BoundSession>, String> {
        if bound_key(job).is_none() {
            return Ok(None);
        }
        let dir = self
            .config_root
            .join("bound-sessions")
            .join(format!("run-{}", job.run));
        let failed = |e: std::io::Error| format!("the session's sign-in copy: {e}");
        // A leftover of a runner that died mid-session is never reused.
        wipe(&dir);
        private_path(&self.config_root, Path::new("bound-sessions")).map_err(failed)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(failed)?;
        // Built first, so a failure below wipes what was copied.
        let session = BoundSession {
            home: home.to_path_buf(),
            dir,
            files: credential_files(&job.harness),
        };
        for rel in session.files {
            if let Some(bytes) = read_credential(home, rel) {
                write_credential(&session.dir, rel, &bytes).map_err(failed)?;
            }
        }
        // Codex keeps its login in `auth.json` only if told: otherwise it asks the OS keyring.
        if job.harness == "codex" {
            fs::write(
                session.dir.join("config.toml"),
                "cli_auth_credentials_store = \"file\"\n",
            )
            .map_err(failed)?;
        }
        Ok(Some(session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ainkrad-bound-session-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_credential_is_read_only_as_a_small_json_regular_file_without_a_symlink() {
        let d = scratch("read");
        fs::write(d.join("auth.json"), br#"{"k":1}"#).unwrap();
        assert!(read_credential(&d, "auth.json").is_some());
        fs::write(d.join("text.json"), b"not json").unwrap();
        assert!(read_credential(&d, "text.json").is_none());
        fs::write(d.join("big.json"), vec![b' '; MAX_CREDENTIAL as usize + 1]).unwrap();
        assert!(read_credential(&d, "big.json").is_none());
        symlink(d.join("auth.json"), d.join("link.json")).unwrap();
        assert!(read_credential(&d, "link.json").is_none());
        fs::create_dir_all(d.join("real")).unwrap();
        fs::write(d.join("real/auth.json"), b"{}").unwrap();
        symlink(d.join("real"), d.join("dirlink")).unwrap();
        assert!(read_credential(&d, "dirlink/auth.json").is_none());
        assert!(read_credential(&d, "../auth.json").is_none());
        let _ = fs::remove_dir_all(&d);
    }

    fn bound_job(harness: &str, key: &str) -> Job {
        Job {
            run: 11,
            agent: 0,
            issue: None,
            harness: harness.to_owned(),
            model: String::new(),
            context_ref: "as_x".to_owned(),
            workspace: None,
            token_cap: None,
            token_caps: None,
            policy: Default::default(),
            issue_key: None,
            instructions: None,
            account: Some(ainkrad_proto::runner::Account {
                id: 0,
                label: "bound".to_owned(),
                config_dir: format!("bound/{key}"),
                credential_ref: None,
                credential_env: None,
            }),
            fallbacks: vec![],
            limits: None,
            resume_session: None,
            prompt: None,
            repos: vec![],
        }
    }

    fn session(d: &Path, harness: &str, key: &str) -> (HarnessExecutor, Job) {
        (
            HarnessExecutor::new(d.join("work"), d.join("config")),
            bound_job(harness, key),
        )
    }

    #[test]
    fn a_session_gets_only_the_credential_and_the_rotated_one_goes_back_then_the_dir_is_wiped() {
        let d = scratch("cycle");
        let (ex, j) = session(&d, "codex", "lg_1");
        let home = d.join("config/bound/lg_1");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("auth.json"), br#"{"t":"old"}"#).unwrap();
        fs::write(home.join("hooks.json"), b"{}").unwrap();
        let s = ex.bound_session(&j, &home).unwrap().unwrap();
        let dir = s.dir().to_path_buf();
        assert_ne!(dir, home);
        assert!(dir.join("auth.json").is_file());
        assert!(
            !dir.join("hooks.json").exists(),
            "only the credential is copied in"
        );
        // The harness rotates its token and the agent plants a file.
        fs::write(dir.join("auth.json"), br#"{"t":"new"}"#).unwrap();
        fs::write(dir.join("planted"), b"x").unwrap();
        drop(s);
        assert_eq!(fs::read(home.join("auth.json")).unwrap(), br#"{"t":"new"}"#);
        assert!(!home.join("planted").exists());
        assert!(!dir.exists(), "the per-session dir is wiped");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_bad_rotation_never_replaces_the_credential_and_a_wiped_home_is_not_recreated() {
        let d = scratch("bad");
        let (ex, j) = session(&d, "codex", "lg_2");
        let home = d.join("config/bound/lg_2");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("auth.json"), br#"{"t":"old"}"#).unwrap();
        for bad in [b"garbage".to_vec(), vec![b' '; MAX_CREDENTIAL as usize + 1]] {
            let s = ex.bound_session(&j, &home).unwrap().unwrap();
            fs::write(s.dir().join("auth.json"), &bad).unwrap();
            drop(s);
            assert_eq!(fs::read(home.join("auth.json")).unwrap(), br#"{"t":"old"}"#);
        }
        // A symlink in place of the file: its target is never read or copied.
        let secret = d.join("secret.json");
        fs::write(&secret, br#"{"t":"stolen"}"#).unwrap();
        let s = ex.bound_session(&j, &home).unwrap().unwrap();
        fs::remove_file(s.dir().join("auth.json")).unwrap();
        symlink(&secret, s.dir().join("auth.json")).unwrap();
        drop(s);
        assert_eq!(fs::read(home.join("auth.json")).unwrap(), br#"{"t":"old"}"#);
        // The account is wiped while the session runs: nothing comes back.
        let s = ex.bound_session(&j, &home).unwrap().unwrap();
        fs::write(s.dir().join("auth.json"), br#"{"t":"late"}"#).unwrap();
        fs::remove_dir_all(&home).unwrap();
        drop(s);
        assert!(!home.exists());
        let _ = fs::remove_dir_all(&d);
    }

    /// A dummy Codex `auth.json`: a fake id_token whose payload carries fake identity claims.
    fn fake_auth(email: &str, acct: &str, refresh: &str) -> Vec<u8> {
        use base64::Engine;
        let b = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let jwt = format!(
            "{}.{}.fake-sig",
            b(&serde_json::json!({"alg": "none"})),
            b(&serde_json::json!({
                "sub": format!("sub-{email}"),
                "email": email,
                "https://api.openai.com/auth": {"chatgpt_account_id": acct}
            }))
        );
        serde_json::json!({"tokens": {"id_token": jwt, "refresh_token": refresh}})
            .to_string()
            .into_bytes()
    }

    /// Runs one session on `home` whose credential the agent replaced with `new`; the stored one after.
    fn rotate(d: &Path, key: &str, old: &[u8], new: &[u8]) -> Vec<u8> {
        let (ex, j) = session(d, "codex", key);
        let home = d.join("config/bound").join(key);
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("auth.json"), old).unwrap();
        let s = ex.bound_session(&j, &home).unwrap().unwrap();
        let dir = s.dir().to_path_buf();
        fs::write(dir.join("auth.json"), new).unwrap();
        drop(s);
        assert!(!dir.exists(), "the session dir is wiped either way");
        fs::read(home.join("auth.json")).unwrap()
    }

    #[test]
    fn a_rotation_comes_back_only_for_the_same_account() {
        let d = scratch("identity");
        let old = fake_auth("fake-a@example.invalid", "acct-fake-1", "r1");
        // Same identity, new refresh token: accepted.
        let rot = fake_auth("fake-a@example.invalid", "acct-fake-1", "r2");
        assert_eq!(rotate(&d, "id_1", &old, &rot), rot);
        // Another account swapped in: refused, the stored one stays.
        let other = fake_auth("fake-b@example.invalid", "acct-fake-2", "r3");
        assert_eq!(rotate(&d, "id_2", &old, &other), old);
        // Same email, different account id: refused too.
        let other = fake_auth("fake-a@example.invalid", "acct-fake-9", "r3");
        assert_eq!(rotate(&d, "id_3", &old, &other), old);
        // The stored one has claims and the new one none: refused.
        assert_eq!(rotate(&d, "id_4", &old, br#"{"tokens":{}}"#), old);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn without_a_claim_the_same_key_set_is_the_account_and_another_one_is_not() {
        let d = scratch("keyset");
        let old = br#"{"a":"x","b":"y"}"#;
        let same = br#"{"b":"y2","a":"x2"}"#;
        assert_eq!(rotate(&d, "ks_1", old, same), same);
        let other = br#"{"a":"x","c":"y"}"#;
        assert_eq!(rotate(&d, "ks_2", old, other), old);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_runner_start_sweeps_every_session_copy_a_crash_left() {
        let d = scratch("sweep");
        let left = d.join("bound-sessions/run-42");
        fs::create_dir_all(&left).unwrap();
        fs::write(left.join("auth.json"), br#"{"t":"dummy"}"#).unwrap();
        fs::create_dir_all(d.join("bound/lg_1")).unwrap();
        sweep(&d);
        assert!(!left.exists(), "no auth.json survives a crash");
        assert!(
            d.join("bound/lg_1").exists(),
            "a bound home is not a session copy"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_job_without_a_bound_account_has_no_session_copy() {
        let d = scratch("plain");
        let ex = HarnessExecutor::new(d.join("work"), d.join("config"));
        let mut plain = bound_job("codex", "x");
        plain.account = None;
        assert!(ex.bound_session(&plain, &d).unwrap().is_none());
        let _ = fs::remove_dir_all(&d);
    }
}
