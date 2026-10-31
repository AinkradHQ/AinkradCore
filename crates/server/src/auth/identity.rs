//! The Core identity key (§3, §13): a P-256 key generated on first start and kept as a PKCS#8
//! file, mode 0600, beside the database. Its fingerprint (`core_fp`) is what `/handshake`
//! shows, and every signed request names it, so a request for one Core is refused by another.
//!
//! **Rotation** (handshake spec §13, planned rotation; never for a compromised key):
//! `ainkrad-core-server identity rotate <db>` ([`rotate`]) writes a new key beside the current
//! one (`core-identity.next.p8`, 0600) and the statement `Rotation{old_fp, new_fp, not_before,
//! seq}` signed by the current key (`core-rotation.json`), `not_before` [`WINDOW`] ahead. The
//! window counts from the first `serve` that loads the statement and so starts announcing it
//! (`core-rotation.announced`, stamped by [`Identity::announce`]), not from `rotate`: a Core not
//! restarted after `rotate` has announced nothing, and switching keys at its first restart would
//! strand every runner (re-review M2). Until `max(not_before, announced + WINDOW)` the Core keeps
//! presenting the current key and the hub sends the statement on every runner connection, so a
//! runner that connects at any time in the window records the new key beside its pin. The first
//! start after that makes the new key the identity: the old key file is replaced (destroyed) and
//! the statement removed. While a rotation is pending, the next key must be there and match the
//! statement, or the Core refuses to start before announcing anything (L1). A runner then
//! moves its pin when the Core first proves the new key. Not covered: a runner offline for the
//! whole window, and native clients (they get no statement); both pair again. A backup taken
//! during the window does not carry the next key.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use ainkrad_proto::v2::{Rotation, rotation_message};

use super::crypto::{b64, fingerprint, spki_of};

/// The file name beside the database.
pub const FILE: &str = "core-identity.p8";
/// The next key during a rotation window.
pub const NEXT: &str = "core-identity.next.p8";
/// The rotation statement during its window.
pub const ROTATION: &str = "core-rotation.json";
/// When a `serve` first announced the statement (unix seconds, unsigned): the window's start.
pub const ANNOUNCED: &str = "core-rotation.announced";
/// How long the current key keeps signing after `identity rotate`, seconds (§13: 7 days).
pub const WINDOW: i64 = 7 * 86_400;

pub struct Identity {
    key: EcdsaKeyPair,
    /// The public key as a 91-byte SPKI.
    pub spki: Vec<u8>,
    /// `core_fp`: base64url of SHA-256 over the SPKI.
    pub fp: String,
    /// The pending rotation's statement, signed by this key, while its window is open: the hub
    /// sends it to every runner that connects.
    pub rotation: Option<Rotation>,
    /// The fingerprint of the key this load replaced, when this load completed a rotation (the
    /// switchover): the caller audits it ([`audit`]).
    pub switched_from: Option<String>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("fp", &self.fp).finish()
    }
}

impl Identity {
    /// The key in `der` (PKCS#8): the file's contents, or a test vector's.
    pub fn from_pkcs8(der: &[u8]) -> std::io::Result<Self> {
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
                .map_err(|e| {
                std::io::Error::other(format!("the Core identity key is unusable: {e}"))
            })?;
        let spki = spki_of(key.public_key().as_ref());
        let fp = fingerprint(&spki);
        Ok(Self {
            key,
            spki,
            fp,
            rotation: None,
            switched_from: None,
        })
    }

    fn generate_pkcs8() -> std::io::Result<Vec<u8>> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| std::io::Error::other("generating the Core identity key failed"))
    }

    /// A key that lives only in memory (tests, and a Core without a state directory).
    pub fn ephemeral() -> Self {
        Self::from_pkcs8(&Self::generate_pkcs8().expect("key generation")).expect("fresh key")
    }

    /// The key in `dir`, created (0600, never overwritten) when there is none. A key file that
    /// others may read is refused rather than used. A pending rotation is attached, or, from
    /// its `not_before` on, completed ([`Identity::load_at`]).
    pub fn load_or_create(dir: &Path) -> std::io::Result<Self> {
        Self::load_at(dir, unix_now())
    }

    /// [`Identity::load_or_create`] at `now` (unix seconds).
    pub fn load_at(dir: &Path, now: i64) -> std::io::Result<Self> {
        let path = dir.join(FILE);
        let pending = read_rotation(dir)?;
        let announced = read_announced(dir)?;
        if let Some(r) = &pending
            && announced.is_some_and(|at| now >= r.not_before.max(at.saturating_add(WINDOW)))
        {
            // The window is over: the next key becomes the identity. A crash after the rename
            // leaves the statement, which the next start removes (the key already matches).
            let next = dir.join(NEXT);
            if next.exists() {
                let fp = Self::from_pkcs8(&read_private(&next)?)?.fp;
                if fp != r.new_fp {
                    return Err(std::io::Error::other(format!(
                        "{} is not the key {ROTATION} announces; nothing changed",
                        next.display()
                    )));
                }
                std::fs::rename(&next, &path)?;
            }
            let mut current = Self::from_pkcs8(&read_private(&path)?)?;
            if current.fp != r.new_fp {
                return Err(std::io::Error::other(format!(
                    "{ROTATION} names {} but {FILE} is {}; nothing changed",
                    r.new_fp, current.fp
                )));
            }
            std::fs::remove_file(dir.join(ROTATION))?;
            let _ = std::fs::remove_file(dir.join(ANNOUNCED));
            tracing::info!(core_fp = current.fp, "Core identity rotated to the new key");
            current.switched_from = Some(r.old_fp.clone());
            return Ok(current);
        }
        if !path.exists() {
            // Written whole to a private temp file, then linked into place: the key file is
            // either absent or complete, and a racing creator's key is kept, never replaced.
            let tmp = dir.join(format!(
                ".{FILE}.{}",
                super::crypto::random_id("t_").trim_start_matches("t_")
            ));
            let der = Self::generate_pkcs8()?;
            let written = (|| {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
                file.write_all(&der)?;
                file.sync_all()?;
                match std::fs::hard_link(&tmp, &path) {
                    Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
                    _ => Ok(()),
                }
            })();
            let _ = std::fs::remove_file(&tmp);
            written?;
        }
        let mut me = Self::from_pkcs8(&read_private(&path)?)?;
        if let Some(r) = pending {
            // Fail closed: a statement that is not this key's own is never sent.
            let sig = super::crypto::unb64(&r.sig, 86).unwrap_or_default();
            if r.old_fp != me.fp || !super::crypto::verify(&me.spki, &rotation_message(&r), &sig) {
                return Err(std::io::Error::other(format!(
                    "{ROTATION} is not signed by this Core's key {}; remove it and rotate again",
                    me.fp
                )));
            }
            // The key the statement announces must be here for the switch, checked before
            // anything is announced (re-review L1).
            let next = dir.join(NEXT);
            let fp = read_private(&next)
                .and_then(|der| Self::from_pkcs8(&der))
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "{ROTATION} announces {} but {} is unusable ({e}); restore it, or remove \
                         {ROTATION} to abandon the rotation",
                        r.new_fp,
                        next.display()
                    ))
                })?
                .fp;
            if fp != r.new_fp {
                return Err(std::io::Error::other(format!(
                    "{} is {fp}, not the key {ROTATION} announces ({})",
                    next.display(),
                    r.new_fp
                )));
            }
            me.rotation = Some(r);
        }
        Ok(me)
    }

    /// Stamps the window's start the first time a `serve` loads a pending statement (and so
    /// announces it); later calls keep the first stamp. Nothing to do without a statement.
    /// `true` when this call stamped it (the announcement to audit).
    pub fn announce(dir: &Path, now: i64) -> std::io::Result<bool> {
        if !dir.join(ROTATION).exists() || read_announced(dir)?.is_some() {
            return Ok(false);
        }
        match write_private(&dir.join(ANNOUNCED), now.to_string().as_bytes(), true) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
            Err(_) => Ok(false),
            Ok(()) => Ok(true),
        }
    }

    /// Starts a rotation in `dir` at `now` (`identity rotate`): writes the next key and the
    /// statement, signed by the current key, with `not_before = now + WINDOW`. Refused while a
    /// rotation is pending. The running Core sends the statement from its next start, and the
    /// window counts from then. What an interrupted earlier `rotate` left (a next key or a
    /// stamp with no statement) is cleared first (re-review L2).
    pub fn rotate(dir: &Path, now: i64) -> std::io::Result<Rotation> {
        if let Some(r) = read_rotation(dir)? {
            return Err(std::io::Error::other(format!(
                "a rotation to {} is already pending (not before {}, and a full window after the \
                 first serve that announces it)",
                r.new_fp, r.not_before
            )));
        }
        for stale in [NEXT, ANNOUNCED] {
            match std::fs::remove_file(dir.join(stale)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        let current = Self::load_at(dir, now)?;
        let der = Self::generate_pkcs8()?;
        let next = Self::from_pkcs8(&der)?;
        write_private(&dir.join(NEXT), &der, true)?;
        let mut r = Rotation {
            old_fp: current.fp.clone(),
            new_fp: next.fp,
            not_before: now + WINDOW,
            // Above any earlier rotation's: one per window at most, and time only grows.
            seq: u64::try_from(now).unwrap_or(0),
            sig: String::new(),
        };
        r.sig = b64(&current.sign(&rotation_message(&r)));
        let json = serde_json::to_vec_pretty(&r).map_err(std::io::Error::other)?;
        write_private(&dir.join(ROTATION), &json, false)?;
        Ok(r)
    }

    /// A raw `r‖s` signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key
            .sign(&SystemRandom::new(), message)
            .expect("signing with a loaded key")
            .as_ref()
            .to_vec()
    }
}

/// Writes the audit row of a rotation step (E1-11.8): `identity.rotation.started` (`identity
/// rotate`), `.announced` (the first `serve` that sends the statement) or `.switched` (the first
/// start after the window), by the system. Fingerprints are public; no key material goes in.
pub async fn audit(
    pool: &sqlx::SqlitePool,
    step: &str,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let event = ainkrad_core::audit::NewAuditEvent {
        actor: ainkrad_core::audit::AuditActor::System,
        action: format!("identity.rotation.{step}"),
        entity: None,
        details: details.to_string(),
    };
    crate::store::audit::append_one(pool, &event)
        .await
        .map(drop)
}

/// [`audit`] that retries a few times and then logs the row instead of failing: the key files
/// have already changed, so a database error must not stop the Core from starting, and the
/// switchover is in memory only. The log line carries the row (public fingerprints).
pub async fn audit_logged(pool: &sqlx::SqlitePool, step: &str, details: serde_json::Value) {
    let mut last = None;
    for wait in [0, 1, 3] {
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        match audit(pool, step, details.clone()).await {
            Ok(()) => return,
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        tracing::error!(step, %details, error = %e, "the rotation audit row could not be written");
    }
}

/// Audits the switchover `identity` completed when it was loaded, if it did.
pub async fn audit_switch(pool: &sqlx::SqlitePool, identity: &Identity) {
    if let Some(old) = &identity.switched_from {
        let details = serde_json::json!({"old_fp": old, "new_fp": identity.fp});
        audit_logged(pool, "switched", details).await;
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Reads a file only this user may read.
fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} is readable by others (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        )));
    }
    std::fs::read(path)
}

/// Writes `bytes` whole to `path`, 0600, through a private temp file. `new`: never over an
/// existing file.
fn write_private(path: &Path, bytes: &[u8], new: bool) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "tmp{}",
        super::crypto::random_id("t_").trim_start_matches("t_")
    ));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if new {
            std::fs::hard_link(&tmp, path)
        } else {
            std::fs::rename(&tmp, path)
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    written
}

/// When a `serve` first announced the pending statement, if one did.
fn read_announced(dir: &Path) -> std::io::Result<Option<i64>> {
    let path = dir.join(ANNOUNCED);
    if !path.exists() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&read_private(&path)?)
        .trim()
        .to_owned();
    text.parse()
        .map(Some)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))
}

/// The pending rotation statement in `dir`, if any.
fn read_rotation(dir: &Path) -> std::io::Result<Option<Rotation>> {
    let path = dir.join(ROTATION);
    if !path.exists() {
        return Ok(None);
    }
    serde_json::from_slice(&read_private(&path)?)
        .map(Some)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_0600_and_reloaded() {
        let dir = std::env::temp_dir().join(format!("core-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = Identity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.fp, b.fp, "the same key after a restart");
        assert!(super::super::crypto::verify(&b.spki, b"x", &a.sign(b"x")));
        std::fs::set_permissions(dir.join(FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load_or_create(&dir).is_err(), "world-readable");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// §13 planned rotation: the statement is signed by the current key and announces the new
    /// one; the Core keeps the current key until `not_before`, refuses a second rotation in the
    /// window, and from `not_before` on is the new key, with the old file and the statement gone.
    #[test]
    fn a_rotation_keeps_the_old_key_for_its_window_then_switches() {
        let dir = std::env::temp_dir().join(format!("core-identity-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = Identity::load_at(&dir, 1_000).unwrap();
        assert!(old.rotation.is_none());
        let r = Identity::rotate(&dir, 1_000).unwrap();
        assert_eq!(
            (r.old_fp.as_str(), r.not_before),
            (old.fp.as_str(), 1_000 + WINDOW)
        );
        let sig = super::super::crypto::unb64(&r.sig, 86).unwrap();
        assert!(super::super::crypto::verify(
            &old.spki,
            &rotation_message(&r),
            &sig
        ));
        for f in [NEXT, ROTATION] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
        assert!(
            Identity::rotate(&dir, 2_000).is_err(),
            "one rotation per window"
        );

        // Never announced (no serve since `rotate`): past `not_before` the old key stays, so a
        // late first restart strands no runner (re-review M2).
        let unannounced = Identity::load_at(&dir, 1_000 + 2 * WINDOW).unwrap();
        assert_eq!(unannounced.fp, old.fp);
        assert_eq!(unannounced.rotation.as_ref(), Some(&r));
        // The first serve announces it late; the window counts from then, and a second stamp
        // keeps the first.
        let first = 1_000 + 2 * WINDOW;
        Identity::announce(&dir, first).unwrap();
        Identity::announce(&dir, first + 50).unwrap();
        let during = Identity::load_at(&dir, first + WINDOW - 1).unwrap();
        assert_eq!(
            during.fp, old.fp,
            "the old key signs through the announced window"
        );
        assert_eq!(during.rotation.as_ref(), Some(&r));

        let after = Identity::load_at(&dir, first + WINDOW).unwrap();
        assert_eq!(after.fp, r.new_fp);
        assert_eq!(after.switched_from.as_deref(), Some(old.fp.as_str()));
        assert_eq!(during.switched_from, None);
        assert!(after.rotation.is_none());
        for f in [NEXT, ROTATION, ANNOUNCED] {
            assert!(!dir.join(f).exists(), "{f}");
        }
        assert_eq!(
            Identity::load_at(&dir, first + WINDOW).unwrap().fp,
            r.new_fp
        );

        // A statement this key did not sign is never used.
        let forged = Rotation {
            old_fp: after.fp.clone(),
            ..r.clone()
        };
        std::fs::write(dir.join(ROTATION), serde_json::to_vec(&forged).unwrap()).unwrap();
        std::fs::set_permissions(dir.join(ROTATION), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(Identity::load_at(&dir, 1_000).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Re-review L1 and L2: a pending rotation whose next key is missing or another key stops
    /// the Core before it announces anything; a `rotate` interrupted before its statement was
    /// written does not block the next one.
    #[test]
    fn a_missing_next_key_fails_early_and_an_interrupted_rotate_recovers() {
        let dir = std::env::temp_dir().join(format!("core-identity-l12-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = Identity::load_at(&dir, 1_000).unwrap();
        // L2: an orphan next key (the crash came before the statement).
        write_private(&dir.join(NEXT), b"not a key", true).unwrap();
        let r = Identity::rotate(&dir, 1_000).unwrap();
        assert_eq!(r.old_fp, old.fp);
        // L1: the next key goes missing, or is replaced, while the rotation is pending.
        let der = std::fs::read(dir.join(NEXT)).unwrap();
        std::fs::remove_file(dir.join(NEXT)).unwrap();
        let e = Identity::load_at(&dir, 1_001).unwrap_err().to_string();
        assert!(e.contains(NEXT), "{e}");
        let other = Identity::generate_pkcs8().unwrap();
        write_private(&dir.join(NEXT), &other, true).unwrap();
        let e = Identity::load_at(&dir, 1_001).unwrap_err().to_string();
        assert!(e.contains("not the key"), "{e}");
        std::fs::remove_file(dir.join(NEXT)).unwrap();
        write_private(&dir.join(NEXT), &der, true).unwrap();
        assert_eq!(Identity::load_at(&dir, 1_001).unwrap().rotation, Some(r));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    /// E1-11.8: each step of a rotation is one audit row by the system, with public fingerprints
    /// only; a plain load, and a repeated announce, write none.
    #[tokio::test]
    async fn each_rotation_step_writes_one_audit_row() {
        let dir = std::env::temp_dir().join(format!("core-identity-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::store::connect(&dir.join("core.db")).await.unwrap();
        let actions = |pool: &sqlx::SqlitePool| {
            let pool = pool.clone();
            async move {
                let mut rows =
                    crate::store::audit::page(&pool, None, Some("identity."), None, None, 20)
                        .await
                        .unwrap();
                rows.reverse();
                rows
            }
        };
        let old = Identity::load_at(&dir, 1_000).unwrap();
        audit_switch(&pool, &old).await;
        assert!(
            actions(&pool).await.is_empty(),
            "a plain load audits nothing"
        );

        let r = Identity::rotate(&dir, 1_000).unwrap();
        let details = serde_json::json!({"old_fp": r.old_fp, "new_fp": r.new_fp,
            "not_before": r.not_before});
        audit(&pool, "started", details).await.unwrap();
        assert!(Identity::announce(&dir, 2_000).unwrap());
        assert!(!Identity::announce(&dir, 2_500).unwrap(), "once");
        audit(&pool, "announced", serde_json::json!({"new_fp": r.new_fp}))
            .await
            .unwrap();
        let after = Identity::load_at(&dir, 2_000 + WINDOW).unwrap();
        audit_switch(&pool, &after).await;
        let again = Identity::load_at(&dir, 2_000 + WINDOW + 5).unwrap();
        audit_switch(&pool, &again).await;

        let rows = actions(&pool).await;
        let names: Vec<&str> = rows.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(
            names,
            [
                "identity.rotation.started",
                "identity.rotation.announced",
                "identity.rotation.switched"
            ]
        );
        assert!(
            rows.iter()
                .all(|e| e.actor == ainkrad_core::audit::AuditActor::System)
        );
        let switched: serde_json::Value = serde_json::from_str(&rows[2].details).unwrap();
        assert_eq!(switched["old_fp"], old.fp.as_str());
        assert_eq!(switched["new_fp"], r.new_fp.as_str());
        // The chain still verifies with the new rows in it.
        assert!(
            crate::store::audit::chain::verify_db(&pool)
                .await
                .unwrap()
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
