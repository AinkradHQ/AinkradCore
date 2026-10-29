//! The keystore: one JSON file, mode 0600 in a 0700 directory, holding this device's routine
//! key (PKCS#8, generated here), its id, the pinned Core fingerprint and where the Core is.
//! It is written to a temporary file and renamed into place, and refused on load when anyone
//! but its owner can read it (as ssh does with a private key).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::{Key, b64, unb64};

/// The file's version; a newer one is refused, not guessed at.
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    device_id: String,
    /// `core_fp`, pinned at pairing: from the QR, or the key `POST /handshake` proved, confirmed by the SAS.
    core_fp: String,
    /// `unix:<path>` or a URL; what `--socket`/`--url` default to.
    endpoint: String,
    /// The `Host` to send, when it is not the endpoint's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    routine_pkcs8: String,
}

pub struct Keystore {
    pub device_id: String,
    pub core_fp: String,
    pub endpoint: String,
    pub host: Option<String>,
    pub key: Key,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("device_id", &self.device_id)
            .field("core_fp", &self.core_fp)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// `$AINKRADCTL_KEYSTORE`, else `$XDG_CONFIG_HOME/ainkradctl/keystore.json`, else under
/// `~/.config`.
pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AINKRADCTL_KEYSTORE") {
        return Some(p.into());
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))?;
    Some(config.join("ainkradctl").join("keystore.json"))
}

impl Keystore {
    pub fn load(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        let meta =
            fs::metadata(path).map_err(|e| format!("no keystore at {shown} ({e}): pair first"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{shown} is readable by others (mode {:o}): chmod 600 it",
                meta.permissions().mode() & 0o777
            ));
        }
        let text = Zeroizing::new(fs::read(path).map_err(|e| format!("reading {shown}: {e}"))?);
        let file: File =
            serde_json::from_slice(&text).map_err(|_| format!("{shown} is not a keystore"))?;
        let file = Zeroizing::new(file);
        if file.version != VERSION {
            return Err(format!(
                "{shown}: keystore version {} unknown",
                file.version
            ));
        }
        let pkcs8 = Zeroizing::new(unb64(&file.routine_pkcs8).unwrap_or_default());
        let key =
            Key::from_pkcs8(&pkcs8).ok_or_else(|| format!("{shown}: the key does not parse"))?;
        Ok(Self {
            device_id: file.device_id.clone(),
            core_fp: file.core_fp.clone(),
            endpoint: file.endpoint.clone(),
            host: file.host.clone(),
            key,
        })
    }

    /// Writes the keystore: the directory is made 0700, the file 0600 from its first byte, and
    /// it replaces any file at `path` only once fully written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let file = Zeroizing::new(File {
            version: VERSION,
            device_id: self.device_id.clone(),
            core_fp: self.core_fp.clone(),
            endpoint: self.endpoint.clone(),
            host: self.host.clone(),
            routine_pkcs8: b64(self.key.pkcs8()),
        });
        let text = Zeroizing::new(serde_json::to_vec_pretty(&*file).expect("serialisable"));
        let tmp = dir.join(format!(".keystore-{}.tmp", std::process::id()));
        let written = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&text)?;
            f.sync_all()?;
            fs::rename(&tmp, path)
        })();
        written.map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("writing {}: {e}", path.display())
        })
    }
}

impl zeroize::Zeroize for File {
    fn zeroize(&mut self) {
        self.routine_pkcs8.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_0600_in_0700_round_trips_and_refuses_loose_modes() {
        let dir = std::env::temp_dir().join(format!("ctl-ks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("keystore.json");
        let ks = Keystore {
            device_id: "d_x".into(),
            core_fp: "fp".into(),
            endpoint: "unix:/s".into(),
            host: None,
            key: Key::generate(),
        };
        ks.save(&path).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let back = Keystore::load(&path).unwrap();
        assert_eq!(back.key.spki(), ks.key.spki());
        assert!(!format!("{back:?}").contains(&b64(ks.key.pkcs8())));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            Keystore::load(&path)
                .unwrap_err()
                .contains("readable by others")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
