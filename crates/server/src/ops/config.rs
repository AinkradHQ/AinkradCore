//! The config (E1-13.1): one TOML file plus `AINKRAD_*` environment overrides, and the layout of
//! a home. The Core has no fixed home (ADR D1): `init <home>` writes `<home>/config.toml`, and
//! every other verb finds it through `--config <file>` or `$AINKRAD_CONFIG`.
//!
//! Keys (each overridden by the environment variable named beside it, when that is non-empty):
//!
//! | key | env | meaning |
//! |---|---|---|
//! | `home` | `AINKRAD_HOME` | the state directory: `core.db`, `keys/`, `backups/`, `tls/` (ACME) |
//! | `listen` | `AINKRAD_LISTEN` | `serve --listen`: `unix:`, `unix:<path>`, `loopback:<port>`, `public` |
//! | `hostname` | `AINKRAD_HOSTNAME` | `serve --hostname` (public only) |
//! | `acme_contact` | `AINKRAD_ACME_CONTACT` | `serve --acme-contact` (public only) |
//! | `log_format` | `AINKRAD_LOG_FORMAT` | `text` or `json` (`serve --log-format`) |
//! | `backup_recipient` | `AINKRAD_BACKUP_RECIPIENT` | the `age1…` public key backups are encrypted to |
//! | `backup_keep_local` | `AINKRAD_BACKUP_KEEP_LOCAL` | encrypted snapshots kept in `<home>/backups` |
//!
//! The bucket's endpoint and credentials are never in this file: they come only from the
//! environment (`s3::Bucket::from_env`), on the VM from `/etc/ainkrad/backup.env`. The bucket's
//! own retention (35 days) is a lifecycle rule on the bucket, not a setting here.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub home: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub acme_contact: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default)]
    pub backup_recipient: String,
    #[serde(default = "default_keep_local")]
    pub backup_keep_local: u32,
}

fn default_listen() -> String {
    "unix:".to_owned()
}

fn default_log_format() -> String {
    "text".to_owned()
}

fn default_keep_local() -> u32 {
    7
}

/// The config `init` writes, with every key documented.
pub fn template(home: &Path) -> String {
    let home = toml::Value::String(home.display().to_string());
    format!(
        "# Ainkrad Core config (E1-13). Every key can be overridden by an environment variable:\n\
         # AINKRAD_<KEY in upper case>, e.g. AINKRAD_LISTEN. Bucket credentials never go here:\n\
         # they come from the environment (AINKRAD_BACKUP_ENDPOINT, _BUCKET, _REGION, _PREFIX,\n\
         # _ACCESS_KEY, _SECRET_KEY), on the VM from /etc/ainkrad/backup.env.\n\
         \n\
         # State: core.db, keys/ (master key, backup signing key), backups/, tls/ (ACME).\n\
         home = {home}\n\
         # serve --listen: unix: (a socket in home), unix:<path>, loopback:<port>, public (TLS on :443).\n\
         listen = \"unix:\"\n\
         # public only: the DNS name and the ACME account's email.\n\
         hostname = \"\"\n\
         acme_contact = \"\"\n\
         # text or json; both are redacted.\n\
         log_format = \"text\"\n\
         # The age recipient (age1...) backups are encrypted to. Its identity stays OFF this host:\n\
         # make one with `ainkrad-core-server backup-keygen` on another machine.\n\
         backup_recipient = \"\"\n\
         # Encrypted snapshots kept in home/backups (the bucket keeps its own 35 days).\n\
         backup_keep_local = 7\n"
    )
}

impl Config {
    /// Reads `path` and applies the environment's overrides.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading the config {}: {e}", path.display()))?;
        Self::parse(&text, |name| std::env::var(name).ok())
            .map_err(|e| format!("config {}: {e}", path.display()))
    }

    /// `--config <file>` if given, else `$AINKRAD_CONFIG`.
    pub fn find(flag: Option<&str>) -> Result<Self, String> {
        let path = flag
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("AINKRAD_CONFIG").map(PathBuf::from))
            .ok_or("no config: pass --config <file> or set AINKRAD_CONFIG")?;
        Self::load(&path)
    }

    /// Parses `text`, then overrides each key from `env` (a lookup, so tests need no process
    /// environment).
    pub fn parse(text: &str, env: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        let env = |name: &str| env(name).filter(|v| !v.is_empty());
        if let Some(v) = env("AINKRAD_HOME") {
            c.home = v.into();
        }
        for (name, field) in [
            ("AINKRAD_LISTEN", &mut c.listen),
            ("AINKRAD_HOSTNAME", &mut c.hostname),
            ("AINKRAD_ACME_CONTACT", &mut c.acme_contact),
            ("AINKRAD_LOG_FORMAT", &mut c.log_format),
            ("AINKRAD_BACKUP_RECIPIENT", &mut c.backup_recipient),
        ] {
            if let Some(v) = env(name) {
                *field = v;
            }
        }
        if let Some(v) = env("AINKRAD_BACKUP_KEEP_LOCAL") {
            c.backup_keep_local = v
                .parse()
                .map_err(|_| format!("AINKRAD_BACKUP_KEEP_LOCAL={v:?} is not a count"))?;
        }
        if !["text", "json"].contains(&c.log_format.as_str()) {
            return Err(format!("log_format {:?}: text or json", c.log_format));
        }
        if c.backup_keep_local == 0 {
            return Err("backup_keep_local must be at least 1".into());
        }
        if c.home.as_os_str().is_empty() {
            return Err("home is empty".into());
        }
        Ok(c)
    }

    pub fn home(&self) -> Home {
        Home(self.home.clone())
    }

    /// `serve`'s flags from the config, each only where `given` (the command line) does not
    /// already set it; the command line wins. The hostname and ACME contact go only with a
    /// public listener.
    pub fn serve_flags(&self, given: &[&str]) -> Vec<String> {
        let has = |f: &str| given.contains(&f);
        let mut out = Vec::new();
        let mut add = |flag: &str, value: &str| {
            if !value.is_empty() && !has(flag) {
                out.extend([flag.to_owned(), value.to_owned()]);
            }
        };
        if !has("--bind") {
            add("--listen", &self.listen);
        }
        let listen = given
            .iter()
            .position(|f| *f == "--listen")
            .and_then(|i| given.get(i + 1).copied())
            .unwrap_or(&self.listen);
        if listen.starts_with("public") {
            add("--hostname", &self.hostname);
            add("--acme-contact", &self.acme_contact);
        }
        add("--log-format", &self.log_format);
        out.extend(given.iter().map(|f| (*f).to_owned()));
        out
    }
}

/// A home's paths.
#[derive(Debug, Clone)]
pub struct Home(pub PathBuf);

impl Home {
    pub fn config(&self) -> PathBuf {
        self.0.join("config.toml")
    }
    pub fn db(&self) -> PathBuf {
        self.0.join("core.db")
    }
    pub fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }
    /// 32 random bytes, 0600: the store's `SecretBox` key.
    pub fn master_key(&self) -> PathBuf {
        self.keys().join("master.key")
    }
    /// PKCS#8 P-256, 0600: signs every snapshot and export.
    pub fn signing_key(&self) -> PathBuf {
        self.keys().join("backup-signing.p8")
    }
    /// PKCS#8 P-256, 0600, made on first serve: the Core identity devices and runners pin.
    pub fn identity(&self) -> PathBuf {
        self.0.join(crate::auth::identity::FILE)
    }
    pub fn backups(&self) -> PathBuf {
        self.0.join("backups")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_parses_and_the_environment_overrides_it() {
        let text = template(Path::new("/var/lib/ainkrad core"));
        let plain = Config::parse(&text, |_| None).unwrap();
        assert_eq!(plain.home, Path::new("/var/lib/ainkrad core"));
        assert_eq!(
            (plain.listen.as_str(), plain.backup_keep_local),
            ("unix:", 7)
        );
        let env = |name: &str| match name {
            "AINKRAD_LISTEN" => Some("loopback:7700".to_owned()),
            "AINKRAD_LOG_FORMAT" => Some("json".to_owned()),
            "AINKRAD_BACKUP_KEEP_LOCAL" => Some("3".to_owned()),
            "AINKRAD_HOSTNAME" => Some(String::new()),
            _ => None,
        };
        let c = Config::parse(&text, env).unwrap();
        assert_eq!(
            (
                c.listen.as_str(),
                c.log_format.as_str(),
                c.backup_keep_local
            ),
            ("loopback:7700", "json", 3)
        );
        assert_eq!(c.hostname, "", "an empty variable overrides nothing");
        assert!(
            Config::parse(&text, |n| (n == "AINKRAD_LOG_FORMAT").then(|| "xml".into())).is_err()
        );
        assert!(Config::parse("home = \"/x\"\nlisten_typo = 1\n", |_| None).is_err());
    }

    #[test]
    fn serve_flags_come_from_the_config_and_the_command_line_wins() {
        let mut c = Config::parse("home = \"/h\"\n", |_| None).unwrap();
        c.hostname = "core.example".into();
        c.acme_contact = "ops@example.test".into();
        assert_eq!(
            c.serve_flags(&[]),
            ["--listen", "unix:", "--log-format", "text"]
        );
        assert_eq!(
            c.serve_flags(&["--listen", "public"]),
            [
                "--hostname",
                "core.example",
                "--acme-contact",
                "ops@example.test",
                "--log-format",
                "text",
                "--listen",
                "public"
            ]
        );
        assert_eq!(
            c.serve_flags(&["--bind", "0.0.0.0:1"]),
            ["--log-format", "text", "--bind", "0.0.0.0:1"]
        );
    }
}
