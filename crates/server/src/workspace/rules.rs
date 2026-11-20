//! What a workspace sync includes (E15-2, spec 4.4). Pure: no I/O.
//!
//! - `.git` is never synced, in either direction, and no project setting can change that.
//! - Build output (`target/`, `node_modules/` ...) stays in the runner's warm cache: not synced in.
//!   Synced out only when it matches a project `outputs` glob.
//! - Secret-shaped files (`.env*`, keys, `.npmrc` ...) are never synced unless the project lists
//!   them in `[sync] include`.
//!
//! The project's overrides come from `.ainkrad/jobs.toml`:
//! ```toml
//! [sync]
//! include = [".env.example", "certs/*.pem"]   # secret-shaped files this project does sync
//! exclude = ["big-fixtures/**"]               # more to leave out
//! outputs = ["target/release/app"]            # build output that comes back
//! ```

use ainkrad_proto::v2::SyncRules;
use serde::Deserialize;

/// Directories that are build output, by name (any depth).
pub const BUILD_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".build",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
    "DerivedData",
    ".next",
    ".turbo",
];

/// Files that look like secrets, by file name (`*` matches any run).
const SECRET_NAMES: &[&str] = &[
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "id_*", ".npmrc", ".pypirc", ".netrc", "*.kdbx",
];

/// The `[sync]` table of `.ainkrad/jobs.toml`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SyncConfig {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Deserialize, Default)]
struct JobsToml {
    #[serde(default)]
    sync: SyncConfig,
}

/// Why a path is not synced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    Git,
    BuildOutput,
    Secret,
    Excluded,
}

#[derive(Clone, Debug, Default)]
pub struct Rules {
    cfg: SyncConfig,
}

impl Rules {
    pub fn new(cfg: SyncConfig) -> Self {
        Self { cfg }
    }

    /// From the text of `.ainkrad/jobs.toml`; a file that does not parse gives the defaults (the
    /// strict ones: nothing extra is included).
    pub fn from_toml(text: &str) -> Self {
        let parsed: JobsToml = toml::from_str(text).unwrap_or_default();
        Self::new(parsed.sync)
    }

    /// The effective rules as they go on the wire (`SyncRules`, spec 4.4): the built-in excludes
    /// (build directories as `name/`, the secret-shaped names) merged with the project's own.
    /// `.git/` is left out of the list: both ends exclude it whatever the rules say.
    pub fn to_wire(&self) -> SyncRules {
        let built = BUILD_DIRS
            .iter()
            .map(|d| format!("{d}/"))
            .chain(SECRET_NAMES.iter().map(|s| (*s).to_owned()));
        SyncRules {
            include: self.cfg.include.clone(),
            exclude: built.chain(self.cfg.exclude.iter().cloned()).collect(),
            outputs: self.cfg.outputs.clone(),
        }
    }

    /// The hash of the wire rules (`SyncManifest::rules_hash`), the same for the same rules in any order.
    pub fn hash(&self) -> [u8; 32] {
        let mut w = self.to_wire();
        for list in [&mut w.include, &mut w.exclude, &mut w.outputs] {
            list.sort();
        }
        let json = serde_json::to_vec(&w).expect("rules serialize");
        *blake3::hash(&json).as_bytes()
    }

    fn listed(&self, rel: &str) -> bool {
        self.cfg.include.iter().any(|g| glob(g, rel))
    }

    fn in_output(&self, rel: &str) -> bool {
        self.cfg.outputs.iter().any(|g| glob(g, rel))
    }

    /// The project lists files to sync (so a build directory may hold some).
    pub fn has_include(&self) -> bool {
        !self.cfg.include.is_empty()
    }

    /// Sync IN (Core to runner): `None` to include `rel` (a file or link path), else why not.
    pub fn sync_in(&self, rel: &str) -> Option<Skip> {
        if has_git(rel) {
            return Some(Skip::Git);
        }
        if self.cfg.exclude.iter().any(|g| glob(g, rel)) {
            return Some(Skip::Excluded);
        }
        if in_build_dir(rel) && !self.listed(rel) {
            return Some(Skip::BuildOutput);
        }
        if is_secret(rel) && !self.listed(rel) {
            return Some(Skip::Secret);
        }
        None
    }

    /// Sync OUT (runner to Core): the same, except build output comes back when `outputs` names it.
    pub fn sync_out(&self, rel: &str) -> Option<Skip> {
        if has_git(rel) {
            return Some(Skip::Git);
        }
        if self.cfg.exclude.iter().any(|g| glob(g, rel)) {
            return Some(Skip::Excluded);
        }
        if in_build_dir(rel) && !self.in_output(rel) && !self.listed(rel) {
            return Some(Skip::BuildOutput);
        }
        if is_secret(rel) && !self.listed(rel) {
            return Some(Skip::Secret);
        }
        None
    }
}

/// Any component of `rel` is `.git`, whatever its case (a case-folding disk would alias it).
pub fn has_git(rel: &str) -> bool {
    rel.split('/').any(|p| p.eq_ignore_ascii_case(".git"))
}

/// Any DIRECTORY component of `rel` (the last is the file) is a build directory.
pub fn in_build_dir(rel: &str) -> bool {
    let mut it = rel.split('/').peekable();
    while let Some(p) = it.next() {
        if it.peek().is_some() && BUILD_DIRS.contains(&p) {
            return true;
        }
    }
    false
}

/// The file name of `rel` looks like a secret (`.env`, `*.pem` ...).
pub fn is_secret(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    SECRET_NAMES.iter().any(|g| glob(g, name))
}

/// A small glob: `*` any run without `/`, `**` any run (also across `/`), `?` one character
/// that is not `/`. A pattern with no `/` also matches the last component anywhere
/// (`*.pem` matches `a/b/c.pem`). Case-sensitive.
pub fn glob(pat: &str, path: &str) -> bool {
    if !pat.contains('/') {
        let name = path.rsplit('/').next().unwrap_or(path);
        return glob_at(pat.as_bytes(), name.as_bytes());
    }
    glob_at(pat.trim_start_matches("./").as_bytes(), path.as_bytes())
}

fn glob_at(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            // `**/` also matches zero folders.
            let rest = rest.strip_prefix(b"/").unwrap_or(rest);
            (0..=s.len()).any(|i| glob_at(rest, &s[i..]))
        }
        Some(b'*') => {
            let rest = &p[1..];
            let run = s.iter().position(|&c| c == b'/').unwrap_or(s.len());
            (0..=run).any(|i| glob_at(rest, &s[i..]))
        }
        Some(b'?') => s.first().is_some_and(|&c| c != b'/') && glob_at(&p[1..], &s[1..]),
        Some(&c) => s.first() == Some(&c) && glob_at(&p[1..], &s[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_is_never_synced_and_no_setting_lifts_it() {
        let r = Rules::new(SyncConfig {
            include: vec![".git/**".into(), "**".into()],
            outputs: vec!["**".into()],
            ..Default::default()
        });
        for p in [".git/config", "a/.git/hooks/x", ".GIT/x", "sub/.Git"] {
            assert_eq!(r.sync_in(p), Some(Skip::Git), "{p}");
            assert_eq!(r.sync_out(p), Some(Skip::Git), "{p}");
        }
        assert_eq!(Rules::default().sync_in(".gitignore"), None);
    }

    #[test]
    fn build_output_and_secrets_stay_out_unless_the_project_says() {
        let r = Rules::default();
        assert_eq!(r.sync_in("target/debug/x"), Some(Skip::BuildOutput));
        assert_eq!(r.sync_in("a/node_modules/p/i.js"), Some(Skip::BuildOutput));
        assert_eq!(
            r.sync_in("src/build.rs"),
            None,
            "a file named build is not a dir"
        );
        assert_eq!(r.sync_in("app/.env"), Some(Skip::Secret));
        assert_eq!(r.sync_in(".env.local"), Some(Skip::Secret));
        for p in [
            "k.pem",
            "x/id_ed25519",
            ".npmrc",
            "a/.netrc",
            "v.kdbx",
            "t.key",
        ] {
            assert_eq!(r.sync_in(p), Some(Skip::Secret), "{p}");
            assert_eq!(r.sync_out(p), Some(Skip::Secret), "{p}");
        }
        let r = Rules::from_toml(
            "[sync]\ninclude=[\".env.example\", \"certs/*.pem\"]\noutputs=[\"target/release/app\"]\n",
        );
        assert_eq!(r.sync_in(".env.example"), None);
        assert_eq!(r.sync_in("certs/a.pem"), None);
        assert_eq!(r.sync_in("other/a.pem"), Some(Skip::Secret));
        assert_eq!(r.sync_in("target/release/app"), Some(Skip::BuildOutput));
        assert_eq!(r.sync_out("target/release/app"), None);
        assert_eq!(r.sync_out("target/release/other"), Some(Skip::BuildOutput));
    }

    #[test]
    fn globs_match_as_documented_and_a_bad_toml_gives_the_strict_defaults() {
        assert!(glob("*.pem", "a/b/c.pem") && !glob("a/*.pem", "a/b/c.pem"));
        assert!(glob("a/**", "a/b/c") && glob("a/**/c", "a/c") && glob("a/**/c", "a/b/c"));
        assert!(glob("a/?.x", "a/b.x") && !glob("a/?.x", "a//.x"));
        assert!(!glob(".env.*", ".env") && glob(".env", ".env"));
        assert_eq!(
            Rules::from_toml("[sync\n").sync_in(".env"),
            Some(Skip::Secret)
        );
    }

    #[test]
    fn the_rules_hash_changes_with_the_rules_and_not_with_their_order() {
        let a = |i: &[&str]| {
            Rules::new(SyncConfig {
                include: i.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            })
        };
        assert_eq!(a(&["x", "y"]).hash(), a(&["y", "x"]).hash());
        assert_ne!(a(&["x"]).hash(), a(&["y"]).hash());
        assert_ne!(
            a(&[]).hash(),
            Rules::new(SyncConfig {
                exclude: vec!["x".into()],
                ..Default::default()
            })
            .hash()
        );
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn the_wire_rules_carry_the_built_ins_and_the_projects_own() {
        let w = Rules::from_toml("[sync]\ninclude=[\".env.example\"]\nexclude=[\"big/**\"]\noutputs=[\"target/release/app\"]\n").to_wire();
        assert!(
            w.exclude.contains(&"target/".to_owned()) && w.exclude.contains(&".env.*".to_owned())
        );
        assert!(w.exclude.contains(&"big/**".to_owned()));
        assert_eq!(w.include, [".env.example"]);
        assert_eq!(w.outputs, ["target/release/app"]);
        assert_eq!(Rules::default().hash(), Rules::default().hash());
    }
}
