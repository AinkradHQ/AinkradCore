//! The include/exclude rules the Core sends with every `sync.*` op (`SyncRules`, spec §4.4), applied
//! exactly as the Core's `workspace::rules::Rules` does (E15-2 defines them; this is the runner's
//! copy, kept in step by the table test below).
//!
//! On the wire `exclude` is the built-ins (each build directory as `name/`, the secret-shaped file
//! names) merged with the project's own. The built-ins give way to a project `include`; a project
//! exclude never does, so the runner tells them apart by the built-in lists.

use ainkrad_proto::v2::SyncRules;

/// Build output: stays on the runner's own warm cache.
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

/// Files that look like secrets, by file name.
pub const SECRET_NAMES: &[&str] = &[
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "id_*", ".npmrc", ".pypirc", ".netrc", "*.kdbx",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    include: Vec<String>,
    /// The project's own excludes (the built-ins are applied by name).
    exclude: Vec<String>,
    outputs: Vec<String>,
}

fn builtin(g: &str) -> bool {
    SECRET_NAMES.contains(&g) || g.strip_suffix('/').is_some_and(|d| BUILD_DIRS.contains(&d))
}

impl Rules {
    pub fn from_wire(w: &SyncRules) -> Self {
        Self {
            include: w.include.clone(),
            exclude: w.exclude.iter().filter(|g| !builtin(g)).cloned().collect(),
            outputs: w.outputs.clone(),
        }
    }

    fn listed(&self, rel: &str) -> bool {
        self.include.iter().any(|g| glob(g, rel))
    }

    fn in_output(&self, rel: &str) -> bool {
        self.outputs.iter().any(|g| glob(g, rel))
    }

    /// A build directory is walked only when a rule can reach into it.
    pub fn enters_build_dirs(&self, out: bool) -> bool {
        !self.include.is_empty() || (out && !self.outputs.is_empty())
    }

    /// Sync IN: `true` to include `rel` (a file or link path).
    pub fn sync_in(&self, rel: &str) -> bool {
        if has_git(rel) || self.exclude.iter().any(|g| glob(g, rel)) {
            return false;
        }
        if in_build_dir(rel) && !self.listed(rel) {
            return false;
        }
        !(is_secret(rel) && !self.listed(rel))
    }

    /// Sync OUT: the same, except build output comes back when `outputs` names it.
    pub fn sync_out(&self, rel: &str) -> bool {
        if has_git(rel) || self.exclude.iter().any(|g| glob(g, rel)) {
            return false;
        }
        if in_build_dir(rel) && !self.in_output(rel) && !self.listed(rel) {
            return false;
        }
        !(is_secret(rel) && !self.listed(rel))
    }
}

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

pub fn is_secret(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    SECRET_NAMES.iter().any(|g| glob(g, name))
}

/// A small glob: `*` any run without `/`, `**` any run (also across `/`), `?` one character that is
/// not `/`. A pattern with no `/` also matches the last component anywhere. Case-sensitive.
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

    /// What the Core's `Rules::to_wire` sends for a project with the given own lists.
    fn wire(include: &[&str], exclude: &[&str], outputs: &[&str]) -> SyncRules {
        let own = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        SyncRules {
            include: own(include),
            exclude: BUILD_DIRS
                .iter()
                .map(|d| format!("{d}/"))
                .chain(SECRET_NAMES.iter().map(|s| (*s).to_owned()))
                .chain(own(exclude))
                .collect(),
            outputs: own(outputs),
        }
    }

    #[test]
    fn built_ins_are_told_from_the_projects_own_excludes() {
        let r = Rules::from_wire(&wire(&[], &["docs/**"], &[]));
        assert_eq!(r.exclude, vec!["docs/**".to_owned()]);
    }

    #[test]
    fn sync_in_drops_git_build_output_secrets_and_project_excludes() {
        let r = Rules::from_wire(&wire(&[], &["docs/**"], &[]));
        for no in [
            ".git/config",
            "a/.GIT/x",
            "target/debug/x",
            "web/node_modules/a.js",
            ".env",
            "k/id_rsa",
            "docs/a.md",
        ] {
            assert!(!r.sync_in(no), "{no}");
        }
        for yes in ["src/main.rs", ".github/ci.yml", "build.rs", "src/target.rs"] {
            assert!(r.sync_in(yes), "{yes}");
        }
    }

    #[test]
    fn a_project_include_lets_a_secret_shaped_file_in_but_never_a_project_exclude() {
        let r = Rules::from_wire(&wire(&[".env.test", "dist/keep.js"], &["dist/**"], &[]));
        assert!(r.sync_in(".env.test"));
        assert!(!r.sync_in(".env.prod"));
        assert!(!r.sync_in("dist/keep.js"), "the project's own exclude wins");
        assert!(r.enters_build_dirs(false));
    }

    #[test]
    fn sync_out_brings_back_named_build_output_only() {
        let r = Rules::from_wire(&wire(&[], &[], &["target/release/app"]));
        assert!(r.sync_out("target/release/app"));
        assert!(!r.sync_out("target/debug/x"));
        assert!(r.sync_out("src/lib.rs"));
        assert!(!r.sync_in("target/release/app"));
        assert!(r.enters_build_dirs(true) && !r.enters_build_dirs(false));
    }

    #[test]
    fn globs_match_like_the_cores() {
        assert!(glob("*.pem", "a/b/c.pem"));
        assert!(glob("src/**/*.rs", "src/a/b.rs"));
        assert!(glob("src/**/*.rs", "src/b.rs"));
        assert!(!glob("src/*.rs", "src/a/b.rs"));
        assert!(glob("a?c", "abc") && !glob("a?c", "a/c"));
    }
}
