//! Probing a repo before it is added (API minor 18): is it reachable, what is its default branch,
//! may the forge token push to it, and what stack and commands does a shallow clone of it show.
//! Nothing is saved. Only network or local-path URLs are taken (`https`, `http`, `ssh`, `git@`,
//! an absolute path), git never prompts, and the forge token travels in git's environment, never
//! its arguments.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use ainkrad_providers::{AnyForge, Secret};
use base64::Engine;
use tokio::process::Command;

use super::repos::RepoCommands;

/// What a probe found.
pub struct Found {
    pub reachable: bool,
    pub default_branch: Option<String>,
    pub can_push: Option<bool>,
    pub stack: String,
    pub commands: RepoCommands,
    /// Why something is unknown, in a line.
    pub note: Option<String>,
}

/// Why `url` cannot be probed, if it cannot.
pub fn url_problem(url: &str) -> Option<String> {
    if let Some(why) = ainkrad_proto::runner::repo_url_problem(url) {
        return Some(why);
    }
    let ok = ["https://", "http://", "ssh://", "git@"]
        .iter()
        .any(|s| url.starts_with(s))
        || url.starts_with('/');
    (!ok).then(|| format!("{url:?} is not an https, http or ssh URL, or an absolute path"))
}

/// The forge's credentials for git, as `http.extraHeader` in git's environment.
pub struct GitAuth {
    pub header: String,
}

impl GitAuth {
    pub fn new(kind: ainkrad_providers::Kind, token: &Secret) -> Self {
        let user = match kind {
            ainkrad_providers::Kind::GitHub => "x-access-token",
            ainkrad_providers::Kind::GitLab => "oauth2",
        };
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{}", token.expose()));
        Self {
            header: format!("Authorization: Basic {b64}"),
        }
    }
}

fn git(auth: Option<&GitAuth>) -> Command {
    let mut c = Command::new("git");
    c.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "file:https:http:ssh:git")
        .env("GIT_ASKPASS", "true")
        .env("SSH_ASKPASS", "true")
        .env(
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o ConnectTimeout=10",
        )
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if let Some(a) = auth {
        c.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraHeader")
            .env("GIT_CONFIG_VALUE_0", &a.header);
    }
    c
}

/// Runs `c` for at most `secs`; its stdout when it succeeds.
async fn run(mut c: Command, secs: u64) -> Option<String> {
    let out = tokio::time::timeout(Duration::from_secs(secs), c.output())
        .await
        .ok()?
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The default branch from `git ls-remote --symref` output.
fn symref_branch(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_owned)
}

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Self> {
        let mut n = [0u8; 8];
        getrandom::fill(&mut n).map_err(std::io::Error::other)?;
        let name: String = n.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self(
            std::env::temp_dir().join(format!("citadel-probe-{name}")),
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Probes `url`, with the forge (its access check and git credentials) when given.
pub async fn probe(url: &str, forge: Option<(&AnyForge, &GitAuth)>) -> Found {
    let auth = forge.map(|(_, a)| a);
    let mut c = git(auth);
    c.args(["ls-remote", "--symref", "--", url, "HEAD"]);
    let listed = run(c, 20).await;
    let mut found = Found {
        reachable: listed.is_some(),
        default_branch: listed.as_deref().and_then(symref_branch),
        can_push: None,
        stack: String::new(),
        commands: RepoCommands::default(),
        note: listed
            .is_none()
            .then(|| "git could not reach it (wrong URL, or it needs access)".to_owned()),
    };
    if let Some((f, _)) = forge {
        match f.repo_access().await {
            Ok(a) => {
                found.can_push = Some(a.can_push);
                found.default_branch = a.default_branch.or(found.default_branch);
                found.reachable = true;
                found.note = None;
            }
            Err(e) => found.note = Some(format!("the forge refused the check: {e}")),
        }
    }
    if found.reachable
        && let Ok(dir) = Scratch::new()
    {
        let mut c = git(auth);
        c.args([
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--quiet",
            "--",
            url,
        ]);
        c.arg(&dir.0);
        if run(c, 60).await.is_some() {
            (found.stack, found.commands) = detect(&dir.0);
        }
    }
    found
}

/// The make targets a Makefile names.
fn make_targets(makefile: &str) -> Vec<String> {
    makefile
        .lines()
        .filter(|l| !l.starts_with(['\t', ' ', '#', '.']))
        .filter_map(|l| l.split_once(':'))
        .filter(|(_, rest)| !rest.starts_with('='))
        .flat_map(|(names, _)| {
            names
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The stack and the build, test, lint and format commands a checkout's files suggest: the
/// toolchain's own, a package manager's scripts, and a Makefile's `build`, `test`, `lint` and
/// `format` targets over both.
pub fn detect(dir: &Path) -> (String, RepoCommands) {
    let has = |f: &str| dir.join(f).exists();
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let mut stacks: Vec<&str> = vec![];
    let mut c = RepoCommands::default();
    let set = |c: &mut RepoCommands, b: &str, t: &str, l: &str, f: &str| {
        if c.build.is_empty() && c.test.is_empty() {
            *c = RepoCommands {
                build: b.into(),
                test: t.into(),
                lint: l.into(),
                format: f.into(),
            };
        }
    };
    if has("Package.swift") {
        stacks.push("Swift");
        set(&mut c, "swift build", "swift test", "", "");
    }
    if has("Cargo.toml") {
        stacks.push("Rust");
        let (b, t, l, f) = (
            "cargo build",
            "cargo test",
            "cargo clippy -- -D warnings",
            "cargo fmt",
        );
        set(&mut c, b, t, l, f);
    }
    if has("go.mod") {
        stacks.push("Go");
        set(
            &mut c,
            "go build ./...",
            "go test ./...",
            "go vet ./...",
            "gofmt -w .",
        );
    }
    if has("package.json") {
        stacks.push("Node");
        let pm = if has("pnpm-lock.yaml") {
            "pnpm"
        } else if has("yarn.lock") {
            "yarn"
        } else {
            "npm"
        };
        let pkg: serde_json::Value =
            serde_json::from_str(&read("package.json")).unwrap_or_default();
        let script = |n: &str| {
            if pkg["scripts"][n].is_string() {
                if n == "test" && pm == "npm" {
                    "npm test".to_owned()
                } else {
                    format!("{pm} run {n}")
                }
            } else {
                String::new()
            }
        };
        set(
            &mut c,
            &script("build"),
            &script("test"),
            &script("lint"),
            &script("format"),
        );
    }
    if has("pyproject.toml") || has("requirements.txt") {
        stacks.push("Python");
        set(&mut c, "", "pytest", "ruff check", "ruff format");
    }
    let targets = make_targets(&read("Makefile"));
    for (name, slot) in [
        ("build", &mut c.build),
        ("test", &mut c.test),
        ("lint", &mut c.lint),
        ("format", &mut c.format),
    ] {
        if targets.iter().any(|t| t == name) {
            *slot = format!("make {name}");
        }
    }
    (stacks.join(" · "), c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(files: &[(&str, &str)]) -> Scratch {
        let d = Scratch::new().unwrap();
        std::fs::create_dir_all(&d.0).unwrap();
        for (f, body) in files {
            std::fs::write(d.0.join(f), body).unwrap();
        }
        d
    }

    #[test]
    fn stacks_and_commands_come_from_the_files() {
        let d = dir(&[
            ("Cargo.toml", ""),
            ("package.json", r#"{"scripts":{"test":"x","lint":"y"}}"#),
        ]);
        let (stack, c) = detect(&d.0);
        assert_eq!(stack, "Rust · Node");
        assert_eq!(
            (c.build.as_str(), c.test.as_str()),
            ("cargo build", "cargo test")
        );

        let d = dir(&[
            ("package.json", r#"{"scripts":{"test":"x","build":"y"}}"#),
            ("pnpm-lock.yaml", ""),
            (
                "Makefile",
                "lint:\n\tfoo\n.PHONY: lint\nFLAGS := x\nformat test: deps\n\tbar\n",
            ),
        ]);
        let (stack, c) = detect(&d.0);
        assert_eq!(stack, "Node");
        assert_eq!(c.build, "pnpm run build");
        assert_eq!(
            (c.test.as_str(), c.lint.as_str(), c.format.as_str()),
            ("make test", "make lint", "make format")
        );
        assert_eq!(detect(&dir(&[]).0).0, "");
    }

    #[test]
    fn urls_and_symrefs() {
        for ok in [
            "https://github.com/a/b",
            "ssh://git@h/a",
            "git@github.com:a/b.git",
            "/srv/repo",
        ] {
            assert_eq!(url_problem(ok), None, "{ok}");
        }
        for bad in [
            "ext::sh -c id",
            "--upload-pack=x",
            "file:///x",
            "relative/path",
            "https://u:p@h/x",
        ] {
            assert!(url_problem(bad).is_some(), "{bad}");
        }
        assert_eq!(
            symref_branch("ref: refs/heads/trunk\tHEAD\nabc\tHEAD\n").as_deref(),
            Some("trunk")
        );
        assert_eq!(symref_branch("abc\tHEAD\n"), None);
    }
}
