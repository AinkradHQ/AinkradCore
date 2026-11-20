//! `git` on a folder an agent may have written (E15 security review H1). The Core and the runner
//! read a file's `HEAD` copy for a revert. The folder is the agent's, so every file git could read
//! there (the repo, its config, its object store) is untrusted. Git is given:
//! - an explicit `--git-dir`: a real `.git` directory (not a link, not a `gitdir:` file) found
//!   beneath the root by [`enclosing_repo`], so a fake bare repository at the root is never used;
//! - no system or global config (`GIT_CONFIG_SYSTEM`/`GLOBAL` empty), no replace objects;
//! - no lazy fetch (`GIT_NO_LAZY_FETCH`), no transport (`protocol.allow=never`), no implicit bare
//!   repo, no fsmonitor, no hooks; `safe.directory` names only this repo, never `*`.
//!
//! A repo whose config could still fetch on a git older than 2.44 (which ignores
//! `GIT_NO_LAZY_FETCH`) is refused outright: a promisor or partial-clone setting, or an `include`
//! that could bring one in. So is one that borrows objects (`alternates`, `commondir`), which
//! would read another project's files.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The repo that holds `rel` (a checked wire path) beneath `root`: its work tree, and `rel` inside
/// it. The deepest folder on the way with a real `.git` directory wins; no folder on the way may
/// be a link. `None` when there is none, or it is not safe to read (see the module docs).
pub fn enclosing_repo(root: &Path, rel: &str) -> Option<(PathBuf, String)> {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return None;
    }
    let mut dirs = vec![root.to_path_buf()];
    for p in &parts[..parts.len() - 1] {
        let next = dirs.last()?.join(p);
        let m = std::fs::symlink_metadata(&next).ok()?;
        if !m.is_dir() {
            return None;
        }
        dirs.push(next);
    }
    for (i, dir) in dirs.iter().enumerate().rev() {
        let git = dir.join(".git");
        match std::fs::symlink_metadata(&git) {
            Ok(m) if m.is_dir() => {
                return repo_clean(&git).then(|| (dir.clone(), parts[i..].join("/")));
            }
            Ok(_) => return None,
            Err(_) => {}
        }
    }
    None
}

/// Whether a `.git` dir can be read without git fetching, borrowing or including anything.
fn repo_clean(git: &Path) -> bool {
    for borrowed in ["objects/info/alternates", "commondir", "config.worktree"] {
        if std::fs::symlink_metadata(git.join(borrowed)).is_ok() {
            return false;
        }
    }
    let Ok(m) = std::fs::symlink_metadata(git.join("config")) else {
        return true;
    };
    if !m.is_file() || m.len() > 64 * 1024 {
        return false;
    }
    let Ok(text) = std::fs::read(git.join("config")) else {
        return false;
    };
    let text = String::from_utf8_lossy(&text).to_ascii_lowercase();
    !["promisor", "partialclone", "include", "worktreeconfig"]
        .iter()
        .any(|w| text.contains(w))
}

/// `git` sealed to one repo: `--git-dir <work>/.git --work-tree <work>`, run in `work`, with the
/// settings in the module docs. The caller adds the subcommand.
pub fn sealed(work: &Path) -> Command {
    let git_dir = work.join(".git");
    let mut c = Command::new("git");
    c.arg("-c")
        .arg(format!("safe.directory={}", work.display()))
        .arg("-c")
        .arg(format!("safe.directory={}", git_dir.display()))
        .args([
            "-c",
            "safe.bareRepository=explicit",
            "-c",
            "protocol.allow=never",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("--git-dir")
        .arg(&git_dir)
        .arg("--work-tree")
        .arg(work)
        .current_dir(work)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(up) = work.parent() {
        c.env("GIT_CEILING_DIRECTORIES", up);
    }
    c
}

/// The text of `rel` (a checked wire path beneath `root`) at its repo's `HEAD`, read with the
/// plumbing `cat-file` (no filter, hook or textconv runs): `None` when untracked, not UTF-8, or
/// there is no safe repo ([`enclosing_repo`]).
pub fn head_blob(root: &Path, rel: &str) -> Option<String> {
    let (work, inner) = enclosing_repo(root, rel)?;
    let out = sealed(&work)
        .args(["cat-file", "blob"])
        .arg(format!("HEAD:{inner}"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-sys-git-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(ok.success(), "git {args:?}");
    }

    fn repo(at: &Path) {
        std::fs::create_dir_all(at.join("src")).unwrap();
        std::fs::write(at.join("src/a.txt"), "head text\n").unwrap();
        git(at, &["init", "-q"]);
        git(at, &["add", "."]);
        git(at, &["commit", "-qm", "x"]);
    }

    #[test]
    fn the_head_copy_comes_from_the_repo_that_holds_the_file() {
        let root = temp("ok");
        repo(&root.join("proj"));
        assert_eq!(
            head_blob(&root, "proj/src/a.txt").as_deref(),
            Some("head text\n")
        );
        assert_eq!(
            enclosing_repo(&root, "proj/src/a.txt"),
            Some((root.join("proj"), "src/a.txt".to_owned()))
        );
        assert_eq!(head_blob(&root, "proj/src/none.txt"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_fake_bare_repo_at_the_root_is_never_used() {
        // H1: the agent turns its session root into a bare repo; git must not discover it.
        let root = temp("bare");
        git(&root, &["init", "-q", "--bare", "."]);
        assert_eq!(enclosing_repo(&root, "a.txt"), None);
        assert_eq!(head_blob(&root, "a.txt"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_repo_that_could_fetch_borrow_or_include_is_refused() {
        let root = temp("evil");
        repo(&root.join("p"));
        let cfg = root.join("p/.git/config");
        let clean = std::fs::read_to_string(&cfg).unwrap();
        let marker = root.join("ran");
        for evil in [
            format!(
                "[extensions]\n\tpartialClone = origin\n[remote \"origin\"]\n\tpromisor = true\n\turl = {}\n\tuploadpack = touch {}\n",
                root.display(),
                marker.display()
            ),
            "[EXTENSIONS]\n\tPartialClone = x\n".to_owned(),
            "[include]\n\tpath = ../../other\n".to_owned(),
            "[includeIf \"gitdir:/\"]\n\tpath = x\n".to_owned(),
        ] {
            std::fs::write(&cfg, format!("{clean}{evil}")).unwrap();
            assert_eq!(head_blob(&root, "p/src/a.txt"), None, "{evil}");
        }
        assert!(!marker.exists());
        std::fs::write(&cfg, &clean).unwrap();
        std::fs::write(root.join("p/.git/objects/info/alternates"), "/elsewhere\n").unwrap();
        assert_eq!(head_blob(&root, "p/src/a.txt"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_gitfile_or_a_linked_folder_is_refused() {
        let root = temp("links");
        repo(&root.join("real"));
        std::os::unix::fs::symlink(root.join("real"), root.join("via")).unwrap();
        assert_eq!(head_blob(&root, "via/src/a.txt"), None);
        std::fs::create_dir_all(root.join("wt/src")).unwrap();
        std::fs::write(
            root.join("wt/.git"),
            format!("gitdir: {}\n", root.join("real/.git").display()),
        )
        .unwrap();
        assert_eq!(head_blob(&root, "wt/src/a.txt"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_sealed_git_never_trusts_every_folder_and_never_fetches() {
        let c = sealed(Path::new("/w/p"));
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(!joined.contains("safe.directory=*"));
        for want in [
            "safe.directory=/w/p",
            "safe.bareRepository=explicit",
            "protocol.allow=never",
            "--git-dir /w/p/.git",
        ] {
            assert!(joined.contains(want), "{want} in {joined}");
        }
        let env: std::collections::BTreeMap<String, Option<String>> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(env["GIT_NO_LAZY_FETCH"].as_deref(), Some("1"));
        assert_eq!(env["GIT_CONFIG_GLOBAL"].as_deref(), Some("/dev/null"));
        assert_eq!(env["GIT_CONFIG_SYSTEM"].as_deref(), Some("/dev/null"));
        assert_eq!(env["GIT_CEILING_DIRECTORIES"].as_deref(), Some("/w"));
    }
}
