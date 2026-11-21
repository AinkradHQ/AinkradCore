//! Unpacks a downloaded `.tar.gz` (AI tools, toolchains) in-process instead of running `tar`.
//!
//! The runner's unit has `RestrictSUIDSGID=yes`, which makes systemd answer `openat2` with ENOSYS; GNU tar 1.35 on Ubuntu
//! 26.04 opens every member with `openat2` and does not fall back, so every install failed with "could not unpack the
//! download" (2026-11-21, Oracle). The rule is the one the `tar -t` checks enforced: regular files and directories, no
//! absolute path, no `..`; with `links`, also symlinks whose target stays inside the archive's top folder (toolchains: Node
//! ships `bin/npm -> ../lib/...`). Hard links and anything else refuse the whole download before a byte is written. Modes keep only the
//! execute bit (0755 or 0644): no owner, no setuid/setgid, no group- or world-writable files.

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

/// Checks every member of `file`, then unpacks it into `dir`, dropping the first `strip` path components (as
/// `--strip-components`). Runs on a blocking thread.
pub async fn unpack(file: &Path, dir: &Path, strip: usize, links: bool) -> Result<(), String> {
    let (file, dir) = (file.to_owned(), dir.to_owned());
    tokio::task::spawn_blocking(move || {
        vet(&file, links)?;
        extract(&file, &dir, strip)
    })
    .await
    .map_err(|e| format!("could not unpack it: {e}"))?
}

fn archive(file: &Path) -> Result<Archive<GzDecoder<File>>, String> {
    let f = File::open(file).map_err(|e| format!("could not read the download: {e}"))?;
    Ok(Archive::new(GzDecoder::new(f)))
}

/// Refuses the archive unless every member is a regular file or directory under the root (or, with `links`, a symlink
/// that stays inside the top folder).
fn vet(file: &Path, links: bool) -> Result<(), String> {
    let mut a = archive(file)?;
    let entries = a
        .entries()
        .map_err(|_| "the download is not a tarball".to_owned())?;
    for e in entries {
        let e = e.map_err(|_| "the download is not a tarball".to_owned())?;
        let path = e
            .path()
            .map_err(|_| "the download is not a tarball".to_owned())?
            .into_owned();
        let ok = inside(&path)
            && match e.header().entry_type() {
                EntryType::Regular | EntryType::Directory => true,
                EntryType::Symlink if links => e
                    .link_name()
                    .ok()
                    .flatten()
                    .is_some_and(|t| link_stays_inside(&path, &t)),
                _ => false,
            };
        if !ok {
            let shown: String = path.to_string_lossy().chars().take(80).collect();
            return Err(format!(
                "the download has a member it must not unpack ({shown}), so it was refused"
            ));
        }
    }
    Ok(())
}

/// A relative path with no `..`, `/` or prefix: it stays under the folder it is unpacked in.
fn inside(p: &Path) -> bool {
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// The toolchain rule: a relative target that, walked from the link's folder, never climbs above the top folder.
fn link_stays_inside(link: &Path, target: &Path) -> bool {
    let target = target.to_string_lossy();
    if target.is_empty() || target.starts_with('/') || target.contains('\0') {
        return false;
    }
    let mut depth = link
        .to_string_lossy()
        .trim_end_matches('/')
        .split('/')
        .count() as i64
        - 1;
    target.split('/').all(|part| {
        match part {
            ".." => depth -= 1,
            "" | "." => {}
            _ => depth += 1,
        }
        depth >= 1
    })
}

fn extract(file: &Path, dir: &Path, strip: usize) -> Result<(), String> {
    let fail = |e: io::Error| format!("could not unpack the download: {e}");
    let mut a = archive(file)?;
    for e in a.entries().map_err(fail)? {
        let mut e = e.map_err(fail)?;
        let path = e.path().map_err(fail)?.into_owned();
        let rel: PathBuf = path
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .skip(strip)
            .collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dir.join(&rel);
        match e.header().entry_type() {
            EntryType::Directory => fs::create_dir_all(&target).map_err(fail)?,
            EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(fail)?;
                }
                let exec = e.header().mode().map(|m| m & 0o111 != 0).unwrap_or(false);
                let mut out = File::create(&target).map_err(fail)?;
                io::copy(&mut e, &mut out).map_err(fail)?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
                )
                .map_err(fail)?;
            }
            EntryType::Symlink => {
                let to = e
                    .link_name()
                    .map_err(fail)?
                    .ok_or("a link with no target".to_owned())?
                    .into_owned();
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(fail)?;
                }
                let _ = fs::remove_file(&target);
                std::os::unix::fs::symlink(&to, &target).map_err(fail)?;
            }
            _ => {
                return Err(
                    "the download has a member it must not unpack, so it was refused".to_owned(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::os::unix::fs::PermissionsExt;

    /// A .tar.gz with `files` (path, mode, body) and optionally one symlink, written into a fresh temp dir.
    fn tarball(dir: &Path, files: &[(&str, u32, &str)], link: Option<(&str, &str)>) -> PathBuf {
        let path = dir.join("t.tgz");
        let mut b = tar::Builder::new(GzEncoder::new(
            File::create(&path).unwrap(),
            Compression::fast(),
        ));
        for (name, mode, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(*mode);
            h.set_entry_type(EntryType::Regular);
            // set_path refuses `..` and absolute paths; write the raw name to build hostile archives too.
            let raw = h.as_old_mut();
            raw.name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            b.append(&h, body.as_bytes()).unwrap();
        }
        if let Some((name, to)) = link {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, name, to).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
        path
    }

    fn temp() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("untar-{}-{}", std::process::id(), rand_suffix()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn unpacks_strips_and_keeps_only_the_execute_bit() {
        let d = temp();
        let t = tarball(
            &d,
            &[
                ("package/bin/tool", 0o4775, "#!/bin/sh\n"),
                ("package/README", 0o666, "hi"),
            ],
            None,
        );
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        unpack(&t, &out, 1, false).await.unwrap();
        let mode = |p: &str| fs::metadata(out.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("bin/tool"), 0o755);
        assert_eq!(mode("README"), 0o644);
        assert_eq!(fs::read_to_string(out.join("README")).unwrap(), "hi");
        fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn refuses_climbing_absolute_and_link_members_before_writing_anything() {
        for (files, link) in [
            (
                vec![("ok", 0o644, "x"), ("package/../../evil", 0o644, "x")],
                None,
            ),
            (vec![("/etc/evil", 0o644, "x")], None),
            (
                vec![("ok", 0o644, "x")],
                Some(("package/link", "/etc/passwd")),
            ),
        ] {
            let d = temp();
            let t = tarball(&d, &files, link);
            let out = d.join("out");
            fs::create_dir_all(&out).unwrap();
            let err = unpack(&t, &out, 0, false).await.unwrap_err();
            assert!(err.contains("must not unpack"), "{err}");
            assert_eq!(
                fs::read_dir(&out).unwrap().count(),
                0,
                "nothing is written before the check"
            );
            fs::remove_dir_all(&d).unwrap();
        }
    }

    #[tokio::test]
    async fn a_toolchain_may_link_inside_its_folder_but_never_out() {
        let d = temp();
        let t = tarball(
            &d,
            &[("node/lib/npm-cli.js", 0o755, "x")],
            Some(("node/bin/npm", "../lib/npm-cli.js")),
        );
        let out = d.join("out");
        fs::create_dir_all(&out).unwrap();
        unpack(&t, &out, 1, true).await.unwrap();
        assert_eq!(
            fs::read_link(out.join("bin/npm")).unwrap(),
            PathBuf::from("../lib/npm-cli.js")
        );
        for bad in ["../../../etc/passwd", "/etc/passwd", "../../x"] {
            let t = tarball(&d, &[("node/a", 0o644, "x")], Some(("node/bin/npm", bad)));
            let out = d.join(format!("out-{}", bad.len()));
            fs::create_dir_all(&out).unwrap();
            assert!(unpack(&t, &out, 1, true).await.is_err(), "{bad}");
            assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_link_rule_matches_the_old_tar_check() {
        let ok = |l: &str, t: &str| link_stays_inside(Path::new(l), Path::new(t));
        assert!(ok(
            "node-v22/bin/npm",
            "../lib/node_modules/npm/bin/npm-cli.js"
        ));
        assert!(!ok("node-v22/bin/npm", "../../../etc/passwd"));
        assert!(!ok("node-v22/bin/npm", "/etc/passwd"));
        assert!(!ok("node-v22/npm", "../x"));
    }

    #[tokio::test]
    async fn a_file_that_is_not_a_tarball_is_refused() {
        let d = temp();
        let f = d.join("x.tgz");
        fs::write(&f, b"not gzip").unwrap();
        assert!(unpack(&f, &d, 0, true).await.is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
