//! `agent.attach` (E4): writes a file the Core sends into the session's own folder, under
//! `.ainkrad/attachments/` (0700, the file 0600), and answers with its absolute path. The folder is
//! the one this runner recorded for the session's run, never one the Core names; nothing is
//! written through a symlink or outside that folder. `.ainkrad/.gitignore` keeps the files out of
//! a worktree's `git status`.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ainkrad_proto::v2::{
    ATTACHMENTS_DIR, AgentAttach, AgentAttached, ErrorCode, MAX_ATTACHMENT_BYTES, StreamError,
    attachment_file_name, valid_attachment_id, valid_attachment_name,
};
use base64::Engine as _;

use super::{AgentDriver, holds_slot, no_session, refuse, valid_session};

impl AgentDriver {
    pub fn attach(&self, req: AgentAttach) -> Result<AgentAttached, StreamError> {
        let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
        if !valid_session(&req.session)
            || !valid_attachment_id(&req.id)
            || !valid_attachment_name(&req.name)
        {
            return Err(bad(
                "a session as_…, an attachment at_… and a plain file name",
            ));
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(&req.data)
            .map_err(|_| bad("the file is not base64"))?;
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(bad("the file is larger than an attachment may be"));
        }
        let folder = {
            let all = self.sessions.lock().unwrap();
            let live = all.get(&req.session).ok_or_else(no_session)?;
            if !holds_slot(live.meta.state) {
                return Err(bad("the session is not running"));
            }
            live.meta.folder.clone()
        };
        let folder = folder.ok_or_else(|| bad("the session has no folder yet"))?;
        let name = attachment_file_name(&req.id, &req.name);
        let path = write(Path::new(&folder), &name, &data).map_err(|e| {
            refuse(
                ErrorCode::InvalidArgs,
                format!("attachment not written: {e}"),
            )
        })?;
        Ok(AgentAttached {
            session: req.session,
            id: req.id,
            path: path.to_string_lossy().into_owned(),
        })
    }
}

/// Writes `data` as `<folder>/.ainkrad/attachments/<name>` and returns that path.
pub(super) fn write(folder: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    let root = folder.canonicalize()?;
    let mut dir = root.clone();
    for part in ATTACHMENTS_DIR {
        dir.push(part);
        match DirBuilder::new().mode(0o700).create(&dir) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
        let meta = std::fs::symlink_metadata(&dir)?;
        if !meta.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a plain folder",
                dir.display()
            )));
        }
        if part == ATTACHMENTS_DIR[0] {
            let ignore = dir.join(".gitignore");
            match exclusive(&ignore).and_then(|mut f| f.write_all(b"*\n")) {
                Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                _ => {}
            }
        }
    }
    // Belt and braces: whatever was swapped in on the way, the folder still holds the file.
    if !dir.canonicalize()?.starts_with(&root) {
        return Err(io::Error::other(
            "the attachments folder escapes the session folder",
        ));
    }
    let path = dir.join(name);
    match std::fs::symlink_metadata(&path) {
        // A resent attach: the same id is the same file.
        Ok(m) if m.is_file() => std::fs::remove_file(&path)?,
        Ok(_) => {
            return Err(io::Error::other(format!(
                "{} is not a plain file",
                path.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // `create_new` is O_EXCL: it never follows a symlink planted in between.
    exclusive(&path)?.write_all(data)?;
    Ok(path)
}

fn exclusive(path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-attach-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_file_lands_private_in_the_folder_and_is_ignored_by_git() {
        let d = temp("ok");
        let p = write(&d, "at_1-shot.png", b"png").unwrap();
        assert_eq!(
            p,
            d.canonicalize()
                .unwrap()
                .join(".ainkrad/attachments/at_1-shot.png")
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"png");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        assert_eq!(
            std::fs::read(d.join(".ainkrad/.gitignore")).unwrap(),
            b"*\n"
        );
        // Again: replaced, not refused.
        write(&d, "at_1-shot.png", b"png2").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"png2");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_is_written_through_a_symlink_out_of_the_folder() {
        let d = temp("link");
        let outside = temp("outside");
        // `.ainkrad` itself a link out.
        symlink(&outside, d.join(".ainkrad")).unwrap();
        assert!(write(&d, "at_1-x", b"x").is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_file(d.join(".ainkrad")).unwrap();
        // The file's own name a link out.
        let dir = d.join(".ainkrad/attachments");
        std::fs::create_dir_all(&dir).unwrap();
        symlink(outside.join("victim"), dir.join("at_1-x")).unwrap();
        assert!(write(&d, "at_1-x", b"x").is_err());
        assert!(!outside.join("victim").exists());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
