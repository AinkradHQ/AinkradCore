//! A session's folder (E14): `agent.files` lists one level, `agent.revert` puts one file back as
//! it was before the session's recorded edits, `agent.write` writes one file. The folder is the one
//! this runner recorded for the session, never one the Core names. A path is cleaned
//! (`folder_relative`: no `..`), then walked component by component: a symlink anywhere on the way
//! is refused, so nothing is read or written outside the folder. A write replaces the file by a
//! rename of a temp file, so it never writes through a link; and it refuses `.git`.
//!
//! ponytail: the walk and the write are not atomic with each other, so a session that swaps a
//! parent folder for a link in between can still win a race. The folder is the session's own, and
//! the harness inside it is what a write is meant for; a `openat2(RESOLVE_BENEATH)` write would
//! close it.

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ainkrad_proto::v2::{
    AgentFiles, AgentFolder, AgentRevert, AgentReverted, AgentWrite, AgentWritten, ErrorCode,
    FolderEntry, MAX_FOLDER_ENTRIES, MAX_REVERT_BYTES, MAX_WRITE_BYTES, RevertEdit, RevertResult,
    StreamError, folder_relative,
};

use super::{AgentDriver, no_session, refuse, valid_session};

/// Names a listing leaves out: noise nobody browses.
const NOISE: [&str; 4] = [".git", "node_modules", ".DS_Store", ".ainkrad"];
/// The most names read from one folder before sorting.
const READ_CAP: usize = 20_000;

impl AgentDriver {
    /// The session's folder, as this runner recorded it: canonical, and a real directory.
    fn folder_of(&self, session: &str) -> Result<PathBuf, StreamError> {
        let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
        if !valid_session(session) {
            return Err(bad("a session as_…"));
        }
        let folder = {
            let all = self.sessions.lock().unwrap();
            all.get(session).ok_or_else(no_session)?.meta.folder.clone()
        };
        let folder = folder.ok_or_else(|| bad("the session has no folder yet"))?;
        fs::canonicalize(&folder).map_err(|_| bad("the session's folder is gone"))
    }

    pub fn files(&self, req: AgentFiles) -> Result<AgentFolder, StreamError> {
        let root = self.folder_of(&req.session)?;
        let rel = relative(&root, &req.dir)?;
        let (entries, truncated) = list(&root, &rel).map_err(io_refusal)?;
        Ok(AgentFolder {
            session: req.session,
            dir: rel,
            entries,
            truncated,
        })
    }

    pub fn revert(&self, req: AgentRevert) -> Result<AgentReverted, StreamError> {
        let root = self.folder_of(&req.session)?;
        let rel = relative(&root, &req.path)?;
        let total: usize = req.edits.iter().map(|e| e.old.len() + e.new.len()).sum();
        if rel.is_empty() || total > MAX_REVERT_BYTES || guarded(&rel) {
            return Err(refuse(
                ErrorCode::InvalidArgs,
                "that path cannot be reverted",
            ));
        }
        let path = resolve(&root, &rel).map_err(io_refusal)?;
        let current = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => Some(read_text(&path).map_err(io_refusal)?),
            Ok(_) => return Err(refuse(ErrorCode::InvalidArgs, "not a plain file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_refusal(e)),
        };
        let head = || head_blob(&root, &rel);
        let done = |result, detail: Option<&str>| AgentReverted {
            session: req.session.clone(),
            path: rel.clone(),
            result,
            detail: detail.map(str::to_owned),
        };
        match reverse(current, &req.edits, req.truncated, head) {
            Ok(Reversal::Content(text, result)) => {
                write_atomic(&path, text.as_bytes()).map_err(io_refusal)?;
                Ok(done(result, None))
            }
            Ok(Reversal::Delete) => {
                fs::remove_file(&path).map_err(io_refusal)?;
                Ok(done(RevertResult::Deleted, None))
            }
            Err((result, why)) => Ok(done(result, Some(why))),
        }
    }

    pub fn write(&self, req: AgentWrite) -> Result<AgentWritten, StreamError> {
        let root = self.folder_of(&req.session)?;
        let rel = relative(&root, &req.path)?;
        if rel.is_empty() || guarded(&rel) {
            return Err(refuse(
                ErrorCode::InvalidArgs,
                "that path cannot be written (empty, or inside .git)",
            ));
        }
        if req.content.len() > MAX_WRITE_BYTES {
            return Err(refuse(ErrorCode::InvalidArgs, "the file is too large"));
        }
        let path = resolve(&root, &rel).map_err(io_refusal)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if !m.is_file() => {
                return Err(refuse(ErrorCode::InvalidArgs, "not a plain file"));
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_refusal(e)),
            _ => {}
        }
        if let Some(parent) = path.parent() {
            // Every existing component was checked by `resolve`, so this makes only new folders
            // inside the session's folder.
            fs::create_dir_all(parent).map_err(io_refusal)?;
        }
        write_atomic(&path, req.content.as_bytes()).map_err(io_refusal)?;
        Ok(AgentWritten {
            session: req.session,
            path: rel,
            bytes: req.content.len() as u64,
        })
    }
}

fn io_refusal(e: io::Error) -> StreamError {
    refuse(ErrorCode::InvalidArgs, format!("not done: {e}"))
}

/// `path` relative to `root`, cleaned (the Core's own check, again here).
fn relative(root: &Path, path: &str) -> Result<String, StreamError> {
    folder_relative(&root.to_string_lossy(), path)
        .ok_or_else(|| refuse(ErrorCode::InvalidArgs, "a path inside the session's folder"))
}

/// A path no write or revert touches: anything under `.git`, whatever its case.
fn guarded(rel: &str) -> bool {
    rel.split('/').any(|p| p.eq_ignore_ascii_case(".git"))
}

/// `root/rel`, every existing component a plain entry (no symlink). `root` is canonical.
pub(super) fn resolve(root: &Path, rel: &str) -> io::Result<PathBuf> {
    let mut path = root.to_path_buf();
    let mut exists = true;
    for part in rel.split('/').filter(|p| !p.is_empty()) {
        path.push(part);
        if !exists {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::other(format!("{part} is a symbolic link")));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => exists = false,
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}

/// One level of `root/rel`: directories first, then by name; at most [`MAX_FOLDER_ENTRIES`].
fn list(root: &Path, rel: &str) -> io::Result<(Vec<FolderEntry>, bool)> {
    let dir = resolve(root, rel)?;
    if !fs::symlink_metadata(&dir)?.is_dir() {
        return Err(io::Error::other("not a folder"));
    }
    let cargo = dir.join("Cargo.toml").is_file();
    let mut all = Vec::new();
    let mut cut = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let noise = NOISE.contains(&name.as_str()) || (cargo && name == "target");
        if noise {
            continue;
        }
        if all.len() >= READ_CAP {
            cut = true;
            break;
        }
        // A link is listed as a file and never followed: `resolve` refuses it as a `dir`.
        let Ok(meta) = entry.metadata() else { continue };
        let is_dir = meta.is_dir() && !entry.file_type().is_ok_and(|t| t.is_symlink());
        all.push(FolderEntry {
            size: (!is_dir).then_some(meta.len()),
            dir: is_dir,
            name,
        });
    }
    Ok(sorted(all, cut))
}

/// Directories first, then names (case-insensitively, ties by bytes), capped.
fn sorted(mut all: Vec<FolderEntry>, cut: bool) -> (Vec<FolderEntry>, bool) {
    all.sort_by(|a, b| {
        (!a.dir, a.name.to_lowercase(), &a.name).cmp(&(!b.dir, b.name.to_lowercase(), &b.name))
    });
    let truncated = cut || all.len() > MAX_FOLDER_ENTRIES;
    all.truncate(MAX_FOLDER_ENTRIES);
    (all, truncated)
}

fn read_text(path: &Path) -> io::Result<String> {
    String::from_utf8(fs::read(path)?).map_err(|_| io::Error::other("the file is not UTF-8 text"))
}

/// Replaces `path` by a temp file renamed over it (never through a link), keeping the old mode.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let tmp = path.with_file_name(format!(".{name}.ainkrad-tmp-{}", std::process::id()));
    let mode =
        fs::metadata(path).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()));
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let put = file.write_all(data).and_then(|()| file.sync_all());
    let put = put.and_then(|()| {
        let mode = mode.unwrap_or(0o644) & 0o777;
        fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(mode))
    });
    let put = put.and_then(|()| fs::rename(&tmp, path));
    if put.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    put
}

/// The text of `rel` at its repo's `HEAD`, through the sealed git of E15 H1: see
/// [`ainkrad_sys::git`].
fn head_blob(root: &Path, rel: &str) -> Option<String> {
    ainkrad_sys::git::head_blob(root, rel)
}

/// What a reversal leaves in the file.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reversal {
    /// The file's new text, and how it was got (`Reverted` or `Restored`).
    Content(String, RevertResult),
    /// The session created the file: it goes.
    Delete,
}

type Refused = (RevertResult, &'static str);

/// The file as it was before `edits` (the session's recorded ones, NEWEST FIRST), from its
/// `current` text (`None`: the file is absent). Each edit is undone by putting its `old` text where
/// its `new` text is; the file must still hold that text exactly once, else nothing is changed
/// (`Conflict`). A write (empty `old`) is the file's creation or whole replacement: what came
/// before is unknown, so the file is restored from `head` when git tracks it, else deleted. Edits
/// that cannot be undone (a cut text, a removal inside the file) fall back to `head`, or are
/// `Impossible`.
pub(super) fn reverse(
    current: Option<String>,
    edits: &[RevertEdit],
    truncated: bool,
    head: impl FnOnce() -> Option<String>,
) -> Result<Reversal, Refused> {
    let restore = |head: Option<String>, why: &'static str| match head {
        Some(text) => Ok(Reversal::Content(text, RevertResult::Restored)),
        None => Err((RevertResult::Impossible, why)),
    };
    if truncated || edits.is_empty() {
        return restore(
            head(),
            "the recorded edits cannot be reversed and git has no copy",
        );
    }
    let mut cur = current;
    for e in edits {
        if e.old.is_empty() && !e.new.is_empty() {
            if cur.as_deref() != Some(e.new.as_str()) {
                return Err((
                    RevertResult::Conflict,
                    "the file changed since the session wrote it",
                ));
            }
            return Ok(match head() {
                Some(text) => Reversal::Content(text, RevertResult::Restored),
                None => Reversal::Delete,
            });
        }
        if e.new.is_empty() {
            // A deleted file comes back; a removal inside a file has no place to go back to.
            match cur {
                None => cur = Some(e.old.clone()),
                Some(_) => {
                    return restore(
                        head(),
                        "a removed text cannot be placed again and git has no copy",
                    );
                }
            }
            continue;
        }
        let Some(text) = cur.as_deref() else {
            return Err((RevertResult::Conflict, "the file is gone"));
        };
        cur = Some(match text.matches(&e.new).count() {
            0 => {
                return Err((
                    RevertResult::Conflict,
                    "the file no longer holds the edited text",
                ));
            }
            1 => text.replacen(&e.new, &e.old, 1),
            _ => {
                return Err((
                    RevertResult::Conflict,
                    "the edited text appears more than once",
                ));
            }
        });
    }
    Ok(Reversal::Content(
        cur.unwrap_or_default(),
        RevertResult::Reverted,
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn edit(old: &str, new: &str) -> RevertEdit {
        RevertEdit {
            old: old.to_owned(),
            new: new.to_owned(),
        }
    }

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-files-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn edits_are_undone_newest_first_and_only_when_the_text_is_still_there() {
        let edits = [edit("B", "B2"), edit("a", "B")];
        let got = reverse(Some("x B2 y".into()), &edits, false, || None);
        assert_eq!(
            got,
            Ok(Reversal::Content("x a y".into(), RevertResult::Reverted))
        );
        let moved = reverse(Some("x other y".into()), &edits, false, || None);
        assert_eq!(moved.unwrap_err().0, RevertResult::Conflict);
        let twice = reverse(Some("B2 B2".into()), &[edit("b", "B2")], false, || None);
        assert_eq!(twice.unwrap_err().0, RevertResult::Conflict);
    }

    #[test]
    fn a_created_file_is_deleted_unless_git_has_it() {
        let w = [edit("", "hello")];
        assert_eq!(
            reverse(Some("hello".into()), &w, false, || None),
            Ok(Reversal::Delete)
        );
        let tracked = reverse(Some("hello".into()), &w, false, || Some("old".into()));
        assert_eq!(
            tracked,
            Ok(Reversal::Content("old".into(), RevertResult::Restored))
        );
        let edited = reverse(Some("hello!".into()), &w, false, || None);
        assert_eq!(edited.unwrap_err().0, RevertResult::Conflict);
    }

    #[test]
    fn what_cannot_be_reversed_falls_back_to_git_or_says_so() {
        let cut = reverse(Some("a".into()), &[edit("x", "a")], true, || {
            Some("g".into())
        });
        assert_eq!(
            cut,
            Ok(Reversal::Content("g".into(), RevertResult::Restored))
        );
        let none = reverse(Some("a".into()), &[], false, || None);
        assert_eq!(none.unwrap_err().0, RevertResult::Impossible);
        // A removal inside a file; and a deleted file that comes back.
        let removal = reverse(Some("ab".into()), &[edit("zz", "")], false, || None);
        assert_eq!(removal.unwrap_err().0, RevertResult::Impossible);
        let gone = reverse(None, &[edit("zz", "")], false, || None);
        assert_eq!(
            gone,
            Ok(Reversal::Content("zz".into(), RevertResult::Reverted))
        );
    }

    #[test]
    fn a_walk_refuses_a_link_on_the_way_and_a_listing_never_follows_one() {
        let d = temp("walk");
        let outside = temp("walk-out");
        fs::create_dir_all(d.join("src")).unwrap();
        fs::write(d.join("src/a.rs"), "x").unwrap();
        fs::write(d.join("b.txt"), "xyz").unwrap();
        fs::create_dir_all(d.join("node_modules")).unwrap();
        symlink(&outside, d.join("link")).unwrap();
        assert!(resolve(&d, "src/a.rs").is_ok());
        assert!(resolve(&d, "new/dir/f").is_ok());
        assert!(resolve(&d, "link").is_err());
        assert!(resolve(&d, "link/x").is_err());
        let (entries, truncated) = list(&d, "").unwrap();
        let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.dir)).collect();
        assert_eq!(names, [("src", true), ("b.txt", false), ("link", false)]);
        assert!(!truncated);
        assert_eq!(entries[1].size, Some(3));
        assert!(list(&d, "link").is_err());
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_listing_is_capped_and_a_write_replaces_a_link_instead_of_following_it() {
        let many: Vec<_> = (0..MAX_FOLDER_ENTRIES + 3)
            .map(|i| FolderEntry {
                name: format!("f{i:04}"),
                dir: false,
                size: Some(1),
            })
            .collect();
        let (cut, truncated) = sorted(many, false);
        assert!(truncated && cut.len() == MAX_FOLDER_ENTRIES);
        let d = temp("write");
        let outside = temp("write-out");
        fs::write(outside.join("victim"), "keep").unwrap();
        symlink(outside.join("victim"), d.join("f")).unwrap();
        assert!(resolve(&d, "f").is_err());
        // The raw writer, were it ever pointed at a link, swaps the entry and leaves the target.
        write_atomic(&d.join("f"), b"new").unwrap();
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"keep");
        assert_eq!(fs::read(d.join("f")).unwrap(), b"new");
        assert!(guarded("a/.GIT/config") && guarded(".git") && !guarded("a/.gitignore"));
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&outside);
    }
}
