//! `agent.docs` (Lore E10-2, D-28): the `.md` files of a session's own folder.
//!
//! Security model. The folder is the one this runner recorded for the session's run (`Meta::folder`), never
//! one the Core names. A path is checked by `valid_doc_path` (relative, no dotted part, `.md`, not an
//! instruction file such as CLAUDE.md), then resolved here: the walk follows no symlink, a read or write
//! opens no symlink (checked with `symlink_metadata` on the file and on the canonical parent, which must stay
//! inside the folder). A write is atomic (a temp file beside it, renamed) and only when the file still has
//! the sha-256 the Core last saw. Nothing here runs a program; file text is returned as data.
//!
//! The harness may swap a path between the check and the use (it has the folder too); the only effect is the
//! write of one `.md` file inside the folder it already controls.

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ainkrad_proto::v2::{
    AgentDocs, DOC_MAX_BYTES, DOC_MAX_DEPTH, DOC_MAX_FILES, DOC_MAX_VISITED, DocFile, DocsAction,
    DocsReply, ErrorCode, StreamError, valid_doc_path, valid_sha256,
};

use super::{AgentDriver, holds_slot, no_session, refuse, valid_session};

type Base = HashMap<String, (u64, i64)>;

/// Where the baseline and the final copies live: `<dir>/<session>/`.
const BASE_FILE: &str = "docs-base.json";
const FINAL_DIR: &str = "docs-final";

fn hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every `.md` file under `root` that `valid_doc_path` accepts, as (relative path, size, mtime ns), without
/// following a symlink. Bounded by depth and by the number of entries looked at.
fn walk(root: &Path) -> Vec<(String, u64, i64)> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack = vec![(root.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, rel, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > DOC_MAX_VISITED {
                return out;
            }
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if meta.is_dir() {
                if depth + 1 < DOC_MAX_DEPTH
                    && !name.starts_with('.')
                    && name != "node_modules"
                    && name != "target"
                {
                    stack.push((e.path(), path, depth + 1));
                }
            } else if meta.is_file() && valid_doc_path(&path) {
                let ns = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(0));
                out.push((path, meta.len(), ns));
            }
        }
    }
    out
}

/// `root/rel` for a checked relative path, when its parent is a real folder inside `root` and the file itself
/// is not a symlink.
fn resolve(root: &Path, rel: &str) -> Result<PathBuf, StreamError> {
    let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
    if !valid_doc_path(rel) {
        return Err(bad("not a document path"));
    }
    let root = root
        .canonicalize()
        .map_err(|_| bad("the session folder is gone"))?;
    let full = root.join(rel);
    let parent = full
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .filter(|p| p.starts_with(&root))
        .ok_or_else(|| bad("the folder of that document is not inside the session folder"))?;
    let full = parent.join(full.file_name().ok_or_else(|| bad("not a document path"))?);
    match std::fs::symlink_metadata(&full) {
        Ok(m) if !m.is_file() => Err(bad("not a plain file")),
        _ => Ok(full),
    }
}

/// The whole read of `full`, at most `DOC_MAX_BYTES`, as UTF-8.
fn read_text(full: &Path) -> Result<(String, String), StreamError> {
    let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
    let m = std::fs::symlink_metadata(full).map_err(|_| bad("no such document"))?;
    if !m.is_file() || m.len() > DOC_MAX_BYTES as u64 {
        return Err(bad("not a plain file, or larger than a document may be"));
    }
    let bytes = std::fs::read(full).map_err(|_| bad("the document could not be read"))?;
    let sha = hex(&bytes);
    let text = String::from_utf8(bytes).map_err(|_| bad("the document is not UTF-8 text"))?;
    Ok((text, sha))
}

fn write_text(full: &Path, text: &str, base: Option<&str>) -> Result<String, StreamError> {
    let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
    if text.len() > DOC_MAX_BYTES {
        return Err(bad("the text is larger than a document may be"));
    }
    match (std::fs::symlink_metadata(full), base) {
        (Ok(_), None) => return Err(bad("changed: the file exists")),
        (Err(_), Some(_)) => return Err(bad("changed: the file is gone")),
        (Ok(_), Some(b)) => {
            if read_text(full)?.1 != b {
                return Err(bad("changed: the file is not as it was"));
            }
        }
        (Err(_), None) => {}
    }
    let tmp = full.with_extension("md.ainkrad-tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(|_| bad("the document could not be written"))?;
    let done = f
        .write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, full));
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(bad("the document could not be written"));
    }
    Ok(hex(text.as_bytes()))
}

impl AgentDriver {
    /// Records the folder's `.md` files before the harness starts (see `docs_base`).
    pub(super) async fn take_docs_baseline(&self, session: &str, folder: Option<PathBuf>) {
        let Some(folder) = folder else { return };
        let base: Base = tokio::task::spawn_blocking(move || {
            walk(&folder)
                .into_iter()
                .map(|(p, size, ns)| (p, (size, ns)))
                .collect()
        })
        .await
        .unwrap_or_default();
        let file = self.config.dir.join(session).join(BASE_FILE);
        if let Ok(bytes) = serde_json::to_vec(&base) {
            let _ = std::fs::write(&file, bytes);
        }
        self.docs_base
            .lock()
            .unwrap()
            .insert(session.to_owned(), base);
    }

    /// The session's baseline: in memory, else the file a start saved (a runner restart).
    fn docs_baseline(&self, session: &str) -> Option<Base> {
        if let Some(b) = self.docs_base.lock().unwrap().get(session) {
            return Some(b.clone());
        }
        let bytes = std::fs::read(self.config.dir.join(session).join(BASE_FILE)).ok()?;
        let base: Base = serde_json::from_slice(&bytes).ok()?;
        self.docs_base
            .lock()
            .unwrap()
            .insert(session.to_owned(), base.clone());
        Some(base)
    }

    /// Before the session's folder is removed: copies the `.md` files it made or changed to
    /// `<dir>/<session>/docs-final/`, where `agent.docs` serves them read-only after the end.
    pub(super) async fn keep_final_docs(&self, session: &str, folder: Option<PathBuf>) {
        let (Some(folder), Some(base)) = (folder, self.docs_baseline(session)) else {
            return;
        };
        let out = self.config.dir.join(session).join(FINAL_DIR);
        let _ = tokio::task::spawn_blocking(move || {
            let _ = std::fs::remove_dir_all(&out);
            for (path, size, ns) in walk(&folder) {
                if base.get(&path) == Some(&(size, ns)) || size > DOC_MAX_BYTES as u64 {
                    continue;
                }
                let to = out.join(&path);
                if let Some(parent) = to.parent()
                    && std::fs::create_dir_all(parent).is_ok()
                {
                    // `folder/path` came from `walk`: a plain file, not a symlink.
                    let _ = std::fs::copy(folder.join(&path), &to);
                }
            }
        })
        .await;
    }

    pub async fn docs(&self, req: AgentDocs) -> Result<DocsReply, StreamError> {
        let bad = |why: &str| refuse(ErrorCode::InvalidArgs, why);
        if !valid_session(&req.session) {
            return Err(bad("a session as_…"));
        }
        let live = {
            let all = self.sessions.lock().unwrap();
            let live = all.get(&req.session).ok_or_else(no_session)?;
            holds_slot(live.meta.state).then(|| live.meta.folder.clone())
        };
        // A running session serves its folder; an ended one, the copies kept at its end (read-only).
        let (folder, ended) = match live {
            Some(f) => (
                PathBuf::from(f.ok_or_else(|| bad("the session has no folder yet"))?),
                false,
            ),
            None => {
                let kept = self.config.dir.join(&req.session).join(FINAL_DIR);
                if !kept.is_dir() {
                    return Err(bad(ainkrad_proto::v2::DOCS_NO_FINAL));
                }
                (kept, true)
            }
        };
        if ended && req.action == DocsAction::Write {
            return Err(bad("the session has ended"));
        }
        match req.action {
            DocsAction::List => {
                let base = if ended {
                    Base::new()
                } else if let Some(b) = self.docs_baseline(&req.session) {
                    b
                } else {
                    return Ok(DocsReply::default());
                };
                tokio::task::spawn_blocking(move || {
                    let mut files = Vec::new();
                    for (path, size, ns) in walk(&folder) {
                        if base.get(&path) == Some(&(size, ns)) || size > DOC_MAX_BYTES as u64 {
                            continue;
                        }
                        let Ok(bytes) = std::fs::read(folder.join(&path)) else {
                            continue;
                        };
                        files.push(DocFile {
                            path,
                            size,
                            sha256: hex(&bytes),
                        });
                        if files.len() >= DOC_MAX_FILES {
                            break;
                        }
                    }
                    files.sort_by(|a, b| a.path.cmp(&b.path));
                    Ok(DocsReply {
                        files,
                        ..DocsReply::default()
                    })
                })
                .await
                .map_err(|_| refuse(ErrorCode::Internal, "the listing did not finish"))?
            }
            DocsAction::Read => {
                let path = req.path.ok_or_else(|| bad("a path"))?;
                let full = resolve(&folder, &path)?;
                let (text, sha) = read_text(&full)?;
                Ok(DocsReply {
                    text: Some(text),
                    sha256: Some(sha),
                    ..DocsReply::default()
                })
            }
            DocsAction::Write => {
                let path = req.path.ok_or_else(|| bad("a path"))?;
                let text = req.text.ok_or_else(|| bad("a text"))?;
                if req.base.as_deref().is_some_and(|b| !valid_sha256(b)) {
                    return Err(bad("base is a sha-256"));
                }
                let full = resolve(&folder, &path)?;
                let sha = write_text(&full, &text, req.base.as_deref())?;
                Ok(DocsReply {
                    sha256: Some(sha),
                    ..DocsReply::default()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-docs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn walk_skips_dotted_folders_symlinks_and_instruction_files() {
        let d = dir("walk");
        std::fs::create_dir_all(d.join("docs")).unwrap();
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join("docs/plan.md"), "a").unwrap();
        std::fs::write(d.join(".git/x.md"), "a").unwrap();
        std::fs::write(d.join("CLAUDE.md"), "a").unwrap();
        std::fs::write(d.join("x.txt"), "a").unwrap();
        symlink(d.join("docs/plan.md"), d.join("link.md")).unwrap();
        let got: Vec<String> = walk(&d).into_iter().map(|f| f.0).collect();
        assert_eq!(got, vec!["docs/plan.md".to_owned()]);
    }

    #[test]
    fn a_path_cannot_leave_the_folder_or_go_through_a_symlink() {
        let d = dir("resolve");
        let out = dir("resolve-out");
        std::fs::write(out.join("secret.md"), "s").unwrap();
        symlink(&out, d.join("escape")).unwrap();
        symlink(out.join("secret.md"), d.join("link.md")).unwrap();
        assert!(resolve(&d, "../x.md").is_err());
        assert!(resolve(&d, "/etc/passwd.md").is_err());
        assert!(
            resolve(&d, "escape/secret.md").is_err(),
            "a symlinked folder"
        );
        assert!(resolve(&d, "link.md").is_err(), "a symlinked file");
        assert!(resolve(&d, "ok.md").is_ok());
    }

    #[test]
    fn a_write_needs_the_sha_the_file_has_and_is_whole() {
        let d = dir("write");
        let f = resolve(&d, "plan.md").unwrap();
        let sha = write_text(&f, "one", None).unwrap();
        assert_eq!(sha, hex(b"one"));
        assert!(
            write_text(&f, "two", None).is_err(),
            "a new file takes no base only when absent"
        );
        assert!(
            write_text(&f, "two", Some(&hex(b"zzz"))).is_err(),
            "the file changed"
        );
        assert_eq!(write_text(&f, "two", Some(&sha)).unwrap(), hex(b"two"));
        assert_eq!(read_text(&f).unwrap().0, "two");
    }

    #[test]
    fn a_baseline_survives_a_restart_as_json() {
        let mut b = Base::new();
        b.insert("docs/a.md".to_owned(), (12, 1_700_000_000_123_456_789));
        let back: Base = serde_json::from_slice(&serde_json::to_vec(&b).unwrap()).unwrap();
        assert_eq!(back, b);
    }
}
