//! Untrusted input for import runs (R4-01, T12). Security model: everything here is hostile until proven
//! otherwise, whether it comes from an uploaded zip or from a repo the Core mirrors.
//! - A path is accepted only if it is relative, has no empty, `.` or `..` component, no NUL, control character,
//!   backslash or drive letter, and stays within 512 bytes and 16 components. Anything else is *refused*: counted,
//!   never stored (a hostile name is not kept or shown). Dot folders, `node_modules`, `build`, `dist`, `vendor`,
//!   `Pods`, `.env*` and anything that is not `.md` are *ignored* (counted).
//! - Zip: the central directory is read (nothing is extracted to disk). Symlinks and any non-regular unix type are
//!   refused. Declared sizes are never trusted: each entry is inflated through `take(FILE_MAX + 1)`. Caps: 5 000 entries,
//!   2 000 files, 1 MiB a file, 64 MiB of text in all.
//! - Mirror: git plumbing only (`rev-parse`, `ls-tree`, `cat-file --batch`) in a cleared environment with no config,
//!   hooks or prompts, against a bare repo found by number under the mirrors directory, which must carry the marker the
//!   mirror code wrote for this project and remote. One commit id is resolved first and every read names it. Only
//!   `Docs/` or `docs/`, only regular blobs (symlink and submodule entries are refused), `.md`, <= 1 MiB each, <= 2 000
//!   files. Blob sizes are checked again from `cat-file`'s own header. Text must be UTF-8 without NUL.
//!   The mirror code is used read-only and is not changed; like its own upload-pack serving, a read takes no
//!   lock (a fetch updates refs atomically). A `gc` that drops the commit mid-read fails the read; the run says so.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub(crate) const FILE_MAX: usize = 1 << 20;
pub(crate) const ITEMS_MAX: usize = 2000;
pub(crate) const RUN_BYTES_MAX: usize = 64 << 20;
const ZIP_ENTRIES_MAX: usize = 5000;
const PATH_MAX: usize = 512;
const DEPTH_MAX: usize = 16;
const TAGS_MAX: usize = 8;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const SKIP_DIRS: [&str; 5] = ["node_modules", "build", "dist", "vendor", "Pods"];

/// What a source yielded: Markdown files, files too large to take, and counts of what was not taken.
#[derive(Default, Debug)]
pub(crate) struct Scan {
    pub files: Vec<(String, String)>,
    pub too_large: Vec<String>,
    /// Entries that were unsafe or unreadable (symlink, submodule, bad path, binary): never stored.
    pub refused: i64,
    /// Entries that are simply not wanted (not `.md`, filtered folders).
    pub ignored: i64,
}

impl Scan {
    fn room(&self) -> bool {
        self.files.len() + self.too_large.len() < ITEMS_MAX
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathClass {
    Ok(String),
    Ignored,
    Refused,
}

/// Unicode category Cf (bidi overrides, zero-width and joiner characters, BOM, tags): they make a name read as
/// something it is not. `char` has no category test, so the ranges are listed.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x890..=0x891 | 0x8E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Sorts one source path: safe and wanted, safe but not wanted, or unsafe.
pub(crate) fn classify_path(raw: &str) -> PathClass {
    if raw.is_empty()
        || raw.len() > PATH_MAX
        || raw.starts_with('/')
        || raw.chars().any(|c| c.is_control() || is_format(c) || c == '\\')
    {
        return PathClass::Refused;
    }
    let parts: Vec<&str> = raw.split('/').collect();
    if parts.len() > DEPTH_MAX
        || parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == ".." || p.as_bytes().get(1) == Some(&b':'))
    {
        return PathClass::Refused;
    }
    let (file, dirs) = parts.split_last().expect("a split has a part");
    let unwanted = parts.iter().any(|p| p.starts_with('.'))
        || dirs.iter().any(|d| SKIP_DIRS.contains(d))
        || !file.to_ascii_lowercase().ends_with(".md");
    if unwanted {
        PathClass::Ignored
    } else {
        PathClass::Ok(raw.to_owned())
    }
}

/// Tags from the folders of `path`, the first `strip` of them dropped (`Docs/Plans/x.md` -> `plans`).
pub(crate) fn folder_tags(path: &str, strip: usize) -> Vec<String> {
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop();
    let mut out: Vec<String> = Vec::new();
    for d in parts.into_iter().skip(strip) {
        let t: String = d
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .flat_map(char::to_lowercase)
            .take(lore_model::limits::MAX_TAG_CHARS)
            .collect();
        if !t.is_empty() && !out.contains(&t) && out.len() < TAGS_MAX {
            out.push(t);
        }
    }
    out
}

/// The text with the folder tags as front matter, unless it already has front matter. The tags are the
/// characters `[alnum - _]` only, so nothing a file said can reach the YAML.
pub(crate) fn with_tags(text: &str, tags: &[String]) -> String {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    if tags.is_empty() || body.starts_with("---\n") || body.starts_with("---\r\n") {
        return text.to_owned();
    }
    format!("---\ntags: [{}]\n---\n\n{text}", tags.join(", "))
}

/// UTF-8 without NUL and not blank, or `None` (binary content named `.md` is refused).
pub(crate) fn clean_text(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    (!s.contains('\0') && !s.trim().is_empty()).then(|| s.to_owned())
}

/// Reads an uploaded zip. `Err` only for a zip that cannot be taken at all (unreadable, too many entries or files,
/// too much text); one bad entry is counted in `refused` and the rest is read.
pub(crate) fn read_zip(bytes: &[u8]) -> Result<Scan, &'static str> {
    let mut z =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| "the zip is not valid")?;
    if z.len() > ZIP_ENTRIES_MAX {
        return Err("the zip has too many entries");
    }
    let mut scan = Scan::default();
    let mut total = 0usize;
    for i in 0..z.len() {
        let Ok(mut f) = z.by_index(i) else {
            scan.refused += 1;
            continue;
        };
        let name = f.name().to_owned();
        if f.is_dir() || name.ends_with('/') {
            continue;
        }
        // Anything but a regular file (symlink, device, fifo) is refused, whatever its name.
        if f.unix_mode().is_some_and(|m| m & 0o170000 != 0o100000) {
            scan.refused += 1;
            continue;
        }
        let path = match classify_path(&name) {
            PathClass::Refused => {
                scan.refused += 1;
                continue;
            }
            PathClass::Ignored => {
                scan.ignored += 1;
                continue;
            }
            PathClass::Ok(p) => p,
        };
        if !scan.room() {
            return Err("the zip has too many files");
        }
        let mut buf = Vec::new();
        let read = f.by_ref().take(FILE_MAX as u64 + 1).read_to_end(&mut buf);
        if read.is_err() {
            scan.refused += 1;
        } else if buf.len() > FILE_MAX {
            scan.too_large.push(path);
        } else {
            total += buf.len();
            if total > RUN_BYTES_MAX {
                return Err("the zip holds too much text");
            }
            match clean_text(&buf) {
                Some(t) => scan.files.push((path, t)),
                None => scan.refused += 1,
            }
        }
    }
    Ok(scan)
}

/// The mirror to read: where it is and what it must have been made for.
pub(crate) struct MirrorRef {
    pub dir: PathBuf,
    pub project: i64,
    pub remote: String,
    pub branch: String,
}

fn branch_plain(b: &str) -> bool {
    !b.is_empty()
        && b.len() <= 200
        && !b.contains("..")
        && !b.starts_with('/')
        && !b.ends_with('/')
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-/".contains(&c))
}

/// One git plumbing command, as described in the module docs. Its stderr is dropped: nothing git says reaches a caller.
async fn git(
    dir: &Path,
    args: &[&str],
    stdin: Option<Vec<u8>>,
    cap: usize,
) -> Result<Vec<u8>, &'static str> {
    let fail = "the repo copy could not be read";
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.allow=never",
    ])
    .arg("--git-dir")
    .arg(dir)
    .args(args)
    .env_clear()
    .env("HOME", "/dev/null")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_NO_REPLACE_OBJECTS", "1")
    .env("GIT_NO_LAZY_FETCH", "1")
    .stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .kill_on_drop(true);
    for name in ["PATH", "LANG"] {
        if let Some(v) = std::env::var_os(name) {
            cmd.env(name, v);
        }
    }
    let mut child = cmd.spawn().map_err(|_| fail)?;
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = si.write_all(&data).await;
        });
    }
    let mut out = child.stdout.take().ok_or(fail)?;
    let mut buf = Vec::new();
    let read = tokio::time::timeout(
        GIT_TIMEOUT,
        (&mut out).take(cap as u64 + 1).read_to_end(&mut buf),
    )
    .await;
    if read.is_err() || buf.len() > cap {
        let _ = child.kill().await;
        return Err(fail);
    }
    match child.wait().await {
        Ok(s) if s.success() => Ok(buf),
        _ => Err(fail),
    }
}

/// Reads `Docs/**/*.md` (or `docs/`) of the mirror's default branch.
pub(crate) async fn read_mirror(m: &MirrorRef) -> Result<Scan, &'static str> {
    let made = std::fs::read_to_string(m.dir.join("ainkrad-remote"))
        .is_ok_and(|k| k == format!("{}\n{}", m.project, m.remote));
    if !made || !m.dir.join("HEAD").exists() {
        return Err("the repo has no copy in the Core yet");
    }
    if !branch_plain(&m.branch) {
        return Err("the default branch name is not valid");
    }
    let spec = format!("refs/heads/{}^{{commit}}", m.branch);
    let sha = git(&m.dir, &["rev-parse", "--verify", "-q", &spec], None, 256).await?;
    let sha = String::from_utf8_lossy(&sha).trim().to_owned();
    if !matches!(sha.len(), 40 | 64) || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("the repo copy could not be read");
    }
    // Up to ~300 bytes a record; more than this many records is hostile whatever it holds.
    let tree = git(
        &m.dir,
        &["ls-tree", "-r", "-z", "-l", &sha, "--", "Docs", "docs"],
        None,
        4 << 20,
    )
    .await?;
    let mut scan = Scan::default();
    let mut wanted: Vec<(String, String, usize)> = Vec::new();
    let mut total = 0usize;
    for rec in tree.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = rec.iter().position(|b| *b == b'\t') else {
            scan.refused += 1;
            continue;
        };
        let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
        let (Ok(meta), Ok(path)) = (std::str::from_utf8(meta), std::str::from_utf8(path)) else {
            scan.refused += 1;
            continue;
        };
        let f: Vec<&str> = meta.split_whitespace().collect();
        let [mode, kind, oid, size] = f[..] else {
            scan.refused += 1;
            continue;
        };
        // Symlinks (120000), submodules (160000, type commit) and anything else: refused.
        if !(matches!(mode, "100644" | "100755") && kind == "blob")
            || !oid.bytes().all(|c| c.is_ascii_hexdigit())
            || !(path.starts_with("Docs/") || path.starts_with("docs/"))
        {
            scan.refused += 1;
            continue;
        }
        let path = match classify_path(path) {
            PathClass::Refused => {
                scan.refused += 1;
                continue;
            }
            PathClass::Ignored => {
                scan.ignored += 1;
                continue;
            }
            PathClass::Ok(p) => p,
        };
        if !scan.room() || wanted.len() + scan.too_large.len() >= ITEMS_MAX {
            return Err("the repo has too many documents (the limit is 2 000)");
        }
        let size: usize = size
            .parse()
            .map_err(|_| "the repo copy could not be read")?;
        if size > FILE_MAX {
            scan.too_large.push(path);
            continue;
        }
        total += size;
        if total > RUN_BYTES_MAX {
            return Err("the repo's documents are too large");
        }
        wanted.push((path, oid.to_owned(), size));
    }
    if wanted.is_empty() {
        return Ok(scan);
    }
    let ask: Vec<u8> = wanted
        .iter()
        .flat_map(|(_, o, _)| format!("{o}\n").into_bytes())
        .collect();
    let cap = total + wanted.len() * 160;
    let out = git(&m.dir, &["cat-file", "--batch"], Some(ask), cap).await?;
    let bad = "the repo copy could not be read";
    let mut at = 0usize;
    for (path, oid, size) in wanted {
        let nl = out[at..].iter().position(|b| *b == b'\n').ok_or(bad)? + at;
        let head = std::str::from_utf8(&out[at..nl]).map_err(|_| bad)?;
        let f: Vec<&str> = head.split(' ').collect();
        let [o, "blob", n] = f[..] else {
            return Err(bad);
        };
        let n: usize = n.parse().map_err(|_| bad)?;
        // The size git reports must be the one the tree listed, which is already within the cap.
        if o != oid || n != size {
            return Err(bad);
        }
        let body = out.get(nl + 1..nl + 1 + n).ok_or(bad)?;
        at = nl + 1 + n + 1;
        match clean_text(body) {
            Some(t) => scan.files.push((path, t)),
            None => scan.refused += 1,
        }
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let ok = |p: &str| classify_path(p) == PathClass::Ok(p.to_owned());
        assert!(ok("Docs/Plans/x.md") && ok("a.MD") && ok("Dokumente/Übersicht.md"));
        for bad in [
            "",
            "/etc/passwd.md",
            "../x.md",
            "a/../x.md",
            "a//b.md",
            "./a.md",
            "a/./b.md",
            "a\\b.md",
            "C:/x.md",
            "a/C:x.md",
            "a\0b.md",
            "a\nb.md",
        ] {
            assert_eq!(classify_path(bad), PathClass::Refused, "{bad:?}");
        }
        assert_eq!(
            classify_path(&format!("{}.md", "a".repeat(600))),
            PathClass::Refused
        );
        assert_eq!(
            classify_path(&"d/".repeat(20).to_owned()),
            PathClass::Refused
        );
        for skip in [
            "x.txt",
            ".git/x.md",
            "a/.hidden/x.md",
            ".env.md",
            "node_modules/p/readme.md",
            "a/build/x.md",
            "vendor/x.md",
            "Pods/x.md",
            "a/dist/x.md",
            "img/a.png",
        ] {
            assert_eq!(classify_path(skip), PathClass::Ignored, "{skip}");
        }
    }

    #[test]
    fn tags_and_front_matter() {
        assert_eq!(
            folder_tags("Docs/Plans/Q4 Plans/x.md", 1),
            ["plans", "q4plans"]
        );
        assert_eq!(folder_tags("x.md", 0), Vec::<String>::new());
        let t = vec!["plans".to_owned()];
        assert_eq!(with_tags("# A", &t), "---\ntags: [plans]\n---\n\n# A");
        assert_eq!(
            with_tags("---\ntags: [x]\n---\nA", &t),
            "---\ntags: [x]\n---\nA"
        );
        assert_eq!(with_tags("# A", &[]), "# A");
        // The tags a note gets are the ones the parser reads back.
        let p = lore_model::parse(&with_tags("# A", &t)).unwrap();
        assert_eq!(
            (p.title.as_str(), p.tags.as_slice()),
            ("A", &["plans".to_owned()][..])
        );
    }

    #[test]
    fn text() {
        assert!(clean_text(b"# ok").is_some());
        assert!(
            clean_text(b"a\0b").is_none()
                && clean_text(&[0xff, 0xfe]).is_none()
                && clean_text(b"  \n").is_none()
        );
    }

    #[test]
    fn branch_names() {
        assert!(branch_plain("main") && branch_plain("feat/x-1.2"));
        assert!(
            !branch_plain("a..b")
                && !branch_plain("-x ")
                && !branch_plain("a b")
                && !branch_plain("")
        );
    }
}
