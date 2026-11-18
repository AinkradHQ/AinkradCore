//! Lore export (R1-06): `GET /export` streams a zip of the live notes as `.md` files, each with a front
//! matter block (`id`, `project`, `tags`, `created`, `updated`), plus `attachments/<sha>.<ext>` for every
//! `lore-attachment:<sha>` a note names. Wikilinks and attachment references are left exactly as written.
//! Security model: the zip is built here (stored, no compression: no zip library, no new crate), one note
//! at a time, so memory stays at one note. Every entry name is made by `slug` or from a sha and is checked
//! again by `Zip::add` (no empty or absolute name, no `..` component, no `\`, no control character), so a
//! hostile title cannot walk out of the folder it is unpacked into. The whole export is bounded: at most
//! `MAX_NOTES` notes, `MAX_BYTES` bytes and `MAX_ENTRIES` files; the note count and text size are refused
//! up front with 413, the byte bound is also enforced while streaming (the stream then fails, so a truncated
//! file never looks complete). Trashed notes are not exported. Note text and titles are outside data.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::io;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use axum::body::{Body, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use sqlx::{Row, SqlitePool};

use crate::attachments::refs;
use crate::notes::{id_ok, none};

const MAX_NOTES: usize = 50_000;
/// Uncompressed bytes of the whole zip (the stored zip is about as big as its contents).
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// The classic zip limit is 65 535 entries; stay under it (no zip64).
const MAX_ENTRIES: usize = 65_000;
/// The model reads front matter that closes within this many lines.
const FRONT_MATTER_LINES: usize = 100;

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    project: Option<String>,
    note: Option<String>,
}

fn bad() -> ApiError {
    ApiError::bad_request("the query is not valid")
}

fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        "the export is too large",
    )
}

#[utoipa::path(get, path = "/export", operation_id = "loreExport", tag = "lore",
    params(("project" = Option<String>, Query, description = "Only the notes of this project id"),
           ("note" = Option<String>, Query, description = "Only this note (and its attachments)")),
    responses((status = 200, description = "A zip of `.md` files with front matter (`id`, `project`, `tags`, `created`, `updated`) and an `attachments/` folder; the live notes only, wikilinks as written. `project` and `note` together are refused; an unknown or trashed `note` is 404; more than 50 000 notes or 1 GiB is 413", body = Vec<u8>, content_type = "application/zip")))]
pub(crate) async fn export(
    State(app): State<App>,
    q: Result<Query<ExportQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(q) = q.map_err(|_| bad())?;
    let rows = match (q.project.as_deref(), q.note.as_deref()) {
        (Some(_), Some(_)) => return Err(bad()),
        (Some(p), None) => {
            if p.is_empty() || p.len() > 18 || !p.bytes().all(|c| c.is_ascii_digit()) {
                return Err(bad());
            }
            sqlx::query("SELECT id, length(text) AS n FROM lore_notes WHERE trashed_at IS NULL AND project = ? ORDER BY id")
                .bind(p)
                .fetch_all(&app.pool)
                .await?
        }
        (None, Some(n)) => {
            if !id_ok(n) {
                return Err(none());
            }
            let r = sqlx::query(
                "SELECT id, length(text) AS n FROM lore_notes WHERE trashed_at IS NULL AND id = ?",
            )
            .bind(n)
            .fetch_all(&app.pool)
            .await?;
            if r.is_empty() {
                return Err(none());
            }
            r
        }
        (None, None) => {
            sqlx::query(
                "SELECT id, length(text) AS n FROM lore_notes WHERE trashed_at IS NULL ORDER BY id",
            )
            .fetch_all(&app.pool)
            .await?
        }
    };
    let mut bytes: u64 = 0;
    let mut ids = VecDeque::new();
    for r in &rows {
        ids.push_back(r.try_get::<String, _>("id")?);
        bytes = bytes.saturating_add(r.try_get::<i64, _>("n")?.max(0) as u64);
    }
    if ids.len() > MAX_NOTES || bytes > MAX_BYTES {
        return Err(too_large());
    }
    let st = St {
        pool: app.pool.clone(),
        ids,
        zip: Zip::default(),
        used: HashSet::new(),
        shas: BTreeSet::new(),
        files: None,
        state: Run::Going,
    };
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        match step(&mut st).await {
            Ok(Some(b)) => Some((Ok::<_, io::Error>(Bytes::from(b)), st)),
            Ok(None) => None,
            Err(e) => {
                st.state = Run::Failed;
                Some((Err(io::Error::other(e)), st))
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"lore-export.zip\"",
        )
        .body(Body::from_stream(stream))
        .map_err(|_| bad())
}

#[derive(PartialEq)]
enum Run {
    Going,
    Failed,
    Done,
}

struct St {
    pool: SqlitePool,
    ids: VecDeque<String>,
    zip: Zip,
    /// Lower-cased entry names already used, so two titles never share a file.
    used: HashSet<String>,
    /// Every attachment sha the exported notes name.
    shas: BTreeSet<String>,
    /// The attachment queue, filled once the notes are done.
    files: Option<VecDeque<String>>,
    state: Run,
}

/// The next chunk of the zip: one note, one attachment, or the closing directory; `None` at the end.
async fn step(st: &mut St) -> Result<Option<Vec<u8>>, String> {
    if st.state != Run::Going {
        return Ok(None);
    }
    if let Some(id) = st.ids.pop_front() {
        return note(st, &id).await.map(Some);
    }
    let files = st
        .files
        .get_or_insert_with(|| std::mem::take(&mut st.shas).into_iter().collect());
    if let Some(sha) = files.pop_front() {
        let row: Option<(String, Vec<u8>)> =
            sqlx::query_as("SELECT content_type, data FROM lore_attachments WHERE sha256 = ?")
                .bind(&sha)
                .fetch_optional(&st.pool)
                .await
                .map_err(|e| e.to_string())?;
        // A reference to a file that is not stored is skipped: the text keeps its reference.
        return match row {
            Some((ct, data)) => st
                .zip
                .add(&format!("attachments/{sha}.{}", ext(&ct)), &data)
                .map(Some),
            None => Ok(Some(Vec::new())),
        };
    }
    st.state = Run::Done;
    Ok(Some(st.zip.finish()))
}

async fn note(st: &mut St, id: &str) -> Result<Vec<u8>, String> {
    let row = sqlx::query(
        "SELECT kind, day, project, title, text, created_at, updated_at FROM lore_notes \
         WHERE id = ? AND trashed_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(|e| e.to_string())?;
    // Purged or trashed since the list was read: leave it out.
    let Some(row) = row else {
        return Ok(Vec::new());
    };
    let g = |c: &str| row.try_get::<String, _>(c).map_err(|e| e.to_string());
    let (text, title) = (g("text")?, g("title")?);
    let project: Option<String> = row.try_get("project").map_err(|e| e.to_string())?;
    let day: Option<String> = row.try_get("day").map_err(|e| e.to_string())?;
    let tags: Vec<String> =
        sqlx::query_scalar("SELECT tag FROM lore_tags WHERE note = ? ORDER BY tag")
            .bind(id)
            .fetch_all(&st.pool)
            .await
            .map_err(|e| e.to_string())?;
    let (dir, stem) = match (&day, &project) {
        (Some(d), _) => ("daily".to_owned(), slug(d)),
        (None, Some(p)) => (format!("project-{}", slug(p)), slug(&title)),
        (None, None) => ("personal".to_owned(), slug(&title)),
    };
    let mut path = format!("{dir}/{stem}.md");
    let mut n = 1;
    while !st.used.insert(path.to_lowercase()) {
        n += 1;
        path = format!("{dir}/{stem}-{n}.md");
    }
    st.shas.extend(refs(&text).map(str::to_owned));
    // ponytail: a note's own front matter is replaced by ours (tags are kept, other keys are not); merge keys if that hurts.
    let file = format!(
        "---\nid: {id}\nproject: {}\ntags: [{}]\ncreated: {}\nupdated: {}\n---\n{}",
        project.as_deref().unwrap_or("null"),
        tags.join(", "),
        g("created_at")?,
        g("updated_at")?,
        body(&text)
    );
    st.zip.add(&path, file.as_bytes())
}

/// `text` without its leading front matter block (the same rule the parser uses).
fn body(text: &str) -> &str {
    let mut lines = text.split_inclusive('\n');
    let mut off = match lines.next() {
        Some(l) if l.trim_end() == "---" => l.len(),
        _ => return text,
    };
    for (i, l) in lines.enumerate() {
        if i >= FRONT_MATTER_LINES {
            break;
        }
        off += l.len();
        if matches!(l.trim_end(), "---" | "...") {
            return &text[off..];
        }
    }
    text
}

/// A file-name stem: lower-case letters and digits of any script, runs of anything else become one `-`.
fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let cut: String = out.chars().take(60).collect();
    let cut = cut.trim_end_matches('-');
    if cut.is_empty() {
        "note".to_owned()
    } else {
        cut.to_owned()
    }
}

fn ext(content_type: &str) -> &'static str {
    match content_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/heic" => "heic",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}

/// A stored (uncompressed) zip written entry by entry: `add` returns the bytes to send, `finish` the
/// central directory. Dates are fixed (1980-01-01) so the same export is the same bytes.
#[derive(Default)]
struct Zip {
    offset: u64,
    entries: Vec<(String, u32, u32, u32)>,
}

const CRC: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn crc32(b: &[u8]) -> u32 {
    !b.iter().fold(!0u32, |c, &x| {
        CRC[((c ^ u32::from(x)) & 0xff) as usize] ^ (c >> 8)
    })
}

/// A name that stays inside the folder it is unpacked into.
fn safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('/')
        && !name
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == ':')
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

impl Zip {
    fn add(&mut self, name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        if !safe(name) {
            return Err("an entry name is not safe".to_owned());
        }
        if self.entries.len() >= MAX_ENTRIES
            || self.offset + data.len() as u64 + name.len() as u64 + 30 > MAX_BYTES
        {
            return Err("the export is too large".to_owned());
        }
        let (crc, size) = (crc32(data), data.len() as u32);
        let mut o = Vec::with_capacity(30 + name.len() + data.len());
        o.extend(0x0403_4b50u32.to_le_bytes());
        o.extend([20, 0, 0x00, 0x08, 0, 0, 0, 0, 0x21, 0]); // version, flags (UTF-8 names), stored, time, date
        o.extend(crc.to_le_bytes());
        o.extend(size.to_le_bytes());
        o.extend(size.to_le_bytes());
        o.extend((name.len() as u16).to_le_bytes());
        o.extend([0, 0]);
        o.extend(name.as_bytes());
        o.extend(data);
        self.entries
            .push((name.to_owned(), crc, size, self.offset as u32));
        self.offset += o.len() as u64;
        Ok(o)
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut o = Vec::new();
        for (name, crc, size, at) in &self.entries {
            o.extend(0x0201_4b50u32.to_le_bytes());
            o.extend([20, 0, 20, 0, 0x00, 0x08, 0, 0, 0, 0, 0x21, 0]);
            o.extend(crc.to_le_bytes());
            o.extend(size.to_le_bytes());
            o.extend(size.to_le_bytes());
            o.extend((name.len() as u16).to_le_bytes());
            o.extend([0u8; 12]); // extra, comment, disk and internal attrs (2 each), external attrs (4)
            o.extend(at.to_le_bytes());
            o.extend(name.as_bytes());
        }
        let n = (self.entries.len() as u16).to_le_bytes();
        let cd = o.len() as u32;
        o.extend(0x0605_4b50u32.to_le_bytes());
        o.extend([0, 0, 0, 0]);
        o.extend(n);
        o.extend(n);
        o.extend(cd.to_le_bytes());
        o.extend((self.offset as u32).to_le_bytes());
        o.extend([0, 0]);
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_slug_names_and_front_matter() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(slug("Hello, World!"), "hello-world");
        assert_eq!(slug("../../etc/passwd\u{7}"), "etc-passwd");
        assert_eq!(slug("مرحبا بالعالم"), "مرحبا-بالعالم");
        assert_eq!(slug("!!!"), "note");
        assert!(slug(&"a".repeat(500)).len() <= 60);
        for ok in ["personal/a.md", "attachments/x.png"] {
            assert!(safe(ok), "{ok}");
        }
        for no in [
            "",
            "/a.md",
            "../a.md",
            "a/../b.md",
            "a//b.md",
            "a\\b.md",
            "a\u{0}b.md",
            "C:/a",
            "./a",
        ] {
            assert!(!safe(no), "{no:?}");
        }
        assert_eq!(body("---\ntags: [x]\n---\n# T\n"), "# T\n");
        assert_eq!(body("---\nno end\n# T\n"), "---\nno end\n# T\n");
        assert_eq!(body("# T\n---\n"), "# T\n---\n");
        let mut z = Zip::default();
        let a = z.add("a.md", b"hi").unwrap();
        assert_eq!(&a[..4], b"PK\x03\x04");
        assert!(z.add("../a.md", b"x").is_err());
        let end = z.finish();
        assert_eq!(&end[end.len() - 22..end.len() - 18], b"PK\x05\x06");
    }
}
