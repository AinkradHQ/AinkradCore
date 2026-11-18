//! Embedding notes for search (R2-02). One chunk per heading section (long sections are cut into windows),
//! one vector per chunk, kept in `lore_chunks`. The job finds notes whose `lore_embedded.rev` is not the
//! note's rev (or whose model changed): no save hook, and a note being typed in is left alone until it has
//! been quiet for 10 s (the debounce). It uses the one shared model with its default of one thread, a few
//! notes at a time with a pause between them, and never runs when the model is absent.
//!
//! ponytail: no `nice` (the workspace forbids unsafe, so no setpriority); one thread and the pauses are the
//! throttle. The model's thread count is the Brain's `semantic.threads` setting; this module never sets it.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{Done, JobHandler, Run};
use ainkrad_core_server::store::begin_write;
use ainkrad_embed::Embedder;
use sqlx::{Row, SqlitePool};

/// The shared model, once loaded.
pub(crate) type Slot = Arc<Mutex<Option<Arc<dyn Embedder>>>>;

pub(crate) fn set(slot: &Slot, e: Arc<dyn Embedder>) {
    *slot.lock().unwrap_or_else(|x| x.into_inner()) = Some(e);
}

pub(crate) fn get(slot: &Slot) -> Option<Arc<dyn Embedder>> {
    slot.lock().unwrap_or_else(|x| x.into_inner()).clone()
}

/// Loads the shared model off the request path (the Brain's directory and variable: one model, one place).
/// A missing directory or failed check leaves search FTS only.
#[cfg(feature = "semantic")]
pub(crate) fn load_in_background(slot: &Slot) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let dir = std::env::var_os("AINKRAD_BRAIN_MODEL_DIR").map_or_else(
        || std::path::PathBuf::from(ainkrad_embed::local::DEFAULT_DIR),
        Into::into,
    );
    if !dir.is_dir() {
        tracing::info!("lore search is text only: no model directory");
        return;
    }
    let slot = slot.clone();
    rt.spawn_blocking(move || match ainkrad_embed::shared(&dir) {
        Ok(m) => {
            set(&slot, m);
            tracing::info!("lore search by meaning is on (local model loaded)");
        }
        Err(e) => {
            tracing::warn!(error = %e, "lore search is text only: the model files did not verify")
        }
    });
}

/// A window of the note text.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Chunk {
    pub heading: Option<String>,
    pub start: usize,
    pub len: usize,
}

/// The longest chunk in bytes. The model reads about 128 tokens (~500 characters), so a longer section is
/// cut into windows instead of losing its tail.
const WINDOW: usize = 800;
const CHUNKS_MAX: usize = 64;

/// Sections between headings (outside code fences), cut at line ends into windows of at most `WINDOW`
/// bytes; a chunk with no letter or digit is dropped.
pub(crate) fn chunks(text: &str) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut heading: Option<String> = None;
    let mut fence = false;
    // The open window: (start, end).
    let mut win: Option<(usize, usize)> = None;
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        let (s, e) = (pos, pos + line.len());
        pos = e;
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
        }
        let h = if fence { None } else { heading_of(t) };
        if let Some(h) = h {
            flush(text, &mut win, &heading, &mut out);
            heading = Some(h.trim().trim_end_matches('#').trim().to_owned());
        }
        // A line longer than the window is cut at a char boundary.
        let mut a = s;
        while a < e {
            let mut b = (a + WINDOW).min(e);
            while !text.is_char_boundary(b) {
                b -= 1;
            }
            match win {
                Some((ws, _)) if b - ws <= WINDOW => win = Some((ws, b)),
                Some(_) => {
                    flush(text, &mut win, &heading, &mut out);
                    win = Some((a, b));
                }
                None => win = Some((a, b)),
            }
            a = b;
        }
        if out.len() >= CHUNKS_MAX {
            return out;
        }
    }
    flush(text, &mut win, &heading, &mut out);
    out.truncate(CHUNKS_MAX);
    out
}

fn flush(text: &str, win: &mut Option<(usize, usize)>, h: &Option<String>, out: &mut Vec<Chunk>) {
    if let Some((s, e)) = win.take()
        && text[s..e].chars().any(char::is_alphanumeric)
    {
        out.push(Chunk {
            heading: h.clone(),
            start: s,
            len: e - s,
        });
    }
}

/// The text of an ATX heading line (`## Part`), else `None`.
fn heading_of(line: &str) -> Option<&str> {
    let n = line.bytes().take_while(|&b| b == b'#').count();
    if (1..=6).contains(&n) {
        line[n..].strip_prefix(' ')
    } else {
        None
    }
}

pub(crate) fn blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub(crate) fn unblob(b: &[u8]) -> impl Iterator<Item = f32> + '_ {
    b.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c))
}

/// Notes embedded per job run, and the pause after each (a gentle pace).
const PER_RUN: usize = 40;
const PAUSE: Duration = Duration::from_millis(100);
/// A run stops starting new notes after this long (the job runs again 30 s later).
const BUDGET: Duration = Duration::from_secs(20);

/// Embeds up to `max` stale notes that were last written more than `quiet` seconds ago. Returns how many.
pub(crate) async fn pass(
    pool: &SqlitePool,
    slot: &Slot,
    quiet: i64,
    max: usize,
) -> Result<usize, String> {
    let Some(emb) = get(slot) else { return Ok(0) };
    let model = emb.model_id().to_owned();
    let t0 = Instant::now();
    let mut done = 0;
    while done < max && (done == 0 || t0.elapsed() < BUDGET) {
        let row = sqlx::query(
            "SELECT n.id, n.title, n.text, n.rev FROM lore_notes n \
             LEFT JOIN lore_embedded e ON e.note = n.id \
             WHERE n.trashed_at IS NULL AND (e.note IS NULL OR e.rev != n.rev OR e.model != ?1) \
               AND n.updated_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-' || ?2 || ' seconds') \
             ORDER BY n.updated_at DESC LIMIT 1",
        )
        .bind(&model)
        .bind(quiet)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
        let Some(row) = row else { break };
        let (id, title, text, rev): (String, String, String, i64) = (
            row.get("id"),
            row.get("title"),
            row.get("text"),
            row.get("rev"),
        );
        let cs = chunks(&text);
        let inputs: Vec<String> = cs
            .iter()
            .map(|c| {
                let h = c.heading.as_deref().unwrap_or(&title);
                format!("{h}\n{}", &text[c.start..c.start + c.len])
            })
            .collect();
        let vecs = if inputs.is_empty() {
            Vec::new()
        } else {
            let e = emb.clone();
            tokio::task::spawn_blocking(move || e.embed(&inputs))
                .await
                .map_err(|e| e.to_string())??
        };
        let mut tx = begin_write(pool).await.map_err(|e| format!("{e:?}"))?;
        sqlx::query("DELETE FROM lore_chunks WHERE note = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        for (seq, (c, v)) in cs.iter().zip(&vecs).enumerate() {
            sqlx::query(
                "INSERT INTO lore_chunks (note, seq, heading, start, len, model, vec) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(seq as i64)
            .bind(&c.heading)
            .bind(c.start as i64)
            .bind(c.len as i64)
            .bind(&model)
            .bind(blob(v))
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        }
        // `rev` is the one the text was read at: a save meanwhile leaves the note stale, so it runs again.
        sqlx::query(
            "INSERT INTO lore_embedded (note, rev, model) VALUES (?, ?, ?) \
             ON CONFLICT(note) DO UPDATE SET rev = excluded.rev, model = excluded.model",
        )
        .bind(&id)
        .bind(rev)
        .bind(&model)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        done += 1;
        tokio::time::sleep(PAUSE).await;
    }
    Ok(done)
}

pub(crate) struct Embed(pub Arc<OnceLock<App>>, pub Slot);

impl JobHandler for Embed {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the lore module is not attached")?;
            if pass(&app.pool, &self.1, 10, PER_RUN).await? == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_follow_headings_and_skip_code_fences() {
        let t = "# Title\nintro\n## Part A\nalpha\n```\n# not a heading\n```\n## Part B\n\n\n## Part C\nzeta\n";
        let c = chunks(t);
        let h: Vec<_> = c.iter().map(|c| c.heading.as_deref()).collect();
        assert_eq!(
            h,
            [
                Some("Title"),
                Some("Part A"),
                Some("Part B"),
                Some("Part C")
            ]
        );
        assert!(t[c[1].start..c[1].start + c[1].len].contains("# not a heading"));
    }

    #[test]
    fn long_sections_are_cut_on_char_boundaries() {
        let t = format!("# H\n{}\n", "مرحبا ".repeat(600));
        let c = chunks(&t);
        assert!(c.len() >= 4);
        for k in &c {
            assert!(k.len <= WINDOW);
            assert!(t.is_char_boundary(k.start) && t.is_char_boundary(k.start + k.len));
        }
        assert!(chunks(&"x\n".repeat(100_000)).len() <= CHUNKS_MAX);
    }
}
