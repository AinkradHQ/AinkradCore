//! The room Overview's local selection: which items the model reads (instruction files and docs
//! first) and which candidate rules it may choose from. Every rule-like line of the room is
//! grouped with the lines that say the same (same words, or the same meaning by the local model);
//! a candidate carries every item that states it, so support is counted here.

use std::collections::HashMap;

use brain_model::item::{hash_of, is_agent_noise};
use sqlx::{Row, SqlitePool};

use crate::Brain;
use crate::ai::cut;
use crate::overview_write::{Check, MAX_SOURCES, Offered, Selection, Shown};
use crate::semantic::pick::{Cand, Candidate, candidate_lines, group, line_key, representatives};

const ITEMS: usize = 40;
/// At most this many documentation items are among the excerpts, first.
const DOC_ITEMS: usize = 12;
const OFFERED: usize = 60;
/// Fewer candidates than this with real support: a note's single mention may fill the list.
const THIN_ROOM: usize = 20;
const ITEM_CHARS: usize = 450;
const DOC_CHARS: usize = 1200;
/// Groups whose first line gets a vector from the local model (the rest group by words only).
const EMBEDDED: usize = 800;

/// Files that hold a project's lasting conventions, by name.
const DOC_NAMES: &[&str] = &[
    "agents.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    "copilot-instructions.md",
    "conventions.md",
];

/// Whether an item is a project's instruction file (AGENTS.md, CLAUDE.md, .cursorrules, ...): its
/// list entries are conventions, and one is enough to make a rule.
/// The `agents_md` collector also brings READMEs, so the file name decides, not the kind.
pub fn is_guide(_kind: &str, path: &str, title: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or("").to_lowercase();
    let title = title.trim().to_lowercase();
    [base.as_str(), title.as_str()]
        .iter()
        .any(|n| DOC_NAMES.contains(n))
        || path.to_lowercase().contains("/.cursor/rules/")
}

/// Whether an item is other documentation: a doc, a note, a README. Its rule lines come before
/// the sessions', but a rule still needs as many items as any other.
pub fn is_note(kind: &str, path: &str, title: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or("").to_lowercase();
    matches!(kind, "doc" | "vault" | "agents_md")
        || base.starts_with("readme.")
        || title.trim().to_lowercase().starts_with("readme.")
        || path.to_lowercase().contains("/docs/") && base.ends_with(".md")
}

/// One item as the selection reads it from a room.
pub struct RoomItem {
    pub id: String,
    pub kind: String,
    /// Documentation that is not an instruction file.
    pub note: bool,
    pub title: String,
    pub text: String,
    pub person: bool,
    /// An instruction file.
    pub doc: bool,
    pub hash: String,
}

/// The room's items, newest first, without agent noise.
/// ponytail: the 3000 newest items and their first 20k characters; a bigger room is sampled by recency.
pub async fn room_items(pool: &SqlitePool) -> Result<Vec<RoomItem>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT item_id, content_hash, source_kind, path, title, substr(text, 1, 20000) AS text, author_kind \
         FROM sources WHERE pointer = 0 ORDER BY started_at DESC, item_id LIMIT 3000",
    )
    .fetch_all(pool)
    .await?;
    let mut out = vec![];
    for r in &rows {
        let (path, title): (String, String) = (r.try_get("path")?, r.try_get("title")?);
        // Sub-agent transcripts and scratch-file prompts are no one's words about the project.
        if is_agent_noise(&path, &title) {
            continue;
        }
        let kind: String = r.try_get("source_kind")?;
        out.push(RoomItem {
            id: r.try_get("item_id")?,
            doc: is_guide(&kind, &path, &title),
            note: is_note(&kind, &path, &title),
            kind,
            title,
            text: r.try_get("text")?,
            person: r.try_get::<String, _>("author_kind")? == "person",
            hash: r.try_get("content_hash")?,
        });
    }
    Ok(out)
}

/// The date of the room's newest item and its age in whole days at `now` (both `None` for a room
/// without items). Pointers and agent noise do not count: the state is about real work.
pub async fn newest_item(
    pool: &SqlitePool,
    now: &str,
) -> Result<(Option<String>, Option<i64>), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT path, title, coalesce(ended_at, started_at) AS at FROM sources \
         WHERE pointer = 0 ORDER BY coalesce(ended_at, started_at) DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    for r in &rows {
        let (path, title): (String, String) = (r.try_get("path")?, r.try_get("title")?);
        if is_agent_noise(&path, &title) {
            continue;
        }
        let at: String = r.try_get("at")?;
        let age: Option<i64> =
            sqlx::query_scalar("SELECT CAST(julianday(?) - julianday(?) AS INTEGER)")
                .bind(now)
                .bind(&at)
                .fetch_one(pool)
                .await?;
        return Ok((Some(at), age));
    }
    Ok((None, None))
}

/// The lines whose groups get a vector: documentation first, then the most repeated, by key.
pub fn to_embed(c: &[Cand], lines: &[(usize, String)]) -> Vec<(String, String)> {
    let mut count: HashMap<String, (bool, usize, String)> = HashMap::new();
    for (i, l) in lines {
        let e = count.entry(line_key(l)).or_insert((false, 0, l.clone()));
        e.0 |= c[*i].doc;
        e.1 += 1;
    }
    let mut v: Vec<(String, (bool, usize, String))> = count.into_iter().collect();
    v.sort_by(|a, b| (b.1.0, b.1.1, &a.0).cmp(&(a.1.0, a.1.1, &b.0)));
    v.into_iter()
        .take(EMBEDDED)
        .map(|(k, (_, _, l))| (k, l))
        .collect()
}

/// The vector key of a rule line in the shared store (kept apart from item hashes).
pub fn line_hash(key: &str) -> String {
    hash_of(&format!("overview rule line\n{key}"))
}

/// The room's representative items and its candidate rules, picked on this machine. `others`
/// are the other rooms' names.
pub async fn select(
    b: &Brain,
    pool: &SqlitePool,
    others: Vec<String>,
) -> Result<Selection, sqlx::Error> {
    let rec = room_items(pool).await?;
    let hashes: Vec<String> = rec.iter().map(|r| r.hash.clone()).collect();
    // Stored item vectors only; no model or no vectors: recency picks.
    let vecs: HashMap<String, Vec<f32>> = b.vectors_for(&hashes).await.unwrap_or_default();
    let cands: Vec<Cand> = rec
        .iter()
        .map(|r| Cand {
            title: &r.title,
            text: &r.text,
            person: r.person,
            doc: r.doc,
            note: r.note,
            vec: vecs.get(&r.hash).map(Vec::as_slice),
        })
        .collect();
    let lines = candidate_lines(&cands);
    // Line vectors from the local model (stored, so the next write reuses them); none in time or
    // no model: lines group by their words only.
    let embed = to_embed(&cands, &lines);
    let pairs: Vec<(String, String)> = embed
        .iter()
        .map(|(k, l)| (line_hash(k), l.clone()))
        .collect();
    let got =
        tokio::time::timeout(std::time::Duration::from_secs(180), b.embed_texts(&pairs)).await;
    let line_vecs: HashMap<String, Vec<f32>> = match got {
        Ok(Ok(v)) => embed
            .into_iter()
            .map(|e| e.0)
            .zip(v)
            .filter(|(_, v)| !v.is_empty())
            .collect(),
        _ => HashMap::new(),
    };
    let check = Check::for_room(others, rec.len());
    let groups = group(&cands, &lines, |t| line_vecs.get(&line_key(t)).cloned());
    let offered = offer(&groups, &check, |i| rec[i].id.clone());
    let docs: Vec<usize> = (0..rec.len())
        .filter(|&i| rec[i].doc)
        .take(DOC_ITEMS)
        .collect();
    let rest: Vec<usize> = (0..rec.len()).filter(|i| !docs.contains(i)).collect();
    let sub: Vec<Cand> = rest.iter().map(|&i| cands[i]).collect();
    let items = docs
        .iter()
        .copied()
        .chain(
            representatives(&sub, ITEMS - docs.len())
                .into_iter()
                .map(|j| rest[j]),
        )
        .map(|i| {
            let n = if rec[i].doc || rec[i].note {
                DOC_CHARS
            } else {
                ITEM_CHARS
            };
            (
                rec[i].id.clone(),
                rec[i].title.clone(),
                cut(&rec[i].text, n).0,
            )
        })
        .collect();
    Ok(Selection { items, offered })
}

/// The candidates the model may choose from: those that pass `check`, documentation first. What
/// only AI sessions say gets at most a third of the places, and a block of lines that always come
/// together (a prompt template pasted into every session) gives one.
pub fn offer(groups: &[Candidate], check: &Check, id_of: impl Fn(usize) -> String) -> Offered {
    let mut blocks: Vec<&[usize]> = vec![];
    let mut sessions = 0;
    // (candidate, whether one item is enough for it)
    let mut picked: Vec<(&Candidate, bool)> = vec![];
    for g in groups {
        if picked.len() >= OFFERED || check.verdict(&g.text, g.items.len(), g.doc).is_err() {
            continue;
        }
        if g.session {
            if sessions >= OFFERED / 3 || g.items.len() >= 3 && blocks.contains(&g.items.as_slice())
            {
                continue;
            }
            sessions += 1;
            blocks.push(&g.items);
        }
        picked.push((g, g.doc));
    }
    // A room of notes that each say a thing once still offers its notes' rules, up to a short
    // list; the model picks the lasting ones.
    for g in groups {
        if picked.len() >= THIN_ROOM {
            break;
        }
        if !g.session && check.verdict(&g.text, g.items.len(), g.doc) == Err("thin") {
            picked.push((g, true));
        }
    }
    let rules = picked
        .into_iter()
        .enumerate()
        .map(|(n, (g, doc))| Shown {
            id: format!("c{}", n + 1),
            text: g.text.clone(),
            items: g
                .items
                .iter()
                .take(MAX_SOURCES)
                .map(|&i| id_of(i))
                .collect(),
            doc,
        })
        .collect();
    Offered {
        rules,
        min_sources: check.min_sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rooms<'a>(texts: &'a [(&'a str, bool, &'a str)]) -> Vec<Cand<'a>> {
        texts
            .iter()
            .map(|(title, doc, text)| Cand {
                title,
                text,
                person: true,
                doc: *doc,
                note: false,
                vec: None,
            })
            .collect()
    }

    /// The owner's case: an AGENTS.md with three conventions and session prompts that repeat one
    /// of them twice among one-off orders. Offered: the three, and the repeated one with both
    /// items; no one-off. Without docs, a big room of single mentions offers nothing.
    #[test]
    fn docs_lead_repeats_are_counted_and_one_offs_are_not_offered() {
        let mut texts = vec![
            (
                "AGENTS.md",
                true,
                "# Conventions\n- Open every PR against the development branch.\n- Keep controllers thin; business logic lives in app/Actions.\n- Never commit secrets or .env files.",
            ),
            (
                "fix login",
                false,
                "User: always run the test suite before you push.\nMerge #312 now, it is billing-blocked until then.",
            ),
            (
                "tidy",
                false,
                "User: Always run the test suite before you push!\nDon't touch the billing code until 2026-12-01.",
            ),
            (
                "notes",
                false,
                "User: you must read docs/plan.md first and do step 3",
            ),
        ];
        let filler: Vec<String> = (0..20).map(|i| format!("filler item {i}")).collect();
        texts.extend(filler.iter().map(|f| ("f", false, f.as_str())));
        let c = rooms(&texts);
        let check = Check::for_room(vec![], c.len());
        let g = group(&c, &candidate_lines(&c), |_| None);
        let o = offer(&g, &check, |i| format!("i{i}"));
        let got: Vec<(&str, Vec<String>)> = o
            .rules
            .iter()
            .map(|r| (r.text.as_str(), r.items.clone()))
            .collect();
        assert_eq!(got.len(), 4, "{got:?}");
        assert!(o.rules[..3].iter().all(|r| r.doc && r.items == ["i0"]));
        assert_eq!(o.rules[3].items, ["i1", "i2"]);
        assert_eq!(o.min_sources, 2);
        let lone = [
            ("a", false, "User: never deploy on a Friday afternoon"),
            ("b", false, "User: always use the staging key for this one"),
        ];
        let mut lone = lone.to_vec();
        lone.extend(filler.iter().map(|f| ("f", false, f.as_str())));
        let c = rooms(&lone);
        let g = group(&c, &candidate_lines(&c), |_| None);
        assert!(
            offer(&g, &Check::for_room(vec![], c.len()), |i| format!("i{i}"))
                .rules
                .is_empty()
        );
    }
}
