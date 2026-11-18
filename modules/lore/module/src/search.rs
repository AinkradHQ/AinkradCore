//! Note search (T10): `GET /search?q=` ranks notes by full text (FTS5: prefix words, "quoted phrases") and
//! by meaning (the shared e5 model over the note's chunks), merged with reciprocal-rank fusion. Filters:
//! `state` (`active` default, `trashed`, `all`), `kind` (`note`/`daily`), `project`, `tag`. With the model
//! absent or not yet loaded the answer is the text ranking alone and `semantic` is `false`. Each hit carries
//! a snippet of the note with the byte ranges of the matched words, for highlighting. The note text is
//! outside data: it is returned only inside a snippet.
//!
//! ponytail: every query reads the stored vectors of the filtered notes (about 1.5 KB per chunk) and
//! scores them in a loop; fine to tens of thousands of chunks, then keep an in-memory matrix.
//! ponytail: highlights match case-insensitively on word starts; a word FTS matched only through diacritic
//! folding is ranked but not highlighted.

use std::collections::HashMap;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Query, State};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;

use crate::Lore;
use crate::embed::{get, unblob};
use crate::notes::{NoteSummary, summary};

const LIMIT_DEFAULT: usize = 20;
const LIMIT_MAX: usize = 50;
/// Candidates taken from each ranking before they are merged.
const POOL: usize = 100;
/// Query length cap (characters) and the most terms used.
const Q_MAX: usize = 300;
const TERMS_MAX: usize = 12;
/// Reciprocal-rank-fusion constant.
const RRF_K: f64 = 60.0;
/// Cosine under which a chunk is not a meaning match (unrelated e5 text still scores about 0.7).
const SIM_FLOOR: f32 = 0.80;
const SNIPPET: usize = 180;

#[derive(Deserialize)]
pub(crate) struct SearchQuery {
    q: Option<String>,
    state: Option<String>,
    kind: Option<String>,
    project: Option<String>,
    tag: Option<String>,
    limit: Option<usize>,
}

/// A matched word inside a snippet: byte offsets into `Snippet.text`.
#[derive(Serialize, ToSchema, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Serialize, ToSchema)]
pub struct Snippet {
    /// A stretch of the note on one line (newlines become spaces), `…` where it was cut. Note text: outside data.
    pub text: String,
    /// The matched words in `text`, in order, not overlapping; empty for a hit by meaning alone.
    pub matches: Vec<Span>,
}

#[derive(Serialize, ToSchema)]
pub struct Hit {
    #[serde(flatten)]
    pub note: NoteSummary,
    /// Higher is better; only comparable within one answer.
    pub score: f64,
    /// `text`, `meaning` or `both`: which ranking found it.
    pub via: String,
    /// The heading of the best matching section, for a hit by meaning.
    pub heading: Option<String>,
    pub snippet: Snippet,
}

#[derive(Serialize, ToSchema)]
pub struct SearchOut {
    pub results: Vec<Hit>,
    /// `false` = the model is absent or not loaded yet, so these are text matches only.
    pub semantic: bool,
}

/// FTS5 `MATCH` text from what a person typed: words become prefix terms, `"quoted words"` a phrase, all
/// ANDed. Nothing typed reaches FTS5 syntax: only letters and digits survive. `None` = no term.
pub(crate) fn match_expr(q: &str) -> Option<String> {
    let mut terms: Vec<String> = Vec::new();
    for (i, part) in q.split('"').enumerate() {
        let words: Vec<&str> = part
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        if words.is_empty() {
            continue;
        }
        if i % 2 == 1 {
            terms.push(format!("\"{}\"", words.join(" ")));
        } else {
            terms.extend(words.iter().map(|w| format!("\"{w}\"*")));
        }
    }
    terms.truncate(TERMS_MAX);
    (!terms.is_empty()).then(|| terms.join(" "))
}

/// The words to highlight: every word of the query, lower-cased.
fn words(q: &str) -> Vec<Vec<char>> {
    let mut w: Vec<Vec<char>> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.chars().flat_map(char::to_lowercase).collect())
        .collect();
    w.sort();
    w.dedup();
    w.truncate(TERMS_MAX);
    w
}

/// A snippet around the first match in `text` at or after byte `from`, or around `from` when nothing matches.
pub(crate) fn snippet(text: &str, ws: &[Vec<char>], from: usize) -> Snippet {
    let cs: Vec<(usize, char)> = text.char_indices().collect();
    let low: Vec<char> = cs
        .iter()
        .map(|&(_, c)| c.to_lowercase().next().unwrap_or(c))
        .collect();
    // Matches as (char start, char end): a query word at the start of a word of the text.
    let mut found: Vec<(usize, usize)> = Vec::new();
    for i in 0..low.len() {
        if i > 0 && low[i - 1].is_alphanumeric() {
            continue;
        }
        let best = ws
            .iter()
            .filter(|w| low[i..].starts_with(w))
            .map(|w| w.len())
            .max();
        if let Some(n) = best {
            // The whole word the prefix opens, as FTS matched it.
            let mut e = i + n;
            while e < low.len() && low[e].is_alphanumeric() {
                e += 1;
            }
            found.push((i, e));
        }
    }
    let from_c = cs.partition_point(|&(b, _)| b < from);
    let first = found
        .iter()
        .find(|m| m.0 >= from_c)
        .or(found.first())
        .map_or(from_c.min(cs.len().saturating_sub(1)), |m| m.0);
    let a = first.saturating_sub(40);
    let z = (a + SNIPPET).min(cs.len());
    let lead = if a > 0 { "…" } else { "" };
    let mut out = String::from(lead);
    let mut spans = Vec::new();
    let mut at = a;
    for &(s, e) in found.iter().filter(|m| m.0 >= a && m.1 <= z) {
        push_line(&mut out, &cs[at..s]);
        let b0 = out.len();
        push_line(&mut out, &cs[s..e]);
        spans.push(Span {
            start: b0,
            end: out.len(),
        });
        at = e;
    }
    push_line(&mut out, &cs[at.min(z)..z]);
    if z < cs.len() {
        out.push('…');
    }
    Snippet {
        text: out,
        matches: spans,
    }
}

fn push_line(out: &mut String, cs: &[(usize, char)]) {
    out.extend(
        cs.iter()
            .map(|&(_, c)| if c.is_control() { ' ' } else { c }),
    );
}

/// The filters, as a literal so a query is built with `concat!`, never by formatting. ?1 state, ?2 kind, ?3 project, ?4 tag.
macro_rules! filter {
    () => {
        "(?1 = 'all' OR (?1 = 'active' AND n.trashed_at IS NULL) \
         OR (?1 = 'trashed' AND n.trashed_at IS NOT NULL)) \
         AND (?2 IS NULL OR n.kind = ?2) AND (?3 IS NULL OR n.project = ?3) \
         AND (?4 IS NULL OR EXISTS (SELECT 1 FROM lore_tags t WHERE t.note = n.id AND t.tag = ?4))"
    };
}

fn cos(a: &[f32], b: impl Iterator<Item = f32>) -> f32 {
    let (mut d, mut nb) = (0.0f32, 0.0f32);
    for (x, y) in a.iter().zip(b) {
        d += x * y;
        nb += y * y;
    }
    let na: f32 = a.iter().map(|x| x * x).sum();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        d / (na.sqrt() * nb.sqrt())
    }
}

#[utoipa::path(get, path = "/search", operation_id = "loreSearch", tag = "lore",
    params(("q" = String, Query, description = "What to find: words (prefix match) and \"quoted phrases\"; at most 300 characters"),
           ("state" = Option<String>, Query, description = "`active` (default), `trashed` or `all`"),
           ("kind" = Option<String>, Query, description = "`note` or `daily`"),
           ("project" = Option<String>, Query, description = "Only notes of this project id"),
           ("tag" = Option<String>, Query, description = "Only notes with this tag"),
           ("limit" = Option<usize>, Query, description = "At most this many hits (default 20, at most 50)")),
    responses((status = 200, description = "Hits, best first, with snippets; `semantic` says whether meaning was used", body = SearchOut)))]
pub(crate) async fn search(
    State(app): State<App>,
    Extension(lore): Extension<Lore>,
    q: Result<Query<SearchQuery>, QueryRejection>,
) -> ApiResult<SearchOut> {
    let bad = || ApiError::bad_request("the query is not valid");
    let Query(q) = q.map_err(|_| bad())?;
    let text = q.q.as_deref().map(str::trim).unwrap_or_default();
    let state = q.state.as_deref().unwrap_or("active");
    let limit = q.limit.unwrap_or(LIMIT_DEFAULT);
    if text.is_empty()
        || text.chars().count() > Q_MAX
        || !["active", "trashed", "all"].contains(&state)
        || q.kind
            .as_deref()
            .is_some_and(|k| !["note", "daily"].contains(&k))
        || !(1..=LIMIT_MAX).contains(&limit)
    {
        return Err(bad());
    }
    let tag = q
        .tag
        .as_deref()
        .map(|t| t.trim().trim_start_matches('#').to_owned());

    // 1. Text ranking: best first.
    let mut ranks: HashMap<String, Rank> = HashMap::new();
    if let Some(m) = match_expr(text) {
        let rows = sqlx::query(concat!(
            "SELECT n.id FROM lore_fts JOIN lore_notes n ON n.rowid = lore_fts.rowid \
             WHERE lore_fts MATCH ?5 AND ",
            filter!(),
            " ORDER BY bm25(lore_fts, 4.0, 1.0), n.id LIMIT 100"
        ))
        .bind(state)
        .bind(&q.kind)
        .bind(&q.project)
        .bind(&tag)
        .bind(&m)
        .fetch_all(&app.pool)
        .await?;
        for (i, r) in rows.iter().enumerate() {
            ranks.entry(r.try_get("id")?).or_default().text = Some(i);
        }
    }

    // 2. Meaning ranking: the best chunk of each note.
    let mut semantic = false;
    if let Some(emb) = get(&lore.emb) {
        let model = emb.model_id().to_owned();
        let query = text.to_owned();
        let vec = tokio::task::spawn_blocking(move || emb.embed(&[query]))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|mut v| v.pop());
        if let Some(qv) = vec {
            semantic = true;
            let rows = sqlx::query(concat!(
                "SELECT c.note, c.heading, c.start, c.vec FROM lore_chunks c \
                 JOIN lore_notes n ON n.id = c.note WHERE c.model = ?5 AND ",
                filter!()
            ))
            .bind(state)
            .bind(&q.kind)
            .bind(&q.project)
            .bind(&tag)
            .bind(&model)
            .fetch_all(&app.pool)
            .await?;
            let mut best: HashMap<String, (f32, Option<String>, usize)> = HashMap::new();
            for r in &rows {
                let v: Vec<u8> = r.try_get("vec")?;
                let s = cos(&qv, unblob(&v));
                if s < SIM_FLOOR {
                    continue;
                }
                let e = best
                    .entry(r.try_get("note")?)
                    .or_insert((f32::MIN, None, 0));
                if s > e.0 {
                    *e = (
                        s,
                        r.try_get("heading")?,
                        usize::try_from(r.try_get::<i64, _>("start")?).unwrap_or(0),
                    );
                }
            }
            let mut v: Vec<_> = best.into_iter().collect();
            v.sort_by(|a, b| b.1.0.total_cmp(&a.1.0).then(a.0.cmp(&b.0)));
            for (i, (id, (_, h, st))) in v.into_iter().take(POOL).enumerate() {
                let r = ranks.entry(id).or_default();
                r.meaning = Some(i);
                r.heading = h;
                r.start = st;
            }
        }
    }

    // 3. Fuse, cut, and fetch what the finalists need.
    let rrf = |r: Option<usize>| r.map_or(0.0, |i| 1.0 / (RRF_K + i as f64 + 1.0));
    let mut order: Vec<(String, f64)> = ranks
        .iter()
        .map(|(id, r)| (id.clone(), rrf(r.text) + rrf(r.meaning)))
        .collect();
    order.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    order.truncate(limit);
    let ids =
        serde_json::to_string(&order.iter().map(|o| &o.0).collect::<Vec<_>>()).unwrap_or_default();
    let rows = sqlx::query("SELECT * FROM lore_notes WHERE id IN (SELECT value FROM json_each(?))")
        .bind(ids)
        .fetch_all(&app.pool)
        .await?;
    let mut notes: HashMap<String, sqlx::sqlite::SqliteRow> = HashMap::new();
    for r in rows {
        notes.insert(r.try_get("id")?, r);
    }
    let ws = words(text);
    let mut results = Vec::new();
    for (id, score) in order {
        let (Some(r), Some(rk)) = (notes.get(&id), ranks.remove(&id)) else {
            continue;
        };
        let body: String = r.try_get("text")?;
        let (via, from) = match (rk.text, rk.meaning) {
            (Some(_), Some(_)) => ("both", 0),
            (Some(_), None) => ("text", 0),
            _ => ("meaning", rk.start),
        };
        results.push(Hit {
            note: summary(r)?,
            score,
            via: via.to_owned(),
            heading: rk.heading,
            snippet: snippet(&body, &ws, from),
        });
    }
    Ok(Json(SearchOut { results, semantic }))
}

#[derive(Default)]
struct Rank {
    text: Option<usize>,
    meaning: Option<usize>,
    heading: Option<String>,
    start: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_expr_keeps_fts_syntax_out() {
        assert_eq!(match_expr("foo bar").unwrap(), r#""foo"* "bar"*"#);
        assert_eq!(
            match_expr(r#"say "hello world" now"#).unwrap(),
            r#""say"* "hello world" "now"*"#
        );
        assert_eq!(
            match_expr("a OR b NEAR(c) -d* col:x").unwrap(),
            r#""a"* "OR"* "b"* "NEAR"* "c"* "d"* "col"* "x"*"#
        );
        assert_eq!(
            match_expr("مرحبا بالعالم").unwrap(),
            r#""مرحبا"* "بالعالم"*"#
        );
        assert_eq!(match_expr(r#"  "" ?! "#), None);
        assert_eq!(
            match_expr(r#""unclosed phrase"#).unwrap(),
            r#""unclosed phrase""#
        );
    }

    #[test]
    fn snippet_marks_whole_words_by_byte_range() {
        let t = "Intro line\nthe Quick brown fox jumps over the lazy dog";
        let s = snippet(t, &words("quick fo"), 0);
        assert_eq!(
            s.text,
            "Intro line the Quick brown fox jumps over the lazy dog"
        );
        let got: Vec<&str> = s.matches.iter().map(|m| &s.text[m.start..m.end]).collect();
        assert_eq!(got, ["Quick", "fox"]);
    }

    #[test]
    fn snippet_cuts_long_text_and_handles_arabic() {
        let t = format!("{} مرحبا بالعالم {}", "كلمة ".repeat(80), "x ".repeat(200));
        let s = snippet(&t, &words("بالع"), 0);
        assert!(s.text.starts_with('…') && s.text.ends_with('…'));
        assert_eq!(&s.text[s.matches[0].start..s.matches[0].end], "بالعالم");
        // No match: a plain stretch from `from`, no highlights.
        let n = snippet("alpha beta", &words("zzz"), 0);
        assert!(n.matches.is_empty() && n.text == "alpha beta");
    }
}
