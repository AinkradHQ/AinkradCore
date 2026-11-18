//! The Brain eval harness (B1-01): runs labelled questions through retrieval on a read-only COPY of
//! a Core home and reports recall, precision and context noise, plus a dry run of the room-file
//! migrations. Content never leaves the copy: reports hold counts, ratios and ids only.
//! Driven by `examples/brain_eval.rs`; the tests run it on a made-up room.

use std::path::{Path, PathBuf};
use std::time::Instant;

use ainkrad_core_server::ops::config::Home;
use ainkrad_core_server::ops::secretbox::SecretBox;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::{cipher, files};

/// The live data dir. A run on it is refused: the eval reads a copy, never the live data.
const LIVE: &str = "/var/lib/ainkrad/core";
/// Retrieval depth the metrics are taken at (hit@5).
pub const K: usize = 5;
/// ponytail: tokens are chars / 4; swap for the model tokenizer if the gate needs exact counts.
const CHARS_PER_TOKEN: usize = 4;
/// A source loads its title and this many characters, as a search snippet would.
const SOURCE_CHARS: usize = 1000;

/// One question set per room. Authoring a file is this and nothing else:
/// `{"room":"<room id>","questions":[{"q":"how do we deploy","answers":["rec-1"]}]}`.
#[derive(Deserialize)]
pub struct QuestionSet {
    pub room: String,
    pub questions: Vec<Question>,
}

#[derive(Deserialize)]
pub struct Question {
    /// Words to find; all must appear (the room search's own rule).
    pub q: String,
    /// Ids (record ids or source item ids) that answer it.
    pub answers: Vec<String>,
    /// `search` (default). `start` and `prompt` are counted as skipped until those paths exist.
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Serialize, Default)]
pub struct RoomReport {
    pub room: String,
    pub questions: usize,
    pub skipped: usize,
    /// Share of questions with at least one answer in the top K.
    pub hit_at_k: f64,
    /// Mean share of the labelled answers found in the top K.
    pub recall_at_k: f64,
    /// Mean share of returned lines that are labelled relevant.
    pub precision: f64,
    /// Share of loaded tokens that are not labelled useful (all questions together).
    pub noise: f64,
    pub latency_ms_mean: f64,
    pub latency_ms_p95: f64,
    /// Question numbers (1-based, file order) with no hit.
    pub missed: Vec<usize>,
    /// Ids a label named that the room does not have (a stale label).
    pub unknown_labels: Vec<String>,
}

#[derive(Serialize)]
pub struct MigrationReport {
    pub room: String,
    /// `None` when every migration applied to the copy of the file.
    pub failure: Option<String>,
}

#[derive(Serialize, Default)]
pub struct Report {
    pub rooms: Vec<RoomReport>,
    pub migrations: Vec<MigrationReport>,
}

/// Refuses the live data dir (or anything inside it) and anything that is not a Core home.
pub fn check_copy(home: &Path, out: &Path) -> Result<(), String> {
    let h = home.canonicalize().map_err(|e| format!("home: {e}"))?;
    let live = Path::new(LIVE).canonicalize().ok();
    if live
        .as_ref()
        .is_some_and(|l| h.starts_with(l) || l.starts_with(&h))
    {
        return Err("that is the live data dir; point at a read-only copy".into());
    }
    if !h.join("core.db").is_file() {
        return Err("no core.db there".into());
    }
    std::fs::create_dir_all(out).map_err(|e| format!("out: {e}"))?;
    if out
        .canonicalize()
        .map_err(|e| format!("out: {e}"))?
        .starts_with(&h)
    {
        return Err("the output dir must be outside the data copy".into());
    }
    Ok(())
}

/// The brain key, opened from a copy of a Core home (the same sealing as `overview_eval`).
pub async fn brain_key(home: &Home) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let core = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename(home.db())
                .read_only(true),
        )
        .await?;
    let sealer = SecretBox::for_serve(&home.master_key()).ok_or("no master key")?;
    let r =
        sqlx::query("SELECT version, key_id, sealed FROM core_secrets WHERE name = 'brain.key'")
            .fetch_one(&core)
            .await?;
    let (version, key_id): (i64, String) = (r.try_get("version")?, r.try_get("key_id")?);
    let hex = sealer
        .open_as(
            &key_id,
            &format!("core.secret:brain.key:v{version}"),
            &r.try_get::<Vec<u8>, _>("sealed")?,
        )
        .map_err(|_| "the brain key did not open")?;
    let hex = std::str::from_utf8(&hex)?;
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).ok_or("bad key")?, 16)?;
    }
    core.close().await;
    Ok(key)
}

/// Active room ids of the copy.
pub async fn room_ids(home: &Home) -> Result<Vec<String>, sqlx::Error> {
    let core = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename(home.db())
                .read_only(true),
        )
        .await?;
    let ids = sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
        .fetch_all(&core)
        .await?;
    core.close().await;
    Ok(ids)
}

/// Every accepted record and every source of a room, held in an in-memory FTS5 table.
/// `loaded` is the text a hit puts into context, only ever measured for length.
pub struct Corpus {
    mem: SqlitePool,
    tokens: std::collections::HashMap<String, usize>,
}

impl Corpus {
    pub async fn load(room: &SqlitePool) -> Result<Self, sqlx::Error> {
        let mem = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::query("CREATE VIRTUAL TABLE t USING fts5(id UNINDEXED, text, tokenize = 'unicode61 remove_diacritics 2')")
            .execute(&mem)
            .await?;
        let mut tokens = std::collections::HashMap::new();
        let mut rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, body FROM records WHERE status = 'accepted'")
                .fetch_all(room)
                .await?;
        let srcs: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT item_id, title, substr(text, 1, ?) FROM sources WHERE pointer = 0",
        )
        .bind(SOURCE_CHARS as i64)
        .fetch_all(room)
        .await?;
        rows.extend(srcs.into_iter().map(|(i, t, x)| (i, format!("{t} {x}"))));
        let mut tx = mem.begin().await?;
        for (id, text) in rows {
            tokens.insert(id.clone(), text.chars().count().div_ceil(CHARS_PER_TOKEN));
            sqlx::query("INSERT INTO t (id, text) VALUES (?, ?)")
                .bind(id)
                .bind(text)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(Self { mem, tokens })
    }

    /// Top `k` ids for `q`: every word ANDed and quoted, like the room search. ponytail: this is
    /// today's FTS; B2-03 adds the e5 half, and this is the one function to swap then.
    pub async fn search(&self, q: &str, k: usize) -> Result<Vec<String>, sqlx::Error> {
        let words: Vec<String> = q
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .take(16)
            .map(|w| format!("\"{w}\""))
            .collect();
        if words.is_empty() {
            return Ok(vec![]);
        }
        sqlx::query_scalar("SELECT id FROM t WHERE t MATCH ? ORDER BY bm25(t), id LIMIT ?")
            .bind(words.join(" "))
            .bind(k as i64)
            .fetch_all(&self.mem)
            .await
    }
}

/// Runs a question set against a room. The numbers are the only output.
pub async fn run_questions(set: &QuestionSet, corpus: &Corpus) -> Result<RoomReport, sqlx::Error> {
    let mut r = RoomReport {
        room: set.room.clone(),
        ..Default::default()
    };
    let (mut hits, mut recall, mut prec) = (0usize, 0.0, 0.0);
    let (mut loaded, mut useful) = (0usize, 0usize);
    let mut ms = vec![];
    for (n, q) in set.questions.iter().enumerate() {
        if q.mode.as_deref().unwrap_or("search") != "search" {
            r.skipped += 1;
            continue;
        }
        for a in &q.answers {
            if !corpus.tokens.contains_key(a) && !r.unknown_labels.contains(a) {
                r.unknown_labels.push(a.clone());
            }
        }
        r.questions += 1;
        let t = Instant::now();
        let got = corpus.search(&q.q, K).await?;
        ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let good: Vec<&String> = got.iter().filter(|g| q.answers.contains(g)).collect();
        if !good.is_empty() {
            hits += 1;
        } else {
            r.missed.push(n + 1);
        }
        recall += good.len() as f64 / q.answers.len().max(1) as f64;
        prec += good.len() as f64 / got.len().max(1) as f64;
        loaded += got.iter().map(|g| corpus.tokens[g]).sum::<usize>();
        useful += good.iter().map(|g| corpus.tokens[*g]).sum::<usize>();
    }
    let n = r.questions.max(1) as f64;
    r.hit_at_k = hits as f64 / n;
    r.recall_at_k = recall / n;
    r.precision = prec / n;
    r.noise = if loaded == 0 {
        0.0
    } else {
        1.0 - useful as f64 / loaded as f64
    };
    r.latency_ms_mean = ms.iter().sum::<f64>() / n;
    ms.sort_by(f64::total_cmp);
    r.latency_ms_p95 = ms
        .get((ms.len() * 95 / 100).min(ms.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0);
    Ok(r)
}

/// Applies every migration this binary knows (so B2-01's too, once it is in) to a scratch copy of
/// each room's `canon.db` and `index.db`. The copy under test is never opened for writing.
pub async fn dry_run_migrations(
    root: &Path,
    key: &[u8; 32],
    rooms: &[String],
    scratch: &Path,
) -> Vec<MigrationReport> {
    let mut out = vec![];
    for room in rooms {
        let mut failure = None;
        for (src, list) in [
            (files::room_path(root, room), files::CANON),
            (files::index_path(root, room), files::INDEX),
        ] {
            if !src.is_file() {
                continue;
            }
            let dst = scratch.join(format!(
                "{room}-{}",
                src.file_name()
                    .map_or_else(Default::default, |f| f.to_string_lossy().into_owned())
            ));
            let res = async {
                std::fs::copy(&src, &dst).map_err(|e| format!("copy: {e}"))?;
                let pool = files::open_migrated(&dst, key, false, list)
                    .await
                    .map_err(|e| e.to_string())?;
                pool.close().await;
                Ok::<(), String>(())
            }
            .await;
            let _ = std::fs::remove_file(&dst);
            if let Err(e) = res {
                // Schema and constraint names only; a message never carries row values.
                failure = Some(format!(
                    "{}: {}",
                    src.file_name()
                        .map_or_else(Default::default, |f| f.to_string_lossy().into_owned()),
                    e.chars().take(160).collect::<String>()
                ));
                break;
            }
        }
        out.push(MigrationReport {
            room: room.clone(),
            failure,
        });
    }
    out
}

/// The whole run: every question file in `questions_dir` (`*.json`), then the migration dry run.
pub async fn run(
    home: &Path,
    questions_dir: &Path,
    out: &Path,
) -> Result<Report, Box<dyn std::error::Error>> {
    check_copy(home, out)?;
    let h = Home(home.to_path_buf());
    let key = brain_key(&h).await?;
    let root = h.0.join("brain");
    let mut report = Report::default();
    let mut sets: Vec<PathBuf> = std::fs::read_dir(questions_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    sets.sort();
    for p in sets {
        let set: QuestionSet = serde_json::from_slice(&std::fs::read(&p)?)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        if !files::safe_id(&set.room) {
            return Err(format!("{}: bad room id", p.display()).into());
        }
        let pool = cipher::open_read_only(&files::room_path(&root, &set.room), &key).await?;
        let corpus = Corpus::load(&pool).await?;
        pool.close().await;
        report.rooms.push(run_questions(&set, &corpus).await?);
    }
    let scratch = out.join(".scratch");
    std::fs::create_dir_all(&scratch)?;
    report.migrations = dry_run_migrations(&root, &key, &room_ids(&h).await?, &scratch).await;
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(report)
}

impl Report {
    /// The aggregate table: numbers and room ids only.
    pub fn table(&self) -> String {
        let mut s = String::from(
            "room                                  q  skip  hit@5  recall  prec  noise  p95ms\n",
        );
        for r in &self.rooms {
            s += &format!(
                "{:<36} {:>3} {:>5} {:>6.2} {:>7.2} {:>5.2} {:>6.2} {:>6.1}\n",
                r.room,
                r.questions,
                r.skipped,
                r.hit_at_k,
                r.recall_at_k,
                r.precision,
                r.noise,
                r.latency_ms_p95
            );
        }
        let bad: Vec<&MigrationReport> = self
            .migrations
            .iter()
            .filter(|m| m.failure.is_some())
            .collect();
        s += &format!(
            "migrations: {} rooms, {} failed\n",
            self.migrations.len(),
            bad.len()
        );
        for m in bad {
            s += &format!("  {} {}\n", m.room, m.failure.as_deref().unwrap_or(""));
        }
        s
    }
}
