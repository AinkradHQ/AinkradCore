//! The room Overview's local part on a real Core, for tuning: for every active room, the items
//! the selection reads, the documentation among them, and every candidate rule with its support,
//! the kinds of its items and whether it would be offered. Reads only; writes nothing. Run it on
//! a COPY of a Core home: `overview_eval <home>` (the directory that holds `core.db`, `keys/` and
//! `brain/`, as `serve --config` finds them). Line vectors come from the local model when the
//! `semantic` feature is on and `AINKRAD_BRAIN_MODEL_DIR` (or the installer's directory) has it.

use std::collections::HashMap;
use std::path::PathBuf;

use ainkrad_core_server::ops::config::Home;
use ainkrad_core_server::ops::secretbox::SecretBox;
use brain_module::overview_select::{RoomItem, offer, room_items, to_embed};
use brain_module::overview_write::Check;
use brain_module::semantic::pick::{Cand, candidate_lines, group, line_key};
use brain_module::{cipher, files};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

type Vectors = HashMap<String, Vec<f32>>;

fn kind(it: &RoomItem) -> &'static str {
    if it.doc {
        "guide"
    } else if it.note {
        "note"
    } else if matches!(
        it.kind.as_str(),
        "claude_code"
            | "codex"
            | "opencode"
            | "antigravity"
            | "cursor"
            | "kimi"
            | "core_transcript"
    ) {
        "session"
    } else {
        "note"
    }
}

#[cfg(feature = "semantic")]
fn embedder() -> Option<brain_module::semantic::local::Local> {
    let dir = std::env::var_os("AINKRAD_BRAIN_MODEL_DIR").map_or_else(
        || PathBuf::from(brain_module::semantic::local::DEFAULT_DIR),
        Into::into,
    );
    brain_module::semantic::local::Local::load(&dir)
        .map_err(|e| eprintln!("no line vectors: {e}"))
        .ok()
}

#[cfg(feature = "semantic")]
fn line_vectors(
    e: &Option<brain_module::semantic::local::Local>,
    todo: &[(String, String)],
) -> Vectors {
    use brain_module::semantic::Embedder;
    let Some(e) = e else { return Vectors::new() };
    let texts: Vec<String> = todo.iter().map(|t| t.1.clone()).collect();
    match e.embed(&texts) {
        Ok(v) => todo
            .iter()
            .map(|t| t.0.clone())
            .zip(v.into_iter().map(brain_model::semantic::normalized))
            .collect(),
        Err(err) => {
            eprintln!("no line vectors: {err}");
            Vectors::new()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = Home(PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: overview_eval <core home>")?,
    ));
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
    // ponytail: the sealing label as `store::secrets` writes it; read here without its audit row.
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
    let rooms: Vec<(String, String)> =
        sqlx::query_as("SELECT id, name FROM brain_rooms WHERE state = 'active' ORDER BY name")
            .fetch_all(&core)
            .await?;
    #[cfg(feature = "semantic")]
    let e = embedder();
    let root = home.0.join("brain");
    for (id, name) in &rooms {
        let pool = cipher::open_read_only(&files::room_path(&root, id), &key).await?;
        let rec = room_items(&pool).await?;
        pool.close().await;
        let cands: Vec<Cand> = rec
            .iter()
            .map(|r| Cand {
                title: &r.title,
                text: &r.text,
                person: r.person,
                doc: r.doc,
                note: r.note,
                vec: None,
            })
            .collect();
        let lines = candidate_lines(&cands);
        #[cfg(feature = "semantic")]
        let vecs = line_vectors(&e, &to_embed(&cands, &lines));
        #[cfg(not(feature = "semantic"))]
        let vecs = {
            let _ = to_embed;
            Vectors::new()
        };
        let groups = group(&cands, &lines, |t| vecs.get(&line_key(t)).cloned());
        let others: Vec<String> = rooms
            .iter()
            .filter(|r| &r.0 != id)
            .map(|r| r.1.clone())
            .collect();
        let check = Check::for_room(others, rec.len());
        let offered = offer(&groups, &check, |i| i.to_string());
        println!(
            "\n== {name}: {} items, {} guides, {} notes, {} rule lines, {} candidates, {} offered (min {} items)",
            rec.len(),
            rec.iter().filter(|r| r.doc).count(),
            rec.iter().filter(|r| r.note && !r.doc).count(),
            lines.len(),
            groups.len(),
            offered.rules.len(),
            check.min_sources
        );
        let mut refused = 0;
        for g in &groups {
            let verdict = check.verdict(&g.text, g.items.len(), g.doc);
            if verdict.is_err() || !offered.rules.iter().any(|r| r.text == g.text) {
                refused += 1;
                if refused > 15 {
                    continue;
                }
            }
            let mut kinds: HashMap<&str, usize> = HashMap::new();
            for &i in &g.items {
                *kinds.entry(kind(&rec[i])).or_default() += 1;
            }
            let mut kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{k}:{n}")).collect();
            kinds.sort();
            let shown = offered.rules.iter().any(|r| r.text == g.text);
            let mark = match verdict {
                Err(w) => format!("drop {w}"),
                Ok(()) if shown => "OFFER".to_owned(),
                Ok(()) => "not offered".to_owned(),
            };
            let text: String = g.text.chars().take(140).collect();
            println!(
                "  [{mark:>16}] {:>3} {:<22} {text}",
                g.items.len(),
                kinds.join(",")
            );
        }
        if refused > 15 {
            println!("  ... and {} more dropped", refused - 15);
        }
    }
    Ok(())
}
