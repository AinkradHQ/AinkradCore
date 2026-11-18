//! The me card (B7-02): a few standing preferences and rules about the person, loaded into every
//! session whatever its project. Built per request in code, from MEMORY ONLY (the `memory` view), and
//! never stored outside the room files. No model writes it.
//!
//! SECURITY MODEL (read before changing anything here)
//! 1. Sources: only rooms of kind `personal` and `global-safe` (`ME_KINDS`). A product, employer,
//!    client or general room is never read, whatever its name or its policy. The room list comes from
//!    `brain_rooms.kind`, not from a name or from the session.
//! 2. Gate: a room contributes only when the session's WHOLE fallback chain passes THAT room's
//!    provider policy (`check_chain`, the rule of every other op). A codex session therefore gets the
//!    card only if the personal room allows OpenAI. A room that fails, is closed or cannot be read adds
//!    nothing, silently: no error names a room, a record or a reason. No chain means nothing.
//! 3. Content: stable `preference`/`rule` records only (no `project-state`, `task`, `summary`; no
//!    `valid_to`, archived or contested record), seen by at least two sources or set by the person.
//!    That is what keeps a project fact out of a card that every session gets.
//! 4. Budget: `BUDGET_TOKENS` (chars / 4). The text is third-party-derived; the caller that sends it
//!    (`brainAiContext`, B7-03) wraps it in the outside-data envelope. Every line keeps its id.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::store::{agents, alloc};
use sqlx::{Row, SqlitePool};

use crate::Brain;
use crate::card::{CHARS_PER_TOKEN, CONTESTED, Card, LINE_CHARS, one_line};
use crate::claim::check_chain;
use crate::policy;

pub const BUDGET_TOKENS: usize = 300;
/// The only room kinds the card reads.
const ME_KINDS: &str = "('personal','global-safe')";
const HEADING: &str = "About the person:\n";
/// Per room; the budget decides how many reach the card.
const PER_ROOM: i64 = 20;

#[derive(Debug, Clone)]
pub(crate) struct Cand {
    pub id: String,
    pub body: String,
    pub support: i64,
    pub seen: String,
}

/// The ids of the rooms the card may read: `personal` and `global-safe`, active. Nothing else.
pub(crate) async fn me_rooms(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT id FROM brain_rooms WHERE kind IN {ME_KINDS} AND state = 'active' ORDER BY id"
    )))
    .fetch_all(pool)
    .await
}

/// One room file's stable preferences and rules, best first.
pub(crate) async fn candidates(pool: &SqlitePool) -> Result<Vec<Cand>, sqlx::Error> {
    let sql = format!(
        "SELECT id, body, support, coalesce(last_seen_at, created_at) AS seen FROM memory \
         WHERE type IN ('preference','rule') \
           AND (support >= 2 OR origin = 'person' OR edited_by_person = 1) \
           AND contests IS NULL
           AND NOT EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END) WHERE value IN {CONTESTED}) \
         ORDER BY support DESC, seen DESC, id LIMIT ?"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(PER_ROOM)
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Cand {
                id: r.try_get("id")?,
                body: r.try_get("body")?,
                support: r.try_get("support")?,
                seen: r.try_get("seen")?,
            })
        })
        .collect()
}

/// The card from candidates of every passing room: best supported first, then newest, one line
/// each, cut at the budget. `None` when nothing qualifies.
pub(crate) fn assemble(mut all: Vec<Cand>) -> Option<Card> {
    all.sort_by(|a, b| {
        (b.support, &b.seen, &a.id).cmp(&(a.support, &a.seen, &b.id))
    });
    let cap = BUDGET_TOKENS * CHARS_PER_TOKEN;
    let (mut text, mut ids, mut complete) = (HEADING.to_owned(), vec![], true);
    let mut seen_text = std::collections::HashSet::new();
    for c in all {
        let body = one_line(&c.body, LINE_CHARS);
        if !seen_text.insert(body.to_lowercase()) {
            continue;
        }
        let line = format!("- [{}] {body}\n", c.id);
        if text.chars().count() + line.chars().count() > cap {
            complete = false;
            break;
        }
        text.push_str(&line);
        ids.push(c.id);
    }
    (!ids.is_empty()).then_some(Card {
        text,
        ids,
        complete,
    })
}

/// The me card for `session`, or `None`. Never an error that says why.
pub async fn build(app: &App, b: &Brain, session: &str) -> Option<Card> {
    build_located(app, b, session).await.map(|c| c.0)
}

/// The card and the `(room, record)` of every record on it, for `brain_session_loaded` (B7-03).
pub(crate) async fn build_located(
    app: &App,
    b: &Brain,
    session: &str,
) -> Option<(Card, Vec<(String, String)>)> {
    let s = agents::get(&app.pool, session).await.ok()??;
    if !s.live() {
        return None;
    }
    let chain = alloc::view(&app.pool, session).await.ok()??.chain?;
    let key = b.key(app).await.ok()?;
    let mut all = vec![];
    let mut at = vec![];
    for room in me_rooms(&app.pool).await.ok()? {
        let Ok(p) = policy::load(app, &room).await else {
            continue;
        };
        if check_chain(&chain, &p).is_err() {
            continue;
        }
        let Ok(a) = b.rooms().access(app, &key, &room).await else {
            continue;
        };
        if let Ok(c) = candidates(a.pool()).await {
            at.extend(c.iter().map(|c| (room.clone(), c.id.clone())));
            all.extend(c);
        }
    }
    let card = assemble(all)?;
    at.retain(|(_, id)| card.ids.contains(id));
    Some((card, at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{self, CANON};
    use crate::policy::Policy;
    use ainkrad_core_server::store::alloc::Entry;

    const KEY: [u8; 32] = [7; 32];

    fn entry(provider: &str) -> Entry {
        Entry {
            pool: 1,
            provider: provider.to_owned(),
            harness: "x".to_owned(),
            model: None,
        }
    }

    fn policy(allowed: &[&str]) -> Policy {
        Policy {
            name: "Me".to_owned(),
            allowed: allowed.iter().map(|s| (*s).to_owned()).collect(),
            auto_accept: vec![],
            min_sources: 1,
            lease_hours: 24,
            review_days: 90,
            retention_days: None,
        }
    }

    #[test]
    fn the_policy_gate_passes_only_a_chain_the_personal_room_allows() {
        let cloud = policy(&["approved_cloud"]);
        assert!(check_chain(&[entry("anthropic")], &cloud).is_ok());
        // A codex session: OpenAI is outside approved_cloud.
        assert!(check_chain(&[entry("openai")], &cloud).is_err());
        // One fallback outside the policy fails the whole chain.
        assert!(check_chain(&[entry("anthropic"), entry("openai")], &cloud).is_err());
        // The room widens its policy: now it passes.
        assert!(check_chain(&[entry("openai")], &policy(&["approved_cloud", "openai"])).is_ok());
        // Local-only room: no cloud chain passes.
        assert!(check_chain(&[entry("anthropic")], &policy(&["local"])).is_err());
        // No chain: nothing (the runner's own login is invisible to policy).
        assert!(check_chain(&[], &cloud).is_err());
    }

    async fn control() -> SqlitePool {
        let p = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE brain_rooms (id TEXT PRIMARY KEY, name TEXT, kind TEXT, state TEXT NOT NULL DEFAULT 'active')")
            .execute(&p)
            .await
            .unwrap();
        for (id, kind, state) in [
            ("me", "personal", "active"),
            ("safe", "global-safe", "active"),
            ("old", "personal", "archived"),
            ("alpha", "product", "active"),
            ("acme", "employer", "active"),
            ("cli", "client", "active"),
            ("gen", "general", "active"),
        ] {
            sqlx::query("INSERT INTO brain_rooms (id, name, kind, state) VALUES (?, ?, ?, ?)")
                .bind(id)
                .bind(id)
                .bind(kind)
                .bind(state)
                .execute(&p)
                .await
                .unwrap();
        }
        p
    }

    #[tokio::test]
    async fn no_project_room_is_ever_read() {
        let p = control().await;
        assert_eq!(me_rooms(&p).await.unwrap(), ["me", "safe"]);
    }

    async fn room() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
            .await
            .unwrap();
        (dir, p)
    }

    async fn put(p: &SqlitePool, id: &str, kind: &str, body: &str, tags: &str, support: i64, origin: &str) {
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, created_at, support, last_seen_at, origin) \
             VALUES (?, ?, 'accepted', ?, ?, '2026-11-01T00:00:00Z', ?, '2026-11-01T00:00:00Z', ?)",
        )
        .bind(id)
        .bind(kind)
        .bind(body)
        .bind(tags)
        .bind(support)
        .bind(origin)
        .execute(p)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn only_stable_uncontested_preferences_and_rules_qualify() {
        let (_d, p) = room().await;
        put(&p, "ok1", "preference", "Answer briefly.", "[]", 3, "distil").await;
        put(&p, "ok2", "rule", "Never commit secrets.", "[]", 1, "person").await;
        put(&p, "weak", "rule", "One-off, unconfirmed.", "[]", 1, "distil").await;
        put(&p, "fight", "rule", "Squash merges.", r#"["contested"]"#, 9, "person").await;
        put(&p, "fight2", "rule", "Rebase merges.", r#"["conflict"]"#, 9, "person").await;
        put(&p, "task", "task", "Ship the export.", "[]", 9, "person").await;
        put(&p, "state", "project-state", "Beta is live.", "[]", 9, "person").await;
        put(&p, "sum", "summary", "A summary.", "[]", 9, "person").await;
        put(&p, "fact", "fact", "A fact.", "[]", 9, "person").await;
        put(&p, "gone", "rule", "Replaced rule.", "[]", 9, "person").await;
        sqlx::query("UPDATE records SET valid_to = '2026-11-10T00:00:00Z' WHERE id = 'gone'")
            .execute(&p)
            .await
            .unwrap();
        put(&p, "arch", "rule", "Archived rule.", "[]", 9, "person").await;
        sqlx::query("UPDATE records SET archived_at = '2026-11-10T00:00:00Z' WHERE id = 'arch'")
            .execute(&p)
            .await
            .unwrap();
        let ids: Vec<String> = candidates(&p).await.unwrap().into_iter().map(|c| c.id).collect();
        assert_eq!(ids, ["ok1", "ok2"]);
        let card = assemble(candidates(&p).await.unwrap()).unwrap();
        assert_eq!(card.ids, ["ok1", "ok2"], "{}", card.text);
        assert!(card.text.starts_with(HEADING) && card.complete);
    }

    #[test]
    fn the_card_stays_inside_its_budget_best_first_and_says_when_it_cut() {
        let all: Vec<Cand> = (0..40)
            .map(|n| Cand {
                id: format!("r{n:02}"),
                body: format!("{n} {}", "w ".repeat(120)),
                support: 40 - n,
                seen: "2026-11-01T00:00:00Z".to_owned(),
            })
            .collect();
        let c = assemble(all).unwrap();
        assert!(!c.complete);
        assert!(c.text.chars().count() <= BUDGET_TOKENS * CHARS_PER_TOKEN, "{}", c.text.len());
        assert_eq!(c.ids[0], "r00", "best supported first");
        assert!(assemble(vec![]).is_none(), "nothing qualifies: no card");
    }
}
