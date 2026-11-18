//! The room card (B7-01): a few lines that say what a room is and what is standing in it, built in
//! code from MEMORY ONLY (the `memory` view) and the Projects store. No model writes it and no
//! source text is read. It is stable: with no new memory, two calls give the same text (it holds
//! no clock reading). Contested records (tagged `conflict`/`contested` by tidy) are left out, so
//! the card never states one side of an open disagreement. `project-state` and `task` records not
//! seen for `review_days` are left out as stale.
//!
//! The text is third-party-derived (record bodies). It is NOT wrapped here: the caller that sends
//! it to a session (`brainAiContext`, B7-03) puts it inside the outside-data envelope. Every
//! record line keeps its id.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use serde::Serialize;
use sqlx::{Row, SqlitePool};

use crate::ai::cut;

/// The card's budget; tokens are chars / 4 (as in `eval`).
pub const BUDGET_TOKENS: usize = 400;
pub(crate) const CHARS_PER_TOKEN: usize = 4;
pub(crate) const LINE_CHARS: usize = 200;
const DESC_CHARS: usize = 160;
const MAX_REPOS: usize = 6;

/// Tags that mark a record as disputed.
pub(crate) const CONTESTED: &str = "('conflict','contested')";

/// What the card says about the room itself.
pub struct Head {
    pub name: String,
    pub kind: String,
    pub review_days: i64,
    pub project: Option<ProjectHead>,
}

pub struct ProjectHead {
    pub name: String,
    pub description: String,
    pub repos: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Card {
    pub text: String,
    /// The records on the card, in order.
    pub ids: Vec<String>,
    /// False when the budget cut a record that would have made it.
    pub complete: bool,
}

/// (heading, record types, how many, rank by support first, drop when stale)
const SECTIONS: [(&str, &str, i64, bool, bool); 4] = [
    (
        "Rules and preferences:",
        r#"["rule","preference"]"#,
        5,
        true,
        false,
    ),
    ("Latest decisions:", r#"["decision"]"#, 3, false, false),
    ("Open tasks:", r#"["task"]"#, 3, false, true),
    ("Project state:", r#"["project-state"]"#, 2, false, true),
];

/// The room's name, kind and linked project, from the control plane.
pub async fn head(app: &App, room: &str) -> Result<Head, ApiError> {
    let r = sqlx::query(
        "SELECT r.name, r.kind, r.review_days, p.project FROM brain_rooms r \
         LEFT JOIN brain_project_rooms p ON p.room = r.id WHERE r.id = ?",
    )
    .bind(room)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such room"))?;
    let mut project = None;
    if let Some(id) = r.try_get::<Option<String>, _>("project")? {
        let p = sqlx::query(
            "SELECT id, name, description FROM core_projects WHERE CAST(id AS TEXT) = ?",
        )
        .bind(&id)
        .fetch_optional(&app.pool)
        .await?;
        if let Some(p) = p {
            let repos = sqlx::query_scalar::<_, String>(
                "SELECT name FROM core_project_repos WHERE project_id = ? ORDER BY is_primary DESC, name",
            )
            .bind(p.try_get::<i64, _>("id")?)
            .fetch_all(&app.pool)
            .await?;
            project = Some(ProjectHead {
                name: p.try_get("name")?,
                description: p.try_get("description")?,
                repos,
            });
        }
    }
    Ok(Head {
        name: r.try_get("name")?,
        kind: r.try_get("kind")?,
        review_days: r.try_get("review_days")?,
        project,
    })
}

/// The card of `room`, whose open file is `pool`. `now` only decides which tasks and states are stale.
pub async fn build(app: &App, pool: &SqlitePool, room: &str, now: &str) -> Result<Card, ApiError> {
    Ok(compose(pool, &head(app, room).await?, now).await?)
}

pub(crate) fn one_line(s: &str, n: usize) -> String {
    cut(&s.split_whitespace().collect::<Vec<_>>().join(" "), n).0
}

fn header(h: &Head) -> String {
    let mut t = format!("Room: {} ({})\n", one_line(&h.name, 100), h.kind);
    if let Some(p) = &h.project {
        t.push_str(&format!("Project: {}", one_line(&p.name, 100)));
        if !p.description.trim().is_empty() {
            t.push_str(&format!(": {}", one_line(&p.description, DESC_CHARS)));
        }
        t.push('\n');
        if !p.repos.is_empty() {
            let r: Vec<String> = p
                .repos
                .iter()
                .take(MAX_REPOS)
                .map(|r| one_line(r, 100))
                .collect();
            t.push_str(&format!("Repos: {}\n", r.join(", ")));
        }
    }
    t
}

/// The card from a room file and its head (no `App`), so it can be tested on its own.
pub(crate) async fn compose(pool: &SqlitePool, h: &Head, now: &str) -> Result<Card, sqlx::Error> {
    let cap = BUDGET_TOKENS * CHARS_PER_TOKEN;
    let mut text = header(h);
    let mut ids = vec![];
    let mut complete = true;
    // ponytail: the header is bounded by its caps (< 1k chars), so it always fits the budget.
    let sql = format!(
        "SELECT id, body FROM memory \
         WHERE type IN (SELECT value FROM json_each(?1)) \
           AND (?2 = 0 OR datetime(coalesce(last_seen_at, created_at)) >= datetime(?3, '-' || ?2 || ' days')) \
           AND NOT EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END) WHERE value IN {CONTESTED}) \
         ORDER BY CASE WHEN ?4 THEN support ELSE 0 END DESC, coalesce(last_seen_at, created_at) DESC, id \
         LIMIT ?5"
    );
    'fill: for (title, types, n, by_support, stale) in SECTIONS {
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql.clone()))
            .bind(types)
            .bind(if stale { h.review_days } else { 0 })
            .bind(now)
            .bind(by_support)
            .bind(n)
            .fetch_all(pool)
            .await?;
        let mut first = true;
        for r in &rows {
            let id: String = r.try_get("id")?;
            let line = format!(
                "- [{id}] {}\n",
                one_line(&r.try_get::<String, _>("body")?, LINE_CHARS)
            );
            let title_len = if first { title.len() + 1 } else { 0 };
            if text.chars().count() + title_len + line.chars().count() > cap {
                complete = false;
                break 'fill;
            }
            if first {
                text.push_str(title);
                text.push('\n');
                first = false;
            }
            text.push_str(&line);
            ids.push(id);
        }
    }
    Ok(Card {
        text,
        ids,
        complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{self, CANON};

    const KEY: [u8; 32] = [7; 32];
    const NOW: &str = "2026-11-18T10:00:00Z";

    async fn room() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
            .await
            .unwrap();
        (dir, p)
    }

    async fn put(
        p: &SqlitePool,
        id: &str,
        kind: &str,
        body: &str,
        tags: &str,
        support: i64,
        seen: &str,
    ) {
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, created_at, support, last_seen_at) \
             VALUES (?, ?, 'accepted', ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(kind)
        .bind(body)
        .bind(tags)
        .bind(seen)
        .bind(support)
        .bind(seen)
        .execute(p)
        .await
        .unwrap();
    }

    fn head() -> Head {
        Head {
            name: "Alpha".to_owned(),
            kind: "product".to_owned(),
            review_days: 90,
            project: Some(ProjectHead {
                name: "Alpha App".to_owned(),
                description: "A made-up billing app.".to_owned(),
                repos: vec!["alpha-api".to_owned(), "alpha-web".to_owned()],
            }),
        }
    }

    #[tokio::test]
    async fn the_card_is_memory_only_ranked_stable_and_leaves_out_contested_and_stale() {
        let (_d, p) = room().await;
        put(
            &p,
            "r1",
            "rule",
            "Run the linter before you push.",
            "[]",
            3,
            "2026-11-01T00:00:00Z",
        )
        .await;
        put(
            &p,
            "r2",
            "preference",
            "Prefer small PRs.",
            "[]",
            1,
            "2026-11-17T00:00:00Z",
        )
        .await;
        put(
            &p,
            "r3",
            "rule",
            "Squash every merge.",
            r#"["conflict"]"#,
            9,
            "2026-11-17T00:00:00Z",
        )
        .await;
        put(
            &p,
            "r4",
            "rule",
            "Old rule, replaced.",
            "[]",
            9,
            "2026-11-17T00:00:00Z",
        )
        .await;
        sqlx::query("UPDATE records SET valid_to = '2026-11-18T00:00:00Z' WHERE id = 'r4'")
            .execute(&p)
            .await
            .unwrap();
        put(
            &p,
            "d1",
            "decision",
            "Use SQLite.",
            "[]",
            1,
            "2026-11-10T00:00:00Z",
        )
        .await;
        put(
            &p,
            "t1",
            "task",
            "Ship the export.",
            "[]",
            1,
            "2026-11-15T00:00:00Z",
        )
        .await;
        put(
            &p,
            "t2",
            "task",
            "Ancient task.",
            "[]",
            1,
            "2026-01-01T00:00:00Z",
        )
        .await;
        put(
            &p,
            "s1",
            "project-state",
            "Beta is live.",
            "[]",
            1,
            "2026-11-16T00:00:00Z",
        )
        .await;
        put(
            &p,
            "f1",
            "fact",
            "Not a card kind.",
            "[]",
            5,
            "2026-11-17T00:00:00Z",
        )
        .await;
        let a = compose(&p, &head(), NOW).await.unwrap();
        assert_eq!(a.ids, ["r1", "r2", "d1", "t1", "s1"], "{}", a.text);
        assert!(a.complete);
        assert!(a.text.starts_with("Room: Alpha (product)\nProject: Alpha App: A made-up billing app.\nRepos: alpha-api, alpha-web\n"), "{}", a.text);
        assert!(a.text.contains("- [r1] Run the linter before you push.\n"));
        assert_eq!(
            a,
            compose(&p, &head(), NOW).await.unwrap(),
            "stable with no new memory"
        );
    }

    #[tokio::test]
    async fn the_card_stays_inside_its_budget_and_says_when_it_cut() {
        let (_d, p) = room().await;
        for n in 0..5 {
            put(
                &p,
                &format!("r{n}"),
                "rule",
                &"w ".repeat(150),
                "[]",
                5 - n,
                "2026-11-17T00:00:00Z",
            )
            .await;
        }
        for n in 0..3 {
            put(
                &p,
                &format!("d{n}"),
                "decision",
                &"x ".repeat(150),
                "[]",
                1,
                "2026-11-17T00:00:00Z",
            )
            .await;
        }
        let c = compose(&p, &head(), NOW).await.unwrap();
        assert!(!c.complete);
        assert!(
            c.text.chars().count() <= BUDGET_TOKENS * CHARS_PER_TOKEN,
            "{}",
            c.text.len()
        );
        assert_eq!(c.ids[0], "r0", "best supported first");
    }
}
