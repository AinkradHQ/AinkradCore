//! Staging and flagging of import items (R4-01): what `import.rs`'s routes put into a run and how each item is
//! compared with the notes Lore already holds. Security model is that of `import.rs` and `import_read.rs`.

use std::collections::HashMap;

use ainkrad_core_server::api::v1::ApiError;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::{Row, SqliteConnection};

use crate::import::sha_hex;
use crate::import_read::{ITEMS_MAX, RUN_BYTES_MAX, Scan, folder_tags, with_tags};

fn too_large(what: &'static str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", what)
}

/// Puts a scan's files into the run as items (an item with the same origin is replaced, so a resent batch is safe).
/// `strip` leading folders are not tags (`Docs/`).
pub(crate) async fn stage(
    conn: &mut SqliteConnection,
    run: &str,
    origin_prefix: &str,
    strip: usize,
    project: Option<&str>,
    scan: Scan,
) -> Result<(), ApiError> {
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM lore_import_items WHERE run = ?")
        .bind(run)
        .fetch_one(&mut *conn)
        .await?;
    let bytes: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(length(text)), 0) FROM lore_import_items WHERE run = ?",
    )
    .bind(run)
    .fetch_one(&mut *conn)
    .await?;
    let add: usize = scan.files.iter().map(|(_, t)| t.len()).sum();
    if held as usize + scan.files.len() + scan.too_large.len() > ITEMS_MAX
        || bytes as usize + add > RUN_BYTES_MAX
    {
        return Err(too_large("the import is over its size limit"));
    }
    for (path, text) in &scan.files {
        let tags = folder_tags(path, strip);
        let text = with_tags(text, &tags);
        let title = lore_model::parse(&text)
            .map(|p| p.title)
            .unwrap_or_else(|_| lore_model::UNTITLED.to_owned());
        insert(
            conn,
            run,
            path,
            &format!("{origin_prefix}{path}"),
            &title,
            &text,
            &sha_hex(&text),
            &tags,
            project,
            None,
        )
        .await?;
    }
    for path in &scan.too_large {
        let title = path.rsplit('/').next().unwrap_or(path);
        insert(
            conn,
            run,
            path,
            &format!("{origin_prefix}{path}"),
            title,
            "",
            "",
            &[],
            project,
            Some("too_large"),
        )
        .await?;
    }
    sqlx::query("UPDATE lore_imports SET refused = refused + ?, ignored = ignored + ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
        .bind(scan.refused)
        .bind(scan.ignored)
        .bind(run)
        .execute(conn)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert(
    conn: &mut SqliteConnection,
    run: &str,
    path: &str,
    origin: &str,
    title: &str,
    text: &str,
    hash: &str,
    tags: &[String],
    project: Option<&str>,
    flag: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO lore_import_items (run, seq, path, origin, title, text, hash, tags, project, flag, mark) \
         VALUES (?1, (SELECT coalesce(max(seq), 0) + 1 FROM lore_import_items WHERE run = ?1), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, \
                 IIF(?9 IS NULL, 'include', 'skip')) \
         ON CONFLICT (run, origin) DO UPDATE SET path = excluded.path, title = excluded.title, text = excluded.text, \
            hash = excluded.hash, tags = excluded.tags, project = excluded.project, flag = excluded.flag, \
            mark = excluded.mark, match_note = NULL",
    )
    .bind(run)
    .bind(path)
    .bind(origin)
    .bind(title)
    .bind(text)
    .bind(hash)
    .bind(json!(tags).to_string())
    .bind(project)
    .bind(flag)
    .execute(conn)
    .await
    .map_err(crate::notes::store_err)?;
    Ok(())
}

/// Flags the items (all, or `only`): an origin already imported (unchanged / changed / conflict), the same content or
/// title already in Lore, or repeated in the run. Sets each item's default mark; a person's later marks are not touched.
pub(crate) async fn classify(
    conn: &mut SqliteConnection,
    run: &str,
    only: Option<&[i64]>,
) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "SELECT seq, origin, title, hash, project, flag FROM lore_import_items WHERE run = ? ORDER BY seq",
    )
    .bind(run)
    .fetch_all(&mut *conn)
    .await?;
    let mut seen: HashMap<String, i64> = HashMap::new();
    for r in rows {
        let seq: i64 = r.try_get("seq")?;
        let (hash, project): (String, Option<String>) = (r.try_get("hash")?, r.try_get("project")?);
        let held: Option<String> = r.try_get("flag")?;
        if matches!(held.as_deref(), Some("too_large" | "skipped")) {
            continue;
        }
        let first = *seen.entry(hash.clone()).or_insert(seq);
        if only.is_some_and(|o| !o.contains(&seq)) {
            continue;
        }
        let origin: String = r.try_get("origin")?;
        let title: String = r.try_get("title")?;
        let matched = sqlx::query(
            "SELECT id, text, import_hash FROM lore_notes WHERE import_origin = ? AND trashed_at IS NULL \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(&origin)
        .fetch_optional(&mut *conn)
        .await?;
        let (flag, mark, note): (Option<&str>, &str, Option<String>) = if first != seq {
            (Some("duplicate"), "skip", None)
        } else if let Some(m) = matched {
            let (id, text): (String, String) = (m.try_get("id")?, m.try_get("text")?);
            let imported: Option<String> = m.try_get("import_hash")?;
            let now = sha_hex(&text);
            if hash == now || imported.as_deref() == Some(hash.as_str()) {
                (Some("duplicate"), "skip", Some(id))
            } else if imported.as_deref() == Some(now.as_str()) {
                (Some("changed"), "include", Some(id))
            } else {
                (Some("conflict"), "include", Some(id))
            }
        } else if sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM lore_notes WHERE import_hash = ? AND project IS ? AND trashed_at IS NULL",
        )
        .bind(&hash)
        .bind(&project)
        .fetch_one(&mut *conn)
        .await?
            > 0
        {
            (Some("duplicate"), "skip", None)
        } else if sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM lore_notes WHERE title_norm = ? AND project IS ? AND trashed_at IS NULL",
        )
        .bind(lore_model::normalize_title(&title))
        .bind(&project)
        .fetch_one(&mut *conn)
        .await?
            > 0
        {
            (Some("duplicate"), "include", None)
        } else {
            (None, "include", None)
        };
        sqlx::query("UPDATE lore_import_items SET flag = ?, mark = ?, match_note = ? WHERE run = ? AND seq = ?")
            .bind(flag)
            .bind(mark)
            .bind(note)
            .bind(run)
            .bind(seq)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
