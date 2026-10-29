//! The issue's branch: one name across every repo it touches, chosen the first time it is
//! needed and stored on the issue, so later runs (and the PR) reuse it even if the project's
//! profile changes. The profile's `branch_pattern` names it when it fills to a plain branch
//! name holding the issue's key; otherwise it is `citadel/<KEY>-<n>`.
//!
//! Placeholders: `<type>` (`fix` for a bug or an issue labelled fix; `chore` or `docs` when
//! labelled so; else `feat`), `<key>` (the issue key, lowercased), `<KEY>` (as is), `<slug>`
//! (the title, lowercased, runs of anything but letters and digits as one `-`, at most 50
//! characters).

use citadel_core::work::{IssueId, IssueKind};
use ainkrad_proto::runner::branch_name_ok;
use sqlx::{Error, SqliteConnection, SqlitePool};

/// The most characters of a title a branch slug keeps.
const SLUG_MAX: usize = 50;

/// `pattern` filled for the issue, or `citadel/<KEY>` when it does not give a plain branch
/// name that holds the key.
pub fn branch_name(pattern: &str, key: &str, kind: &str, title: &str) -> String {
    let fallback = format!("citadel/{key}");
    let pattern = pattern.trim().trim_matches('`');
    if !pattern.contains("<key>") && !pattern.contains("<KEY>") {
        return fallback;
    }
    let filled = pattern
        .replace("<type>", kind)
        .replace("<key>", &key.to_lowercase())
        .replace("<KEY>", key)
        .replace("<slug>", &slug(title));
    if branch_name_ok(&filled) && !filled.ends_with(['/', '.', '-']) && !filled.contains("//") {
        filled
    } else {
        fallback
    }
}

fn slug(title: &str) -> String {
    let mut out = String::new();
    for c in title.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.truncate(SLUG_MAX);
    out.trim_end_matches('-').to_owned()
}

/// The issue's branch: stored, or named now and stored; `None` when there is no such issue.
pub async fn issue_branch(pool: &SqlitePool, issue: IssueId) -> Result<Option<String>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let branch = issue_branch_in(&mut tx, issue).await?;
    tx.commit().await?;
    Ok(branch)
}

/// `issue_branch` inside the caller's write transaction.
pub(crate) async fn issue_branch_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
) -> Result<Option<String>, Error> {
    let found: Option<(Option<String>, String, String, String, i64)> = sqlx::query_as(
        "SELECT i.branch, p.key || '-' || i.number, i.kind, i.title, i.project_id FROM issues i \
         JOIN projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((stored, key, kind, title, project)) = found else {
        return Ok(None);
    };
    if let Some(branch) = stored {
        return Ok(Some(branch));
    }
    let labelled: Option<String> = sqlx::query_scalar(
        "SELECT l.name FROM issue_labels il JOIN labels l ON l.id = il.label_id \
         WHERE il.issue_id = ? AND lower(l.name) IN ('fix', 'chore', 'docs', 'feat') \
         ORDER BY l.name LIMIT 1",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    let kind = match labelled {
        Some(label) => label.to_lowercase(),
        None if kind == IssueKind::Bug.as_str() => "fix".to_owned(),
        None => "feat".to_owned(),
    };
    let profile = super::profile_in(conn, citadel_core::work::ProjectId(project)).await?;
    let pattern = profile
        .map(|p| p.profile.branch_pattern)
        .unwrap_or_default();
    let branch = branch_name(&pattern, &key, &kind, &title);
    sqlx::query("UPDATE issues SET branch = ? WHERE id = ?")
        .bind(&branch)
        .bind(issue.0)
        .execute(&mut *conn)
        .await?;
    Ok(Some(branch))
}

#[cfg(test)]
mod tests {
    use super::branch_name;

    #[test]
    fn the_pattern_names_the_branch_or_the_default_does() {
        let p = "<type>/<key>-<slug>";
        assert_eq!(
            branch_name(p, "WKS-12", "feat", "Add the tenant invoice PDF!"),
            "feat/wks-12-add-the-tenant-invoice-pdf"
        );
        assert_eq!(branch_name("`fix/<KEY>`", "WKS-3", "fix", "x"), "fix/WKS-3");
        let long = "a".repeat(30) + " " + &"b".repeat(30);
        let b = branch_name(p, "A-1", "feat", &long);
        assert_eq!(b, format!("feat/a-1-{}-{}", "a".repeat(30), "b".repeat(19)));
        assert_eq!(
            branch_name(p, "A-1", "feat", "  émoji 🚀 -- "),
            "feat/a-1-moji"
        );
        // No key, an unknown placeholder, prose or an empty slug: the default.
        for bad in [
            "",
            "feature/<slug>",
            "<type>/<key>-<who>",
            "use <type>/<key> please",
        ] {
            assert_eq!(branch_name(bad, "A-1", "feat", "t"), "citadel/A-1", "{bad}");
        }
        assert_eq!(branch_name(p, "A-1", "feat", "!!!"), "citadel/A-1");
    }
}
