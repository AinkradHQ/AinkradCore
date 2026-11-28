//! A project made from GitHub repos (P2-01): the project, its repos (the first is primary), its
//! kind and the source `github`, in one transaction, so a bad repo leaves nothing behind. The slug is derived
//! from the name; a taken or reserved one gets `-2`, `-3`, ... An explicit slug is used as given.

use sqlx::sqlite::SqlitePool;

use super::{Error, Project, Who, add_repo_in, create_in, kinds_of, line, refused, slug_problem};
use crate::store::connections::{Who as ConnWho, bindings};

pub struct NewGithubRepo {
    /// The folder name.
    pub name: String,
    pub remote_url: String,
    pub default_branch: String,
}

/// `Acme Shop!` -> `acme-shop`: a-z0-9 runs joined by `-`, starting with a letter, at most 36
/// characters (room for a `-NN` suffix).
pub(super) fn slugify(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        match c.is_ascii_alphanumeric() {
            true => out.push(c),
            false if !out.ends_with('-') => out.push('-'),
            false => {}
        }
    }
    let out = out.trim_matches('-');
    let out = match out.starts_with(|c: char| c.is_ascii_lowercase()) {
        true => out.to_owned(),
        false => format!("p-{out}"),
    };
    let cut: String = out.chars().take(36).collect();
    cut.trim_end_matches('-').to_owned()
}

pub async fn create_from_github(
    pool: &SqlitePool,
    slug: Option<&str>,
    name: &str,
    repos: &[NewGithubRepo],
    who: Who<'_>,
    bind: Option<(i64, ConnWho<'_>)>,
    (kinds, room): (Option<&[String]>, Option<&str>),
) -> Result<Project, Error> {
    line(name, 100, "a name")?;
    let kinds = kinds
        .map(|k| kinds_of(None, Some(k)))
        .transpose()?
        .flatten();
    if repos.is_empty() {
        return refused("bad_request", "name at least one repo");
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let slug = match slug {
        Some(s) => s.to_owned(),
        None => {
            let base = slugify(name);
            let mut n = 1;
            loop {
                let c = match n {
                    1 => base.clone(),
                    _ => format!("{base}-{n}"),
                };
                let taken: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM core_projects WHERE slug = ?")
                        .bind(&c)
                        .fetch_one(&mut *tx)
                        .await?;
                if taken == 0 && slug_problem(&c).is_none() {
                    break c;
                }
                n += 1;
                if n > 99 {
                    return refused("conflict", "no free slug for that name");
                }
            }
        }
    };
    if let Some(why) = slug_problem(&slug) {
        return refused("bad_request", why);
    }
    let mut p = create_in(&mut tx, &slug, name, "", ("github", room), who).await?;
    if let Some(ks) = kinds {
        sqlx::query("UPDATE core_projects SET kind = ?, kinds = ? WHERE id = ?")
            .bind(&ks[0])
            .bind(ks.join(","))
            .bind(p.id)
            .execute(&mut *tx)
            .await?;
        p.kind.clone_from(&ks[0]);
        p.kinds = ks;
    }
    for (i, r) in repos.iter().enumerate() {
        let r = (
            r.name.as_str(),
            r.remote_url.as_str(),
            r.default_branch.as_str(),
        );
        add_repo_in(&mut tx, p.id, r, i == 0, who).await?;
    }
    // Same transaction: if the binding is refused (limit, connection gone) no project is left.
    if let Some((conn, cw)) = bind {
        bindings::set_in(&mut tx, conn, ("project", &p.id.to_string()), cw).await?;
    }
    tx.commit().await?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::slugify;

    #[test]
    fn slugs_are_dns_labels() {
        assert_eq!(slugify("Acme Shop!"), "acme-shop");
        assert_eq!(slugify("9lives"), "p-9lives");
        assert_eq!(slugify("--x--y--"), "x-y");
        assert_eq!(slugify(&"a".repeat(60)).len(), 36);
    }
}
