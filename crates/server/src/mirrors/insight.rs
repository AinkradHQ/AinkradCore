//! What a mirror says about its repo, for the project's Code and changes pages (Core 0.10,
//! E11-3). Read-only, straight from the bare copy with git plumbing (`for-each-ref`, `rev-list`,
//! `ls-tree`, `log`): nothing is checked out and no hook or filter runs. Names that reach a git
//! argument are checked first.

use super::{Mirrors, branch_name_ok};

/// A commit as the pages show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub sha: String,
    pub author: String,
    pub message: String,
    /// Author date, ISO 8601.
    pub at: String,
}

/// One repo's Code card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeInfo {
    pub files: i64,
    /// The most recently updated branch (the default one when it is the only one).
    pub branch: String,
    /// Commits `branch` has that the default branch lacks, and the other way round.
    pub ahead: i64,
    pub behind: i64,
    pub last: Option<Commit>,
}

const SEP: char = '\u{1f}';
const END: char = '\u{1e}';
const FORMAT: &str = "--format=%H%x1f%an%x1f%aI%x1f%s%x1e";

/// Reads `git log` output made with [`FORMAT`].
pub fn parse_log(text: &str) -> Vec<Commit> {
    text.split(END)
        .filter_map(|rec| {
            let mut f = rec.trim_matches('\n').splitn(4, SEP);
            Some(Commit {
                sha: f.next().filter(|s| !s.is_empty())?.to_owned(),
                author: f.next()?.to_owned(),
                at: f.next()?.to_owned(),
                message: f.next()?.chars().take(200).collect(),
            })
        })
        .collect()
}

/// `(left, right)` of `git rev-list --left-right --count` output.
pub fn parse_counts(text: &str) -> (i64, i64) {
    let mut n = text.split_whitespace().map(|x| x.parse().unwrap_or(0));
    (n.next().unwrap_or(0), n.next().unwrap_or(0))
}

impl Mirrors {
    /// The Code card of a repo, `default` being its default branch. `Err` when there is no copy.
    pub async fn code(&self, repo: i64, key: &str, default: &str) -> Result<CodeInfo, String> {
        let dir = self
            .ready(repo, key)
            .map_err(|_| "the Core has not fetched this repo yet".to_owned())?;
        let heads = self
            .run(
                &[
                    "-C",
                    &dir,
                    "for-each-ref",
                    "--sort=-committerdate",
                    "--count=20",
                    "--format=%(refname:short)",
                    "refs/heads",
                ],
                None,
            )
            .await
            .unwrap_or_default();
        let branch = heads
            .lines()
            .find(|b| branch_name_ok(b))
            .unwrap_or(default)
            .to_owned();
        // The default branch is HEAD of the copy; another one is its own ref.
        let tip = if branch == default || !branch_name_ok(&branch) {
            "HEAD".to_owned()
        } else {
            format!("refs/heads/{branch}")
        };
        let counts = if tip == "HEAD" {
            (0, 0)
        } else {
            let range = format!("HEAD...{tip}");
            let out = self
                .run(
                    &["-C", &dir, "rev-list", "--left-right", "--count", &range],
                    None,
                )
                .await
                .unwrap_or_default();
            // left is only on HEAD (behind), right only on the branch (ahead)
            let (behind, ahead) = parse_counts(&out);
            (ahead, behind)
        };
        // ponytail: lists every path to count it; a very large repo costs a few MB of output,
        // cache the count per fetched head if that shows up.
        let files = self
            .run(&["-C", &dir, "ls-tree", "-r", "--name-only", &tip], None)
            .await
            .map(|t| t.lines().count() as i64)
            .unwrap_or(0);
        let last = self
            .run(&["-C", &dir, "log", "-n", "1", FORMAT, &tip], None)
            .await
            .ok()
            .and_then(|t| parse_log(&t).into_iter().next());
        Ok(CodeInfo {
            files,
            branch: if tip == "HEAD" {
                default.to_owned()
            } else {
                branch
            },
            ahead: counts.0,
            behind: counts.1,
            last,
        })
    }

    /// Commits on any branch in the last `days` days, newest first, at most `max`.
    pub async fn commits_since(
        &self,
        repo: i64,
        key: &str,
        days: u32,
        max: u32,
    ) -> Result<Vec<Commit>, String> {
        let dir = self
            .ready(repo, key)
            .map_err(|_| "the Core has not fetched this repo yet".to_owned())?;
        let since = format!("--since={days}.days.ago");
        let n = format!("--max-count={max}");
        let out = self
            .run(&["-C", &dir, "log", "--branches", &since, &n, FORMAT], None)
            .await?;
        Ok(parse_log(&out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_and_counts_are_read() {
        let t = "abc\u{1f}Mia\u{1f}2026-11-19T10:00:00+00:00\u{1f}Fix: login\u{1e}\ndef\u{1f}Sam\u{1f}2026-11-18T09:00:00+00:00\u{1f}a\u{1f}b\u{1e}\n";
        let c = parse_log(t);
        assert_eq!(c.len(), 2);
        assert_eq!(
            (
                c[0].sha.as_str(),
                c[0].author.as_str(),
                c[0].message.as_str()
            ),
            ("abc", "Mia", "Fix: login")
        );
        // a subject never holds the separator, but extra ones are kept in the message
        assert_eq!(c[1].message, "a\u{1f}b");
        assert!(parse_log("").is_empty());
        assert_eq!(parse_counts("3\t5\n"), (3, 5));
        assert_eq!(parse_counts(""), (0, 0));
    }
}
