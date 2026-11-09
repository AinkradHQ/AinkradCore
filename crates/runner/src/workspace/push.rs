//! Pushing an issue's branch to its repo's origin (E9.1), and why a push failed: the remote's
//! own reason for each ref it rejected (`git push --porcelain` prints those on stdout, as
//! `!` lines), its `remote:` lines and git's `error:` and `fatal:` lines (stderr), with any
//! credentials in a URL cut out and the whole capped. The caller's transcript redaction runs
//! over it too. A failed push also lists the workflow files (`.github/workflows`) the branch
//! changes, since a forge token may be refused for exactly those.

use super::*;

/// The most of a failure's reason kept, and of each rejected ref's, in chars.
const REASON_MAX: usize = 1000;
const REF_REASON_MAX: usize = 300;
/// The most rejected refs and workflow files listed.
const LIST_MAX: usize = 20;

/// Why a push failed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PushFailure {
    /// One line for people: the rejections and the remote's and git's words.
    pub reason: String,
    /// Each ref the remote rejected, with its reason (`(ref, reason)`).
    pub rejected: Vec<(String, String)>,
    /// The branch's head, when it has one.
    pub sha: Option<String>,
    /// The files under `.github/workflows` the branch changes against its base.
    pub workflow_files: Vec<String>,
}

impl From<String> for PushFailure {
    fn from(reason: String) -> Self {
        Self {
            reason: clean(&reason, REASON_MAX),
            ..Self::default()
        }
    }
}

impl Workspaces {
    /// Pushes the issue's branch to the repo's origin, with the askpass's credentials: its sha,
    /// `None` when it has nothing the base has not, or why it failed. The push leases on
    /// `expected_head` (`--force-with-lease`), so a rewritten branch lands only over the head
    /// the server last saw; with none it is a plain push, which never overwrites. A branch that
    /// is not `issue_key`'s own is refused before git runs.
    pub async fn push(
        &self,
        ws: &Workspace,
        issue_key: Option<&str>,
    ) -> Result<Option<String>, PushFailure> {
        if let Some(why) = ws
            .problem()
            .filter(|_| !(cfg!(test) && Path::new(&ws.repo).is_absolute()))
        {
            return Err(why.into());
        }
        match issue_key {
            Some(key) if is_issue_branch(&ws.branch, key) => {}
            _ => {
                return Err(format!(
                    "refusing to push {:?}: it is not this issue's branch",
                    ws.branch
                )
                .into());
            }
        }
        let mirror = self.mirror(&ws.repo);
        let _repo = self.lock(&mirror).await;
        let branch = format!("refs/heads/{}", ws.branch);
        let range = format!("refs/remotes/origin/{}..{branch}", ws.base);
        let ahead = self.git(&mirror, &["rev-list", "--count", &range]).await?;
        if ahead.trim() == "0" {
            return Ok(None);
        }
        let sha = self.git(&mirror, &["rev-parse", &branch]).await?;
        let sha = sha.trim().to_owned();
        let refspec = format!("{branch}:{branch}");
        let lease = ws
            .expected_head
            .as_deref()
            .map(|head| format!("--force-with-lease={branch}:{head}"));
        let mut args = vec!["push", "--porcelain"];
        args.extend(lease.as_deref());
        args.extend(["origin", &refspec]);
        let out = self.git_output(&mirror, &args, None).await;
        let out = out.map_err(|e| format!("git push: {e}"))?;
        if out.status.success() {
            return Ok(Some(sha));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let mut failure = failure(&stdout, &stderr, &out.status.to_string());
        if failure
            .rejected
            .iter()
            .any(|(_, why)| why.contains("stale info"))
        {
            let head = ws.expected_head.as_deref().unwrap_or_default();
            failure.reason = format!(
                "remote branch moved since its last push (expected {head}); not overwritten"
            );
        }
        failure.sha = Some(sha);
        let changed = format!("refs/remotes/origin/{}...{branch}", ws.base);
        let names = ["diff", "--name-only", &changed, "--", ".github/workflows"];
        if let Ok(files) = self.git(&mirror, &names).await {
            let files = files.lines().map(str::trim).filter(|f| !f.is_empty());
            failure.workflow_files = files.take(LIST_MAX).map(str::to_owned).collect();
        }
        Err(failure)
    }
}

/// Whether `branch` is the issue `key`'s own: the key (case-blind) as a whole path or name
/// segment, so `citadel/CIT-1` and `feat/cit-1-slug` are CIT-1's and `feat/cit-12` is not.
pub fn is_issue_branch(branch: &str, key: &str) -> bool {
    let branch = branch.to_ascii_lowercase();
    let key = key.to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }
    branch.match_indices(&key).any(|(at, _)| {
        let before = branch[..at].chars().next_back();
        let after = branch[at + key.len()..].chars().next();
        matches!(before, None | Some('/')) && matches!(after, None | Some('-'))
    })
}

/// Reads a failed `git push --porcelain`: its stdout, stderr and exit status.
fn failure(stdout: &str, stderr: &str, status: &str) -> PushFailure {
    // `!<TAB><from>:<to><TAB><summary> (<reason>)`
    let rejected: Vec<(String, String)> = stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.strip_prefix('!')?.trim_start().split('\t');
            let refs = fields.next()?;
            let to = refs.rsplit_once(':').map_or(refs, |(_, to)| to);
            let said = fields.collect::<Vec<_>>().join(" ");
            let why = match (said.find('('), said.rfind(')')) {
                (Some(a), Some(b)) if a < b => &said[a + 1..b],
                _ => said.as_str(),
            };
            Some((clean(to, 200), clean(why, REF_REASON_MAX)))
        })
        .take(LIST_MAX)
        .collect();
    let said: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter_map(|l| match l.strip_prefix("remote:") {
            Some(r) => Some(r.trim()),
            None => ["error:", "fatal:"]
                .iter()
                .any(|p| l.starts_with(p))
                .then_some(l),
        })
        .filter(|l| !l.is_empty())
        .collect();
    let mut parts: Vec<String> = rejected
        .iter()
        .map(|(r, why)| format!("{r} rejected: {why}"))
        .collect();
    parts.extend(said.iter().map(|l| (*l).to_owned()));
    if parts.is_empty() {
        parts.push(tail(stderr, 500).to_owned());
    }
    PushFailure {
        reason: clean(
            &format!("git push failed ({status}): {}", parts.join("; ")),
            REASON_MAX,
        ),
        rejected,
        ..PushFailure::default()
    }
}

/// `s` with any `user:password@` cut out of its URLs, on one line, at most `max` chars.
fn clean(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let host_end = tail
            .find(|c: char| c == '/' || c.is_whitespace() || c == '\'' || c == '"')
            .unwrap_or(tail.len());
        match tail[..host_end].rfind('@') {
            Some(i) => {
                out.push_str("[redacted]@");
                rest = &tail[i + 1..];
            }
            None => rest = tail,
        }
    }
    out.push_str(rest);
    let one: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    match one.char_indices().nth(max) {
        Some((at, _)) => format!("{}…", &one[..at]),
        None => one,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GitHub's refusal of a workflow change (WRK-3), as git prints it.
    #[test]
    fn reads_the_remote_reason_of_a_rejected_ref() {
        let stdout = "To https://x-access-token:ghp_secret@github.com/o/r.git\n\
            !\trefs/heads/feat/wrk-3:refs/heads/feat/wrk-3\t[remote rejected] (refusing to \
            allow a Personal Access Token to create or update workflow \
            `.github/workflows/images.yml` without `workflow` scope)\nDone\n";
        let stderr = "error: failed to push some refs to \
            'https://x-access-token:ghp_secret@github.com/o/r.git'\n";
        let f = failure(stdout, stderr, "exit status: 1");
        assert_eq!(f.rejected.len(), 1);
        assert_eq!(f.rejected[0].0, "refs/heads/feat/wrk-3");
        assert!(f.rejected[0].1.starts_with("refusing to allow"), "{f:?}");
        assert!(
            f.rejected[0].1.ends_with("without `workflow` scope"),
            "{f:?}"
        );
        assert!(f.reason.contains("workflow` scope"), "{}", f.reason);
        assert!(!f.reason.contains("ghp_secret"), "{}", f.reason);
        assert!(f.reason.contains("https://[redacted]@github.com/o/r.git"));
    }

    #[test]
    fn keeps_remote_lines_and_caps_the_reason() {
        let stderr = format!(
            "remote: error: GH006: Protected branch update failed\n{}\n",
            "x".repeat(5000)
        );
        let f = failure("", &stderr, "exit status: 1");
        assert!(f.rejected.is_empty());
        assert!(f.reason.contains("GH006: Protected branch"), "{}", f.reason);
        assert!(f.reason.chars().count() <= REASON_MAX + 1);
    }
}
