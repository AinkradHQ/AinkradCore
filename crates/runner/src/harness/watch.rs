//! The progress watchdog (E15.7, pain #3): a run is making progress when its harness calls a
//! tool (or one ends), its working dir changes, its model says something new, or its tokens
//! grow. A model repeating itself ("working on it") is not progress, and neither are the tokens
//! that buy only that. With no progress for the run's stall limit (`run.stall_after_secs`), the
//! turn is interrupted and the run ends `Stalled`.
//!
//! Progress goes to the server as `Report::Progress`, at most every `REPORT_EVERY` unless the
//! worktree's diff changed, which is reported at once: an agent's `done` is refused while its
//! issue has no diff to show (the server's `done_evidence`).

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use ainkrad_harness::HarnessEvent;

/// The longest gap between two looks at the working dir.
const LOOK_EVERY: Duration = Duration::from_secs(30);
/// The shortest gap between two progress reports with an unchanged diff.
const REPORT_EVERY: Duration = Duration::from_secs(5);
/// Files hashed per look, at most: a huge tree is sampled, not walked to the end.
const MAX_FILES: usize = 100_000;

pub(super) struct Watch {
    stall_after: Duration,
    cwd: PathBuf,
    /// The last progress.
    last: Instant,
    /// Assistant texts seen, by hash.
    said: HashSet<u64>,
    /// The last event was the model repeating itself: the tokens it bought are no progress.
    chatter: bool,
    tokens: u64,
    /// The working dir's fingerprint at the last look.
    files: Option<u64>,
    looked: Instant,
    /// When progress was last reported, and the diff it carried.
    reported: Option<(Instant, Option<u32>)>,
}

impl Watch {
    pub fn new(stall_after: Duration, cwd: PathBuf) -> Self {
        let now = Instant::now();
        Self {
            stall_after,
            cwd,
            last: now,
            said: HashSet::new(),
            chatter: false,
            tokens: 0,
            files: None,
            looked: now,
            reported: None,
        }
    }

    /// Notes progress now (a tool call, an answered approval: waiting on a human is no stall).
    pub fn progress(&mut self) {
        self.last = Instant::now();
    }

    /// Whether `event` is progress, noting it; `spent` is the run's tokens so far.
    pub fn see(&mut self, event: &HarnessEvent, spent: u64) -> bool {
        let moved = match event {
            HarnessEvent::ToolUse { .. }
            | HarnessEvent::ToolResult { .. }
            | HarnessEvent::ApprovalRequested { .. } => {
                self.chatter = false;
                true
            }
            HarnessEvent::AssistantText { text } => {
                let mut h = DefaultHasher::new();
                text.trim().hash(&mut h);
                let new = self.said.insert(h.finish());
                self.chatter = !new;
                new
            }
            HarnessEvent::Usage(_) | HarnessEvent::UsageSoFar(_) => {
                let grew = spent > self.tokens && !self.chatter;
                self.tokens = self.tokens.max(spent);
                grew
            }
            _ => false,
        };
        if moved {
            self.progress();
        }
        moved
    }

    /// When to look at the working dir next, or call the run stalled.
    pub fn next_check(&self) -> tokio::time::Instant {
        let look = (self.stall_after / 4).clamp(Duration::from_millis(10), LOOK_EVERY);
        let at = (self.looked + look).min(self.last + self.stall_after);
        tokio::time::Instant::from_std(at)
    }

    /// Looks at the working dir: `true` (progress) when it changed since the last look.
    pub async fn files_changed(&mut self) -> bool {
        let cwd = self.cwd.clone();
        let now = tokio::task::spawn_blocking(move || fingerprint(&cwd))
            .await
            .unwrap_or_default();
        self.looked = Instant::now();
        let changed = self.files.is_some_and(|before| before != now);
        self.files = Some(now);
        if changed {
            self.chatter = false;
            self.progress();
        }
        changed
    }

    /// The diff last reported.
    pub fn diff(&self) -> Option<u32> {
        self.reported.and_then(|(_, diff)| diff)
    }

    pub fn stalled(&self) -> bool {
        self.last.elapsed() >= self.stall_after
    }

    /// Whether progress with `diff` is worth a report now: the first, a changed diff, or the
    /// last one `REPORT_EVERY` ago. Notes it as reported when so.
    pub fn report(&mut self, diff: Option<u32>) -> bool {
        let due = match self.reported {
            None => true,
            Some((at, before)) => before != diff || at.elapsed() >= REPORT_EVERY,
        };
        if due {
            self.reported = Some((Instant::now(), diff));
        }
        due
    }
}

/// A hash of every file's path, size and modification time under `dir` (`.git` aside).
fn fingerprint(dir: &Path) -> u64 {
    let mut h = DefaultHasher::new();
    let (mut stack, mut seen) = (vec![dir.to_owned()], 0);
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if e.file_name() == ".git" {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            if meta.is_dir() {
                stack.push(e.path());
                continue;
            }
            seen += 1;
            if seen > MAX_FILES {
                return h.finish();
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
            (e.path(), meta.len(), mtime).hash(&mut h);
        }
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainkrad_harness::Usage;

    fn text(t: &str) -> HarnessEvent {
        HarnessEvent::AssistantText { text: t.to_owned() }
    }

    #[test]
    fn repeating_itself_is_no_progress_nor_are_its_tokens() {
        let mut w = Watch::new(Duration::from_secs(60), PathBuf::from("/nonexistent"));
        let usage = HarnessEvent::UsageSoFar(Usage::default());
        assert!(w.see(&text("working on it"), 0));
        assert!(w.see(&usage, 10), "the first answer's tokens");
        assert!(!w.see(&text("working on it "), 10));
        assert!(!w.see(&usage, 20), "tokens spent repeating itself");
        assert!(!w.see(&usage, 20), "no growth");
        let tool = HarnessEvent::ToolUse {
            id: "1".to_owned(),
            name: "Edit".to_owned(),
            input: serde_json::json!({}),
        };
        assert!(w.see(&tool, 20));
        assert!(w.see(&usage, 30), "tokens after real work count again");
        assert!(w.see(&text("done: fixed the bound"), 30));
    }

    #[tokio::test]
    async fn a_changed_file_is_progress() {
        let dir = std::env::temp_dir().join(format!("citadel-watch-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let mut w = Watch::new(Duration::from_secs(60), dir.clone());
        assert!(!w.files_changed().await, "the first look is the baseline");
        std::fs::write(dir.join(".git/index"), "x").unwrap();
        assert!(!w.files_changed().await, "git's own files are not the work");
        std::fs::write(dir.join("a.rs"), "fn main() {}").unwrap();
        assert!(w.files_changed().await);
        assert!(!w.files_changed().await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn progress_is_reported_when_due_or_when_the_diff_moves() {
        let mut w = Watch::new(Duration::from_secs(60), PathBuf::new());
        assert!(w.report(None));
        assert!(!w.report(None));
        assert!(w.report(Some(2)), "a new diff goes at once");
        assert!(!w.report(Some(2)));
    }
}
