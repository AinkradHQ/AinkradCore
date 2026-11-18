//! One cgroup per design job, under the runner unit's own delegated subtree (`Delegate=yes` and
//! `ProtectControlGroups=private` in `deploy/systemd/ainkrad-runner.service`): `memory.max` and
//! `pids.max` are kernel limits on the whole sandboxed tree, and `cgroup.kill` ends whatever is
//! left of it. No user manager is needed (the unit has `ProtectHome` and none runs for its user).
//!
//! cgroup v2 lets a cgroup hand controllers to children only while it holds no process itself, so
//! the runner lives in `<unit>/runner` (`DelegateSubgroup=runner`; a runner found in the unit's own
//! cgroup moves its processes there first). Where the subtree is not writable
//! (a runner outside that unit, an older systemd), there is no job cgroup: the limits are then the
//! sandbox's `ulimit`s and the runner's RSS watch.

use std::path::{Path, PathBuf};

/// The runner's delegated cgroup, ready for job children.
pub struct Cgroups {
    base: PathBuf,
}

/// A job's cgroup: killed and removed when dropped.
pub(super) struct JobCgroup {
    dir: PathBuf,
}

/// This process's cgroup v2 directory (`0::<path>` in `/proc/self/cgroup`).
fn own() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Whether `subtree_control` (its text) enables both controllers.
pub(super) fn enabled(subtree_control: &str) -> bool {
    let on: Vec<&str> = subtree_control
        .split_whitespace()
        .map(|c| c.trim_start_matches('+'))
        .collect();
    on.contains(&"memory") && on.contains(&"pids")
}

impl Cgroups {
    /// The runner unit's subtree, when it is delegated and writable.
    pub fn delegated() -> Option<Self> {
        let own = own()?;
        // The unit starts the runner in `<unit>/runner` (`DelegateSubgroup=runner`).
        let base = match own.file_name() {
            Some(n) if n == "runner" => own.parent()?.to_path_buf(),
            _ => own,
        };
        Self::at(&base)
    }

    /// `base` made a parent of job cgroups: its processes moved to `base/runner`, then `memory`
    /// and `pids` enabled for its children. `None` when any step is refused.
    pub(super) fn at(base: &Path) -> Option<Self> {
        let control = base.join("cgroup.subtree_control");
        if !enabled(&std::fs::read_to_string(&control).ok()?) {
            let leaf = base.join("runner");
            if let Err(e) = std::fs::create_dir(&leaf)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return None;
            }
            let procs = std::fs::read_to_string(base.join("cgroup.procs")).ok()?;
            for pid in procs.split_whitespace() {
                std::fs::write(leaf.join("cgroup.procs"), pid).ok()?;
            }
            std::fs::write(&control, "+memory +pids").ok()?;
        }
        Some(Self {
            base: base.to_path_buf(),
        })
    }

    /// A fresh child with `memory.max` = `memory`, no swap, and `pids.max` = `pids`.
    pub(super) fn job(&self, memory: u64, pids: u32) -> std::io::Result<JobCgroup> {
        let name: String = crate::v2::key::random::<8>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = self.base.join(format!("design-{name}"));
        std::fs::create_dir(&dir)?;
        let job = JobCgroup { dir };
        std::fs::write(job.dir.join("memory.max"), memory.to_string())?;
        std::fs::write(job.dir.join("pids.max"), pids.to_string())?;
        // Absent where swap accounting is off; then there is no swap to cap.
        let _ = std::fs::write(job.dir.join("memory.swap.max"), "0");
        Ok(job)
    }
}

impl JobCgroup {
    /// Its `cgroup.procs`, open for [`ainkrad_sys::join_cgroup`].
    pub(super) fn procs(&self) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(self.dir.join("cgroup.procs"))
    }

    #[cfg(test)]
    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for JobCgroup {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("cgroup.kill"), "1");
        // The kernel removes a cgroup once its last process is gone; give the kill a moment.
        for _ in 0..50 {
            if std::fs::remove_dir(&self.dir).is_ok() || !self.dir.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
