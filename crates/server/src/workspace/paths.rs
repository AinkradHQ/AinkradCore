//! The canonical workspace's layout (E15 §4.1): one directory on the Core host, shared by the
//! `ainkrad` and `ainkrad-runner` users through group `ainkrad-ws` (mode 2770, both units
//! `UMask=0007`, set up by the installer). Pure: nothing here touches the disk.
//!
//! ```text
//! <ws>/p/<project_id>/main/<repo>/      project working copy (worktree of the Core mirror)
//! <ws>/p/<project_id>/s/<session_id>/   project session folder
//! <ws>/u/<user_id>/s/<session_id>/      session with no project
//! <ws>/u/<user_id>/home/                persistent Core-terminal home (D-17)
//! <ws>/p/<project_id>/.ainkrad/{jobs.toml, conflicts/<job_id>/...}
//! <ws>/.trash/<date>/...
//! ```
//!
//! Every name that becomes a path component (a repo, a session or job id, a date) must be one
//! plain wire-path component (`wire_path_problem`, no `/`): anything else is `None`.

use std::path::{Path, PathBuf};

use ainkrad_core::ids::UserId;
use ainkrad_proto::v2::wire_path_problem;

/// `workspace.root` when unset.
pub const DEFAULT_ROOT: &str = "/var/lib/ainkrad-ws";
/// The group both service users share the workspace through.
pub const WS_GROUP: &str = "ainkrad-ws";

/// What places a session's folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKey<'a> {
    /// `as_…`.
    pub id: &'a str,
    pub user: UserId,
    pub project: Option<i64>,
}

/// The workspace at `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    root: PathBuf,
}

/// `name` as one path component, or `None`.
fn one(name: &str) -> Option<&str> {
    (wire_path_problem(name).is_none() && !name.contains('/')).then_some(name)
}

impl Workspace {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn project(&self, project: i64) -> PathBuf {
        self.root.join("p").join(project.to_string())
    }

    fn user(&self, user: UserId) -> PathBuf {
        self.root.join("u").join(user.0.to_string())
    }

    /// `<ws>/p/<project_id>/main/<repo>/`.
    pub fn project_repo(&self, project: i64, repo: &str) -> Option<PathBuf> {
        Some(self.project(project).join("main").join(one(repo)?))
    }

    /// A session's folder: under its project, else under its user.
    pub fn session_dir(&self, s: &SessionKey) -> Option<PathBuf> {
        let base = match s.project {
            Some(p) => self.project(p),
            None => self.user(s.user),
        };
        Some(base.join("s").join(one(s.id)?))
    }

    /// `<ws>/u/<user_id>/home/`.
    pub fn user_home(&self, user: UserId) -> PathBuf {
        self.user(user).join("home")
    }

    /// `<ws>/p/<project_id>/.ainkrad/`.
    pub fn project_meta(&self, project: i64) -> PathBuf {
        self.project(project).join(".ainkrad")
    }

    /// `<ws>/p/<project_id>/.ainkrad/jobs.toml`.
    pub fn jobs_toml(&self, project: i64) -> PathBuf {
        self.project_meta(project).join("jobs.toml")
    }

    /// `<ws>/p/<project_id>/.ainkrad/conflicts/<job_id>/`.
    pub fn conflicts_dir(&self, project: i64, job: &str) -> Option<PathBuf> {
        Some(self.project_meta(project).join("conflicts").join(one(job)?))
    }

    /// `<ws>/.trash/<date>/` (`date` as `YYYY-MM-DD`).
    pub fn trash(&self, date: &str) -> Option<PathBuf> {
        Some(self.root.join(".trash").join(one(date)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_the_spec_and_names_cannot_escape() {
        let ws = Workspace::new(DEFAULT_ROOT);
        let p = |s: &str| Some(PathBuf::from(s));
        assert_eq!(
            ws.project_repo(3, "app"),
            p("/var/lib/ainkrad-ws/p/3/main/app")
        );
        let s = SessionKey {
            id: "as_abc",
            user: UserId(1),
            project: Some(3),
        };
        assert_eq!(ws.session_dir(&s), p("/var/lib/ainkrad-ws/p/3/s/as_abc"));
        let s = SessionKey { project: None, ..s };
        assert_eq!(ws.session_dir(&s), p("/var/lib/ainkrad-ws/u/1/s/as_abc"));
        assert_eq!(
            ws.user_home(UserId(1)),
            PathBuf::from("/var/lib/ainkrad-ws/u/1/home")
        );
        assert_eq!(
            ws.jobs_toml(3),
            PathBuf::from("/var/lib/ainkrad-ws/p/3/.ainkrad/jobs.toml")
        );
        assert_eq!(
            ws.conflicts_dir(3, "j_1"),
            p("/var/lib/ainkrad-ws/p/3/.ainkrad/conflicts/j_1")
        );
        assert_eq!(
            ws.trash("2026-11-20"),
            p("/var/lib/ainkrad-ws/.trash/2026-11-20")
        );
        for bad in ["..", "a/b", "", ".git", "a\\b"] {
            assert_eq!(ws.project_repo(3, bad), None, "{bad}");
            assert_eq!(ws.conflicts_dir(3, bad), None, "{bad}");
            let s = SessionKey { id: bad, ..s };
            assert_eq!(ws.session_dir(&s), None, "{bad}");
        }
    }
}
