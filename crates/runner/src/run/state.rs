//! A run's state across the project stores: status, the whole list, and stop. A run is its
//! containers' labels in whichever project store holds them.

use std::time::Instant;

use ainkrad_proto::v2::{RunInfo, RunList, RunPhase};

use super::{CLEANUP_BUDGET, Engine, LABEL_RUN, QUICK, network, runs_from_ps};

impl Engine {
    /// Podman's global flags for `project`: its own store, the shared network definitions, and
    /// (with a runtime dir) libpod's tmp dir on tmpfs, where its reboot marker must live.
    pub(super) fn store_args(&self, project: u64) -> Vec<String> {
        let p = self.projects.join(project.to_string());
        let mut a = vec![
            "--root".to_owned(),
            p.join("storage").display().to_string(),
            "--runroot".to_owned(),
            p.join("runroot").display().to_string(),
            "--network-config-dir".to_owned(),
            self.networks.display().to_string(),
        ];
        if let Some(r) = &self.runtime_dir {
            a.push("--tmpdir".to_owned());
            a.push(r.join(network(project)).display().to_string());
        }
        a
    }

    /// The projects that have a store here.
    pub(super) fn stores(&self) -> Vec<u64> {
        std::fs::read_dir(&self.projects)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) fn ps(
        &self,
        project: u64,
        filter: &str,
        deadline: Instant,
    ) -> Result<Vec<RunInfo>, String> {
        runs_from_ps(&self.podman(
            project,
            &["ps", "-a", "--filter", filter, "--format", "json"],
            deadline,
        )?)
    }

    pub(super) fn status_by(
        &self,
        run: &str,
        project: u64,
        deadline: Instant,
    ) -> Result<RunInfo, String> {
        let filter = format!("label={LABEL_RUN}={run}");
        Ok(self
            .ps(project, &filter, deadline)?
            .pop()
            .unwrap_or(RunInfo {
                run: run.to_owned(),
                project,
                phase: RunPhase::Stopped,
                failed_service: None,
                reason: None,
                services: Vec::new(),
            }))
    }

    /// One run of `project`; `Stopped` when it has no container.
    pub fn status(&self, run: &str, project: u64) -> Result<RunInfo, String> {
        self.status_by(run, project, Instant::now() + QUICK)
    }

    /// One run, whichever project's store holds it (the helper's `stop`/`status` name no project);
    /// `Stopped` (project 0) when none does.
    // ponytail: one `podman ps` per project store; index run -> project if a host ever has hundreds.
    pub fn find(&self, run: &str) -> Result<RunInfo, String> {
        let deadline = Instant::now() + CLEANUP_BUDGET;
        for p in self.stores() {
            let r = self.status_by(run, p, deadline)?;
            if !r.services.is_empty() {
                return Ok(r);
            }
        }
        Ok(RunInfo {
            run: run.to_owned(),
            project: 0,
            phase: RunPhase::Stopped,
            failed_service: None,
            reason: None,
            services: Vec::new(),
        })
    }

    /// Every run on this host (the reconcile after a runner restart).
    pub fn list(&self) -> Result<RunList, String> {
        let deadline = Instant::now() + CLEANUP_BUDGET;
        let mut runs = Vec::new();
        for p in self.stores() {
            runs.extend(self.ps(p, &format!("label={LABEL_RUN}"), deadline)?);
        }
        Ok(RunList { runs })
    }

    /// Stops and removes the run's containers (`stop -t 10`) and built images, in every project
    /// store, all within [`CLEANUP_BUDGET`]; volumes and the network stay.
    pub fn stop(&self, run: &str) -> Result<RunInfo, String> {
        let deadline = Instant::now() + CLEANUP_BUDGET;
        let filter = format!("label={LABEL_RUN}={run}");
        let tag = format!(":{run}");
        let mut project = 0;
        for p in self.stores() {
            let ids = self.podman(p, &["ps", "-a", "-q", "--filter", &filter], deadline)?;
            let ids: Vec<&str> = ids.split_whitespace().collect();
            if !ids.is_empty() {
                project = p;
                let _ = self.podman(p, &[&["stop", "-t", "10"][..], &ids].concat(), deadline);
                self.podman(p, &[&["rm", "-f"][..], &ids].concat(), deadline)?;
            }
            // The run's own builds (`localhost/ainkrad-p<project>-<service>:<run>`).
            let images = self.podman(
                p,
                &["images", "--format", "{{.Repository}}:{{.Tag}}"],
                deadline,
            )?;
            let own = format!("localhost/{}-", network(p));
            let built: Vec<&str> = images
                .lines()
                .filter(|i| i.starts_with(&own) && i.ends_with(&tag))
                .collect();
            if !built.is_empty() {
                project = p;
                let _ = self.podman(p, &[&["rmi", "-f"][..], &built].concat(), deadline);
            }
        }
        if ainkrad_proto::v2::valid_run_id(run) {
            let _ = std::fs::remove_dir_all(self.root.join(run));
        }
        Ok(RunInfo {
            run: run.to_owned(),
            project,
            phase: RunPhase::Stopped,
            failed_service: None,
            reason: None,
            services: Vec::new(),
        })
    }
}
