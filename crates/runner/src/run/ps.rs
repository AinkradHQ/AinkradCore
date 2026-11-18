//! Runs as Podman lists them: a run is its containers' labels.

use std::collections::BTreeMap;

use ainkrad_proto::v2::{PublishedPort, RunInfo, RunPhase, ServiceStatus};

use super::{LABEL_EXPOSE, LABEL_PROJECT, LABEL_RUN, LABEL_SERVICE};

/// What `podman ps --format json` says of one container (the fields used).
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ps {
    #[serde(default)]
    state: String,
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    ports: Option<Vec<PsPort>>,
}

#[derive(serde::Deserialize)]
struct PsPort {
    #[serde(default)]
    host_ip: String,
    container_port: u16,
    host_port: u16,
}

/// Runs, grouped from `podman ps -a --format json` output.
pub fn runs_from_ps(json: &str) -> Result<Vec<RunInfo>, String> {
    let list: Vec<Ps> =
        serde_json::from_str(json).map_err(|e| format!("reading podman ps: {e}"))?;
    let mut runs: BTreeMap<String, RunInfo> = BTreeMap::new();
    for c in list {
        let labels = c.labels.unwrap_or_default();
        let (Some(run), Some(service)) = (labels.get(LABEL_RUN), labels.get(LABEL_SERVICE)) else {
            continue;
        };
        let info = runs.entry(run.clone()).or_insert_with(|| RunInfo {
            run: run.clone(),
            project: labels
                .get(LABEL_PROJECT)
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            phase: RunPhase::Running,
            failed_service: None,
            reason: None,
            services: Vec::new(),
        });
        let running = c.state == "running";
        let exposed: Vec<u16> = labels
            .get(LABEL_EXPOSE)
            .map(|l| l.split(',').filter_map(|p| p.parse().ok()).collect())
            .unwrap_or_default();
        info.services.push(ServiceStatus {
            name: service.clone(),
            exit_code: (!running && c.state == "exited").then_some(c.exit_code),
            state: c.state,
            ports: c
                .ports
                .unwrap_or_default()
                .into_iter()
                // Anything published off loopback would be a bug; it is never reported as reachable.
                .filter(|p| p.host_ip == "127.0.0.1")
                .map(|p| PublishedPort {
                    port: p.container_port,
                    host_port: p.host_port,
                    expose: exposed.contains(&p.container_port),
                })
                .collect(),
        });
    }
    let mut out: Vec<RunInfo> = runs.into_values().collect();
    for r in &mut out {
        r.services.sort_by(|a, b| a.name.cmp(&b.name));
        let starting = |s: &str| matches!(s, "created" | "configured" | "initialized" | "stopping");
        if let Some(s) = r
            .services
            .iter()
            .find(|s| s.state != "running" && !starting(&s.state))
        {
            r.phase = RunPhase::Failed;
            r.failed_service = Some(s.name.clone());
            r.reason = Some(match s.exit_code {
                Some(c) => format!("{} exited with code {c}", s.name),
                None => format!("{} is {}", s.name, s.state),
            });
        } else if r.services.iter().any(|s| starting(&s.state)) {
            r.phase = RunPhase::Starting;
        }
    }
    Ok(out)
}
