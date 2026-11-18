//! `run.observe` (Core 0.9 Projects, P5-04): what a running project is doing. One op answers with
//! each service's health, CPU, memory and restarts, and the log lines that are new since the
//! caller's cursor. The runner keeps a bounded, redacted ring of lines per run; the Core reads it
//! by `seq` (the same resume idea as the event stream), so a viewer that falls behind loses lines,
//! never memory.

use serde::{Deserialize, Serialize};

pub const OP_RUN_OBSERVE: &str = "run.observe";

/// One log line is cut to this many bytes (a flood of long lines cannot fill the ring).
pub const LOG_LINE_MAX: usize = 2048;
/// The most lines one `run.observe` answers with.
pub const OBSERVE_LINES_MAX: u32 = 500;

/// `limit` 0 asks for the metrics only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunObserveReq {
    pub run: String,
    /// Lines with a `seq` above this (0: from the oldest the runner still holds).
    #[serde(default)]
    pub after: u64,
    /// Only this service's lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// At most this many lines (default and most [`OBSERVE_LINES_MAX`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl RunObserveReq {
    pub fn problem(&self) -> Option<String> {
        if !super::valid_run_id(&self.run) {
            return Some("run: 1-40 of a-z, 0-9, _ and -".to_owned());
        }
        if self
            .service
            .as_deref()
            .is_some_and(|s| !super::valid_run_id(s))
        {
            return Some("service: 1-40 of a-z, 0-9, _ and -".to_owned());
        }
        None
    }
}

/// A service's own health check, when its spec has one.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealth {
    /// No health check.
    #[default]
    None,
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServiceMetrics {
    pub name: String,
    /// Podman's state: `running`, `exited`, ...
    pub state: String,
    #[serde(default)]
    pub health: ServiceHealth,
    /// Percent of one CPU (it passes 100 with more than one core in use); `None` while it is not
    /// running or Podman gave no sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    #[serde(default)]
    pub memory_bytes: u64,
    /// The cap Podman reports (the project's memory limit); 0 when unknown.
    #[serde(default)]
    pub memory_limit_bytes: u64,
    #[serde(default)]
    pub restarts: u32,
}

/// One line of a service's output, redacted and cut to [`LOG_LINE_MAX`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LogLine {
    /// Grows by one per line of the run, across services; the resume cursor.
    pub seq: u64,
    pub service: String,
    /// When the container wrote it (RFC 3339, from Podman).
    pub at: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunObserve {
    #[serde(default)]
    pub services: Vec<ServiceMetrics>,
    #[serde(default)]
    pub lines: Vec<LogLine>,
    /// Ask again with `after` = this.
    #[serde(default)]
    pub next: u64,
    /// Lines between `after` and the oldest line held that the ring had already dropped.
    #[serde(default)]
    pub lost: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_names_a_valid_run_and_service() {
        let ok = RunObserveReq {
            run: "r_1".into(),
            service: Some("web".into()),
            ..Default::default()
        };
        assert_eq!(ok.problem(), None);
        for (run, service) in [("../x", None), ("r1", Some("a b")), ("", None)] {
            let bad = RunObserveReq {
                run: run.into(),
                service: service.map(str::to_owned),
                ..Default::default()
            };
            assert!(bad.problem().is_some(), "{run:?} {service:?}");
        }
    }
}
