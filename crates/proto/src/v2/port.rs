//! `port.open` (Core 0.9 Projects, P6-01): one TCP connection from the Core to a service port of a
//! live run, carried as a command stream. SECURITY: the Core names the run, the service and the
//! container port; the runner picks the address itself, `127.0.0.1:<port Podman published>`, and only
//! for a port the run's spec marked `expose: true` (see `RunPort`). The bytes are `output` frames
//! both ways under `credit`; the stream ends with a `result` ([`PortClosed`]) or an `error`.

use serde::{Deserialize, Serialize};

pub const OP_PORT_OPEN: &str = "port.open";

/// Opens a stream to `port` (the container port, as written in the spec) of `service` in run `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortOpen {
    /// The project the run belongs to; the runner refuses a run of another project.
    pub project: u64,
    pub run: String,
    pub service: String,
    pub port: u16,
}

/// Why a port stream ended, as its last frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortClosed {
    /// `eof` (the service closed it) or `run_ended` (the run stopped, failed or lost the port).
    pub reason: String,
}

impl PortOpen {
    /// What is wrong with the request, if anything, as `path: why`.
    pub fn problem(&self) -> Option<String> {
        if !super::valid_run_id(&self.run) {
            return Some("run: 1-40 of a-z, 0-9, _ and -".to_owned());
        }
        if !super::valid_run_id(&self.service) {
            return Some("service: 1-40 of a-z, 0-9, _ and -".to_owned());
        }
        (self.port == 0).then(|| "port: 1-65535".to_owned())
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn the_project_is_required() {
        let ok = serde_json::json!({"project": 7, "run": "r1", "service": "web", "port": 3000});
        assert_eq!(serde_json::from_value::<PortOpen>(ok).unwrap().project, 7);
        let none = serde_json::json!({"run": "r1", "service": "web", "port": 3000});
        assert!(serde_json::from_value::<PortOpen>(none).is_err());
    }
}
