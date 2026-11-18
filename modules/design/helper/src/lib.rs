//! The `ainkrad-design` helper as a library, so its tests drive the same code in-process; the
//! security model is in `main.rs`.

pub mod export;
pub mod fidelity;
pub mod icon;
pub mod ops;

use ainkrad_proto::v2::{Command, DESIGN_MAX_INPUT};

/// One job's JSON to its answer's JSON.
pub fn run(job: &[u8]) -> Result<String, String> {
    if job.len() > DESIGN_MAX_INPUT {
        return Err("the job is too large".into());
    }
    let cmd: Command = serde_json::from_slice(job).map_err(|_| "the job is not valid")?;
    let v = match cmd {
        Command::DesignRender(r) => serde_json::to_value(ops::render(&r)?),
        Command::DesignMeasure(m) => serde_json::to_value(ops::measure(&m.doc)?),
        Command::DesignReview(r) => serde_json::to_value(ops::review(&r.doc)?),
        Command::DesignCheck(c) => serde_json::to_value(ops::check(&c)),
        Command::DesignExport(e) => serde_json::to_value(export::export(&e)?),
        Command::DesignFidelity(f) => serde_json::to_value(fidelity::fidelity(&f)?),
        _ => return Err("not a helper op".into()),
    };
    v.map(|v| v.to_string())
        .map_err(|_| "the answer did not serialise".into())
}
