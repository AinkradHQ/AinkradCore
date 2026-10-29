//! Stage timings (E15.6): how fast a project's runs start, per stage.

use std::path::Path;

use ainkrad_core::work::ProjectId;
use ainkrad_core_server::store::{self, exec};

use super::id;
use crate::Result_;

pub const USAGE: &str = "  ainkrad-core-server runs timing <db> <project-id> [--since <timestamp>]
One line per stage of a run's start (wake_to_claim, claim_to_workspace, workspace_to_harness,
harness_to_first_token, wake_to_first_token, first_token_to_end): the runs that reached it,
then its median and 95th-percentile seconds. A first token later than
latency.first_token_budget_secs after the wake is audited as run.first_token_slow.";

/// Runs a timing command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["runs", "timing", db, project, rest @ ..] => {
            let since = match rest {
                [] => None,
                ["--since", s] => Some(*s),
                _ => return None,
            };
            timing(Path::new(db), ProjectId(id(project).ok()?), since).await
        }
        _ => return None,
    })
}

/// `<stage>\t<runs>\t<p50 s>\t<p95 s>`, `-` for no run.
async fn timing(db: &Path, project: ProjectId, since: Option<&str>) -> Result_ {
    let pool = store::connect(db).await?;
    let secs = |s: Option<f64>| s.map_or_else(|| "-".to_owned(), |s| format!("{s:.3}"));
    for s in exec::stage_timing(&pool, project, since).await? {
        let (p50, p95) = (secs(s.p50_secs), secs(s.p95_secs));
        println!("{}\t{}\t{p50}\t{p95}", s.stage, s.runs);
    }
    Ok(())
}
