//! The Brain eval: `brain_eval <core home copy> <questions dir> <out dir>`.
//! Run on a READ-ONLY COPY of a Core home (never the live dir; it refuses that). Question files
//! are `<room>.json`, see `brain_module::eval::QuestionSet`. Prints the aggregate table and writes
//! `brain-eval-<unix time>.json` (counts, ratios, ids; no content) to the out dir.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    let [home, questions, out] = &a[..] else {
        return Err("usage: brain_eval <core home copy> <questions dir> <out dir>".into());
    };
    let report = brain_module::eval::run(home, questions, out).await?;
    print!("{}", report.table());
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    std::fs::write(
        out.join(format!("brain-eval-{at}.json")),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
