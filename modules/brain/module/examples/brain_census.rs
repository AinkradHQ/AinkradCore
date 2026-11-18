//! The Brain junk census: `brain_census <core home copy> <out dir>`. Counts only; see `eval_census`.
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    let [home, out] = &a[..] else {
        return Err("usage: brain_census <core home copy> <out dir>".into());
    };
    let rooms = brain_module::eval_census::run(home, out).await?;
    let json = serde_json::to_string_pretty(&rooms)?;
    std::fs::write(out.join("brain-census.json"), &json)?;
    println!("{json}");
    Ok(())
}
