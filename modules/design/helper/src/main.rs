//! `ainkrad-design /in/job.json`: one design job (`design.render`, `design.measure`, `design.review`,
//! `design.check`) to one JSON answer on stdout; exit 2 with a sentence on stderr when it cannot.
//!
//! Security model: everything in the job is untrusted (the document, fonts, images, zips). This
//! process is where they are parsed, and it runs only inside the runner's sandbox (no network, a
//! read-only `/in`, CPU, memory and file limits; `crates/runner/src/v2/design.rs`). A Skia or
//! FreeType bug can kill or stall this process; the runner then reports the job failed. On top of
//! that, cheap checks here keep the common hostile shapes from reaching the parsers at all: image
//! headers are sized before any decode, zips are walked with every length bounds-checked, and every
//! output is capped. Nothing here opens a socket or a path outside the job.

use std::process::ExitCode;

use ainkrad_design::run;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: ainkrad-design <job.json>");
        return ExitCode::from(2);
    };
    if path == "--version" {
        println!("ainkrad-design {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match std::fs::read(&path)
        .map_err(|_| "the job cannot be read".to_owned())
        .and_then(|b| run(&b))
    {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("{why}");
            ExitCode::from(2)
        }
    }
}
