//! `ainkrad-ptyhost serve --dir <dir> --id <t_…>`: reads the terminal's spec (JSON) on stdin,
//! leaves the runner's session, starts the terminal and prints `ready <info>` (or
//! `error <why>`) on stdout. Started by the runner only (`client::launch`).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use ainkrad_ptyhost::host::{HostConfig, prepare, serve};
use ainkrad_ptyhost::pty::{Pty, Spec};
use ainkrad_ptyhost::screen::Raw;

const USAGE: &str = "usage: ainkrad-ptyhost serve --dir <dir> --id <t_…> < spec.json
Started by ainkrad-runner for each terminal; not meant to be run by hand.";

fn say(line: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    let (Some("serve"), Some(dir), Some(id)) = (
        args.first().map(String::as_str),
        flag("--dir"),
        flag("--id"),
    ) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // Its own session: the runner's death, or a hang-up of whatever started it, does not
    // reach the host (E2-03.2).
    if let Err(e) = ainkrad_sys::setsid() {
        say(&format!("error setsid: {e}"));
        return ExitCode::FAILURE;
    }
    let mut input = Vec::new();
    let spec: Spec = match std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_slice(&input).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => {
            say(&format!("error spec: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // The child is forked while this process has one thread: no runtime yet (review L1).
    let cfg = HostConfig::new(PathBuf::from(dir), id);
    let spawned = match prepare(&cfg).and_then(|()| Pty::spawn(&spec)) {
        Ok(s) => s,
        Err(e) => {
            say(&format!("error {e}"));
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            say(&format!("error runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let ready = |info: &ainkrad_ptyhost::wire::HostInfo| {
        say(&format!(
            "ready {}",
            serde_json::to_string(info).unwrap_or_default()
        ));
    };
    let screen = Box::new(Raw::new(64 * 1024));
    match rt.block_on(serve(cfg, spawned, spec.size, screen, ready)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            say(&format!("error {e}"));
            ExitCode::FAILURE
        }
    }
}
