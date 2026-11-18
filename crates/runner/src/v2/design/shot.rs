//! `design.shot`: the site written under the job's `in/site`, and Chromium's arguments.

use ainkrad_proto::v2::{
    DESIGN_MAX_FILES, DESIGN_MAX_PIXELS, DESIGN_MAX_SIDE, DesignShot, ErrorCode, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Job, internal};

/// A `design.shot` site path: relative, plain segments, no NUL or backslash.
pub(super) fn path_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 512
        && !p.starts_with('/')
        && !p.contains(['\0', '\\'])
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Writes the site under `in/site` and answers Chromium's arguments.
pub(super) fn shot_args(s: &DesignShot, job: &Job) -> Result<Vec<String>, StreamError> {
    let bad = |m: &str| StreamError::new(ErrorCode::InvalidArgs, m);
    if s.files.is_empty() || s.files.len() > DESIGN_MAX_FILES {
        return Err(bad("a shot has 1 to 200 files"));
    }
    let (w, h) = (s.width, s.height);
    let px = |v: u32| (f64::from(v) * f64::from(s.scale)).round() as u64;
    if !(0.25..=4.0).contains(&s.scale)
        || !(1..=4096).contains(&w)
        || !(1..=4096).contains(&h)
        || px(w) > u64::from(DESIGN_MAX_SIDE)
        || px(h) > u64::from(DESIGN_MAX_SIDE)
        || px(w) * px(h) > DESIGN_MAX_PIXELS
    {
        return Err(bad("the shot size is out of range"));
    }
    if !path_ok(&s.entry) || !s.files.iter().any(|f| f.path == s.entry) {
        return Err(bad("the entry must be one of the files"));
    }
    let site = job.dir.join("in/site");
    for f in &s.files {
        if !path_ok(&f.path) {
            return Err(bad(
                "a file path must be relative, without `..`, NUL or `\\`",
            ));
        }
        let bytes = STANDARD
            .decode(&f.data)
            .map_err(|_| bad("a file is not base64"))?;
        let to = site.join(&f.path);
        if let Some(d) = to.parent() {
            std::fs::create_dir_all(d).map_err(|e| internal(&e))?;
        }
        // `create_new`: two files with one path, or a file over a directory, is refused.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)
            .and_then(|mut o| std::io::Write::write_all(&mut o, &bytes))
            .map_err(|_| bad("two files have the same path"))?;
    }
    let url: String = s
        .entry
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    Ok([
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--hide-scrollbars",
        "--mute-audio",
        "--user-data-dir=/tmp/profile",
        "--virtual-time-budget=3000",
        "--screenshot=/out/shot.png",
    ]
    .map(str::to_owned)
    .into_iter()
    .chain([
        format!("--window-size={w},{h}"),
        format!("--force-device-scale-factor={}", s.scale),
        format!("file:///in/site/{url}"),
    ])
    .collect())
}

/// Width and height from a PNG's IHDR.
pub(super) fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 24 || !b.starts_with(b"\x89PNG\r\n\x1a\n") || &b[12..16] != b"IHDR" {
        return None;
    }
    let n = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    Some((n(16), n(20)))
}
