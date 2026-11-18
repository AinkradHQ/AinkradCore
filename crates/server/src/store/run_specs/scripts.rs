//! Script converters (Core 0.9, P4-03): a `package.json`, `Makefile` or `run.sh` text in, a draft
//! run spec out; `draft` picks the converter (compose is P4-02) from the file's name.
//!
//! Security model: the file is untrusted DATA. Every function here is pure over a string: nothing
//! is run, sourced, expanded or included, and there is no file or network access. The only things
//! read are a few fixed keys or lines (`scripts.start`, a `Makefile` target name, a shebang), and
//! the draft never contains file text except a port number found in it. The command is a fixed
//! shape (`npm run start`, `make <target>`, `bash run.sh`) that the runner later runs inside the
//! same sandboxed container as any spec; a draft goes through `spec::validate` here and again
//! on save (P4-01), so it can say nothing a hand-written spec cannot. A file that cannot be drafted
//! is an `Err` with a plain reason, never a guess.

use std::collections::BTreeMap;

use serde_json::Value;

use super::compose::{self, Converted, NotConverted};
use super::spec::{self, Port, Problem, RunSpec, Service};

const MAX_BYTES: usize = 64 * 1024;

/// Files `draft` knows, in the order a repo is searched.
pub const FILES: [&str; 7] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "run.sh",
    "Makefile",
    "package.json",
];

/// Image for a `run.sh`, which needs nothing but a shell.
const SHELL_IMAGE: &str = "debian:stable-slim";
const DEFAULT_NODE: u32 = 22;

/// The origin a draft is saved with, from the file's name.
pub fn origin_of(file: &str) -> Option<&'static str> {
    match file {
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml" => {
            Some("compose")
        }
        "run.sh" => Some("run_sh"),
        "Makefile" | "makefile" => Some("makefile"),
        "package.json" => Some("package_json"),
        _ => None,
    }
}

/// Drafts a spec from `text`, the file `name` (its last path part) found in folder `dir` of
/// project repo `repo` (`""` for the root). `image` is the caller's choice of image for a script.
pub fn draft(
    name: &str,
    text: &str,
    repo: &str,
    dir: &str,
    image: Option<&str>,
) -> Result<(&'static str, Converted), Problem> {
    let origin =
        origin_of(name).ok_or_else(|| format!("{name}: not a file that can be drafted"))?;
    if text.len() > MAX_BYTES {
        return Err(format!("{name}: larger than {} KiB", MAX_BYTES / 1024));
    }
    let c = match origin {
        "compose" => compose::convert(text, repo, dir)?,
        "package_json" => package_json(text, repo, dir, image)?,
        "makefile" => makefile(text, repo, dir, image)?,
        _ => run_sh(text, repo, dir, name, image)?,
    };
    Ok((origin, c))
}

pub fn package_json(
    text: &str,
    repo: &str,
    dir: &str,
    image: Option<&str>,
) -> Result<Converted, Problem> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("package.json: {e}"))?;
    let Some(scripts) = v.get("scripts").and_then(Value::as_object) else {
        return Err("package.json: no `scripts` to run".to_owned());
    };
    let Some((script, body)) = ["start", "dev", "serve"]
        .into_iter()
        .find_map(|k| Some((k, scripts.get(k)?.as_str()?)))
    else {
        return Err("package.json: no `start`, `dev` or `serve` script".to_owned());
    };
    let mut notes = Vec::new();
    let manager = v
        .get("packageManager")
        .and_then(Value::as_str)
        .and_then(|p| p.split('@').next())
        .filter(|m| matches!(*m, "pnpm" | "yarn"));
    let line = match manager {
        Some(m) => format!("corepack enable && {m} install && {m} run {script}"),
        None => format!("npm install && npm run {script}"),
    };
    let node = v
        .pointer("/engines/node")
        .and_then(Value::as_str)
        .and_then(major)
        .filter(|n| (16..=30).contains(n));
    if node.is_none() {
        note(
            &mut notes,
            "engines.node",
            format!("no usable Node version; node:{DEFAULT_NODE} is used"),
        );
    }
    if v.get("workspaces").is_some() {
        note(
            &mut notes,
            "workspaces",
            "workspaces are not handled; the draft installs and runs from this folder",
        );
    }
    let default_image = format!("node:{}", node.unwrap_or(DEFAULT_NODE));
    finish(
        "package.json",
        image.unwrap_or(&default_image),
        vec!["sh".into(), "-c".into(), line],
        (repo, dir),
        port_in(body),
        notes,
    )
}

pub fn makefile(
    text: &str,
    repo: &str,
    dir: &str,
    image: Option<&str>,
) -> Result<Converted, Problem> {
    let Some(image) = image else {
        return Err(
            "Makefile: it has no image to run in; give `image` (one that has make and \
                    what the Makefile uses)"
                .to_owned(),
        );
    };
    let lines: Vec<&str> = text.lines().collect();
    let target = ["run", "dev", "start", "serve"].into_iter().find_map(|t| {
        let at = lines.iter().position(|l| {
            l.strip_prefix(t).is_some_and(|r| {
                r.trim_start().starts_with(':') && !r.trim_start().starts_with(":=")
            })
        })?;
        Some((t, at))
    });
    let Some((target, at)) = target else {
        return Err("Makefile: no `run`, `dev`, `start` or `serve` target".to_owned());
    };
    // The recipe: the tab-indented lines under the target.
    let recipe: String = lines[at + 1..]
        .iter()
        .take_while(|l| l.is_empty() || l.starts_with('\t'))
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    finish(
        "Makefile",
        image,
        vec!["make".into(), target.into()],
        (repo, dir),
        port_in(&recipe),
        Vec::new(),
    )
}

pub fn run_sh(
    text: &str,
    repo: &str,
    dir: &str,
    file: &str,
    image: Option<&str>,
) -> Result<Converted, Problem> {
    let shell = match text.lines().next().and_then(|l| l.strip_prefix("#!")) {
        None => "sh",
        Some(l) => match l
            .split_whitespace()
            .filter_map(|t| t.rsplit('/').next())
            .find(|t| matches!(*t, "sh" | "bash"))
        {
            Some(s) => s,
            None => {
                return Err(format!(
                    "{file}: it starts with `#!{}`; only sh and bash scripts can be drafted",
                    l.trim()
                ));
            }
        },
    };
    finish(
        file,
        image.unwrap_or(SHELL_IMAGE),
        vec![shell.into(), file.into()],
        (repo, dir),
        port_in(text),
        Vec::new(),
    )
}

fn note(notes: &mut Vec<NotConverted>, path: &str, reason: impl Into<String>) {
    notes.push(NotConverted {
        path: path.to_owned(),
        reason: reason.into(),
    });
}

/// One service `app` that runs `command` in `image` with the repo's checkout mounted, in `dir`.
fn finish(
    file: &str,
    image: &str,
    command: Vec<String>,
    (repo, dir): (&str, &str),
    port: Option<u16>,
    mut notes: Vec<NotConverted>,
) -> Result<Converted, Problem> {
    let dir = dir.trim_matches('/');
    let workdir = match dir {
        "" => format!("/repo/{repo}"),
        d => format!("/repo/{repo}/{d}"),
    };
    match port {
        Some(p) => note(
            &mut notes,
            "ports",
            format!("port {p} was found in the file and is the public URL; check it"),
        ),
        None => note(
            &mut notes,
            "ports",
            "no port found in the file; add one to get a public URL",
        ),
    }
    let svc = Service {
        image: Some(image.to_owned()),
        build: None,
        repo: Some(repo.to_owned()),
        workdir: Some(workdir),
        command: Some(command),
        env: BTreeMap::new(),
        volumes: BTreeMap::new(),
        ports: port
            .map(|port| Port { port, expose: true })
            .into_iter()
            .collect(),
        depends_on: Vec::new(),
        health: None,
    };
    let spec = RunSpec {
        services: BTreeMap::from([("app".to_owned(), svc)]),
    };
    spec::validate(&spec).map_err(|e| format!("{file}: the drafted spec is invalid: {e}"))?;
    Ok(Converted {
        spec,
        not_converted: notes,
    })
}

/// The first number after a `port` word (`--port 3000`, `PORT=8080`, `"port": 4000`).
fn port_in(text: &str) -> Option<u16> {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("port").find_map(|(i, w)| {
        let rest = lower[i + w.len()..].trim_start_matches([' ', '=', ':', '"', '\'']);
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u16>().ok().filter(|p| *p > 0)
    })
}

/// The first whole number in an engines range (`>=20.11`, `^22`, `22.x`).
fn major(range: &str) -> Option<u32> {
    let from = range.find(|c: char| c.is_ascii_digit())?;
    let digits: String = range[from..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests;
