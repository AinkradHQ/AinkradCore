//! Compose converter (Core 0.9, P4-02): a `docker-compose.yml` text in, a draft run spec out.
//!
//! Security model: the compose file is untrusted DATA. This module is a pure function over a
//! string: it parses YAML, reads fields, and builds a `RunSpec`. It never runs, expands or
//! includes anything: no shell, no `${VAR}` expansion (a host variable is listed as not
//! converted), no `include`/`extends`/`env_file` reads, no file or network access, and a
//! `command` is split into words, never handed to a shell. The result is only a draft; it goes
//! through the same validator as a hand-written spec (`spec::validate`) before anyone can save it
//! (P4-01), and everything the spec cannot say (privileged, host networking, host bind mounts,
//! capabilities, devices...) is dropped and listed in `not_converted`, never carried over.
//! Hostile YAML is bounded: the text is capped at 64 KiB and alias use at 32 (an alias bomb needs
//! deep nesting of many aliases; 32 aliases cannot expand past a few tens of thousands of nodes).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value};

use super::spec::{self, Build, Health, MAX_SERVICES, Port, Problem, RunSpec, Service};

const MAX_BYTES: usize = 64 * 1024;
const MAX_ALIASES: usize = 32;

/// Container ports of common datastores: a published one is never picked as the public URL.
const DATASTORE_PORTS: [u16; 9] = [1433, 3306, 5432, 5672, 6379, 9200, 11211, 27017, 15672];

/// Service keys the converter reads (the rest is listed as not converted).
const HANDLED: [&str; 11] = [
    "image",
    "build",
    "command",
    "entrypoint",
    "working_dir",
    "environment",
    "env_file",
    "ports",
    "expose",
    "volumes",
    "depends_on",
];

/// Keys that would widen what a container may do; the spec cannot say them by design.
const REFUSED: [&str; 11] = [
    "privileged",
    "network_mode",
    "cap_add",
    "devices",
    "pid",
    "ipc",
    "security_opt",
    "sysctls",
    "userns_mode",
    "volumes_from",
    "uts",
];

/// One thing in the compose file that is not in the spec, for the "not converted" list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotConverted {
    /// Where, as a dotted path (`services.web.volumes[1]`).
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Converted {
    pub spec: RunSpec,
    pub not_converted: Vec<NotConverted>,
}

#[derive(Default)]
struct Notes(Vec<NotConverted>);

impl Notes {
    fn add(&mut self, path: impl Into<String>, reason: impl Into<String>) {
        self.0.push(NotConverted {
            path: path.into(),
            reason: reason.into(),
        });
    }
}

/// Converts compose `text`. `repo` is the project repo that holds the file and `dir` the folder
/// of the file inside that repo (`""` for the root): build contexts are repo-relative in a spec.
/// The error is a plain problem for the user; anything partial is listed in `not_converted`.
pub fn convert(text: &str, repo: &str, dir: &str) -> Result<Converted, Problem> {
    let base = join_in_repo("", dir).ok_or("the compose file's folder must be inside the repo")?;
    let root = parse_yaml(text)?;
    let mut n = Notes::default();
    for (k, v) in &root {
        match k.as_str() {
            "services" | "version" | "name" => {}
            k if k.starts_with("x-") => {}
            "volumes" => top_volumes(v, &mut n),
            other => n.add(other, "not supported by a run spec; ignored"),
        }
    }
    let Some(Value::Object(services)) = root.get("services") else {
        return Err("compose file: no `services` mapping".to_owned());
    };

    let mut out: BTreeMap<String, (Service, Vec<String>, Vec<u16>)> = BTreeMap::new();
    let mut names: BTreeMap<&str, String> = BTreeMap::new(); // compose name -> spec name
    for (cname, v) in services {
        let name = cname.to_ascii_lowercase().replace(['_', '.'], "-");
        let at = format!("services.{cname}");
        if out.len() >= MAX_SERVICES {
            n.add(&at, format!("more than {MAX_SERVICES} services; skipped"));
            continue;
        }
        if out.contains_key(&name) {
            n.add(
                &at,
                format!("its name becomes {name}, already used; skipped"),
            );
            continue;
        }
        let Some((svc, deps, published)) = service(cname, v, repo, &base, &mut n) else {
            continue;
        };
        let probe = RunSpec {
            services: BTreeMap::from([(name.clone(), svc.clone())]),
        };
        if let Err(why) = spec::validate(&probe) {
            n.add(&at, format!("service skipped: {why}"));
            continue;
        }
        if name != *cname {
            n.add(
                &at,
                format!("renamed to {name} (a spec name is a-z, 0-9 and -); fix references to the old name"),
            );
        }
        names.insert(cname, name.clone());
        out.insert(name, (svc, deps, published));
    }

    // Resolve depends_on onto the services that survived.
    let mut spec = RunSpec {
        services: BTreeMap::new(),
    };
    let mut web: Vec<(String, u16)> = Vec::new();
    for (name, (mut svc, deps, published)) in out {
        let mut seen = BTreeSet::new();
        for d in deps {
            match names.get(d.as_str()) {
                Some(to) if *to != name && seen.insert(to.clone()) => {
                    svc.depends_on.push(to.clone())
                }
                Some(_) => {}
                None => n.add(
                    format!("services.{name}.depends_on"),
                    format!("{d} was not converted; dependency dropped"),
                ),
            }
        }
        if let Some(p) = published.iter().find(|p| !DATASTORE_PORTS.contains(p)) {
            web.push((name.clone(), *p));
        }
        spec.services.insert(name, svc);
    }
    match web.as_slice() {
        [] => {}
        [(name, port)] => {
            for p in &mut spec.services.get_mut(name).expect("just inserted").ports {
                p.expose = p.port == *port;
            }
        }
        _ => n.add(
            "ports",
            "several services publish a web port; choose which one is the public URL",
        ),
    }

    if spec.services.is_empty() {
        return Err(format!(
            "compose file: no service could be converted ({} things not converted)",
            n.0.len()
        ));
    }
    spec::validate(&spec).map_err(|e| format!("the converted spec is invalid: {e}"))?;
    Ok(Converted {
        spec,
        not_converted: n.0,
    })
}

fn parse_yaml(text: &str) -> Result<Map<String, Value>, Problem> {
    if text.len() > MAX_BYTES {
        return Err(format!(
            "compose file: larger than {} KiB",
            MAX_BYTES / 1024
        ));
    }
    let b = text.as_bytes();
    let aliases = b
        .windows(2)
        .filter(|w| w[0] == b'*' && (w[1].is_ascii_alphanumeric() || matches!(w[1], b'_' | b'-')))
        .count();
    if aliases > MAX_ALIASES {
        return Err(format!(
            "compose file: more than {MAX_ALIASES} YAML aliases"
        ));
    }
    let mut y: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("compose file: {e}"))?;
    y.apply_merge().map_err(|e| format!("compose file: {e}"))?;
    match serde_json::to_value(&y) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err("compose file: the top level must be a mapping".to_owned()),
        Err(e) => Err(format!("compose file: {e}")),
    }
}

fn top_volumes(v: &Value, n: &mut Notes) {
    if let Value::Object(m) = v {
        for (name, def) in m {
            if def.as_object().is_some_and(|d| !d.is_empty()) {
                n.add(
                    format!("volumes.{name}"),
                    "driver, external and other volume options are not converted; a plain named volume is used",
                );
            }
        }
    }
}

/// A scalar as text: strings, numbers and booleans.
fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(x) => Some(x.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `rel` under `base` (both repo-relative, `/`-separated), `..` resolved; `None` when it is
/// absolute or climbs out of the repo. `""` is the repo root.
fn join_in_repo(base: &str, rel: &str) -> Option<String> {
    if rel.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for c in base.split('/').chain(rel.split('/')) {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            c => parts.push(c),
        }
    }
    Some(parts.join("/"))
}

/// One compose service: the draft, its `depends_on` (compose names) and its published TCP ports.
fn service(
    cname: &str,
    v: &Value,
    repo: &str,
    base: &str,
    n: &mut Notes,
) -> Option<(Service, Vec<String>, Vec<u16>)> {
    let at = format!("services.{cname}");
    let Some(m) = v.as_object() else {
        n.add(&at, "not a mapping; service skipped");
        return None;
    };
    if m.get("profiles").is_some_and(|p| !p.is_null()) {
        n.add(
            &at,
            "has profiles (not started by default); service skipped",
        );
        return None;
    }
    for k in m.keys() {
        let k = k.as_str();
        if HANDLED.contains(&k) || k == "healthcheck" || k == "profiles" || k.starts_with("x-") {
            continue;
        }
        let why = if REFUSED.contains(&k) {
            "refused: a run spec cannot express it, by design"
        } else {
            "not supported by a run spec; ignored"
        };
        n.add(format!("{at}.{k}"), why);
    }

    let mut s = Service {
        image: None,
        build: None,
        repo: None,
        workdir: None,
        command: None,
        env: BTreeMap::new(),
        volumes: BTreeMap::new(),
        ports: Vec::new(),
        depends_on: Vec::new(),
        health: None,
    };
    match (m.get("build"), m.get("image").and_then(str_of)) {
        (Some(b), image) => {
            s.build = build(&at, b, repo, base, n);
            if s.build.is_some() && image.is_some() {
                n.add(
                    format!("{at}.image"),
                    "a build is used; the image name it would be tagged with is ignored",
                );
            } else if s.build.is_none() {
                s.image = image; // the build could not be converted; fall back to a named image
            }
        }
        (None, image) => s.image = image,
    }
    if s.image.is_none() && s.build.is_none() {
        n.add(&at, "no image and no convertible build; service skipped");
        return None;
    }

    if let Some(c) = m.get("command") {
        s.command = command(c);
        if s.command.is_none() {
            n.add(
                format!("{at}.command"),
                "not a command a run spec can run; ignored",
            );
        }
    }
    if m.contains_key("entrypoint") {
        n.add(
            format!("{at}.entrypoint"),
            "a run spec has only `command`; put the entrypoint in the command or the image",
        );
    }
    if m.contains_key("env_file") {
        n.add(
            format!("{at}.env_file"),
            "a file is never read; add its variables as environment or project secrets",
        );
    }
    s.workdir = m.get("working_dir").and_then(str_of);
    if let Some(e) = m.get("environment") {
        env(&at, e, &mut s, n);
    }
    if let Some(v) = m.get("volumes") {
        volumes(&at, v, &mut s, n);
    }
    let mut published = Vec::new();
    for (key, list) in [("ports", true), ("expose", false)] {
        let Some(Value::Array(items)) = m.get(key) else {
            continue;
        };
        for (i, e) in items.iter().enumerate() {
            match port_of(e) {
                Ok(p) => {
                    if list && !published.contains(&p) {
                        published.push(p);
                    }
                    if !s.ports.iter().any(|x| x.port == p) {
                        s.ports.push(Port {
                            port: p,
                            expose: false,
                        });
                    }
                }
                Err(why) => n.add(format!("{at}.{key}[{i}]"), why),
            }
        }
    }
    s.health = m.get("healthcheck").and_then(|h| health(&at, h, n));
    let deps = m
        .get("depends_on")
        .map_or_else(Vec::new, |d| depends(&at, d, n));
    Some((s, deps, published))
}

fn build(at: &str, v: &Value, repo: &str, base: &str, n: &mut Notes) -> Option<Build> {
    let here = format!("{at}.build");
    let (ctx, dockerfile) = match v {
        Value::String(c) => (c.as_str(), None),
        Value::Object(b) => {
            for k in b
                .keys()
                .filter(|k| !matches!(k.as_str(), "context" | "dockerfile"))
            {
                n.add(
                    format!("{here}.{k}"),
                    "not supported by a run spec; ignored",
                );
            }
            (
                b.get("context").and_then(Value::as_str).unwrap_or("."),
                b.get("dockerfile").and_then(Value::as_str),
            )
        }
        _ => {
            n.add(&here, "not a path or a mapping");
            return None;
        }
    };
    if ctx.contains("://") || ctx.starts_with("git@") {
        n.add(
            &here,
            "a remote build context is not fetched; clone it as a project repo",
        );
        return None;
    }
    let ctx_path = join_in_repo(base, ctx);
    let file = ctx_path
        .as_deref()
        .and_then(|c| join_in_repo(c, dockerfile.unwrap_or("Dockerfile")))
        .filter(|f| !f.is_empty());
    let (Some(ctx_path), Some(file)) = (ctx_path, file) else {
        n.add(
            &here,
            "the context or Dockerfile is outside the repo; build not converted",
        );
        return None;
    };
    Some(Build {
        repo: repo.to_owned(),
        dockerfile: (file != "Dockerfile").then_some(file),
        context: (!ctx_path.is_empty()).then_some(ctx_path),
    })
}

fn command(v: &Value) -> Option<Vec<String>> {
    let words = match v {
        Value::String(s) => split_words(s)?,
        Value::Array(a) => a.iter().map(str_of).collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    (!words.is_empty()).then_some(words)
}

/// Compose's own splitting of a string command: whitespace, quotes and backslashes, no shell
/// (so `;`, `&&`, `$(...)` stay plain characters of an argument). `None` for an open quote.
fn split_words(s: &str) -> Option<Vec<String>> {
    let (mut out, mut cur, mut has) = (Vec::new(), String::new(), false);
    let mut q: Option<char> = None;
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match (q, c) {
            (Some(x), c) if c == x => q = None,
            (Some('"'), '\\') => match it.next()? {
                e @ ('"' | '\\' | '$') => cur.push(e),
                e => {
                    cur.push('\\');
                    cur.push(e);
                }
            },
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                q = Some(c);
                has = true;
            }
            (None, '\\') => {
                cur.push(it.next()?);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => {
                cur.push(c);
                has = true;
            }
        }
    }
    if q.is_some() {
        return None;
    }
    if has {
        out.push(cur);
    }
    Some(out)
}

fn env(at: &str, v: &Value, s: &mut Service, n: &mut Notes) {
    let pairs: Vec<(String, Option<String>)> = match v {
        Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), str_of(v))).collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|e| match e.split_once('=') {
                Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
                None => (e.to_owned(), None),
            })
            .collect(),
        _ => {
            n.add(format!("{at}.environment"), "not a mapping or a list");
            return;
        }
    };
    for (k, v) in pairs {
        let here = format!("{at}.environment.{k}");
        match v {
            None => n.add(
                here,
                "no value: compose takes it from the host; give a value or ${secret:NAME}",
            ),
            Some(v) if spec::secret_refs_in(&v).is_err() => n.add(
                here,
                "uses ${...} (a host variable); make it a project secret and write ${secret:NAME}",
            ),
            Some(v) => {
                s.env.insert(k, v);
            }
        }
    }
}

fn volumes(at: &str, v: &Value, s: &mut Service, n: &mut Notes) {
    let Value::Array(items) = v else {
        n.add(format!("{at}.volumes"), "not a list");
        return;
    };
    for (i, e) in items.iter().enumerate() {
        let here = format!("{at}.volumes[{i}]");
        // (kind, source, target, read only); kind is "volume", "bind", "tmpfs" or "other".
        let (kind, source, target, ro) = match e {
            Value::String(t) => {
                let p: Vec<&str> = t.split(':').collect();
                match p.as_slice() {
                    [target] => ("volume", None, (*target).to_owned(), false),
                    [src, target, rest @ ..] => {
                        let bind = src.starts_with(['.', '/', '~']);
                        (
                            if bind { "bind" } else { "volume" },
                            Some((*src).to_owned()),
                            (*target).to_owned(),
                            rest.iter().any(|m| m.split(',').any(|x| x == "ro")),
                        )
                    }
                    [] => unreachable!("split yields at least one part"),
                }
            }
            Value::Object(m) => (
                m.get("type").and_then(Value::as_str).unwrap_or("volume"),
                m.get("source").and_then(str_of),
                m.get("target").and_then(str_of).unwrap_or_default(),
                m.get("read_only") == Some(&Value::Bool(true)),
            ),
            _ => ("other", None, String::new(), false),
        };
        match (kind, source) {
            ("bind", _) => n.add(
                here,
                "a host bind mount is not converted; use a named volume or the repo checkout (/repo/<name>)",
            ),
            // The validator refuses a volume over the checkouts; the service must survive without it.
            ("volume", Some(_))
                if target == "/" || target == "/repo" || target.starts_with("/repo/") =>
            {
                n.add(here, "a volume cannot cover / or the /repo checkouts; not converted");
            }
            ("volume", Some(src)) if !target.is_empty() => {
                let name = src.to_ascii_lowercase().replace('.', "-");
                if s.volumes.insert(name, target).is_some() {
                    n.add(&here, "the same volume is mounted twice; the last one is kept");
                }
                if ro {
                    n.add(&here, "read-only is not supported; mounted read-write");
                }
            }
            ("volume", None) => n.add(here, "an anonymous volume is not converted; give it a name"),
            (other, _) => n.add(here, format!("a {other} mount is not converted")),
        }
    }
}

/// The container port of one `ports`/`expose` entry (short string, number or long mapping).
fn port_of(e: &Value) -> Result<u16, String> {
    let (num, proto) = match e {
        Value::Number(x) => (x.to_string(), "tcp".to_owned()),
        Value::String(t) => {
            let (p, proto) = t.split_once('/').unwrap_or((t.as_str(), "tcp"));
            (
                p.rsplit(':').next().unwrap_or("").to_owned(),
                proto.to_owned(),
            )
        }
        Value::Object(m) => (
            m.get("target").and_then(str_of).unwrap_or_default(),
            m.get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("tcp")
                .to_owned(),
        ),
        _ => return Err("not a port".to_owned()),
    };
    if proto != "tcp" {
        return Err(format!("{proto} is not supported; only tcp"));
    }
    num.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
        "not a single port number from 1 to 65535 (ranges and variables are not converted)"
            .to_owned()
    })
}

fn health(at: &str, v: &Value, n: &mut Notes) -> Option<Health> {
    let here = format!("{at}.healthcheck");
    let Value::Object(h) = v else {
        n.add(&here, "not a mapping");
        return None;
    };
    for k in h
        .keys()
        .filter(|k| !matches!(k.as_str(), "test" | "disable"))
    {
        n.add(
            format!("{here}.{k}"),
            "the runner uses its own timing; ignored",
        );
    }
    if h.get("disable") == Some(&Value::Bool(true)) {
        return None;
    }
    let cmd = match h.get("test") {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Array(a)) => {
            let w: Vec<String> = a.iter().filter_map(str_of).collect();
            match w.split_first() {
                Some((f, rest)) if f == "CMD-SHELL" => rest.join(" "),
                Some((f, rest)) if f == "CMD" => rest
                    .iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
                Some((f, _)) if f == "NONE" => return None,
                _ => {
                    n.add(format!("{here}.test"), "not a CMD, CMD-SHELL or NONE test");
                    return None;
                }
            }
        }
        _ => return None,
    };
    if cmd.is_empty() || cmd.len() > 512 || cmd.contains(['\n', '\r', '\0']) {
        n.add(format!("{here}.test"), "not one line of 1-512 characters");
        return None;
    }
    Some(Health { cmd })
}

/// One argument, quoted so a shell reads it back as the same single word.
fn shell_quote(a: &str) -> String {
    let plain = !a.is_empty()
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@%+,".contains(&b));
    if plain {
        a.to_owned()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

fn depends(at: &str, v: &Value, n: &mut Notes) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::Object(m) => {
            for (name, d) in m {
                let cond = d.get("condition").and_then(Value::as_str);
                if let Some(c) =
                    cond.filter(|c| !matches!(*c, "service_started" | "service_healthy"))
                {
                    n.add(
                        format!("{at}.depends_on.{name}"),
                        format!("condition {c} is not supported; plain ordering is used"),
                    );
                }
            }
            m.keys().cloned().collect()
        }
        _ => {
            n.add(format!("{at}.depends_on"), "not a list or a mapping");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests;
