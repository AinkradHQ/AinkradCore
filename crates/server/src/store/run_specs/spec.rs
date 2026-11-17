//! The run spec (Core 0.9, P4-01): what a project runs, as JSON.
//!
//! Security model: a spec is untrusted input that ends up as `podman` arguments on a runner (P5).
//! So the shape itself cannot say the dangerous things: every struct is `deny_unknown_fields`, and
//! there is no field for `privileged`, a network mode, a capability, a device or a host path. A
//! volume is a NAME (the runner makes `ainkrad-p<id>-<name>`) mounted at a container path, never
//! a host directory; a repo is mounted only by its name from the project's own checkout. Images
//! are checked against the reference grammar, so one can never be read as a flag. Secrets are
//! only ever `${secret:NAME}` (the value is sealed elsewhere and never in the spec). Everything
//! here is pure: no I/O, no clock.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

pub const MAX_SERVICES: usize = 16;
pub const MAX_PORTS: usize = 8;
pub const MAX_VOLUMES: usize = 8;
pub const MAX_ENV: usize = 64;
pub const MAX_COMMAND: usize = 64;

/// The whole spec: its services by name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    /// 1-16 services. A name is 1-20 of `a-z0-9-`, starting with a letter: it is the service's
    /// network alias and part of its public host name.
    pub services: BTreeMap<String, Service>,
}

/// One container. Exactly one of `image` and `build`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// An image reference such as `postgres:17` or `ghcr.io/acme/app@sha256:...`.
    pub image: Option<String>,
    /// Build the image from a Dockerfile in one of the project's repos.
    pub build: Option<Build>,
    /// Mount this project repo's checkout at `/repo/<name>`.
    pub repo: Option<String>,
    /// Absolute path inside the container; default is the image's.
    pub workdir: Option<String>,
    /// Replaces the image's command; at most 64 arguments.
    pub command: Option<Vec<String>>,
    /// Environment. A value is plain text or contains `${secret:NAME}` references.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Named volumes: volume name to the absolute container path it is mounted at.
    #[serde(default)]
    pub volumes: BTreeMap<String, String>,
    /// At most 8 ports the service listens on.
    #[serde(default)]
    pub ports: Vec<Port>,
    /// Services that must be started (and healthy, when they have a `health`) first.
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub health: Option<Health>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// A repo of the project.
    pub repo: String,
    /// Path of the Dockerfile inside that repo; default `Dockerfile`.
    pub dockerfile: Option<String>,
    /// Build context inside that repo; default `.`.
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Port {
    /// The container port, 1-65535. It is only ever published on the runner's loopback.
    pub port: u16,
    /// Give it a public URL (when the project is exposed); at most one per service.
    #[serde(default)]
    pub expose: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// Run inside the container, one line of 1-512 characters; exit 0 is healthy.
    pub cmd: String,
}

/// `path: what is wrong`, the first problem found.
pub type Problem = String;

fn bad<T>(path: &str, why: impl std::fmt::Display) -> Result<T, Problem> {
    Err(format!("{path}: {why}"))
}

/// Parses and validates; the problem names the path of the bad field (`services.web.ports[0].port`).
pub fn parse(v: &Value) -> Result<RunSpec, Problem> {
    let spec: RunSpec = serde_path_to_error::deserialize(v).map_err(|e| {
        let path = e.path().to_string();
        let path = if path == "." { "spec" } else { path.as_str() };
        format!("{path}: {}", e.inner())
    })?;
    validate(&spec)?;
    Ok(spec)
}

pub fn validate(spec: &RunSpec) -> Result<(), Problem> {
    if !(1..=MAX_SERVICES).contains(&spec.services.len()) {
        return bad(
            "services",
            format!(
                "a spec has 1-{MAX_SERVICES} services, not {}",
                spec.services.len()
            ),
        );
    }
    for (name, s) in &spec.services {
        service(spec, name, s)?;
    }
    cycle(spec)
}

fn service_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=20).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[b.len() - 1] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn service(spec: &RunSpec, name: &str, s: &Service) -> Result<(), Problem> {
    let at = format!("services.{name}");
    if !service_name_ok(name) {
        return bad(
            &at,
            "a service name is 1-20 of a-z, 0-9 and -, starting with a letter, not ending in -",
        );
    }
    match (&s.image, &s.build) {
        (Some(_), Some(_)) => return bad(&at, "give an image or a build, not both"),
        (None, None) => return bad(&at, "give an image or a build"),
        (Some(i), None) => {
            if let Some(why) = image_ref_problem(i) {
                return bad(&format!("{at}.image"), why);
            }
        }
        (None, Some(b)) => {
            if b.repo.is_empty() {
                return bad(&format!("{at}.build.repo"), "name a repo of the project");
            }
            for (key, p, dot_ok) in [
                ("dockerfile", &b.dockerfile, false),
                ("context", &b.context, true),
            ] {
                if let Some(p) = p
                    && let Some(why) = rel_path_problem(p, dot_ok)
                {
                    return bad(&format!("{at}.build.{key}"), why);
                }
            }
        }
    }
    if let Some(w) = &s.workdir
        && let Some(why) = abs_path_problem(w)
    {
        return bad(&format!("{at}.workdir"), why);
    }
    if let Some(c) = &s.command
        && (c.is_empty()
            || c.len() > MAX_COMMAND
            || c.iter().any(|a| a.len() > 4096 || a.contains('\0')))
    {
        return bad(
            &format!("{at}.command"),
            format!("1-{MAX_COMMAND} arguments of up to 4096 characters, no NUL"),
        );
    }
    env(&at, &s.env)?;
    volumes(&at, &s.volumes)?;
    ports(&at, &s.ports)?;
    if let Some(h) = &s.health
        && !((1..=512).contains(&h.cmd.len()) && !h.cmd.contains(['\n', '\r', '\0']))
    {
        return bad(&format!("{at}.health.cmd"), "one line of 1-512 characters");
    }
    let mut seen = BTreeSet::new();
    for (i, d) in s.depends_on.iter().enumerate() {
        let here = format!("{at}.depends_on[{i}]");
        if d == name {
            return bad(&here, "a service cannot depend on itself");
        }
        if !spec.services.contains_key(d) {
            return bad(&here, format!("no service named {d}"));
        }
        if !seen.insert(d) {
            return bad(&here, format!("{d} is listed twice"));
        }
    }
    Ok(())
}

fn env(at: &str, env: &BTreeMap<String, String>) -> Result<(), Problem> {
    if env.len() > MAX_ENV {
        return bad(&format!("{at}.env"), format!("at most {MAX_ENV} variables"));
    }
    for (k, v) in env {
        let here = format!("{at}.env.{k}");
        let b = k.as_bytes();
        if !((1..=128).contains(&b.len())
            && (b[0].is_ascii_alphabetic() || b[0] == b'_')
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'))
        {
            return bad(
                &here,
                "a variable name is [A-Za-z_][A-Za-z0-9_]*, up to 128",
            );
        }
        if v.len() > 4096 || v.contains('\0') {
            return bad(&here, "a value is up to 4096 characters, no NUL");
        }
        if let Err(why) = secret_refs_in(v) {
            return bad(&here, why);
        }
    }
    Ok(())
}

fn volumes(at: &str, vols: &BTreeMap<String, String>) -> Result<(), Problem> {
    if vols.len() > MAX_VOLUMES {
        return bad(
            &format!("{at}.volumes"),
            format!("at most {MAX_VOLUMES} volumes"),
        );
    }
    let mut paths = BTreeSet::new();
    for (name, path) in vols {
        let here = format!("{at}.volumes.{name}");
        let b = name.as_bytes();
        if !((1..=40).contains(&b.len())
            && b[0].is_ascii_alphanumeric()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c)))
        {
            return bad(
                &here,
                "a volume is a name of a-z, 0-9, _ and - (a host path cannot be expressed)",
            );
        }
        if let Some(why) = abs_path_problem(path) {
            return bad(&here, why);
        }
        if path == "/" || path == "/repo" || path.starts_with("/repo/") {
            return bad(&here, "a volume cannot cover / or the /repo checkouts");
        }
        if !paths.insert(path) {
            return bad(&here, "another volume is mounted at that path");
        }
    }
    Ok(())
}

fn ports(at: &str, ports: &[Port]) -> Result<(), Problem> {
    if ports.len() > MAX_PORTS {
        return bad(&format!("{at}.ports"), format!("at most {MAX_PORTS} ports"));
    }
    let mut seen = BTreeSet::new();
    for (i, p) in ports.iter().enumerate() {
        if p.port == 0 {
            return bad(&format!("{at}.ports[{i}].port"), "a port is 1-65535");
        }
        if !seen.insert(p.port) {
            return bad(&format!("{at}.ports[{i}].port"), "listed twice");
        }
    }
    // ponytail: one public port per service (a host name maps to one port); which service is the
    // project's primary URL is P6's to decide.
    if ports.iter().filter(|p| p.expose).count() > 1 {
        return bad(
            &format!("{at}.ports"),
            "at most one port per service is exposed",
        );
    }
    Ok(())
}

fn cycle(spec: &RunSpec) -> Result<(), Problem> {
    // 1 = on the current path, 2 = done.
    fn visit<'a>(
        spec: &'a RunSpec,
        n: &'a str,
        state: &mut BTreeMap<&'a str, u8>,
    ) -> Result<(), Problem> {
        match state.get(n) {
            Some(2) => return Ok(()),
            Some(_) => return bad(&format!("services.{n}.depends_on"), "a dependency cycle"),
            None => {}
        }
        state.insert(n, 1);
        for d in &spec.services[n].depends_on {
            visit(spec, d, state)?;
        }
        state.insert(n, 2);
        Ok(())
    }
    let mut state = BTreeMap::new();
    for n in spec.services.keys() {
        visit(spec, n, &mut state)?;
    }
    Ok(())
}

/// An absolute path inside the container: no `..`, `.` or empty parts, no NUL or newline.
fn abs_path_problem(p: &str) -> Option<&'static str> {
    let ok = p.len() <= 255
        && p.starts_with('/')
        && !p.contains(['\0', '\n', '\r'])
        && (p == "/" || p[1..].split('/').all(|c| !matches!(c, "" | "." | "..")));
    (!ok).then_some("an absolute container path of up to 255 characters, with no .. parts")
}

/// A path inside a repo: relative, no `..`; `dot_ok` allows `.` alone (a context).
fn rel_path_problem(p: &str, dot_ok: bool) -> Option<&'static str> {
    let ok = !p.is_empty()
        && p.len() <= 255
        && !p.starts_with('/')
        && !p.contains(['\0', '\n', '\r'])
        && ((p == "." && dot_ok) || p.split('/').all(|c| !matches!(c, "" | "." | "..")));
    (!ok).then_some("a path inside the repo: relative, up to 255 characters, with no .. parts")
}

/// The names a `${secret:NAME}` reference may carry: the same rule as a secret's own name.
pub use crate::store::secrets::valid_name as secret_name_ok;

/// Every `${secret:NAME}` in `v`. Any other use of `${` is an error: compose-style interpolation
/// is not supported, and a half-written reference must not slip through as plain text.
pub fn secret_refs_in(v: &str) -> Result<Vec<&str>, &'static str> {
    let mut out = Vec::new();
    let mut rest = v;
    while let Some(i) = rest.find("${") {
        let after = &rest[i + 2..];
        let Some(end) = after.find('}') else {
            return Err("an unterminated ${...}; a secret is written ${secret:NAME}");
        };
        match after[..end].strip_prefix("secret:") {
            Some(n) if secret_name_ok(n) => out.push(n),
            _ => {
                return Err(
                    "only ${secret:NAME} may use ${...}, NAME being [a-z][a-z0-9_.-]{0,63}",
                );
            }
        }
        rest = &after[end + 1..];
    }
    Ok(out)
}

/// The secret names a spec refers to. P4-04 checks them against the project's secret group.
pub fn secret_refs(spec: &RunSpec) -> BTreeSet<String> {
    spec.services
        .values()
        .flat_map(|s| s.env.values())
        .flat_map(|v| secret_refs_in(v).unwrap_or_default())
        .map(str::to_owned)
        .collect()
}

/// `(path, repo name)` for every repo the spec mounts or builds from.
pub fn repo_refs(spec: &RunSpec) -> Vec<(String, &str)> {
    let mut out = Vec::new();
    for (n, s) in &spec.services {
        if let Some(r) = &s.repo {
            out.push((format!("services.{n}.repo"), r.as_str()));
        }
        if let Some(b) = &s.build {
            out.push((format!("services.{n}.build.repo"), b.repo.as_str()));
        }
    }
    out
}

const BAD_IMAGE: &str =
    "not a valid image reference such as postgres:17 or ghcr.io/acme/app@sha256:<64 hex>";

/// What is wrong with an image reference, per the distribution grammar
/// `[host[:port]/]path[:tag][@sha256:<64 hex>]`; `None` when it is fine. Keeps a reference from
/// being a flag (`--privileged`), holding whitespace, or being an unparseable name.
pub fn image_ref_problem(r: &str) -> Option<&'static str> {
    if r.is_empty() || r.len() > 255 || r.bytes().any(|b| !b.is_ascii_graphic()) {
        return Some(BAD_IMAGE);
    }
    let (name, digest) = r.split_once('@').map_or((r, None), |(n, d)| (n, Some(d)));
    if let Some(d) = digest
        && !d.strip_prefix("sha256:").is_some_and(|h| {
            h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        return Some(BAD_IMAGE);
    }
    // A tag follows the last `:` when that comes after the last `/` (else it is a registry port).
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    let (path, tag) = match name[slash..].rfind(':') {
        Some(i) => (&name[..slash + i], Some(&name[slash + i + 1..])),
        None => (name, None),
    };
    if let Some(t) = tag {
        let b = t.as_bytes();
        let ok = (1..=128).contains(&b.len())
            && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c));
        if !ok {
            return Some(BAD_IMAGE);
        }
    }
    let parts: Vec<&str> = path.split('/').collect();
    let (domain, comps) = match parts.as_slice() {
        [d, rest @ ..] if !rest.is_empty() && (d.contains(['.', ':']) || *d == "localhost") => {
            (Some(*d), rest)
        }
        all => (None, all),
    };
    if domain.is_some_and(|d| !domain_ok(d)) || !comps.iter().all(|c| path_component_ok(c)) {
        return Some(BAD_IMAGE);
    }
    None
}

fn domain_ok(d: &str) -> bool {
    let (host, port) = d.split_once(':').map_or((d, None), |(h, p)| (h, Some(p)));
    port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        && host.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `[a-z0-9]+` runs joined by one separator: `.`, `_`, `__` or any number of `-`.
fn path_component_ok(c: &str) -> bool {
    let alnum = |ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit();
    let mut rest = c;
    loop {
        let after_run = rest.trim_start_matches(alnum);
        if after_run.len() == rest.len() {
            return false; // an empty run: leading, doubled or trailing separator
        }
        if after_run.is_empty() {
            return true;
        }
        let next = after_run.trim_start_matches(|ch: char| !alnum(ch));
        let sep = &after_run[..after_run.len() - next.len()];
        if !(matches!(sep, "." | "_" | "__") || sep.bytes().all(|b| b == b'-')) {
            return false;
        }
        rest = next;
    }
}
