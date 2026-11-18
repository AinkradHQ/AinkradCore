//! What a run is doing, for `run.observe` (P5-04): per-service health, CPU, memory and restarts
//! from Podman, and the newest log lines. Runs in the helper (as `ainkrad-run`, the only user that
//! can read the project stores). Everything it reads from a container is untrusted text: lines are
//! read through a bounded window (a flood or one endless line costs time, never memory) and the
//! runner redacts them before they are kept (`v2::observe`).

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{LOG_LINE_MAX, ServiceHealth, ServiceMetrics};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Engine, QUICK, container};

/// Lines asked of each service per poll (`podman logs --tail`).
const TAIL: usize = 200;
const LOGS_MAX: Duration = Duration::from_secs(10);

/// One line as the container wrote it, not yet redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawLine {
    pub service: String,
    pub at: String,
    pub text: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Observed {
    /// Empty when the caller asked for lines only.
    pub services: Vec<ServiceMetrics>,
    /// Oldest first.
    pub lines: Vec<RawLine>,
}

/// The newest `keep` lines of `r`, each cut to `max_line` bytes; the rest is read and dropped, so
/// memory stays at `keep * max_line` whatever `r` holds.
pub fn newest_lines(mut r: impl BufRead, keep: usize, max_line: usize) -> VecDeque<String> {
    let mut out: VecDeque<String> = VecDeque::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut push = |cur: &mut Vec<u8>| {
        if out.len() == keep {
            out.pop_front();
        }
        out.push_back(String::from_utf8_lossy(cur).into_owned());
        cur.clear();
    };
    loop {
        let buf = match r.fill_buf() {
            Ok([]) | Err(_) => break,
            Ok(b) => b,
        };
        let (chunk, newline) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..i], true),
            None => (buf, false),
        };
        let room = max_line.saturating_sub(cur.len());
        cur.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let used = chunk.len() + usize::from(newline);
        r.consume(used);
        if newline {
            push(&mut cur);
        }
    }
    if !cur.is_empty() {
        push(&mut cur);
    }
    out
}

/// `2026-11-18T10:00:00.123456789+00:00 text` as `(at, text)`; a line with no timestamp keeps
/// its text whole.
pub fn split_stamp(line: &str) -> (String, String) {
    match line.split_once(' ') {
        Some((at, text))
            if at.len() >= 20
                && at.as_bytes()[0].is_ascii_digit()
                && at.contains('T')
                && at.len() <= 40 =>
        {
            (at.to_owned(), text.to_owned())
        }
        _ => (String::new(), line.to_owned()),
    }
}

/// A sortable key for a Podman timestamp: the whole seconds as text and the nanoseconds. Podman
/// writes one host's offset, so the offset is left out.
pub fn stamp_key(at: &str) -> Option<(String, u32)> {
    let secs = at.get(..19)?;
    let frac = at.get(19..)?.strip_prefix('.').map_or("", |f| {
        &f[..f.find(|c: char| !c.is_ascii_digit()).unwrap_or(f.len())]
    });
    let mut nanos = frac.chars().take(9).collect::<String>();
    while nanos.len() < 9 {
        nanos.push('0');
    }
    Some((secs.to_owned(), nanos.parse().ok()?))
}

/// `1.05MB`, `2 GiB`, `512kB`, `10B` as bytes (Podman prints decimal units).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let i = s.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let n: f64 = s[..i].parse().ok()?;
    let mult: f64 = match s[i..].trim().to_ascii_lowercase().as_str() {
        "b" | "" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "kib" => 1024.0,
        "mib" => 1048576.0,
        "gib" => 1073741824.0,
        "tib" => 1099511627776.0,
        _ => return None,
    };
    Some((n * mult) as u64)
}

/// What `podman stats --no-stream --format json` says per container name: (CPU percent, memory
/// bytes, limit bytes). Field names differ between Podman versions, so a few are tried.
pub fn parse_stats(json: &str) -> BTreeMap<String, (Option<f64>, u64, u64)> {
    let list: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    let pick = |v: &Value, keys: &[&str]| keys.iter().find_map(|k| v.get(*k).cloned());
    let mut out = BTreeMap::new();
    for v in &list {
        let Some(name) = pick(v, &["name", "Name"]).and_then(|n| n.as_str().map(str::to_owned))
        else {
            continue;
        };
        let cpu = pick(v, &["cpu_percent", "CPU", "cpu"]).and_then(|c| match c {
            Value::String(s) => s.trim().trim_end_matches('%').parse().ok(),
            other => other.as_f64(),
        });
        let (mem, limit) = pick(v, &["mem_usage", "MemUsage"])
            .and_then(|m| m.as_str().map(str::to_owned))
            .map(|m| {
                let (a, b) = m.split_once('/').unwrap_or((&m, ""));
                (parse_size(a).unwrap_or(0), parse_size(b).unwrap_or(0))
            })
            .unwrap_or((0, 0));
        out.insert(name.trim_start_matches('/').to_owned(), (cpu, mem, limit));
    }
    out
}

/// A container's `podman inspect`: its restarts, and whether its spec has a health check.
pub fn parse_inspect(json: &str) -> BTreeMap<String, (u32, bool)> {
    let list: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    list.iter()
        .filter_map(|v| {
            let name = v["Name"].as_str()?.trim_start_matches('/').to_owned();
            let restarts = v["RestartCount"]
                .as_u64()
                .or_else(|| v["State"]["Restarts"].as_u64())
                .unwrap_or(0);
            let test = v["Config"]["Healthcheck"]["Test"].as_array();
            let has = test.is_some_and(|t| !t.is_empty() && t[0].as_str() != Some("NONE"));
            Some((name, (u32::try_from(restarts).unwrap_or(u32::MAX), has)))
        })
        .collect()
}

/// `cmd`'s output, its stdout and stderr together (`podman logs` writes a container's stderr to
/// its own), as the newest `keep` lines. In its own process group, killed with the helper and
/// after `timeout`.
fn logs_of(mut cmd: Command, timeout: Duration, keep: usize) -> Result<VecDeque<String>, String> {
    let (r, w) = std::io::pipe().map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::null())
        .stdout(w.try_clone().map_err(|e| e.to_string())?)
        .stderr(w)
        .process_group(0);
    ainkrad_sys::die_with_parent(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| format!("podman logs: {e}"))?;
    // The pipe's write ends live in `cmd`; without this the read below never sees the end.
    drop(cmd);
    let pgid = child.id();
    let (done, wait) = std::sync::mpsc::channel::<()>();
    let dog = std::thread::spawn(move || {
        if wait.recv_timeout(timeout) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            if let Some(kill) = ainkrad_sys::signal_number("KILL") {
                let _ = ainkrad_sys::killpg(pgid, kill);
            }
        }
    });
    let lines = newest_lines(BufReader::new(r), keep, LOG_LINE_MAX + 64);
    let _ = child.wait();
    drop(done);
    let _ = dog.join();
    Ok(lines)
}

impl Engine {
    /// The project whose store holds `run`, and its services (name, state).
    fn run_services(&self, run: &str) -> Result<Option<(u64, Vec<(String, String)>)>, String> {
        let deadline = Instant::now() + QUICK;
        for p in self.stores() {
            let info = self.status_by(run, p, deadline)?;
            if !info.services.is_empty() {
                let s = info
                    .services
                    .into_iter()
                    .map(|s| (s.name, s.state))
                    .collect();
                return Ok(Some((p, s)));
            }
        }
        Ok(None)
    }

    /// The services' metrics (when `metrics`) and the newest lines of the run's services (of
    /// `only`, when given) written at or after `since`. An unknown run is empty.
    pub fn observe(
        &self,
        run: &str,
        only: Option<&str>,
        since: Option<&str>,
        metrics: bool,
    ) -> Result<Observed, String> {
        let Some((project, services)) = self.run_services(run)? else {
            return Ok(Observed::default());
        };
        let names: Vec<String> = services.iter().map(|(s, _)| container(run, s)).collect();
        let mut out = Observed::default();
        if metrics {
            out.services = self.metrics(project, &services, &names);
        }
        let mut lines: Vec<(String, RawLine)> = Vec::new();
        for ((service, _), ctr) in services.iter().zip(&names) {
            if only.is_some_and(|o| o != service) {
                continue;
            }
            let tail = TAIL.to_string();
            let mut args = vec!["logs", "--timestamps", "--tail", &tail];
            if let Some(s) = since {
                args.extend(["--since", s]);
            }
            args.push(ctr);
            let got = logs_of(self.podman_cmd(project, &args), LOGS_MAX, TAIL).unwrap_or_default();
            for l in got {
                let (at, text) = split_stamp(&l);
                lines.push((
                    at.clone(),
                    RawLine {
                        service: service.clone(),
                        at,
                        text,
                    },
                ));
            }
        }
        // Oldest first, across services (a stable sort keeps one service's own order).
        lines.sort_by_key(|(at, _)| stamp_key(at));
        out.lines = lines.into_iter().map(|(_, l)| l).collect();
        Ok(out)
    }

    fn metrics(
        &self,
        project: u64,
        services: &[(String, String)],
        names: &[String],
    ) -> Vec<ServiceMetrics> {
        let deadline = Instant::now() + QUICK;
        let refs = |first: &[&'static str]| -> Vec<&str> {
            first
                .iter()
                .copied()
                .chain(names.iter().map(String::as_str))
                .collect()
        };
        let stats = self
            .podman(
                project,
                &refs(&["stats", "--no-stream", "--format", "json"]),
                deadline,
            )
            .map(|j| parse_stats(&j))
            .unwrap_or_default();
        let inspected = self
            .podman(project, &refs(&["inspect", "--format", "json"]), deadline)
            .map(|j| parse_inspect(&j))
            .unwrap_or_default();
        services
            .iter()
            .zip(names)
            .map(|((name, state), ctr)| {
                let (cpu, memory_bytes, memory_limit_bytes) =
                    stats.get(ctr).copied().unwrap_or((None, 0, 0));
                let (restarts, has_health) = inspected.get(ctr).copied().unwrap_or((0, false));
                let running = state == "running";
                // Our health checks are not on a timer (`--health-interval disable`): run it now.
                let health = match (running, has_health) {
                    (true, true) => {
                        match self.podman(project, &["healthcheck", "run", ctr], deadline) {
                            Ok(_) => ServiceHealth::Healthy,
                            Err(_) => ServiceHealth::Unhealthy,
                        }
                    }
                    _ => ServiceHealth::None,
                };
                ServiceMetrics {
                    name: name.clone(),
                    state: state.clone(),
                    health,
                    cpu_percent: if running { cpu } else { None },
                    memory_bytes: if running { memory_bytes } else { 0 },
                    memory_limit_bytes,
                    restarts,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    #[test]
    fn the_window_keeps_the_newest_lines_and_cuts_long_ones() {
        let mut data = String::new();
        for i in 0..1000 {
            data.push_str(&format!("line {i}\n"));
        }
        let got = newest_lines(Cursor::new(data), 3, 100);
        assert_eq!(got, ["line 997", "line 998", "line 999"]);
        let long = format!("{}\nok\n", "x".repeat(100_000));
        let got = newest_lines(Cursor::new(long), 5, 64);
        assert_eq!(got[0].len(), 64);
        assert_eq!(got[1], "ok");
    }

    #[test]
    fn an_endless_line_is_read_in_bounded_memory() {
        // 64 MiB with no newline: the window never holds more than `max_line`.
        let endless = BufReader::new(std::io::repeat(b'a').take(64 << 20));
        let got = newest_lines(endless, 10, 128);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].len(), 128);
    }

    #[test]
    fn stamps_split_and_sort() {
        let (at, text) = split_stamp("2026-11-18T10:00:00.5+00:00 hello world");
        assert_eq!(
            (at.as_str(), text.as_str()),
            ("2026-11-18T10:00:00.5+00:00", "hello world")
        );
        assert_eq!(split_stamp("no stamp here").0, "");
        let a = stamp_key("2026-11-18T10:00:00.5+00:00").unwrap();
        let b = stamp_key("2026-11-18T10:00:00.123456789+00:00").unwrap();
        assert!(b < a, "0.123 is before 0.5");
        assert_eq!(a.1, 500_000_000);
    }

    #[test]
    fn sizes_and_stats_read() {
        assert_eq!(parse_size("1.5kB"), Some(1500));
        assert_eq!(parse_size("2MiB"), Some(2 << 20));
        assert_eq!(parse_size("10B"), Some(10));
        assert_eq!(parse_size("junk"), None);
        let json = r#"[{"name":"ainkrad-r1-web","cpu_percent":"12.50%","mem_usage":"20.5MB / 268.4MB"},
                       {"Name":"ainkrad-r1-db","CPU":3.0,"MemUsage":"1GB / 2GB"}]"#;
        let s = parse_stats(json);
        assert_eq!(s["ainkrad-r1-web"], (Some(12.5), 20_500_000, 268_400_000));
        assert_eq!(
            s["ainkrad-r1-db"],
            (Some(3.0), 1_000_000_000, 2_000_000_000)
        );
    }

    #[test]
    fn inspect_reads_restarts_and_health_checks() {
        let json = r#"[{"Name":"ainkrad-r1-db","RestartCount":2,
                        "Config":{"Healthcheck":{"Test":["CMD-SHELL","pg_isready"]}}},
                       {"Name":"ainkrad-r1-web","Config":{"Healthcheck":{"Test":["NONE"]}}}]"#;
        let i = parse_inspect(json);
        assert_eq!(i["ainkrad-r1-db"], (2, true));
        assert_eq!(i["ainkrad-r1-web"], (0, false));
    }
}
