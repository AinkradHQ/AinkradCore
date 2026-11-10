//! Shared test fixtures: a fake `systemctl`/`journalctl`, a temporary state and bin directory, and
//! a socket pair that runs `serve` on one end.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ainkrad_host::{Ctx, Exec, JOURNALCTL, Out, SYSTEMCTL, serve};
use serde_json::{Value, json};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
pub const T0: u64 = 1_794_000_000;

#[derive(Default)]
pub struct Fake {
    pub calls: Mutex<Vec<(String, Vec<String>)>>,
    /// Unit name -> LoadState. Anything absent is `not-found`.
    pub loaded: Mutex<HashMap<String, String>>,
    /// Chronological journal entries: (cursor, priority, MESSAGE).
    pub journal: Mutex<Vec<(String, String, Value)>>,
    pub restart_fails: Mutex<bool>,
    pub journal_fails: Mutex<bool>,
}

impl Fake {
    pub fn argv(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, a)| a.clone())
            .collect()
    }
    pub fn programs(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }
    pub fn restarts(&self) -> usize {
        self.argv()
            .iter()
            .filter(|a| a.get(2).map(String::as_str) == Some("restart"))
            .count()
    }
    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    pub fn load(&self, unit: &str) {
        self.loaded
            .lock()
            .unwrap()
            .insert(unit.into(), "loaded".into());
    }
    pub fn fill_journal(&self, n: usize) {
        *self.journal.lock().unwrap() = (0..n)
            .map(|i| (format!("c{i}"), "6".into(), json!(format!("line {i}"))))
            .collect();
    }
}

pub struct Shared(pub Arc<Fake>);

impl Exec for Shared {
    fn run(&self, prog: &str, args: &[String], _max: usize) -> std::io::Result<Out> {
        let f = &self.0;
        f.calls.lock().unwrap().push((prog.into(), args.into()));
        let ok = |s: String| {
            Ok(Out {
                ok: true,
                stdout: s.into_bytes(),
            })
        };
        match (prog, args.first().map(String::as_str)) {
            (SYSTEMCTL, Some("--no-ask-password"))
                if args.get(1).map(String::as_str) == Some("show") =>
            {
                let unit = args.last().unwrap();
                let load = f
                    .loaded
                    .lock()
                    .unwrap()
                    .get(unit)
                    .cloned()
                    .unwrap_or("not-found".into());
                ok(format!(
                    "LoadState={load}\nActiveState=active\nSubState=running\nActiveEnterTimestamp=Tue 2026-11-10 10:00:00 UTC\nNRestarts=2\n"
                ))
            }
            (SYSTEMCTL, Some("--no-block")) => Ok(Out {
                ok: !*f.restart_fails.lock().unwrap(),
                stdout: vec![],
            }),
            (JOURNALCTL, Some("-u")) => {
                if *f.journal_fails.lock().unwrap() {
                    return Ok(Out {
                        ok: false,
                        stdout: vec![],
                    });
                }
                let j = f.journal.lock().unwrap();
                let n: usize = args[args.iter().position(|a| a == "-n").unwrap() + 1]
                    .parse()
                    .unwrap();
                let rev = args.iter().any(|a| a == "-r");
                let cursor = args.iter().find_map(|a| a.strip_prefix("--cursor="));
                let picked: Vec<&(String, String, Value)> = if rev {
                    let at = j
                        .iter()
                        .position(|e| Some(e.0.as_str()) == cursor)
                        .unwrap_or(j.len());
                    j[..=at.min(j.len() - 1)].iter().rev().take(n).collect()
                } else {
                    j[j.len().saturating_sub(n)..].iter().collect()
                };
                let mut out = String::new();
                for (i, (c, p, m)) in picked.iter().enumerate() {
                    let us = (T0 + i as u64) * 1_000_000;
                    out += &json!({"__CURSOR": c, "__REALTIME_TIMESTAMP": us.to_string(), "PRIORITY": p, "MESSAGE": m}).to_string();
                    out.push('\n');
                }
                ok(out)
            }
            _ => Err(std::io::Error::other("unexpected command")),
        }
    }
}

pub struct Fx {
    pub dir: tempfile::TempDir,
    pub ctx: Ctx,
    pub fake: Arc<Fake>,
    pub clock: Arc<AtomicU64>,
}

pub fn mkdir(p: &Path, mode: u32) {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Fx {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // The helper wants the state directory's parent closed to others, as /var/lib is.
        mkdir(dir.path(), 0o700);
        mkdir(&dir.path().join("state"), 0o700);
        mkdir(&dir.path().join("bin"), 0o755);
        Self::over(dir)
    }

    /// A fresh context over the same directories (a "restarted" helper: no memory but the files).
    pub fn again(self) -> Self {
        Self::over(self.dir)
    }

    fn over(dir: tempfile::TempDir) -> Self {
        let fake = Arc::new(Fake::default());
        fake.load("ainkrad-core.service");
        let clock = Arc::new(AtomicU64::new(T0));
        let c = clock.clone();
        let me = ainkrad_sys::getuid();
        let ctx = Ctx {
            state_dir: dir.path().join("state"),
            bin_dir: dir.path().join("bin"),
            ainkrad_uid: Some(me),
            owner_uid: me,
            exec: Box::new(Shared(fake.clone())),
            now: Box::new(move || c.load(Ordering::SeqCst)),
            hashes: AtomicUsize::new(0),
        };
        Fx {
            dir,
            ctx,
            fake,
            clock,
        }
    }

    pub fn clear_reads(&self) {
        let _ = std::fs::remove_file(self.state().join("reads.json"));
    }

    pub fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }
    pub fn bin(&self) -> PathBuf {
        self.dir.path().join("bin")
    }
    pub fn at(&self, secs_after_t0: u64) {
        self.clock.store(T0 + secs_after_t0, Ordering::SeqCst);
    }
    pub fn id(&self) -> String {
        format!(
            "01HZX3J8K9M2N4P5Q6{:08}",
            NEXT_ID.fetch_add(1, Ordering::SeqCst)
        )
    }

    pub fn line(&self, id: &str, action: &str, params: &str) -> Vec<u8> {
        format!(r#"{{"v":1,"id":"{id}","action":"{action}","params":{params},"actor":{{"device":"d_test-1","audit_seq":42}}}}"#)
            .into_bytes()
    }

    /// Sends `bytes` (plus a newline when `nl`) and returns the raw answer and bytes read.
    pub fn raw(&self, bytes: &[u8], nl: bool) -> (Vec<u8>, usize) {
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::scope(|s| {
            let h = s.spawn(|| serve(&self.ctx, server));
            let mut c = &client;
            let _ = c.write_all(bytes);
            if nl {
                let _ = c.write_all(b"\n");
            }
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out);
            (out, h.join().unwrap())
        })
    }

    pub fn send(&self, bytes: &[u8]) -> Value {
        let (out, _) = self.raw(bytes, true);
        assert_eq!(
            out.iter().filter(|b| **b == b'\n').count(),
            1,
            "one response line"
        );
        serde_json::from_slice(&out).unwrap()
    }

    pub fn call(&self, action: &str, params: &str) -> Value {
        let id = self.id();
        let v = self.send(&self.line(&id, action, params));
        assert_eq!(v["id"], id.as_str());
        v
    }

    pub fn code(&self, action: &str, params: &str) -> String {
        let v = self.call(action, params);
        assert_eq!(v["ok"], false, "{v}");
        v["code"].as_str().unwrap().to_owned()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.state().join("actions.log")).unwrap_or_default()
    }
}

/// Writes an executable file `bin/name` with `body`, mode 0755, and returns its sha256.
pub fn put_bin(fx: &Fx, name: &str, body: &str) -> String {
    let p = fx.bin().join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    sha(body.as_bytes())
}

pub fn sha(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

pub fn manifest(fx: &Fx, entries: &[(&str, &str, &str, usize)]) {
    let bins: Vec<Value> = entries
        .iter()
        .map(|(n, v, s, z)| json!({"name": n, "version": v, "sha256": s, "size": z}))
        .collect();
    std::fs::write(
        fx.state().join("installed.json"),
        json!({"v": 1, "binaries": bins}).to_string(),
    )
    .unwrap();
}
