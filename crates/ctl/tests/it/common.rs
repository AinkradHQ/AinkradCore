//! The real `ainkrad-core-server` binary in a scratch home, and `ainkradctl` run as a process
//! against it. Every ctl run's output is kept, so a test can prove no secret was printed.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The server binary, built once per test binary by the same cargo into the same target dir.
pub fn server_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| built("ainkrad-core-server")).clone()
}

/// The real runner binary (`ainkrad-runner`), built the same way.
pub fn runner_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| built("ainkrad-runner")).clone()
}

/// Builds the package's binary of the same name; its path.
fn built(name: &str) -> PathBuf {
    // target/<profile>/deps/<test> → target/<profile>
    let profile_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let target = profile_dir.parent().unwrap().to_owned();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "-p", name, "--bin", name, "--manifest-path"])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", &target)
        .status()
        .expect("running cargo");
    assert!(status.success(), "building {name}");
    profile_dir.join(name)
}

pub const CTL: &str = env!("CARGO_BIN_EXE_ainkradctl");

/// The step-up passphrase every test device seals its step-up key with.
pub const PASSPHRASE: &str = "ctl test step-up passphrase";

/// A file holding [`PASSPHRASE`], given to every ctl run through
/// `$AINKRAD_STEPUP_PASSPHRASE_FILE`, so no run ever waits on a terminal prompt.
pub fn passphrase_file() -> PathBuf {
    static FILE: OnceLock<PathBuf> = OnceLock::new();
    FILE.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("ctl-pass-{}", std::process::id()));
        std::fs::write(&p, format!("{PASSPHRASE}\n")).unwrap();
        p
    })
    .clone()
}

/// ctl with the test passphrase file and stdin closed.
fn ctl_command(args: &[String]) -> Command {
    let mut c = Command::new(CTL);
    c.args(args)
        .env("AINKRAD_STEPUP_PASSPHRASE_FILE", passphrase_file())
        .stdin(Stdio::null());
    c
}

/// What every ctl run printed (stdout and stderr), but `device add`'s, whose job is to print
/// the code.
static PRINTED: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn record(text: String) {
    PRINTED.lock().unwrap().push(text);
}

/// No run printed any of `secrets`, nor anything shaped like a signature (86 base64url
/// characters), a key (100+) or a nonce (22 characters that are 16 bytes of base64url).
pub fn assert_nothing_secret_printed(secrets: &[String]) {
    let all = PRINTED.lock().unwrap();
    assert!(!all.is_empty());
    for text in all.iter() {
        for s in secrets.iter().filter(|s| !s.is_empty()) {
            assert!(!text.contains(s.as_str()), "a secret was printed:\n{text}");
        }
        for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            assert!(
                token.len() != 86 && token.len() < 100,
                "a signature- or key-shaped token was printed: {token}"
            );
            assert!(
                token.len() != 22 || ainkrad_ctl::proto::unb64(token).is_none(),
                "a nonce-shaped token was printed: {token}"
            );
        }
    }
}

/// The base64url PKCS#8 in a keystore file: what must never be printed.
pub fn private_key_of(keystore: &Path) -> String {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(keystore).unwrap()).unwrap();
    v["routine_pkcs8"].as_str().unwrap().to_owned()
}

/// The base64url PKCS#8 of a keystore's step-up key, unsealed: what must never be printed.
pub fn stepup_key_of(keystore: &Path) -> String {
    let ks = ainkrad_ctl::keystore::Keystore::load(keystore).unwrap();
    let path = ainkrad_ctl::stepup::path_for(keystore);
    let key = ainkrad_ctl::stepup::load(&path, PASSPHRASE.as_bytes(), &ks.device_id, &ks.core_fp)
        .unwrap();
    ainkrad_ctl::proto::b64(key.pkcs8())
}

pub struct Core {
    pub dir: PathBuf,
    pub db: PathBuf,
    /// The socket ctl talks to: the main one, or `admin.sock` beside a TCP listener.
    pub sock: PathBuf,
    /// `--host`, when the Core's host is not the socket's `localhost`.
    pub host: Option<String>,
    listen: Vec<String>,
    child: Option<Child>,
}

impl Core {
    /// A Core on a Unix socket in a new home.
    pub fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ctl-{name}-{}", std::process::id()));
        let sock = dir.join("core.sock");
        let listen = vec!["--listen".to_owned(), format!("unix:{}", sock.display())];
        Self::start_with(dir, sock, listen, None, |_| {})
    }

    /// A Core with `listen` flags; `sock` is where its Unix socket (main or admin) appears.
    /// `prepare` runs on the new home before the Core starts.
    pub fn start_with(
        dir: PathBuf,
        sock: PathBuf,
        listen: Vec<String>,
        host: Option<String>,
        prepare: impl FnOnce(&Path),
    ) -> Self {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        prepare(&dir);
        assert!(
            sock.as_os_str().len() < 100,
            "a Unix socket path must stay short: {}",
            sock.display()
        );
        let mut core = Self {
            db: dir.join("core.db"),
            dir,
            sock,
            host,
            listen,
            child: None,
        };
        core.serve();
        core
    }

    fn serve(&mut self) {
        let _ = std::fs::remove_file(&self.sock);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("serve.log"))
            .unwrap();
        let child = Command::new(server_bin())
            .arg("serve")
            .arg(&self.db)
            .args(&self.listen)
            // Tests run many processes at once: the host's real load must not make a runner busy.
            .args(["--max-host-load", "100000"])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(&self.sock).is_err() {
            assert!(
                Instant::now() < deadline,
                "the Core did not start: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `kill -9`, as the exit gate does.
    pub fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn restart(&mut self) {
        self.kill9();
        self.serve();
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    /// `--socket <sock>` (and `--host`).
    pub fn at(&self) -> Vec<String> {
        let mut a = vec!["--socket".into(), self.sock.display().to_string()];
        if let Some(h) = &self.host {
            a.extend(["--host".into(), h.clone()]);
        }
        a
    }

    pub fn keystore(&self, name: &str) -> PathBuf {
        self.dir.join("devices").join(name).join("keystore.json")
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.kill9();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Runs ctl to the end and records what it printed.
pub fn ctl(args: &[String]) -> Output {
    // Every ctl run opens with a pre-auth handshake, and a Core gives one address 30 of those a
    // minute (spec §11), shared by the whole test and by ctl's own single retry. A run refused
    // for that budget alone says nothing about the test: wait for the budget and run it again.
    // No test here asserts the rate limit (the server's own tests do).
    let mut out = ctl_command(args).output().unwrap();
    for _ in 0..8 {
        if out.status.success() || !String::from_utf8_lossy(&out.stderr).contains("rate_limited") {
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
        out = ctl_command(args).output().unwrap();
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !args.iter().any(|a| a == "add") {
        record(text);
    }
    out
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn args(parts: &[&[String]]) -> Vec<String> {
    parts.concat()
}

pub fn s(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

/// The value of the first `key value` line of `text`.
pub fn field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key} ")).map(str::to_owned))
}

/// Reads lines from `out` until one starts with `key `; returns its value and what was read.
pub fn read_until(out: &mut BufReader<ChildStdout>, key: &str, seen: &mut String) -> String {
    loop {
        let mut line = String::new();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "no `{key}` line; got:\n{seen}"
        );
        seen.push_str(&line);
        if let Some(v) = line.trim_end().strip_prefix(&format!("{key} ")) {
            return v.to_owned();
        }
    }
}

/// Starts ctl in the background, stdout and stderr piped.
pub fn spawn_ctl(args: &[String]) -> Child {
    ctl_command(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Starts `ctl pair <credential>` in the background.
pub fn spawn_pair(base: &[String], keystore: &Path, credential: &str, extra: &[String]) -> Child {
    let ks = keystore.display().to_string();
    spawn_ctl(&args(&[
        base,
        &s(&["--keystore", &ks, "pair", credential]),
        extra,
    ]))
}

/// A child's stdout, line by line, with a timeout per line.
pub struct Lines {
    rx: std::sync::mpsc::Receiver<String>,
    pub seen: String,
}

impl Lines {
    pub fn of(out: ChildStdout) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            rx,
            seen: String::new(),
        }
    }

    pub fn next(&mut self, wait: Duration) -> Option<String> {
        let line = self.rx.recv_timeout(wait).ok()?;
        self.seen.push_str(&line);
        self.seen.push('\n');
        Some(line)
    }
}

/// The host's `bootstrap` and ctl's `pair` together, the operator comparing the two SAS lines
/// and typing `y`. Returns the first device's id and the Core fingerprint the host printed.
pub fn bootstrap(core: &Core, keystore: &Path) -> (String, String) {
    let mut boot = Command::new(server_bin())
        .arg("bootstrap")
        .arg(&core.db)
        .arg("admin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut host = BufReader::new(boot.stdout.take().unwrap());
    let mut host_seen = String::new();
    let code = read_until(&mut host, "code", &mut host_seen);
    let core_fp = read_until(&mut host, "core_fp", &mut host_seen);
    let mut pair = spawn_pair(&core.at(), keystore, &code, &s(&["--core-fp", &core_fp]));
    let mut dev = BufReader::new(pair.stdout.take().unwrap());
    let mut dev_seen = String::new();
    let device = read_until(&mut dev, "device", &mut dev_seen);
    let sas = read_until(&mut dev, "sas", &mut dev_seen);
    assert_eq!(
        read_until(&mut host, "sas", &mut host_seen),
        sas,
        "both screens show one SAS"
    );
    boot.stdin.take().unwrap().write_all(b"y\n").unwrap();
    assert!(boot.wait().unwrap().success(), "bootstrap approved");
    assert_eq!(read_until(&mut dev, "status", &mut dev_seen), "active");
    let rest = pair.wait_with_output().unwrap();
    assert!(rest.status.success());
    dev_seen.push_str(&String::from_utf8_lossy(&rest.stdout));
    dev_seen.push_str(&String::from_utf8_lossy(&rest.stderr));
    assert!(
        !dev_seen.contains(&code),
        "the claimant never echoes the code"
    );
    record(dev_seen);
    (device, core_fp)
}
