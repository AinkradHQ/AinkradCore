//! Host-side spike driver: boots Firecracker guests, speaks the vsock protocol, runs benches and negative tests.
use spike::proto::*;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn base() -> PathBuf {
    PathBuf::from(std::env::var("SPIKE_DIR").unwrap())
}

#[derive(Clone)]
struct Cfg {
    mem_mib: u32,
    vcpus: u32,
    scratch_mib: u32,
}

struct Vm {
    child: Child,
    dir: PathBuf,
    uds: PathBuf,
    t0: Instant,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

impl Vm {
    fn boot(name: &str, c: &Cfg) -> (Vm, Duration) {
        let b = base();
        let dir = b.join("run").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p0 = Instant::now();
        let scratch = dir.join("scratch.ext4");
        let st = Command::new("cp")
            .args(["--sparse=always", b.join(format!("img/scratch-{}.ext4", c.scratch_mib)).to_str().unwrap(), scratch.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(st.success());
        let prep = p0.elapsed();
        let uds = dir.join("v.sock");
        let img = |n: &str| b.join("img").join(n).display().to_string();
        let cfg = format!(
            r#"{{"boot-source":{{"kernel_image_path":"{k}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd root=/dev/vda ro init=/sbin/guest-init quiet"}},
"drives":[{{"drive_id":"rootfs","path_on_host":"{r}","is_root_device":true,"is_read_only":true}},
{{"drive_id":"scratch","path_on_host":"{s}","is_root_device":false,"is_read_only":false}},
{{"drive_id":"tools","path_on_host":"{t}","is_root_device":false,"is_read_only":true}}],
"machine-config":{{"vcpu_count":{v},"mem_size_mib":{m}}},
"vsock":{{"guest_cid":3,"uds_path":"{u}"}}}}"#,
            k = img("vmlinux-6.1.155"),
            r = img("rootfs.ext4"),
            s = scratch.display(),
            t = img("tools.ext4"),
            v = c.vcpus,
            m = c.mem_mib,
            u = uds.display()
        );
        fs::write(dir.join("fc.json"), cfg).unwrap();
        let t0 = Instant::now();
        let child = Command::new(b.join("fc/firecracker"))
            .args(["--no-api", "--config-file", dir.join("fc.json").to_str().unwrap(), "--level", "Error"])
            .stdin(Stdio::null())
            .stdout(fs::File::create(dir.join("console.log")).unwrap())
            .stderr(fs::File::create(dir.join("fc.err")).unwrap())
            .spawn()
            .expect("spawn firecracker");
        (Vm { child, dir, uds, t0 }, prep)
    }

    /// Retry until the guest listener answers a Ping. Returns the connection and time since spawn.
    fn connect(&mut self, within: Duration) -> Result<(UnixStream, Duration), String> {
        let start = Instant::now();
        loop {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Err(format!("firecracker exited early: {st}"));
            }
            if start.elapsed() > within {
                return Err("guest not ready in time".into());
            }
            if let Ok(mut s) = UnixStream::connect(&self.uds) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                if s.write_all(format!("CONNECT {VSOCK_PORT}\n").as_bytes()).is_ok() {
                    let mut line = String::new();
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    if r.read_line(&mut line).is_ok() && line.starts_with("OK ") {
                        let _ = s.set_read_timeout(None);
                        if write_frame(&mut s, T_PING, b"").is_ok() {
                            if let Ok((R_PONG, _)) = read_frame(&mut s) {
                                return Ok((s, self.t0.elapsed()));
                            }
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// (Rss kB, Pss kB) of the firecracker process: guest RAM touched plus VMM overhead.
    fn mem(&self) -> (u64, u64) {
        let s = fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid())).unwrap_or_default();
        let g = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0);
        (g("Rss:"), g("Pss:"))
    }

    fn shutdown(mut self, s: Option<UnixStream>) -> Duration {
        let t = Instant::now();
        if let Some(mut s) = s {
            let _ = write_frame(&mut s, T_SHUTDOWN, b"");
            let _ = read_frame(&mut s);
        }
        for _ in 0..3000 {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let d = t.elapsed();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
        d
    }

    fn kill(mut self) -> Duration {
        let t = Instant::now();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let d = t.elapsed();
        let _ = fs::remove_dir_all(&self.dir);
        d
    }
}

struct Out {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Exit,
    first_chunk: Option<Duration>,
    chunks: usize,
}

fn exec(s: &mut UnixStream, e: &Exec) -> Result<Out, String> {
    write_frame(s, T_EXEC, &e.encode()).map_err(|x| x.to_string())?;
    let t = Instant::now();
    let mut o = Out { stdout: vec![], stderr: vec![], exit: Exit { code: 0, signal: 0, timed_out: false, oom: false }, first_chunk: None, chunks: 0 };
    loop {
        let (k, p) = read_frame(s).map_err(|x| x.to_string())?;
        match k {
            R_OUT | R_ERR => {
                o.first_chunk.get_or_insert(t.elapsed());
                o.chunks += 1;
                if k == R_OUT { o.stdout.extend(p) } else { o.stderr.extend(p) }
            }
            R_EXIT => {
                o.exit = Exit::decode(&p).map_err(|x| x.to_string())?;
                return Ok(o);
            }
            R_ERROR => return Err(String::from_utf8_lossy(&p).into()),
            _ => return Err(format!("unexpected frame {k}")),
        }
    }
}

fn sh(script: &str) -> Exec {
    Exec {
        argv: vec!["/bin/bash".into(), "-c".into(), script.into()],
        env: vec!["PATH=/usr/local/bin:/usr/bin:/bin".into(), "HOME=/work".into()],
        cwd: "/work".into(),
        timeout_ms: 60_000,
        mem_max: 512 << 20,
        pids_max: 512,
        stdin: vec![],
    }
}

fn pctl(v: &mut Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn bench_boot(n: usize, c: &Cfg) {
    let (mut ready, mut first, mut rss, mut pss, mut down) = (vec![], vec![], vec![], vec![], vec![]);
    for i in 0..n {
        let (mut vm, prep) = Vm::boot(&format!("b{i}"), c);
        let (mut s, r) = vm.connect(Duration::from_secs(30)).expect("boot");
        let o = exec(&mut s, &sh("true")).unwrap();
        let f = vm.t0.elapsed();
        assert_eq!(o.exit.code, 0);
        let (rs, ps) = vm.mem();
        println!("boot {i}: disk_prep_ms={:.1} ready_ms={:.1} first_exec_ms={:.1} rss_kb={rs} pss_kb={ps}", ms(prep), ms(r), ms(f));
        ready.push(ms(r));
        first.push(ms(f));
        rss.push(rs as f64);
        pss.push(ps as f64);
        down.push(ms(vm.shutdown(Some(s))));
    }
    println!("SUMMARY mem={}MiB vcpus={} n={n}", c.mem_mib, c.vcpus);
    for (k, v) in [("ready_ms", &mut ready), ("first_exec_ms", &mut first), ("rss_kb", &mut rss), ("pss_kb", &mut pss), ("shutdown_ms", &mut down)] {
        println!("  {k}: min={:.1} p50={:.1} p95={:.1} max={:.1}", pctl(v, 0.0), pctl(v, 0.5), pctl(v, 0.95), pctl(v, 1.0));
    }
}

fn conc(n: usize) {
    let c = Cfg { mem_mib: 512, vcpus: 1, scratch_mib: 128 };
    let t = Instant::now();
    let hs: Vec<_> = (0..n)
        .map(|i| {
            let c = c.clone();
            std::thread::spawn(move || {
                let (mut vm, _) = Vm::boot(&format!("c{i}"), &c);
                let (mut s, _) = vm.connect(Duration::from_secs(120)).expect("boot");
                let o = exec(&mut s, &sh("true")).unwrap();
                assert_eq!(o.exit.code, 0);
                let first = ms(vm.t0.elapsed());
                // keep each guest busy: 2 s of CPU and 100 MiB touched
                let o = exec(&mut s, &sh("x=$(head -c 100000000 /dev/zero | tr '\\0' a); e=$((SECONDS+2)); while [ $SECONDS -lt $e ]; do :; done; echo ${#x}")).unwrap();
                assert_eq!(o.exit.code, 0, "{}", String::from_utf8_lossy(&o.stderr));
                (vm, s, first)
            })
        })
        .collect();
    let vms: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let wall = t.elapsed();
    let mut firsts: Vec<f64> = vms.iter().map(|v| v.2).collect();
    let (rss, pss): (u64, u64) = vms.iter().map(|v| v.0.mem()).fold((0, 0), |a, m| (a.0 + m.0, a.1 + m.1));
    println!("conc n={n} all_alive_wall_s={:.2} first_exec_ms p50={:.0} max={:.0} sum_rss_mib={} sum_pss_mib={}", wall.as_secs_f64(), pctl(&mut firsts, 0.5), pctl(&mut firsts, 1.0), rss / 1024, pss / 1024);
    for (vm, s, _) in vms {
        vm.shutdown(Some(s));
    }
}

macro_rules! check {
    ($fails:expr, $name:expr, $cond:expr, $($msg:tt)*) => {{
        let ok = $cond;
        println!("{} {}{}", if ok { "PASS" } else { "FAIL" }, $name, if ok { String::new() } else { format!("  -- {}", format!($($msg)*)) });
        if !ok { $fails.push($name); }
    }};
}

fn neg() -> i32 {
    let mut f: Vec<&str> = vec![];
    let canary = format!("CANARY-{}", std::process::id());
    let cpath = std::env::temp_dir().join(&canary);
    fs::write(&cpath, &canary).unwrap();
    let lst = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lst.local_addr().unwrap().port();
    let (mut vm, _) = Vm::boot("neg", &Cfg { mem_mib: 512, vcpus: 2, scratch_mib: 128 });
    let (mut s, _) = vm.connect(Duration::from_secs(30)).expect("boot");

    // the stack runs commands as an unprivileged user
    let o = exec(&mut s, &sh("id -u; id -g; grep CapEff /proc/self/status; grep NoNewPrivs /proc/self/status; cat /proc/1/cmdline; echo rc=$?")).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    check!(f, "non-root uid/gid 1000", t.starts_with("1000\n1000\n"), "{t}");
    check!(f, "no effective capabilities", t.contains("CapEff:\t0000000000000000"), "{t}");
    check!(f, "no_new_privs set", t.contains("NoNewPrivs:\t1"), "{t}");
    check!(f, "PID 1 (guest init) invisible to the job", t.contains("rc=1") || t.contains("rc=2"), "{t}");
    let o = exec(&mut s, &sh("touch /etc/x 2>&1; echo r1=$?; mount -t tmpfs t /mnt 2>&1; echo r2=$?; echo hi > /work/ok && echo r3=$?")).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    check!(f, "rootfs read-only, mount refused, /work writable", t.contains("r1=1") && !t.contains("r2=0") && t.contains("r3=0"), "{t}");
    // host files / runner state
    let o = exec(&mut s, &sh(&format!("find / -xdev -name 'CANARY*' 2>/dev/null | wc -l; grep -rIl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev {canary} / 2>/dev/null | wc -l; ls /home | wc -l; ls /dev | grep -c '^vd'"))).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    let l: Vec<&str> = t.lines().collect();
    check!(f, "host canary file/content absent in guest", l.len() == 4 && l[0] == "0" && l[1] == "0" && l[2] == "0", "{t}");
    check!(f, "guest sees exactly its 3 disks", l.get(3) == Some(&"3"), "{t}");
    // control: the canary is readable on the host
    check!(f, "control: canary readable on host", fs::read_to_string(&cpath).unwrap() == canary, "host read");
    // network
    let probe = |h: &str, p: u16| format!("(exec 3<>/dev/tcp/{h}/{p}) 2>/dev/null && echo REACHED || echo refused");
    let o = exec(&mut s, &sh(&format!("cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' ' | tr '\\n' ,; echo; {}; {}; {}; /sbin/guest-init probe-vsock 2 1234; echo vsock_rc=$?", probe("127.0.0.1", port), probe("169.254.169.254", 80), probe("10.0.0.1", 80)))).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    check!(f, "guest has loopback only (no NIC)", t.starts_with("lo,\n"), "{t}");
    check!(f, "host loopback canary + metadata + LAN unreachable", t.matches("refused").count() == 3 && !t.contains("REACHED"), "{t}");
    check!(f, "guest-initiated vsock to host refused (no listener)", t.contains("vsock_rc=0"), "{t}");
    let ctl = Command::new("/bin/bash").args(["-c", &probe("127.0.0.1", port)]).output().unwrap();
    check!(f, "control: same probe reaches the canary on the host", String::from_utf8_lossy(&ctl.stdout).contains("REACHED"), "probe broken");
    // host process visibility
    let o = exec(&mut s, &sh("ps -e -o comm= | tr '\\n' ' '; echo; ls /proc | grep -c '^[0-9]'")).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    check!(f, "no host processes visible; job sees only own", !t.contains("firecracker") && !t.contains("driver") && t.lines().nth(1).map(|n| n.trim().parse::<u32>().unwrap_or(99) <= 6).unwrap_or(false), "{t}");
    // streaming
    let o = exec(&mut s, &sh("for i in 1 2 3 4 5; do echo line$i; sleep 0.3; done")).unwrap();
    check!(f, "output streams while running (first chunk < 0.6s of 1.5s run, 5 chunks)", o.first_chunk.unwrap() < Duration::from_millis(600) && o.chunks >= 5, "first={:?} chunks={}", o.first_chunk, o.chunks);
    // mock harness: reads a task on stdin, streams JSON-line events, exits 0
    let mut e = sh("read -r task; for s in plan edit test; do echo \"{\\\"event\\\":\\\"$s\\\",\\\"task\\\":$task}\"; sleep 0.1; done; echo '{\"event\":\"done\"}'");
    e.stdin = b"{\"id\":7}\n".to_vec();
    let o = exec(&mut s, &e).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    check!(f, "mock harness completes a task in the guest (stdin in, 4 events out, exit 0)", o.exit.code == 0 && t.lines().count() == 4 && t.contains("\"task\":{\"id\":7}") && t.ends_with("{\"event\":\"done\"}\n"), "{t} {:?}", o.exit);
    // fork bomb
    let mut e = sh("( sleep 2; n=0; for d in /proc/[0-9]*; do c=; read -r c < $d/comm; [ \"$c\" = sleep ] && n=$((n+1)); done; echo $n > /work/alive ) & for i in $(seq 1 400); do sleep 300 & done 2>/dev/null; wait");
    e.pids_max = 64;
    e.timeout_ms = 4000;
    let o = exec(&mut s, &e).unwrap();
    let o2 = exec(&mut s, &sh("cat /work/alive")).unwrap();
    let alive: u32 = String::from_utf8_lossy(&o2.stdout).trim().parse().unwrap_or(999);
    check!(f, "pids.max=64 caps a fork loop (live sleepers <= 64)", alive <= 64 && alive >= 30 && (o.exit.timed_out || o.exit.code != 0), "alive={alive} {:?}", o.exit);
    e.pids_max = 1024;
    let _ = exec(&mut s, &e).unwrap();
    let o2 = exec(&mut s, &sh("cat /work/alive")).unwrap();
    let alive2: u32 = String::from_utf8_lossy(&o2.stdout).trim().parse().unwrap_or(0);
    check!(f, "control: same loop with pids.max=1024 exceeds 64 live sleepers", alive2 > 64, "alive={alive2}");
    let mut e = sh(":(){ :|:& };:; sleep 5");
    e.pids_max = 128;
    e.timeout_ms = 4000;
    let o = exec(&mut s, &e).unwrap();
    check!(f, "real fork bomb ends at the deadline", o.exit.timed_out || o.exit.code != 0 || o.exit.signal != 0, "{:?}", o.exit);
    let o = exec(&mut s, &sh("ps -e | wc -l")).unwrap();
    let n: u32 = String::from_utf8_lossy(&o.stdout).trim().parse().unwrap_or(999);
    check!(f, "guest responsive after the bomb, no stragglers", o.exit.code == 0 && n < 12, "ps lines {n}");
    // memory
    let mut e = sh("tail /dev/zero");
    e.mem_max = 64 << 20;
    let o = exec(&mut s, &e).unwrap();
    check!(f, "memory.max=64MiB kills an unbounded allocation", o.exit.oom && o.exit.signal == 9, "{:?}", o.exit);
    let o = exec(&mut s, &sh("echo alive")).unwrap();
    check!(f, "guest alive after OOM kill", o.stdout == b"alive\n", "");
    // disk
    let o = exec(&mut s, &sh("dd if=/dev/zero of=/work/fill bs=1M count=400 2>/dev/shm/e1; echo rc=$?; grep -c 'No space left' /dev/shm/e1; dd if=/dev/zero of=/tmp/fill bs=1M count=100 2>/dev/shm/e2; echo rc2=$?; grep -c 'No space left' /dev/shm/e2")).unwrap();
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    let img_size = fs::metadata(vm.dir.join("scratch.ext4")).unwrap().len();
    check!(f, "disk fill on /work stops at ENOSPC (image 128 MiB)", t.contains("rc=1\n1\n") && img_size == 128 << 20, "{t} img={img_size}");
    check!(f, "/tmp tmpfs capped at 64 MiB", t.contains("rc2=1\n1\n"), "{t}");
    // deadline inside the guest
    let mut e = sh("sleep 600");
    e.timeout_ms = 1000;
    let t0 = Instant::now();
    let o = exec(&mut s, &e).unwrap();
    check!(f, "guest-side deadline kills the job in ~1s", o.exit.timed_out && t0.elapsed() < Duration::from_secs(3), "{:?} {:?}", o.exit, t0.elapsed());
    // oversize frame: guest drops the connection and keeps serving
    let _ = s.write_all(&(MAX_FRAME + 1).to_be_bytes());
    let _ = s.write_all(&[1]);
    drop(s);
    std::thread::sleep(Duration::from_millis(200));
    let r = vm.connect(Duration::from_secs(5));
    check!(f, "oversize frame rejected; guest still serves a new connection", r.is_ok(), "{:?}", r.as_ref().err());
    let (s2, _) = r.unwrap_or_else(|_| panic!("lost guest"));
    // VM hard kill at the host deadline
    let mut s2 = s2;
    let mut e = sh("sleep 600");
    e.timeout_ms = 0;
    write_frame(&mut s2, T_EXEC, &e.encode()).unwrap();
    s2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let waited = read_frame(&mut s2); // times out: job still running
    let pid = vm.pid();
    let took = vm.kill();
    check!(f, "host deadline: job still running at 2s, then VM killed", waited.is_err() && took < Duration::from_secs(1) && !Path::new(&format!("/proc/{pid}")).exists(), "waited={waited:?} took={took:?}");
    let gone = UnixStream::connect(base().join("run/neg/v.sock")).is_err();
    check!(f, "vsock endpoint gone after kill", gone, "still connectable");
    let _ = fs::remove_file(&cpath);
    println!("{} failures", f.len());
    f.len() as i32
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let num = |i: usize, d: u32| a.get(i).and_then(|v| v.parse().ok()).unwrap_or(d);
    match a.get(1).map(String::as_str) {
        Some("boot-bench") => bench_boot(num(2, 10) as usize, &Cfg { mem_mib: num(3, 512), vcpus: num(4, 1), scratch_mib: 128 }),
        Some("conc") => conc(num(2, 5) as usize),
        Some("neg") => std::process::exit(neg()),
        Some("run") => {
            // run <mem_mib> <vcpus> <script> : one VM, stream output, print timing
            let (mut vm, _) = Vm::boot("run", &Cfg { mem_mib: num(2, 2048), vcpus: num(3, 2), scratch_mib: 2048 });
            let (mut s, r) = vm.connect(Duration::from_secs(30)).expect("boot");
            let mut e = sh(&a[4]);
            e.timeout_ms = 1_800_000;
            e.mem_max = 0;
            e.pids_max = 4096;
            let t = Instant::now();
            let o = exec(&mut s, &e).unwrap();
            print!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            println!("ready_ms={:.0} exec_s={:.2} exit={:?} rss_kb_after={}", ms(r), t.elapsed().as_secs_f64(), o.exit, vm.mem().0);
            vm.shutdown(Some(s));
        }
        _ => eprintln!("usage: driver boot-bench N [mem vcpus] | conc N | neg | run mem vcpus script"),
    }
}
