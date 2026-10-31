//! Request handling shared by the real guest init (vsock) and the unix-socket test stand-in.
use crate::proto::*;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
pub struct Policy {
    /// Drop workload to this uid/gid (None only in unit tests).
    pub uid: Option<u32>,
    /// cgroup v2 root to create per-job groups under (None in unit tests).
    pub cgroup_root: Option<PathBuf>,
}

#[derive(PartialEq, Debug)]
pub enum Next {
    Continue,
    Shutdown,
}

pub fn handle(conn: &mut (impl Read + Write), pol: &Policy) -> io::Result<Next> {
    loop {
        let (t, p) = match read_frame(conn) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Next::Continue),
            Err(e) => return Err(e),
        };
        match t {
            T_PING => write_frame(conn, R_PONG, b"")?,
            T_SHUTDOWN => {
                write_frame(conn, R_ACK, b"")?;
                return Ok(Next::Shutdown);
            }
            T_EXEC => match Exec::decode(&p) {
                Ok(e) => exec(conn, &e, pol)?,
                Err(e) => write_frame(conn, R_ERROR, e.to_string().as_bytes())?,
            },
            _ => write_frame(conn, R_ERROR, b"unknown request")?,
        }
    }
}

fn wr(path: &std::path::Path, v: &str) {
    let _ = std::fs::write(path, v);
}

fn exec(conn: &mut impl Write, e: &Exec, pol: &Policy) -> io::Result<()> {
    static JOB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let cg = pol.cgroup_root.as_ref().map(|r| {
        let d = r.join(format!("job{}", JOB.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        let _ = std::fs::create_dir(&d);
        if e.mem_max > 0 {
            wr(&d.join("memory.max"), &e.mem_max.to_string());
            wr(&d.join("memory.swap.max"), "0");
        }
        if e.pids_max > 0 {
            wr(&d.join("pids.max"), &e.pids_max.to_string());
        }
        d
    });
    let mut cmd = Command::new(&e.argv[0]);
    cmd.args(&e.argv[1..])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for kv in &e.env {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }
    if !e.cwd.is_empty() {
        cmd.current_dir(&e.cwd);
    }
    let uid = pol.uid;
    let procs = cg.as_ref().map(|d| std::ffi::CString::new(d.join("cgroup.procs").to_str().unwrap()).unwrap());
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(p) = &procs {
                let fd = libc::open(p.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::write(fd, b"0".as_ptr().cast(), 1) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(fd);
            }
            libc::setsid();
            let lim = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            let z = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &z);
            if let Some(u) = uid {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(u) != 0
                    || libc::setuid(u) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                // privilege drop must be irreversible
                if libc::setuid(0) == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            if let Some(d) = &cg {
                let _ = std::fs::remove_dir(d);
            }
            return write_frame(conn, R_ERROR, format!("spawn: {err}").as_bytes());
        }
    };
    let mut si = child.stdin.take().unwrap();
    let input = e.stdin.clone();
    std::thread::spawn(move || {
        let _ = si.write_all(&input);
    });
    let (tx, rx) = mpsc::channel::<(u8, Vec<u8>)>();
    let mut readers = 0;
    for (kind, mut s) in [
        (R_OUT, Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>),
        (R_ERR, Box::new(child.stderr.take().unwrap())),
    ] {
        readers += 1;
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut b = vec![0u8; 32 * 1024];
            while let Ok(n) = s.read(&mut b) {
                if n == 0 || tx.send((kind, b[..n].to_vec())).is_err() {
                    break;
                }
            }
            let _ = tx.send((0, vec![]));
        });
    }
    drop(tx);
    let deadline = (e.timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(e.timeout_ms));
    let kill = |cg: &Option<PathBuf>, child: &mut std::process::Child| match cg {
        Some(d) => wr(&d.join("cgroup.kill"), "1"),
        None => unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        },
    };
    let (mut status, mut timed_out, mut done) = (None, false, 0);
    while done < readers || status.is_none() {
        if status.is_none() {
            status = child.try_wait()?;
            if status.is_some() {
                kill(&cg, &mut child); // straggler processes die with the job
            }
        }
        if let Some(dl) = deadline {
            if status.is_none() && !timed_out && Instant::now() >= dl {
                timed_out = true;
                kill(&cg, &mut child);
            }
        }
        match rx.recv_timeout(Duration::from_millis(5)) {
            Ok((0, _)) => done += 1,
            Ok((k, d)) => {
                // frames are bounded: chunk if needed
                for c in d.chunks((MAX_FRAME - 1) as usize) {
                    write_frame(conn, k, c)?;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => done = readers,
        }
    }
    let oom = cg
        .as_ref()
        .and_then(|d| std::fs::read_to_string(d.join("memory.events")).ok())
        .map(|s| s.lines().any(|l| l.starts_with("oom_kill ") && !l.ends_with(" 0")))
        .unwrap_or(false);
    if let Some(d) = &cg {
        for _ in 0..50 {
            if std::fs::remove_dir(d).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // PID 1 reaps the orphans the job left behind
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    let st = status.unwrap();
    let x = Exit { code: st.code().unwrap_or(-1), signal: st.signal().unwrap_or(0), timed_out, oom };
    write_frame(conn, R_EXIT, &x.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn run(e: Exec) -> (Vec<u8>, Vec<u8>, Exit) {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || handle(&mut b, &Policy::default()));
        write_frame(&mut a, T_PING, b"").unwrap();
        assert_eq!(read_frame(&mut a).unwrap().0, R_PONG);
        write_frame(&mut a, T_EXEC, &e.encode()).unwrap();
        let (mut o, mut er) = (vec![], vec![]);
        let x = loop {
            let (t, p) = read_frame(&mut a).unwrap();
            match t {
                R_OUT => o.extend(p),
                R_ERR => er.extend(p),
                R_EXIT => break Exit::decode(&p).unwrap(),
                R_ERROR => panic!("{}", String::from_utf8_lossy(&p)),
                _ => panic!("unexpected {t}"),
            }
        };
        write_frame(&mut a, T_SHUTDOWN, b"").unwrap();
        assert_eq!(read_frame(&mut a).unwrap().0, R_ACK);
        assert_eq!(h.join().unwrap().unwrap(), Next::Shutdown);
        (o, er, x)
    }

    fn sh(s: &str, ms: u64) -> Exec {
        Exec { argv: vec!["/bin/sh".into(), "-c".into(), s.into()], timeout_ms: ms, stdin: b"IN".to_vec(), ..Default::default() }
    }

    #[test]
    fn exec_returns_output_stdin_env_and_exit_code() {
        let mut e = sh("cat; echo \"$A\" >&2; exit 7", 0);
        e.env = vec!["A=x".into()];
        let (o, er, x) = run(e);
        assert_eq!((o, er), (b"IN".to_vec(), b"x\n".to_vec()));
        assert_eq!((x.code, x.timed_out), (7, false));
    }

    #[test]
    fn deadline_kills_the_job_and_reports_it() {
        let t = Instant::now();
        let (_, _, x) = run(sh("sleep 30", 200));
        assert!(x.timed_out && x.signal == libc::SIGKILL && t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn spawn_failure_is_an_error_frame_not_a_hang() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || handle(&mut b, &Policy::default()));
        let e = Exec { argv: vec!["/nonexistent".into()], ..Default::default() };
        write_frame(&mut a, T_EXEC, &e.encode()).unwrap();
        assert_eq!(read_frame(&mut a).unwrap().0, R_ERROR);
        drop(a);
        h.join().unwrap().unwrap();
    }
}
