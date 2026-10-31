//! PID 1 of the spike guest. Mounts only what it needs, listens on vsock, runs jobs as uid 1000.
use spike::proto::VSOCK_PORT;
use spike::serve::{handle, Next, Policy};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;

fn mount(src: &str, dst: &str, fs: &str, flags: u64, data: &str) {
    let (s, d, f, o) = (CString::new(src).unwrap(), CString::new(dst).unwrap(), CString::new(fs).unwrap(), CString::new(data).unwrap());
    let _ = std::fs::create_dir_all(dst);
    let r = unsafe { libc::mount(s.as_ptr(), d.as_ptr(), f.as_ptr(), flags, o.as_ptr().cast()) };
    if r != 0 {
        eprintln!("init: mount {dst}: {}", std::io::Error::last_os_error());
    }
}

/// `guest-init probe-vsock <cid> <port>`: exit 0 if the connect is refused (used by negative tests).
fn probe_vsock(cid: u32, port: u32) -> i32 {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as _;
    a.svm_port = port;
    a.svm_cid = cid;
    let r = unsafe { libc::connect(fd, (&a as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&a) as u32) };
    if r == 0 { 99 } else { 0 }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 4 && a[1] == "probe-vsock" {
        std::process::exit(probe_vsock(a[2].parse().unwrap(), a[3].parse().unwrap()));
    }
    let (nsd, ro) = (libc::MS_NOSUID | libc::MS_NODEV, libc::MS_RDONLY);
    mount("proc", "/proc", "proc", nsd | libc::MS_NOEXEC, "hidepid=2");
    mount("sysfs", "/sys", "sysfs", nsd | libc::MS_NOEXEC, "");
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "mode=0755");
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2", nsd | libc::MS_NOEXEC, "");
    mount("tmpfs", "/tmp", "tmpfs", nsd, "mode=1777,size=64m");
    mount("tmpfs", "/dev/shm", "tmpfs", nsd | libc::MS_NOEXEC, "mode=1777,size=64m");
    mount("/dev/vdb", "/work", "ext4", nsd, "");
    mount("/dev/vdc", "/opt/tools", "ext4", nsd | ro, "");
    unsafe { libc::chown(CString::new("/work").unwrap().as_ptr(), 1000, 1000) };
    // controllers for per-job limits (the root cgroup may hold PID 1 itself)
    let _ = std::fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+memory +pids");

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "vsock socket");
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as _;
    a.svm_port = VSOCK_PORT;
    a.svm_cid = u32::MAX; // VMADDR_CID_ANY
    let r = unsafe { libc::bind(fd, (&a as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&a) as u32) };
    assert!(r == 0 && unsafe { libc::listen(fd, 4) } == 0, "vsock bind/listen");
    let pol = Policy { uid: Some(1000), cgroup_root: Some("/sys/fs/cgroup".into()) };
    loop {
        let c = unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if c < 0 {
            continue;
        }
        let mut conn = unsafe { File::from_raw_fd(c) };
        if let Ok(Next::Shutdown) = handle(&mut conn, &pol) {
            unsafe {
                libc::sync();
                libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
            }
        }
    }
}
