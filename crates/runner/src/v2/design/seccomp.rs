//! The seccomp deny-list bubblewrap applies to a design job (`--seccomp`): classic BPF that answers
//! EPERM to the calls a parser exploit would reach for next (io_uring, bpf, perf, userfaultfd, the
//! keyring, ptrace and cross-process memory, mounts and namespaces, modules, kexec, reboot). Every
//! other call is allowed. A call from another architecture (x32 on x86_64 included) gets EPERM.
//! Also (round 2): `socket`/`socketpair` only for `AF_UNIX` (all Chromium's IPC needs; the job has no
//! network anyway), `clone` without any namespace flag, `clone3` answers ENOSYS (so libc falls back
//! to `clone`, whose flags a classic filter can read), and `personality`, `kcmp`, `pidfd_getfd` and
//! `process_madvise` are denied.

const LD_ABS_W: u16 = 0x20;
const JEQ: u16 = 0x15;
const JGE: u16 = 0x35;
const JSET: u16 = 0x45;
const RET: u16 = 0x06;
pub(super) const ALLOW: u32 = 0x7fff_0000;
pub(super) const EPERM: u32 = 0x0005_0001;
pub(super) const ENOSYS: u32 = 0x0005_0026;
/// `seccomp_data.args[0]`, its low 32 bits (both supported CPUs are little-endian).
const ARG0: u32 = 16;
const AF_UNIX: u32 = 1;
/// CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
pub(super) const CLONE_NS: u32 = 0x7e02_0000;

#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "x86_64")]
const DENY: &[u32] = &[
    425, 426, 427, // io_uring_setup, _enter, _register
    321, 298, 323, // bpf, perf_event_open, userfaultfd
    248, 249, 250, // add_key, request_key, keyctl
    101, 310, 311, // ptrace, process_vm_readv, _writev
    165, 166, 155, 161, // mount, umount2, pivot_root, chroot
    272, 308, // unshare, setns
    428, 429, 430, 431, 432, 433,
    442, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr
    175, 313, 176, // init_module, finit_module, delete_module
    246, 320, 169, // kexec_load, kexec_file_load, reboot
    303, 304, // name_to_handle_at, open_by_handle_at
    163, 167, 168, 179, // acct, swapon, swapoff, quotactl
    135, 312, 438, 440, // personality, kcmp, pidfd_getfd, process_madvise
];
#[cfg(target_arch = "x86_64")]
pub(super) const NR: Nr = Nr {
    socket: 41,
    socketpair: 53,
    clone: 56,
    clone3: 435,
};

#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "aarch64")]
const DENY: &[u32] = &[
    425, 426, 427, // io_uring_setup, _enter, _register
    280, 241, 282, // bpf, perf_event_open, userfaultfd
    217, 218, 219, // add_key, request_key, keyctl
    117, 270, 271, // ptrace, process_vm_readv, _writev
    40, 39, 41, 51, // mount, umount2, pivot_root, chroot
    97, 268, // unshare, setns
    428, 429, 430, 431, 432, 433,
    442, // open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr
    105, 273, 106, // init_module, finit_module, delete_module
    104, 294, 142, // kexec_load, kexec_file_load, reboot
    264, 265, // name_to_handle_at, open_by_handle_at
    89, 224, 225, 60, // acct, swapon, swapoff, quotactl
    92, 272, 438, 440, // personality, kcmp, pidfd_getfd, process_madvise
];
#[cfg(target_arch = "aarch64")]
pub(super) const NR: Nr = Nr {
    socket: 198,
    socketpair: 199,
    clone: 220,
    clone3: 435,
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ARCH: u32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const DENY: &[u32] = &[];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) const NR: Nr = Nr {
    socket: 0,
    socketpair: 0,
    clone: 0,
    clone3: 0,
};

/// The calls the filter looks at more closely than by number.
pub(super) struct Nr {
    pub(super) socket: u32,
    pub(super) socketpair: u32,
    pub(super) clone: u32,
    pub(super) clone3: u32,
}

/// A jump target: the next instruction, or one of the blocks after the checks.
#[derive(Clone, Copy)]
enum To {
    Next,
    Allow,
    Deny,
    NoSys,
    Domain,
    Flags,
}

fn op(code: u16, jt: u8, jf: u8, k: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..2].copy_from_slice(&code.to_ne_bytes());
    b[2] = jt;
    b[3] = jf;
    b[4..].copy_from_slice(&k.to_ne_bytes());
    b
}

/// The filter as bubblewrap reads it (an array of `struct sock_filter`, native endian); `None` on an
/// architecture without a table (the driver is then not offered).
pub fn program() -> Option<Vec<u8>> {
    use To::{Allow, Deny, Domain, Flags, Next, NoSys};
    if DENY.is_empty() {
        return None;
    }
    let mut p: Vec<(u16, To, To, u32)> = vec![
        (LD_ABS_W, Next, Next, 4), // arch
        (JEQ, Next, Deny, ARCH),
        (LD_ABS_W, Next, Next, 0), // syscall number
    ];
    if cfg!(target_arch = "x86_64") {
        p.push((JGE, Deny, Next, 0x4000_0000)); // x32
    }
    p.push((JEQ, NoSys, Next, NR.clone3));
    p.push((JEQ, Domain, Next, NR.socket));
    p.push((JEQ, Domain, Next, NR.socketpair));
    p.push((JEQ, Flags, Next, NR.clone));
    p.extend(DENY.iter().map(|nr| (JEQ, Deny, Next, *nr)));
    p.push((RET, Next, Next, ALLOW));
    // Every jump is forward: the argument checks, then the three returns.
    let socket = p.len();
    p.push((LD_ABS_W, Next, Next, ARG0)); // domain
    p.push((JEQ, Allow, Deny, AF_UNIX));
    let clone = p.len();
    p.push((LD_ABS_W, Next, Next, ARG0)); // flags
    p.push((JSET, Deny, Allow, CLONE_NS));
    let allow = p.len();
    p.push((RET, Next, Next, ALLOW));
    p.push((RET, Next, Next, EPERM));
    p.push((RET, Next, Next, ENOSYS));
    let at = |t: To| match t {
        Next => None,
        Allow => Some(allow),
        Deny => Some(allow + 1),
        NoSys => Some(allow + 2),
        Domain => Some(socket),
        Flags => Some(clone),
    };
    let mut out = Vec::with_capacity(p.len() * 8);
    for (i, (code, jt, jf, k)) in p.into_iter().enumerate() {
        let off = |t: To| at(t).map_or(0, |to| u8::try_from(to - i - 1).expect("a short jump"));
        out.extend(op(code, off(jt), off(jf), k));
    }
    Some(out)
}
