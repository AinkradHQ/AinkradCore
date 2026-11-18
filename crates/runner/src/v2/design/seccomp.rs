//! The seccomp deny-list bubblewrap applies to a design job (`--seccomp`): classic BPF that answers
//! EPERM to the calls a parser exploit would reach for next (io_uring, bpf, perf, userfaultfd, the
//! keyring, ptrace and cross-process memory, mounts and namespaces, modules, kexec, reboot). Every
//! other call is allowed. A call from another architecture (x32 on x86_64 included) gets EPERM.

const LD_ABS_W: u16 = 0x20;
const JEQ: u16 = 0x15;
const JGE: u16 = 0x35;
const RET: u16 = 0x06;
const ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 0x0005_0001;

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
];

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
];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ARCH: u32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const DENY: &[u32] = &[];

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
    if DENY.is_empty() {
        return None;
    }
    let x32 = cfg!(target_arch = "x86_64");
    let mut ops: Vec<(u16, u8, u8, u32)> = vec![
        (LD_ABS_W, 0, 0, 4), // arch
        (JEQ, 1, 0, ARCH),
        (RET, 0, 0, EPERM),
        (LD_ABS_W, 0, 0, 0), // syscall number
    ];
    let first = ops.len();
    let checks = DENY.len() + usize::from(x32);
    // The EPERM return sits after every check and the ALLOW return.
    let deny_at = first + checks + 1;
    if x32 {
        let here = ops.len();
        ops.push((JGE, (deny_at - here - 1) as u8, 0, 0x4000_0000));
    }
    for nr in DENY {
        let here = ops.len();
        ops.push((JEQ, (deny_at - here - 1) as u8, 0, *nr));
    }
    ops.push((RET, 0, 0, ALLOW));
    ops.push((RET, 0, 0, EPERM));
    debug_assert_eq!(ops.len(), deny_at + 1);
    Some(
        ops.into_iter()
            .flat_map(|(c, t, f, k)| op(c, t, f, k))
            .collect(),
    )
}
