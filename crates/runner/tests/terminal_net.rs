//! KAN-416: a terminal shell's network, against real bubblewrap. Each refusal has a control (the
//! same probe on the host network succeeds), so a refusal cannot be an artefact of the probe.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::TcpListener;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_runner::egress::{self, Policy};
use ainkrad_runner::v2::termbox::{Net, wrap_net};

fn listener(ip: &str) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let _ = c.write_all(b"hello");
        }
    });
    (port, hits)
}

/// Runs `script` in bash the way a terminal shell is started, and returns its stdout.
async fn shell(net: &Net, script: &str) -> String {
    let (launcher, args) = wrap_net(
        &[],
        &[],
        "/bin/bash",
        &["-c".to_owned(), script.to_owned()],
        "/",
        net,
    )
    .unwrap();
    let out = tokio::process::Command::new(launcher)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_none_shell_has_no_host_network_and_a_filtered_shell_only_the_policy() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "bubblewrap cannot run here: this test must not be skipped"
    );
    let (canary, canary_hits) = listener("127.0.0.1");
    let (target, target_hits) = listener("127.0.0.2");
    let name = format!("termnet-{}", std::process::id());
    let _abstract = UnixListener::bind_addr(&UnixAddr::from_abstract_name(&name).unwrap()).unwrap();
    let tcp = |ip: &str, port: u16| {
        format!(
            "(exec 9<>/dev/tcp/{ip}/{port}) 2>/dev/null && echo OPEN-{port} || echo REFUSED-{port}; "
        )
    };
    let probe = format!(
        "{}{}echo ABSTRACT=$(grep -c {name} /proc/net/unix); echo IFACES=$(tail -n +3 /proc/net/dev | wc -l)",
        tcp("127.0.0.1", canary),
        tcp("127.0.0.2", target),
    );

    // Control: the host network reaches both listeners, sees the abstract socket and the NICs.
    let host = shell(&Net::Host, &probe).await;
    assert!(host.contains(&format!("OPEN-{canary}")), "{host}");
    assert!(host.contains(&format!("OPEN-{target}")), "{host}");
    assert!(host.contains("ABSTRACT=1"), "{host}");
    let before = (
        canary_hits.load(Ordering::SeqCst),
        target_hits.load(Ordering::SeqCst),
    );

    // None: nothing is reachable, the abstract socket is not visible, only `lo` exists.
    let none = shell(&Net::None, &probe).await;
    assert!(none.contains(&format!("REFUSED-{canary}")), "{none}");
    assert!(none.contains(&format!("REFUSED-{target}")), "{none}");
    assert!(none.contains("ABSTRACT=0"), "{none}");
    assert!(none.contains("IFACES=1"), "{none}");
    assert_eq!(
        before,
        (
            canary_hits.load(Ordering::SeqCst),
            target_hits.load(Ordering::SeqCst)
        ),
        "a none shell reached the host network"
    );

    // Filtered: the same direct attempts fail; through the proxy only the listed address passes.
    let dir = std::env::temp_dir().join(format!("termnet-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = Policy::parse("127.0.0.2/32", "", &format!("{target},{canary}")).unwrap();
    let _proxy = egress::start(&egress::socket_in(&dir), Arc::new(policy)).unwrap();
    let net = Net::Filtered {
        dir: dir.clone(),
        exe: PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner")),
    };
    let via = |port: u16, ip: &str| {
        format!(
            "for i in $(seq 40); do exec 3<>/dev/tcp/127.0.0.1/{p} && break; sleep 0.1; done 2>/dev/null; \
             printf 'CONNECT {ip}:{port} HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n' >&3; read -r -t 5 l <&3; echo \"VIA-{port}=$l\"; ",
            p = egress::EGRESS_PORT
        )
    };
    let filtered = shell(
        &net,
        &format!(
            "{probe}; {}{}",
            via(target, "127.0.0.2"),
            via(canary, "127.0.0.1")
        ),
    )
    .await;
    assert!(
        filtered.contains(&format!("REFUSED-{canary}")),
        "{filtered}"
    );
    assert!(
        filtered.contains(&format!("REFUSED-{target}")),
        "{filtered}"
    );
    assert!(filtered.contains("ABSTRACT=0"), "{filtered}");
    assert!(
        filtered.contains(&format!("VIA-{target}=HTTP/1.1 200")),
        "{filtered}"
    );
    assert!(
        !filtered.contains(&format!("VIA-{canary}=HTTP/1.1 200")),
        "{filtered}"
    );
    assert_eq!(
        canary_hits.load(Ordering::SeqCst),
        before.0,
        "the proxy dialled an address the policy does not list"
    );
    assert_eq!(
        target_hits.load(Ordering::SeqCst),
        before.1 + 1,
        "the listed address is reached once"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
